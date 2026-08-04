#!/usr/bin/env python3
"""Controls for check-custody-tier.py, driven in BOTH directions.

A gate that has never been shown to FAIL has not been shown to work, and this one is
easy to get wrong in the direction that reads as success: a parser that returns an empty
import list makes every component look minimal, and a capability map that classifies
everything as harmless makes every manifest look honest. Both would print a clean sweep.

So every must-fail case here is paired with a near-miss that must still PASS, differing
only in the discriminating feature, and the parser cases assert an exact expected list
rather than merely "did not raise".

CASE 1 IS THE INCIDENT SHAPE VERBATIM: a manifest asserting a capability set narrower
than its binary's import table. That is the class this gate exists for. If case 1 stops
failing, the gate is decorative.

The component fixtures are synthesized byte-for-byte from the encoding measured off a
real `cargo build --target wasm32-wasip2 --release` artifact, so the suite pins the
encoding and runs in a fresh clone with nothing built. When real artifacts ARE present
the suite additionally cross-checks the parser against them, and says so; when they are
absent it reports those cases as SKIPPED rather than counting them as passes, because a
skipped case that tallies as green is the exact false-green this gate is built against.

Run: python scripts/test_check_custody_tier.py
"""

import importlib.util
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent
GATE = (
    pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else HERE / "check-custody-tier.py"
)

spec = importlib.util.spec_from_file_location("cct", GATE)
cct = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cct)

passed = failed = skipped = 0


def check(name, cond, detail: object = ""):
    global passed, failed
    if cond:
        passed += 1
        print(f"  ok    {name}")
    else:
        failed += 1
        print(f"  FAIL  {name}  {detail}")


def skip(name, why):
    global skipped
    skipped += 1
    print(f"  skip  {name}  ({why})")


# --------------------------------------------------------------------------------------
# Component fixtures, synthesized from the encoding measured off a real artifact:
#   magic "\0asm" | layer 0d000100 | per import section: id 10, leb size,
#   count=1, kind byte 0x00, leb name length, utf-8 name, then a type descriptor.


def leb(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


def import_section(name: str, *, count: int = 1, kind: int = 0x00) -> bytes:
    body = leb(count) + bytes([kind]) + leb(len(name)) + name.encode() + b"\x05\x00"
    return bytes([cct.IMPORT_SECTION]) + leb(len(body)) + body


def component(*names: str, **kw) -> bytes:
    return (
        b"\x00asm"
        + cct.COMPONENT_LAYER
        + b"".join(import_section(n, **kw) for n in names)
    )


TYPICAL = (
    "zeroclaw:plugin/types@0.1.0",
    "zeroclaw:plugin/logging@0.1.0",
    "wasi:io/streams@0.2.9",
    "wasi:cli/stdout@0.2.9",
    "wasi:http/outgoing-handler@0.2.9",
)

print("\n-- parser --")

check(
    "reads every import name from a multi-section component",
    cct.component_imports(component(*TYPICAL)) == list(TYPICAL),
    cct.component_imports(component(*TYPICAL)),
)


def raises(fn, needle):
    try:
        fn()
    except cct.BadComponent as e:
        return needle in str(e)
    except Exception:
        return False
    return False


check(
    "refuses a core module rather than reporting zero imports",
    raises(
        lambda: cct.component_imports(b"\x00asm\x01\x00\x00\x00"), "not a component"
    ),
)
check(
    "refuses a non-wasm file",
    raises(lambda: cct.component_imports(b"not a wasm file at all"), "not a wasm"),
)
check(
    "refuses a multi-import section instead of silently reporting a subset",
    raises(
        lambda: cct.component_imports(component("wasi:io/poll@0.2.9", count=2)),
        "will not silently",
    ),
)
check(
    "refuses an unexpected import-name kind",
    raises(
        lambda: cct.component_imports(component("wasi:io/poll@0.2.9", kind=0x01)),
        "import-name kind",
    ),
)

# The must-not-fire control for the two refusals above: the same shapes, valid, still parse.
check(
    "a valid single-import section still parses (over-correction control)",
    cct.component_imports(component("wasi:io/poll@0.2.9")) == ["wasi:io/poll@0.2.9"],
)

print("\n-- capability classification --")

check(
    "http maps to network-http",
    cct.capability_of("wasi:http/outgoing-handler@0.2.9") == "network-http",
)
check(
    "filesystem maps to filesystem",
    cct.capability_of("wasi:filesystem/types@0.2.9") == "filesystem",
)
check(
    "sockets map to network-sockets",
    cct.capability_of("wasi:sockets/tcp@0.2.9") == "network-sockets",
)
check(
    "host logging maps to host-logging",
    cct.capability_of("zeroclaw:plugin/logging@0.1.0") == "host-logging",
)
check(
    "a NEW interface in an already-triaged package falls back to the package",
    cct.capability_of("wasi:http/some-future-interface@0.3.0") == "network-http",
)
check(
    "an UNTRIAGED package is unclassified, so it fails closed rather than being allowed",
    cct.capability_of("acme:evil/exfiltrate@1.0.0") is None,
)
# Pinned because it was a REAL defect, and one only an external component could expose.
# The map was first keyed on wit/v0 FILENAMES, which put `zeroclaw:plugin/sockets` here.
# The interface is `socket`, singular, declared inside `sockets.wit`. Our own eight
# components import neither, so the wrong key passed every run against our own corpus and
# was caught the first time the gate read an upstream plugin that opens a socket.
check(
    "the host socket interface is keyed on its INTERFACE name, not its wit filename",
    cct.capability_of("zeroclaw:plugin/socket@0.1.0") == "host-sockets",
    cct.capability_of("zeroclaw:plugin/socket@0.1.0"),
)
check(
    "and a host socket counts as network reachability",
    "host-sockets" in cct.NETWORK_CAPABILITIES,
)
check(
    "the wrong plural key is NOT silently accepted (over-correction control)",
    cct.capability_of("zeroclaw:plugin/sockets@0.1.0") is None,
)
# Every interface the vendored WIT declares must be classified, or a plugin using one is
# rejected as unclassified for no reason. Derived from the WIT, never from a hand list.
wit_dir = ROOT / "wit" / "v0"
if wit_dir.is_dir():
    declared_ifaces = set()
    for w in wit_dir.glob("*.wit"):
        for line in w.read_text(encoding="utf-8").splitlines():
            if line.startswith("interface "):
                declared_ifaces.add("zeroclaw:plugin/" + line.split()[1].strip("{ "))
    unmapped = sorted(
        i for i in declared_ifaces if cct.capability_of(i + "@0.1.0") is None
    )
    check(
        f"all {len(declared_ifaces)} interfaces in wit/v0 are classified",
        not unmapped,
        unmapped,
    )
else:
    skip("wit/v0 interface coverage", "wit/v0 not present")
check(
    "the version suffix is dropped, so a wasi bump does not spuriously fail the gate",
    cct.interface_of("wasi:http/types@0.2.9")
    == cct.interface_of("wasi:http/types@0.2.2"),
)

print("\n-- audit, both directions --")

TMP = ROOT / ".custody-test-tmp"
TMP.mkdir(exist_ok=True)


def write_case(name: str, manifest_body: str, comp: bytes):
    d = TMP / name
    d.mkdir(exist_ok=True)
    (d / "manifest.toml").write_text(manifest_body, encoding="utf-8")
    w = d / "x.wasm"
    w.write_bytes(comp)
    return d / "manifest.toml", w


HONEST = """
name = "honest"
permissions = ["http_client"]
[custody]
tier = "T0"
network_reachable = true
filesystem = false
config_injected = false
host_capabilities = ["host-types", "host-logging", "io-streams", "stdio", "network-http"]
"""

# CASE 1, the incident shape: the binary reaches the network and the declaration omits it.
UNDERDECLARED = HONEST.replace('"network-http"]', "]").replace(
    "network_reachable = true", "network_reachable = false"
)

mp, wp = write_case("honest", HONEST, component(*TYPICAL))
fails, _ = cct.audit(mp, wp)
check("an honest declaration passes (must-not-fire control)", fails == [], fails)

mp_u, wp_u = write_case("underdeclared", UNDERDECLARED, component(*TYPICAL))
fails_u, _ = cct.audit(mp_u, wp_u)
check(
    "CASE 1: a manifest omitting a capability its binary imports FAILS",
    any("network-http" in f for f in fails_u),
    fails_u,
)
check(
    "CASE 1 also catches the network_reachable claim specifically",
    any("network_reachable" in f for f in fails_u),
    fails_u,
)

FS_LIE = HONEST.replace("filesystem = false", "filesystem = true")
mp_f, wp_f = write_case("fslie", FS_LIE, component(*TYPICAL))
check(
    "a filesystem claim the binary contradicts FAILS",
    any("filesystem" in f for f in cct.audit(mp_f, wp_f)[0]),
)

FS_REAL = HONEST.replace("filesystem = false", "filesystem = true").replace(
    '"network-http"]', '"network-http", "filesystem"]'
)
mp_r, wp_r = write_case(
    "fsreal", FS_REAL, component(*TYPICAL, "wasi:filesystem/types@0.2.9")
)
check(
    "a truthful filesystem = true declaration passes (over-correction control)",
    cct.audit(mp_r, wp_r)[0] == [],
    cct.audit(mp_r, wp_r)[0],
)

# The permissions list the HOST enforces, cross-checked against the binary. This is the
# strongest of the checks because `permissions` is not decorative: the host reads it.
PERM_LIE = HONEST.replace('permissions = ["http_client"]', "permissions = []")
mp_p, wp_p = write_case("permlie", PERM_LIE, component(*TYPICAL))
check(
    "a permissions list omitting http_client while the binary reaches the network FAILS",
    any("http_client" in f for f in cct.audit(mp_p, wp_p)[0]),
    cct.audit(mp_p, wp_p)[0],
)

PERM_OFFLINE = HONEST.replace('permissions = ["http_client"]', "permissions = []")
PERM_OFFLINE = PERM_OFFLINE.replace(
    "network_reachable = true", "network_reachable = false"
)
PERM_OFFLINE = PERM_OFFLINE.replace(', "network-http"]', "]")
mp_o, wp_o = write_case("permoffline", PERM_OFFLINE, component(*TYPICAL[:-1]))
check(
    "a genuinely offline plugin with permissions = [] passes (over-correction control)",
    cct.audit(mp_o, wp_o)[0] == [],
    cct.audit(mp_o, wp_o)[0],
)

CFG_LIE = HONEST.replace("config_injected = false", "config_injected = true")
mp_c, wp_c = write_case("cfglie", CFG_LIE, component(*TYPICAL))
check(
    "config_injected disagreeing with the permissions list FAILS",
    any("config_injected" in f for f in cct.audit(mp_c, wp_c)[0]),
    cct.audit(mp_c, wp_c)[0],
)

NO_BLOCK = 'name = "nocustody"\n'
mp_n, wp_n = write_case("nocustody", NO_BLOCK, component(*TYPICAL))
check(
    "a manifest with NO [custody] block fails rather than passing silently",
    any("no [custody]" in f for f in cct.audit(mp_n, wp_n)[0]),
)

NO_TIER = HONEST.replace('tier = "T0"\n', "")
mp_t, wp_t = write_case("notier", NO_TIER, component(*TYPICAL))
check(
    "a [custody] block with no tier fails",
    any("no tier" in f for f in cct.audit(mp_t, wp_t)[0]),
)

UNKNOWN = HONEST
mp_x, wp_x = write_case(
    "unknown", UNKNOWN, component(*TYPICAL, "acme:evil/exfiltrate@1.0.0")
)
check(
    "an UNCLASSIFIED import fails closed even though nothing declared it",
    any("not classified" in f for f in cct.audit(mp_x, wp_x)[0]),
    cct.audit(mp_x, wp_x)[0],
)

print("\n-- signing scan (HEURISTIC; asserted to be non-gating) --")

check("markers are found when present", cct.SIGNING_MARKERS[0] in b"...ed25519_sign...")
check(
    "the scan gates nothing: audit() never consults it",
    "signing_scan" not in cct.audit.__code__.co_names,
    cct.audit.__code__.co_names,
)

print("\n-- mutation control: is the over-privilege detector load-bearing? --")

src = GATE.read_text(encoding="utf-8")
MUT = "over = sorted(set(actual) - declared)"
check("the mutation target is present in the gate source", MUT in src)
mutant_src = src.replace(MUT, "over = []")
mspec = importlib.util.spec_from_loader("cct_mutant", loader=None)
mutant = importlib.util.module_from_spec(mspec)
mutant.__dict__["__file__"] = str(GATE)  # the gate derives ROOT from __file__ at import
exec(compile(mutant_src, "cct_mutant", "exec"), mutant.__dict__)
mut_fails, _ = mutant.audit(mp_u, wp_u)
check(
    "with over-privilege detection neutered, CASE 1's capability finding DISAPPEARS",
    not any("imports network-http which" in f for f in mut_fails),
    mut_fails,
)
check(
    "and the mutant is otherwise a working gate, so the control tested the right branch",
    mutant.audit(mp, wp)[0] == [],
)

print("\n-- cross-check against real artifacts, if any are built --")

real = sorted((ROOT / "plugins").glob("*/target/wasm32-wasip2/release/*.wasm"))
real = [p for p in real if "deps" not in p.parts]
if not real:
    skip(
        "parser vs a real component",
        "nothing built; run cargo build --target wasm32-wasip2 --release",
    )
else:
    p = real[0]
    imports = cct.component_imports(p.read_bytes())
    check(f"parses a real artifact ({p.name})", len(imports) > 5, imports)
    check(
        "every real import is classified, so the live corpus needs no fail-closed exception",
        all(cct.capability_of(i) is not None for i in imports),
        [i for i in imports if cct.capability_of(i) is None],
    )
    check(
        "no shipped component imports wasi:filesystem",
        not any(i.startswith("wasi:filesystem") for i in imports),
    )

for d in sorted(TMP.glob("*")):
    for f in d.glob("*"):
        f.unlink()
    d.rmdir()
TMP.rmdir()

print(f"\n{passed} passed, {failed} failed, {skipped} skipped")
sys.exit(1 if failed else 0)
