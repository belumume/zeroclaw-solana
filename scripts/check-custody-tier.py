#!/usr/bin/env python3
"""Check each plugin's declared custody tier against the COMPILED component's import table.

WHY THIS EXISTS. The bounty's stated non-negotiable is that every showcase declares its
custody tier, and it carries 25 of 100 points. Until this gate landed, ours were declared
in PROSE, in three different formats across eight components: a manifest comment, README
prose, and a source doc-comment. `plugins/payment-watch/manifest.toml` ended with the
sentence "There is no code path that signs or moves funds." That is a falsifiable claim
about a compiled binary, asserted in a comment, checked by nothing. This project has filed
ten upstream defects whose shared shape is "a control the operator sets, the config
validates, and no runtime path reads". A tier written in a comment is a weaker version of
that same defect, because a comment cannot even be parsed.

WHAT THIS GATE DECIDES, AND WHY IT IS SOUND. A wasm component reaches the outside world
only through imports the host supplies. A capability absent from the component's import
table therefore has no function through which it could ever be called, whatever the source
says. So two properties are decidable from the shipped artifact alone:

  CAPABILITY MINIMALITY  the component imports nothing outside the capability set its
                         manifest declares. Over-privilege is caught; an unclassified
                         import is caught too, and fails closed rather than passing.
  NETWORK REACHABILITY   whether the component can originate a request at all. With no
                         wasi:http, wasi:sockets or host socket interface in the table,
                         there is no route to an RPC endpoint and none to a broadcast.

WHAT THIS GATE DELIBERATELY DOES NOT CLAIM. It cannot prove a component does not sign.
Ed25519 is pure computation over bytes in linear memory; it imports nothing, so no import
audit can exclude it. Anyone shipping "this binary cannot sign" on the strength of an
import table is publishing exactly the unfalsifiable control this project spends its safety
axis refuting. The optional signing-surface scan below is a HEURISTIC, is labelled as one
everywhere it prints, gates nothing, and its false negative is stated in the same breath:
a hand-rolled or inlined implementation leaves no marker and the scan reports clean.

  config_read IS ALSO OUT OF SCOPE, and for a different reason worth stating rather than
  omitting. The host injects operator config as a `__config` field inside the JSON tool
  arguments (see `ExecuteArgs` in any plugin that declares it), so it crosses no import
  boundary and leaves no trace in the artifact. This gate can neither confirm nor refute
  it, and says so instead of quietly scoring it.

SCOPE IS DISCOVERED, NOT LISTED, matching check-all.py: every directory under plugins/
holding a manifest.toml is audited, so a plugin added later joins by itself.

EXIT CODES. 0 pass. 1 a declaration disagrees with its binary. 2 the components are not
built, which is the state of a fresh clone and is not a finding; check-all.py reads 2 as a
skip. Build them with, from each plugin directory:

    cargo build --target wasm32-wasip2 --release

Run: python3 scripts/check-custody-tier.py [--wasm PATH ...] [--signing-scan]
"""

import argparse
import pathlib
import re
import sys

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - python < 3.11
    print("FAIL  this gate needs Python 3.11+ for tomllib")
    sys.exit(1)

ROOT = pathlib.Path(__file__).resolve().parent.parent
PLUGINS = ROOT / "plugins"

COMPONENT_LAYER = (
    b"\x0d\x00\x01\x00"  # bytes 4..8 of a component; a core module is 01000000
)
IMPORT_SECTION = 10  # verified empirically against a real wasm32-wasip2 component
CANNOT_CHECK = 2

# Every import is classified. An interface that matches nothing here is UNCLASSIFIED and
# fails the run, because a host capability nobody has triaged must not be silently allowed
# into a tier that never considered it.
CAPABILITY_OF = {
    "wasi:http/types": "network-http",
    "wasi:http/outgoing-handler": "network-http",
    "wasi:http/incoming-handler": "network-inbound",
    "wasi:filesystem/types": "filesystem",
    "wasi:filesystem/preopens": "filesystem",
    "wasi:cli/environment": "environment",
    "wasi:cli/exit": "process-exit",
    "wasi:cli/stdin": "stdio",
    "wasi:cli/stdout": "stdio",
    "wasi:cli/stderr": "stdio",
    "wasi:cli/terminal-input": "stdio",
    "wasi:cli/terminal-output": "stdio",
    "wasi:cli/terminal-stdin": "stdio",
    "wasi:cli/terminal-stdout": "stdio",
    "wasi:cli/terminal-stderr": "stdio",
    "wasi:clocks/monotonic-clock": "clock",
    "wasi:clocks/wall-clock": "clock",
    "wasi:random/random": "random-secure",
    "wasi:random/insecure": "random-insecure",
    "wasi:random/insecure-seed": "random-insecure",
    "wasi:io/poll": "io-streams",
    "wasi:io/error": "io-streams",
    "wasi:io/streams": "io-streams",
    # Every zeroclaw entry is the INTERFACE name declared inside wit/v0/*.wit, which is
    # not always the filename. `zeroclaw:plugin/socket` is singular and lives in
    # `sockets.wit`; keying this map on filenames put `sockets` here, and that wrong key
    # was invisible until the gate was run against an upstream component that actually
    # imports it. Re-derive rather than reading the directory listing:
    #   grep -h '^interface' wit/v0/*.wit
    "zeroclaw:plugin/types": "host-types",
    "zeroclaw:plugin/logging": "host-logging",
    "zeroclaw:plugin/memory": "host-memory",
    "zeroclaw:plugin/channel": "host-channel",
    "zeroclaw:plugin/inbound": "host-inbound",
    "zeroclaw:plugin/socket": "host-sockets",
    "zeroclaw:plugin/ws-client": "host-ws-client",
    # EXPORT-only in wit/v0 today, verified from the worlds rather than assumed:
    # `grep -A6 '^world ' wit/v0/*.wit` shows tool-plugin and memory-plugin EXPORT these
    # and import only logging. They are classified anyway so that a component which one
    # day IMPORTS one is named rather than rejected as untriaged; because classification
    # is not permission, such an import would still have to appear in host_capabilities
    # for the plugin to pass.
    "zeroclaw:plugin/tool": "host-plugin-contract",
    "zeroclaw:plugin/plugin-info": "host-plugin-contract",
}

# Prefix fallbacks, so a NEW interface inside an already-triaged package is classified by
# its package rather than failing the build. A new PACKAGE still fails closed.
PACKAGE_FALLBACK = {
    "wasi:sockets": "network-sockets",
    "wasi:filesystem": "filesystem",
    "wasi:http": "network-http",
}

# Any of these means the component can originate traffic. Derived, never declared.
NETWORK_CAPABILITIES = {
    "network-http",
    "network-sockets",
    "host-sockets",
    "host-ws-client",
}

# Markers of a known signing implementation. HEURISTIC ONLY: presence is suggestive,
# absence proves nothing, and nothing in this file gates on the result.
SIGNING_MARKERS = (b"ed25519", b"curve25519", b"Ed25519", b"signature::", b"sha2::")


class BadComponent(Exception):
    pass


def _leb(buf: bytes, i: int) -> tuple[int, int]:
    """Unsigned LEB128. Returns (value, next index)."""
    val = shift = 0
    while True:
        if i >= len(buf):
            raise BadComponent("truncated LEB128")
        b = buf[i]
        i += 1
        val |= (b & 0x7F) << shift
        if not (b & 0x80):
            return val, i
        shift += 7
        if shift > 35:
            raise BadComponent("LEB128 too long")


def component_imports(data: bytes) -> list[str]:
    """Every top-level import name in a component, read from the import sections.

    Deliberately NOT a strings scan. A strings scan over the same artifact returns a wildly
    noisy superset: the embedded core modules carry their own core-level import names, the
    adapter shims carry `indirect-` duplicates, and the name section carries `ty-` entries,
    so one component yielded both `wasi:cli/exit@0.2.0` and `@0.2.9` alongside entries that
    are not imports at all. The import section is the only precise instrument.
    """
    if data[:4] != b"\x00asm":
        raise BadComponent("not a wasm file")
    if data[4:8] != COMPONENT_LAYER:
        raise BadComponent(
            f"not a component (layer bytes {data[4:8].hex()}; a core module is 01000000)"
        )

    names: list[str] = []
    i = 8
    while i < len(data):
        sec_id = data[i]
        size, j = _leb(data, i + 1)
        if sec_id == IMPORT_SECTION:
            names.extend(_parse_import_section(data[j : j + size]))
        i = j + size
        if size == 0 and sec_id == 0:
            raise BadComponent("zero-length section, refusing to loop")
    return names


def _parse_import_section(body: bytes) -> list[str]:
    """Read the names out of one component import section.

    Only the NAME of each import is read. The type descriptor that follows it is not
    needed to decide capability and is the part most likely to change between
    component-model revisions, so this deliberately does not pin a shape it never uses.

    That is also why a section carrying more than one import RAISES rather than reading
    the first and moving on: without walking the type descriptor there is no way to find
    where the second name begins, and returning a partial list would understate the
    component's capabilities, which is the one direction this gate must never fail in.
    Every wasip2 component measured here emits exactly one import per section.
    """
    count, i = _leb(body, 0)
    if count != 1:
        raise BadComponent(
            f"import section declares {count} imports; this parser reads one per section "
            f"and will not silently report a subset"
        )
    if i >= len(body):
        raise BadComponent("import section truncated before its declared count")
    kind = body[i]
    i += 1
    if kind != 0x00:
        raise BadComponent(f"unexpected import-name kind 0x{kind:02x}")
    n, i = _leb(body, i)
    raw = body[i : i + n]
    if len(raw) != n:
        raise BadComponent("import name truncated")
    return [raw.decode("utf-8")]


def interface_of(import_name: str) -> str:
    """`wasi:http/types@0.2.9` -> `wasi:http/types`. Version is deliberately dropped."""
    return import_name.split("@", 1)[0]


def capability_of(import_name: str) -> str | None:
    iface = interface_of(import_name)
    if iface in CAPABILITY_OF:
        return CAPABILITY_OF[iface]
    pkg = iface.split("/", 1)[0]
    return PACKAGE_FALLBACK.get(pkg)


def audit(
    manifest_path: pathlib.Path, wasm_path: pathlib.Path
) -> tuple[list[str], list[str]]:
    """Returns (failures, info lines). A failure means the declaration is not true of the binary."""
    fails: list[str] = []
    info: list[str] = []
    manifest = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
    name = manifest.get("name", manifest_path.parent.name)
    custody = manifest.get("custody")

    if custody is None:
        fails.append(
            f"{name}: manifest has no [custody] block, so its tier is unverifiable"
        )
        return fails, info

    declared = set(custody.get("host_capabilities", []))
    tier = custody.get("tier")
    if not tier:
        fails.append(f"{name}: [custody] declares no tier")

    imports = component_imports(wasm_path.read_bytes())
    if not imports:
        fails.append(
            f"{name}: no imports parsed from {wasm_path.name}; the parser found nothing"
        )
        return fails, info

    actual: dict[str, list[str]] = {}
    unclassified: list[str] = []
    for imp in imports:
        cap = capability_of(imp)
        if cap is None:
            unclassified.append(imp)
        else:
            actual.setdefault(cap, []).append(imp)

    for imp in unclassified:
        fails.append(
            f"{name}: import {imp} is not classified by this gate. "
            f"Classify it in CAPABILITY_OF before it can be permitted."
        )

    over = sorted(set(actual) - declared)
    for cap in over:
        fails.append(
            f"{name}: imports {cap} which [custody].host_capabilities does not declare "
            f"(via {', '.join(sorted(actual[cap]))})"
        )

    unused = sorted(declared - set(actual))
    if unused:
        info.append(
            f"      declared but not imported: {', '.join(unused)} (under-claim, not a risk)"
        )

    reachable = bool(set(actual) & NETWORK_CAPABILITIES)
    declared_network = custody.get("network_reachable")
    if declared_network is None:
        fails.append(f"{name}: [custody] declares no network_reachable")
    elif bool(declared_network) != reachable:
        fails.append(
            f"{name}: declares network_reachable = {declared_network!r} but the import table "
            f"says {reachable} ({'has' if reachable else 'has no'} network import)"
        )

    # The strongest cross-check available, because `permissions` is the list the HOST
    # actually enforces at load time. Tying it to the import table means the grant the
    # operator sees and the capability the binary can reach cannot drift apart silently:
    # a plugin that stopped needing the network keeps its grant until someone notices,
    # and one that gained a dependency pulling in http would otherwise gain reach under
    # a manifest that still reads as offline.
    permissions = set(manifest.get("permissions", []))
    if ("http_client" in permissions) != reachable:
        fails.append(
            f"{name}: permissions {'grant' if 'http_client' in permissions else 'omit'} "
            f"http_client but the import table says network reachable = {reachable}"
        )

    # config_read leaves no import trace at all (host-injected via tool args), so this is
    # a manifest-internal consistency check rather than a claim about the binary, and it
    # is worth having only because the two declarations would otherwise drift unwatched.
    declared_cfg = custody.get("config_injected")
    if declared_cfg is None:
        fails.append(f"{name}: [custody] declares no config_injected")
    elif bool(declared_cfg) != ("config_read" in permissions):
        fails.append(
            f"{name}: [custody].config_injected = {declared_cfg!r} disagrees with "
            f"permissions {'granting' if 'config_read' in permissions else 'omitting'} config_read"
        )

    fs = "filesystem" in actual
    declared_fs = custody.get("filesystem")
    if declared_fs is None:
        fails.append(f"{name}: [custody] declares no filesystem")
    elif bool(declared_fs) != fs:
        fails.append(
            f"{name}: declares filesystem = {declared_fs!r} but the import table says {fs}"
        )

    info.append(
        f"      tier {tier}  {len(imports)} imports -> {len(actual)} capabilities: "
        f"{', '.join(sorted(actual))}"
    )
    info.append(f"      network reachable: {reachable}   filesystem: {fs}")
    return fails, info


def signing_scan(wasm_path: pathlib.Path) -> list[str]:
    """HEURISTIC. Reports markers of a known signing implementation.

    A hit means a recognised crate is probably linked. A MISS MEANS NOTHING: ed25519 is
    pure arithmetic over bytes, imports no host function, and an inlined or hand-rolled
    implementation carries none of these strings. Never gate on this and never headline it.
    """
    data = wasm_path.read_bytes()
    return sorted({m.decode() for m in SIGNING_MARKERS if m in data})


def wasm_for(plugin_dir: pathlib.Path, manifest: dict) -> pathlib.Path:
    stem = manifest.get("wasm_path") or f"{plugin_dir.name.replace('-', '_')}.wasm"
    return plugin_dir / "target" / "wasm32-wasip2" / "release" / stem


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--wasm",
        action="append",
        default=[],
        metavar="PATH",
        help="audit an arbitrary component's import table and print it; repeatable. "
        "Used to run this gate against components we did not write.",
    )
    ap.add_argument(
        "--signing-scan",
        action="store_true",
        help="also run the HEURISTIC signing-surface scan (gates nothing)",
    )
    args = ap.parse_args()

    if args.wasm:
        for p in args.wasm:
            path = pathlib.Path(p)
            print(f"{path.name}  ({path.stat().st_size} bytes)")
            try:
                imports = component_imports(path.read_bytes())
            except BadComponent as e:
                print(f"  UNREADABLE  {e}")
                return 1
            caps: dict[str, list[str]] = {}
            for imp in imports:
                cap = capability_of(imp)
                if cap is not None:
                    caps.setdefault(cap, []).append(imp)
            for imp in sorted(imports):
                print(f"    {capability_of(imp) or 'UNCLASSIFIED':<18} {imp}")
            reachable = bool(set(caps) & NETWORK_CAPABILITIES)
            print(f"  capabilities: {', '.join(sorted(caps)) or 'none'}")
            print(
                f"  network reachable: {reachable}   filesystem: {'filesystem' in caps}"
            )
            if args.signing_scan:
                print(
                    f"  signing markers (HEURISTIC, gates nothing): {signing_scan(path) or 'none found'}"
                )
        return 0

    manifests = sorted(PLUGINS.glob("*/manifest.toml"))
    if not manifests:
        print("FAIL  no plugin manifests found; the discovery walk is broken")
        return 1

    missing = []
    audited = 0
    all_fails: list[str] = []
    for mp in manifests:
        manifest = tomllib.loads(mp.read_text(encoding="utf-8"))
        wp = wasm_for(mp.parent, manifest)
        if not wp.is_file():
            missing.append(mp.parent.name)
            continue
        print(f"  {mp.parent.name}")
        try:
            fails, info = audit(mp, wp)
        except BadComponent as e:
            fails, info = [f"{mp.parent.name}: {wp.name} unreadable: {e}"], []
        for line in info:
            print(line)
        if args.signing_scan:
            print(
                f"      signing markers (HEURISTIC, gates nothing): {signing_scan(wp) or 'none found'}"
            )
        all_fails.extend(fails)
        audited += 1

    if audited == 0:
        print(
            f"cannot check: none of {len(manifests)} components are built.\n"
            f"  This is the state of a fresh clone and is not a finding.\n"
            f"  Build one with: cd plugins/<name> && "
            f"cargo build --target wasm32-wasip2 --release"
        )
        return CANNOT_CHECK

    if missing:
        print(f"\n  not built, so not audited: {', '.join(missing)}")

    if all_fails:
        print(
            f"\nFAIL  {len(all_fails)} custody declaration(s) disagree with the binary:\n"
        )
        for f in all_fails:
            print(f"  - {f}")
        return 1

    print(f"\nall {audited} built component(s) match their declared custody tier")
    return 0


if __name__ == "__main__":
    sys.exit(main())
