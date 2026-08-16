#!/usr/bin/env python3
"""Write the SHOP-INVARIANTS.json that deploy/box_selfcheck.py consumes. (stdlib only)

    python3 deploy/make_invariants.py                     # emit deploy/SHOP-INVARIANTS.json
    python3 deploy/make_invariants.py --bless payment-watch --wasm <path-to-built.wasm>
    python3 deploy/make_invariants.py --self-test         # drive every case both directions

    0  manifest written
    1  refused: something is stated wrong and emitting would bake it in
    2  NOT CHECKED: could not run, or the discovery walk is broken

WHY THIS EXISTS. `box_selfcheck.py` is a well-built drift gate that has never caught anything,
because nothing writes its input. Its logic is sound and its self-test is real; it simply cannot
run on the box, whatever the code says. The two worst failures of 2026-08-06 are both exactly
what it was written to catch:

  THE LIVE SKILL DRIFTED ELEVEN DAYS BEHIND THE REPO and was minting devnet pay links while the
  page settles mainnet. The repo copy was correct the whole time. A content hash per deployed
  file is the entire fix, and it is the easy half.

  A PLUGIN FIX WAS DEPLOYED TO THE WRONG DIRECTORY. The daemon loads `~/.zeroclaw/plugins/<name>/`
  by directory convention; the rebuild was written to `~/zc-shop/plugins/`. The LOADED binary
  stayed at the Jul 26 build while the fresh one sat elsewhere, and it was reported as FIXED
  because the measurement was taken against the wrong path. So a manifest that pins CONTENT and
  not LOCATION would have passed this. Every path here is relative to ZEROCLAW_HOME, which is the
  root box_selfcheck resolves against, and that is the point of the `dst` field in the map.

WHAT IS DERIVED AND WHAT IS DECLARED, because a hardcoded enumeration never grows as the surface
does and this repo has already been bitten by one.

  DERIVED, from `git ls-files`, so adding a file to git is what puts it in the manifest:
    the deployed file set, the merchant and mint pins (parsed out of the script that enforces
    them), the network (looked up from the pinned mint), which files carry both pins, which are
    prose, and which get scanned for a foreign address.

  DECLARED, in deploy/deploy-targets.json, and ONLY the things a repo cannot know:
    where the daemon loads each artifact from, and which units must be alive.

THE HARD CASE IS BINARIES, and skipping them was not available: the plugin binary is the artifact
that caused the second incident and the one the demo depends on. The repo holds Rust and the box
holds a compiled .wasm, so there is no repo hash to compare against. A manifest is a STATEMENT of
what should be deployed, so a built artifact's hash has to be RECORDED at the moment someone
builds and deploys it. `--bless` is that moment, and it writes deploy/blessed-binaries.json.

A blessed pin can go stale, and a stale pin is worse than no pin because it reads as coverage. So
every record also carries the sha256 of the SOURCE that produced it, over the plugin's own tracked
files plus `wit/` and `crates/solana-core/`. This run recomputes it. If the source has moved, the
generator REFUSES; `--allow-stale-binaries` emits anyway and records `stale: true` with both
hashes, so the staleness becomes a fact on the box rather than something to remember. `wit/` is in
that hash deliberately: the 2026-08-06 arity defect was one extra enum variant in a vendored .wit,
it broke every plugin's instantiation, and no Rust changed.

IT DRY-RUNS THE GATE ON THE REPO'S OWN BYTES BEFORE SHIPPING ANY SCAN TARGET, and that step
earned itself on the first real run. A check that is RED against the reference content is red on a
PERFECT deployment, and box_selfcheck's verdict is all-of, so one permanently-red check pins the
whole box to DRIFTED and destroys the value of every other check beside it. Measured: the real
SKILL.md fires network-prose at two lines, both WRAPPED prohibitions whose marker sits on the
previous line, and the file itself carries a note telling gate authors not to assert the word is
absent because a prohibition has to name what it forbids. Those targets are dropped from the scan,
recorded in `not_checked` with the gate's own words, and still hash-compared in `files`. A file
reworded so the gate passes returns to scope by itself.

FAILS CLOSED IN THE ONE DIRECTION THAT MATTERS. An empty or short file set, a map entry matching
nothing, an unreadable config or an unknown mint all return non-zero and say NOT CHECKED. A
generator that quietly emits a two-file manifest is worse than one that emits nothing, because
box_selfcheck would then compare two files and print a green verdict.

A `dst` THAT IS WRONG FAILS LOUD. check_manifest reports the path it looked for as MISSING, so a
first run on the box is how this map gets confirmed rather than assumed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
TARGETS_PATH = HERE / "deploy-targets.json"
BLESSED_PATH = HERE / "blessed-binaries.json"
DEFAULT_OUT = HERE / "SHOP-INVARIANTS.json"

# Below this the discovery walk is broken rather than the repo being small, and a short manifest
# is the false-green this file exists to prevent: box_selfcheck would compare what it was given
# and report a clean verdict. Currently 19 files resolve; the floor is set well under that so an
# ordinary addition or removal does not trip it, and a collapsed walk does.
MIN_FILES = 10

# The script that ENFORCES the two pins is the source of truth for their values. Reading them out
# of it means the manifest cannot disagree with the code that refuses a wrong link.
PIN_SOURCE = "skills/solana-pay/scripts/pay_link.py"
PIN_RE = {
    "merchant": re.compile(r'^MERCHANT\s*=\s*"([1-9A-HJ-NP-Za-km-z]{32,44})"', re.M),
    "mint": re.compile(r'^MINT\s*=\s*"([1-9A-HJ-NP-Za-km-z]{32,44})"', re.M),
}

# Network follows from the pinned mint rather than being declared, so the two can never disagree.
# An unknown mint is a refusal: guessing the network is precisely the sentence that reached a
# customer on 2026-08-06 ("Esta loja funciona na devnet") over a real mainnet charge.
MINT_NETWORK = {
    "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v": "mainnet",
    "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU": "devnet",
}

# Files whose content is scannable as text by box_selfcheck's mint and prose checks.
TEXT_SUFFIXES = {".md", ".py", ".toml", ".sh", ".txt", ".json"}

# Valid base58, so a hand-written extra cannot be a typo the scan then silently never matches.
B58_TOKEN = re.compile(r"^[1-9A-HJ-NP-Za-km-z]{32,44}$")

# What determines a plugin binary. Anything here moving invalidates a blessed hash.
PLUGIN_SOURCE_SHARED = ("wit", "crates/solana-core")

WASM_MAGIC = b"\x00asm"


# ---------------------------------------------------------------------------------------------
# primitives
# ---------------------------------------------------------------------------------------------


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def git(root: Path, *args: str) -> tuple[int, str]:
    r = subprocess.run(
        ["git", "-C", str(root), *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    return r.returncode, (r.stdout or "")


def git_ls(root: Path, *patterns: str) -> list[str]:
    """Tracked files under the given pathspecs, as repo-relative posix paths."""
    rc, out = git(root, "ls-files", "-z", "--", *patterns)
    if rc != 0:
        return []
    return sorted(p for p in out.split("\0") if p.strip())


def is_test_file(repo_rel: str) -> bool:
    """A test that proves a wrong mint is REFUSED has to contain that wrong mint.

    Measured 2026-08-06 across every tracked file under skills/ and sops/: the only foreign
    base58 tokens anywhere are two fixtures inside test_pay_link.py, one of them the devnet mint.
    So this exclusion is what keeps a CORRECT deploy green, and the self-test proves that by
    disabling it and requiring box_selfcheck's mint scan to go red on a clean box.

    Scoped to the scans only. Test files stay in `files` and are hash-compared like everything
    else, because a drifted test is still drift.
    """
    return Path(repo_rel).name.startswith("test_")


def import_gate():
    """The consumer, imported so the generator can dry-run its own output.

    A hard dependency on purpose: box_selfcheck is what makes this manifest mean anything, and a
    manifest emitted without ever being run through it is a statement nobody checked.
    """
    sys.path.insert(0, str(HERE))
    import box_selfcheck

    return box_selfcheck


def validate_scans(
    root: Path,
    pairs: list[tuple[str, str]],
    mint_scan: list[str],
    prose_scan: list[str],
    pins: dict,
    declared: set[str],
) -> tuple[list[str], list[str], list[dict]]:
    """Run the REAL gate over the REPO's own bytes and drop anything red on correct content.

    A scan target that is RED against the reference bytes is not drift. It is a mismatch between
    the check and the file, and shipping it makes the gate red on a PERFECT deployment. That
    matters more than it sounds: `Result.ok` is all-of, so one permanently-red check pins the
    whole verdict to DRIFTED and destroys the value of every other check beside it. It is the
    exact defect this gate's own audit called BLOCKING, and re-introducing it through the input
    file rather than through the code would be the same wound from a new direction.

    MEASURED, and it is why this function exists rather than an exclusion list: the real
    SKILL.md fires network-prose at two lines, both of them WRAPPED prohibitions whose marker
    sits on the previous line ("...under a sentence saying" / "the shop runs on devnet."). The
    file even carries a note to gate authors saying not to assert the word is absent, because a
    prohibition has to name what it forbids. Both are false positives, and no wording change to
    a correct file would fix them.

    Dropping is recorded, never silent: every drop lands in the manifest's not_checked block
    with the gate's own detail line, and a file reworded so the gate passes returns to scope by
    itself. Declared box-only targets are not validated here because their content does not
    exist in the repo; they are labelled as such rather than assumed clean.
    """
    gate = import_gate()
    tmp = Path(tempfile.mkdtemp(prefix="mkinv-validate-"))
    dropped: list[dict] = []
    try:
        for repo_rel, box_rel in pairs:
            dst = tmp / box_rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(root / repo_rel, dst)
        saved_zc = gate.ZC
        gate.ZC = tmp
        try:

            def survives(check, key: str, target: str) -> tuple[bool, str]:
                # `pins` is the full base invariant set, so a legitimately DECLARED address does
                # not read as a foreign one and cause a false drop.
                r = gate.Result()
                check({**pins, key: [target]}, r)
                return r.checks[0]["ok"], r.checks[0]["detail"]

            keep_prose = []
            for target in prose_scan:
                ok, detail = survives(gate.check_network_prose, "prose_scan", target)
                if ok:
                    keep_prose.append(target)
                else:
                    dropped.append(
                        {
                            "kind": "scan-target-red-on-reference",
                            "path": target,
                            "scan": "prose_scan",
                            "reason": "the gate is RED on this file's own correct bytes, so "
                            "shipping it would pin the whole box verdict to DRIFTED forever",
                            "gate_said": detail[:300],
                        }
                    )

            keep_mint = []
            for target in mint_scan:
                if target in declared:
                    keep_mint.append(target)
                    continue
                ok, detail = survives(gate.check_mint_prohibition, "mint_scan", target)
                if ok:
                    keep_mint.append(target)
                else:
                    dropped.append(
                        {
                            "kind": "scan-target-red-on-reference",
                            "path": target,
                            "scan": "mint_scan",
                            "reason": "the gate is RED on this file's own correct bytes",
                            "gate_said": detail[:300],
                        }
                    )
        finally:
            gate.ZC = saved_zc
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return sorted(keep_mint), sorted(keep_prose), dropped


def load_json(p: Path) -> dict | None:
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return None


def write_json(p: Path, obj: dict) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    # newline="\n" because a default text write emits CRLF on Windows and this artifact is copied
    # to a Linux box where every sibling is LF.
    p.write_text(json.dumps(obj, indent=2) + "\n", encoding="utf-8", newline="\n")


# ---------------------------------------------------------------------------------------------
# the map
# ---------------------------------------------------------------------------------------------


def resolve_map(root: Path, targets: dict) -> tuple[list[tuple[str, str]], list[str]]:
    """(repo_rel, box_rel) for every deployed file, plus problems.

    A map entry that resolves to nothing is a BROKEN MAP, not an empty directory: it means a
    prefix was renamed and the manifest silently stopped covering that surface.
    """
    pairs: list[tuple[str, str]] = []
    problems: list[str] = []
    seen: dict[str, str] = {}

    for entry in targets.get("map") or []:
        src = (entry.get("src") or "").strip("/")
        dst = (entry.get("dst") or "").strip("/")
        include = entry.get("include") or "**"
        flatten = bool(entry.get("flatten"))
        if not src or not dst:
            problems.append(f"map entry missing src or dst: {entry!r}")
            continue

        matched = []
        for repo_rel in git_ls(root, src):
            rel = Path(repo_rel).relative_to(src).as_posix()
            if include != "**" and not Path(rel).match(include):
                continue
            box_rel = f"{dst}/{Path(rel).name if flatten else rel}"
            matched.append((repo_rel, box_rel))

        if not matched:
            problems.append(
                f"map {src} -> {dst} (include={include}) matched NO tracked file; "
                "the map is broken or the prefix was renamed"
            )
            continue

        for repo_rel, box_rel in matched:
            if box_rel in seen and seen[box_rel] != repo_rel:
                problems.append(
                    f"two repo files claim the same box path {box_rel}: "
                    f"{seen[box_rel]} and {repo_rel}"
                )
                continue
            seen[box_rel] = repo_rel
            pairs.append((repo_rel, box_rel))

    return sorted(set(pairs)), problems


# ---------------------------------------------------------------------------------------------
# pins
# ---------------------------------------------------------------------------------------------


def derive_pins(root: Path) -> tuple[dict, list[str]]:
    src = root / PIN_SOURCE
    if not src.is_file():
        return {}, [
            f"{PIN_SOURCE} is absent, so the merchant and mint cannot be derived"
        ]
    text = src.read_text(encoding="utf-8", errors="replace")
    out, problems = {}, []
    for field, rx in PIN_RE.items():
        m = rx.search(text)
        if not m:
            problems.append(
                f"{PIN_SOURCE} has no top-level {field.upper()} constant; the pin that "
                "refuses a wrong link is gone, which is a defect rather than a missing input"
            )
            continue
        out[field] = m.group(1)
    if "mint" in out:
        net = MINT_NETWORK.get(out["mint"])
        if not net:
            problems.append(
                f"the pinned mint {out['mint'][:10]}.. maps to no known network; refusing to "
                "guess, because a wrong network sentence is what a customer reads"
            )
        else:
            out["network"] = net
    return out, problems


def derive_retired_mints(pins: dict, targets: dict) -> tuple[list[str], list[str]]:
    """Every mint this shop must NOT be using, for box_selfcheck's state-scan prohibition.

    DERIVED FROM MINT_NETWORK rather than declared, so a mint cannot be known to the
    network table and unknown to the prohibition. Adding a row above puts it in both at once,
    and the configured mint is removed by construction rather than by anyone remembering to.

    `retired_mints_extra` exists for an address that was never in the network table at all: a
    merchant wallet that has been rotated, a mint from a superseded deployment. It is a
    DELIBERATE DECLARATION and it is never auto-populated, for the same reason
    `allowed_addresses` is not -- a generator that harvested whatever it found on the box would
    bless the current state including the drift, which is the one thing this manifest exists to
    detect. The denylist inverts the polarity of the scan; it must not inherit the failure mode
    of the allowlist it replaces.
    """
    problems: list[str] = []
    mint = pins.get("mint")
    retired = {m for m in MINT_NETWORK if m != mint}
    for extra in targets.get("retired_mints_extra") or []:
        tok = (extra or {}).get("address") if isinstance(extra, dict) else extra
        tok = (tok or "").strip()
        if not B58_TOKEN.match(tok):
            problems.append(
                f"retired_mints_extra carries {tok[:12]!r}, which is not a base58 address; a "
                "typo here is a prohibition that matches nothing and reports clean forever"
            )
            continue
        if tok == mint:
            problems.append(
                "retired_mints_extra names the CONFIGURED mint, which would make the shop's "
                "own mint a finding on every scan"
            )
            continue
        retired.add(tok)
    return sorted(retired), problems


# ---------------------------------------------------------------------------------------------
# binaries
# ---------------------------------------------------------------------------------------------


def plugin_source_sha256(root: Path, plugin: str) -> str | None:
    """Hash of everything that determines the plugin's compiled artifact."""
    files = git_ls(root, f"plugins/{plugin}", *PLUGIN_SOURCE_SHARED)
    if not files:
        return None
    h = hashlib.sha256()
    for rel in files:
        p = root / rel
        if not p.is_file():
            continue
        h.update(rel.encode("utf-8") + b"\0" + sha256_file(p).encode("ascii") + b"\n")
    return h.hexdigest()


def plugin_dirs(root: Path) -> list[str]:
    names = set()
    for rel in git_ls(root, "plugins"):
        parts = Path(rel).parts
        if len(parts) >= 2:
            names.add(parts[1])
    return sorted(names)


def wasm_box_path(root: Path, plugin: str) -> str:
    """Where the daemon loads this plugin's artifact from, relative to ZEROCLAW_HOME.

    `zeroclaw plugin install ./plugins/<name>/` puts the component under
    ~/.zeroclaw/plugins/<name>/, and the filename is the manifest's own wasm_path (cargo turns
    the hyphens in the crate name into underscores). Read from the manifest rather than
    reconstructed, so a plugin that names its artifact differently is still pinned correctly.
    """
    man = root / "plugins" / plugin / "manifest.toml"
    name = f"{plugin.replace('-', '_')}.wasm"
    if man.is_file():
        m = re.search(
            r'^\s*wasm_path\s*=\s*"([^"]+)"', man.read_text(encoding="utf-8"), re.M
        )
        if m:
            name = m.group(1)
    return f"plugins/{plugin}/{name}"


def _repo_relative(root: Path, p: Path) -> str:
    """A path safe to record in a TRACKED file: repo-relative, or a bare basename."""
    try:
        return p.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return p.name


def bless(root: Path, plugin: str, wasm: Path) -> int:
    if not (root / "plugins" / plugin).is_dir():
        print(f"NOT CHECKED  no such plugin directory: plugins/{plugin}")
        return 2
    if not wasm.is_file():
        print(f"NOT CHECKED  no such artifact: {wasm}")
        return 2
    head = wasm.open("rb").read(4)
    if head != WASM_MAGIC:
        # A blessed hash of the wrong file is the same failure class as a deploy to the wrong
        # directory, so this is checked rather than trusted.
        print(
            f"REFUSED  {wasm} does not start with the wasm magic bytes; blessed nothing"
        )
        return 1

    src_sha = plugin_source_sha256(root, plugin)
    if not src_sha:
        print(
            f"NOT CHECKED  plugins/{plugin} has no tracked source; cannot record provenance"
        )
        return 2

    _, head_out = git(root, "rev-parse", "HEAD")
    _, dirty_out = git(
        root, "status", "--porcelain", "--", f"plugins/{plugin}", *PLUGIN_SOURCE_SHARED
    )

    blessed = load_json(BLESSED_PATH) or {"version": 1, "entries": {}}
    blessed.setdefault("entries", {})[plugin] = {
        "box_path": wasm_box_path(root, plugin),
        "sha256": sha256_file(wasm),
        "size": wasm.stat().st_size,
        "blessed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "source_sha256": src_sha,
        "source_commit": head_out.strip() or "unknown",
        "source_dirty": bool(dirty_out.strip()),
        # REPO-RELATIVE, never absolute. This file is TRACKED, and `str(wasm)` would write the
        # operator's home path into every clone the moment someone blessed from an absolute
        # path. That is the exact defect deploy/deploy_shop_page.py:32 already shipped once and
        # check-identifier-leaks.py was red on. A basename for anything outside the repo keeps
        # the record useful without naming anyone.
        "blessed_from": _repo_relative(root, wasm),
    }
    write_json(BLESSED_PATH, blessed)

    e = blessed["entries"][plugin]
    print(f"blessed {plugin}")
    print(f"  box path      {e['box_path']}")
    print(f"  sha256        {e['sha256']}")
    print(f"  size          {e['size']} B")
    print(f"  source        {e['source_sha256'][:16]}.. at {e['source_commit'][:12]}")
    if e["source_dirty"]:
        print(
            "  WARNING       the source tree is dirty, so the commit does not identify it"
        )
        print(
            "                the source hash does, and that is the field the gate uses"
        )
    return 0


# ---------------------------------------------------------------------------------------------
# the manifest
# ---------------------------------------------------------------------------------------------


def build_manifest(
    root: Path, targets: dict, blessed: dict, *, allow_stale: bool
) -> tuple[dict | None, list[str], list[str], list[str]]:
    """(manifest, problems, broken, notes).

    `problems` refuse the emit (rc 1). `broken` means the walk itself did not run (rc 2).
    """
    problems: list[str] = []
    notes: list[str] = []

    pairs, broken = resolve_map(root, targets)
    if len(pairs) < MIN_FILES:
        broken.append(
            f"only {len(pairs)} deployed file(s) resolved, below the floor of {MIN_FILES}; "
            "a short manifest reads as coverage, so nothing is emitted"
        )
    if broken:
        return None, problems, broken, notes

    files: dict[str, str] = {}
    for repo_rel, box_rel in pairs:
        p = root / repo_rel
        if not p.is_file():
            problems.append(f"tracked but absent from the working tree: {repo_rel}")
            continue
        files[box_rel] = sha256_file(p)

    pins, pin_problems = derive_pins(root)
    problems.extend(pin_problems)

    # Scans, all derived from the resolved set rather than listed.
    scannable = [
        (repo_rel, box_rel)
        for repo_rel, box_rel in pairs
        if Path(repo_rel).suffix in TEXT_SUFFIXES and not is_test_file(repo_rel)
    ]
    prose_scan = sorted(b for r, b in scannable if Path(r).suffix == ".md")
    mint_scan = sorted(b for _, b in scannable)

    # A pinned script is one whose SOURCE carries both constants. Derived by content, so a new
    # script that gains the pins is covered without anyone remembering to list it.
    pinned_scripts = []
    if pins.get("merchant") and pins.get("mint"):
        for repo_rel, box_rel in pairs:
            if is_test_file(repo_rel) or Path(repo_rel).suffix != ".py":
                continue
            body = (root / repo_rel).read_text(encoding="utf-8", errors="replace")
            if pins["merchant"] in body and pins["mint"] in body:
                pinned_scripts.append(box_rel)
    pinned_scripts = sorted(set(pinned_scripts))
    if not pinned_scripts:
        problems.append(
            "no deployed script carries both pins; box_selfcheck's code-pins check would "
            "compare nothing and it fails closed on that, so the manifest would be red forever"
        )

    # POLARITY IS PER TARGET, because the two tiers are not the same problem. A deployed file we
    # write and hash gets the ALLOWLIST (anything unfamiliar is drift, and measurement says there
    # is nothing unfamiliar in a correct tree). Agent state gets the DENYLIST, because a fresh
    # reference key per order makes an allowlist unbounded by construction and the check can only
    # go redder as the shop trades. box_selfcheck's docstring carries the full argument.
    declared: set[str] = set()
    state_scan: list[str] = []
    for extra in targets.get("mint_scan_extra") or []:
        if not extra.get("enabled"):
            continue
        policy = (extra.get("policy") or "allowlist").strip().lower()
        if policy == "denylist":
            state_scan.append(extra["path"])
            notes.append(
                f"state scan covers {extra['path']} as a RETIRED-MINT PROHIBITION "
                "(declared box-only target, so its content could not be dry-run)"
            )
        elif policy == "allowlist":
            mint_scan.append(extra["path"])
            declared.add(extra["path"])
            notes.append(
                f"mint scan also covers {extra['path']} (declared box-only target, "
                "so its content could not be dry-run against the repo)"
            )
        else:
            problems.append(
                f"mint_scan_extra entry {extra['path']} declares policy {policy!r}; only "
                "'allowlist' and 'denylist' exist, and guessing which was meant would ship a "
                "scan with the wrong polarity"
            )
    mint_scan = sorted(set(mint_scan))
    state_scan = sorted(set(state_scan))

    retired_mints, retired_problems = derive_retired_mints(pins, targets)
    problems.extend(retired_problems)
    if state_scan and not retired_mints:
        problems.append(
            "a state scan target is configured with an EMPTY retired-mint list, so the "
            "prohibition would read every database as clean and report green"
        )

    not_checked: list[dict] = []

    # DRY-RUN THE GATE ON THE REPO'S OWN BYTES before shipping any scan target. A check that is
    # red on correct content is red forever on the box, and box_selfcheck's verdict is all-of.
    if problems:
        # The pins did not derive, so every prose check would fail for the wrong reason and the
        # validation would drop the whole scan set on a false signal.
        return None, problems, broken, notes
    base_inv = {
        **pins,
        "allowed_addresses": targets.get("allowed_addresses") or [],
        "known_other": targets.get("known_other") or [],
    }
    try:
        mint_scan, prose_scan, dropped = validate_scans(
            root, pairs, mint_scan, prose_scan, base_inv, declared
        )
    except Exception as exc:
        broken.append(
            f"could not dry-run box_selfcheck over the repo bytes ({exc}); the manifest was "
            "never validated against its own consumer, so nothing is emitted"
        )
        return None, problems, broken, notes
    not_checked.extend(dropped)

    # box_selfcheck FAILS CLOSED on an empty mint_scan and an empty pinned_scripts, and PASSES
    # on an empty prose_scan (`not bad` over zero findings is True). So that one asymmetry has to
    # be guarded here, or a manifest that dropped every prose target would ship a check that
    # reports green having read nothing.
    if not prose_scan:
        problems.append(
            "prose_scan is empty after validation; box_selfcheck passes an empty prose scan "
            "silently, so this manifest would ship a check that reads nothing and reports green"
        )

    # Binaries. Three states, and a reader has to be able to tell them apart.
    provenance: dict[str, dict] = {}
    stale: list[str] = []
    entries = (blessed or {}).get("entries") or {}

    for plugin in plugin_dirs(root):
        rec = entries.get(plugin)
        if not rec:
            not_checked.append(
                {
                    "kind": "unblessed-binary",
                    "plugin": plugin,
                    "reason": "never blessed; no hash exists for what should be deployed",
                    "fix": f"python3 deploy/make_invariants.py --bless {plugin} --wasm "
                    f"plugins/{plugin}/target/wasm32-wasip2/release/"
                    f"{plugin.replace('-', '_')}.wasm",
                }
            )
            continue
        want_src = plugin_source_sha256(root, plugin)
        is_stale = want_src != rec.get("source_sha256")
        box_path = rec.get("box_path") or wasm_box_path(root, plugin)
        files[box_path] = rec["sha256"]
        provenance[box_path] = {
            "plugin": plugin,
            "kind": "blessed-binary",
            "blessed_at": rec.get("blessed_at"),
            "source_commit": rec.get("source_commit"),
            "source_sha256_at_bless": rec.get("source_sha256"),
            "source_sha256_now": want_src,
            "stale": is_stale,
            "size": rec.get("size"),
        }
        if is_stale:
            stale.append(plugin)

    if stale and not allow_stale:
        for plugin in stale:
            problems.append(
                f"{plugin}: blessed against source that has since moved, so the pin no longer "
                "describes current source. Rebuild and re-bless, or pass "
                "--allow-stale-binaries to emit with stale:true recorded"
            )

    if problems:
        return None, problems, broken, notes

    _, head_out = git(root, "rev-parse", "HEAD")
    _, dirty_out = git(root, "status", "--porcelain")

    manifest = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "generated_at_epoch": int(time.time()),
        "generator": "deploy/make_invariants.py",
        "repo_commit": head_out.strip() or "unknown",
        "repo_dirty": bool(dirty_out.strip()),
        "files": files,
        "merchant": pins.get("merchant"),
        "mint": pins.get("mint"),
        "network": pins.get("network"),
        "allowed_addresses": targets.get("allowed_addresses") or [],
        "known_other": targets.get("known_other") or [],
        "retired_mints": retired_mints,
        "mint_scan": mint_scan,
        "state_scan": state_scan,
        "prose_scan": prose_scan,
        "pinned_scripts": pinned_scripts,
        "units": [u["unit"] for u in (targets.get("units") or []) if u.get("unit")],
        "provenance": provenance,
        "not_checked": not_checked,
    }
    if stale:
        notes.append(
            f"{len(stale)} binary pin(s) emitted STALE by explicit flag: {', '.join(stale)}"
        )
    return manifest, problems, broken, notes


# ---------------------------------------------------------------------------------------------
# self-test
# ---------------------------------------------------------------------------------------------

T_MERCHANT = "C331X4YCHCdcESexRTKSjE5etjsWyWJLK73Z18ZWiLHJ"
T_MINT = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
T_DEVNET = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU"

T_TARGETS = {
    "version": 1,
    "map": [
        {
            "src": "skills/solana-pay",
            "dst": "shared/skills/default/solana-pay",
            "include": "**",
        },
        {
            "src": "skills/solana-pay/scripts",
            "dst": "agents/demo/workspace/tools",
            "include": "pay_link.py",
            "flatten": True,
        },
        {"src": "sops", "dst": "data/sops", "include": "**"},
        {"src": "sops", "dst": "agents/demo/workspace/sops", "include": "**"},
    ],
    "units": [],
    "mint_scan_extra": [],
    "allowed_addresses": [],
    "known_other": [],
}


def _plant_repo(root: Path) -> None:
    """A synthetic repo with the same SHAPE as the real one: two SOP destinations, a skill tree
    deployed twice, a test file carrying the devnet fixture, and one plugin with source."""
    (root / "skills" / "solana-pay" / "scripts").mkdir(parents=True)
    (root / "plugins" / "pw" / "src").mkdir(parents=True)
    (root / "wit" / "v0").mkdir(parents=True)
    (root / "crates" / "solana-core" / "src").mkdir(parents=True)

    # The last two lines reproduce the REAL false positive verbatim in shape: a prohibition whose
    # marker sits on the previous line, so the line the gate scans reads as a bare assertion.
    # No wording change to a correct file fixes it, which is why the generator validates rather
    # than trusting the check.
    (root / "skills" / "solana-pay" / "SKILL.md").write_text(
        "Esta loja recebe em USDC na mainnet da Solana.\n"
        f"Pay {T_MERCHANT} with {T_MINT}.\n"
        "A customer was quoted a real mainnet charge under a sentence saying\n"
        "the shop runs on devnet.\n",
        encoding="utf-8",
        newline="\n",
    )
    (root / "skills" / "solana-pay" / "scripts" / "pay_link.py").write_text(
        f'MERCHANT = "{T_MERCHANT}"\nMINT = "{T_MINT}"\n',
        encoding="utf-8",
        newline="\n",
    )
    (root / "skills" / "solana-pay" / "scripts" / "test_pay_link.py").write_text(
        f'# must REFUSE this one\nWRONG = "{T_DEVNET}"\nOK = "{T_MINT}"\n',
        encoding="utf-8",
        newline="\n",
    )
    for name in (
        "evening-reconciliation",
        "payment-confirmation",
        "node-earnings-report",
    ):
        d = root / "sops" / name
        d.mkdir(parents=True)
        (d / "SOP.md").write_text(
            f"# {name}\nSettles on mainnet.\n", encoding="utf-8", newline="\n"
        )
        (d / "SOP.toml").write_text(
            f'name = "{name}"\n', encoding="utf-8", newline="\n"
        )

    (root / "plugins" / "pw" / "manifest.toml").write_text(
        'name = "pw"\nwasm_path = "pw.wasm"\n', encoding="utf-8", newline="\n"
    )
    (root / "plugins" / "pw" / "src" / "lib.rs").write_text(
        "// v1\n", encoding="utf-8", newline="\n"
    )
    (root / "wit" / "v0" / "logging.wit").write_text(
        "enum plugin-action { a, b }\n", encoding="utf-8", newline="\n"
    )
    (root / "crates" / "solana-core" / "src" / "lib.rs").write_text(
        "// core\n", encoding="utf-8", newline="\n"
    )

    git(root, "init", "-q")
    git(root, "add", "-A")
    subprocess.run(
        [
            "git",
            "-C",
            str(root),
            "-c",
            "user.email=t@t",
            "-c",
            "user.name=t",
            "commit",
            "-q",
            "-m",
            "t",
        ],
        capture_output=True,
        text=True,
    )


def _plant_box(root: Path, box: Path, manifest: dict, wasm_src: Path | None) -> None:
    """A CORRECT deployment: every manifest path present with the repo's bytes."""
    pairs, _ = resolve_map(root, T_TARGETS)
    for repo_rel, box_rel in pairs:
        dst = box / box_rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(root / repo_rel, dst)
    for box_rel, info in (manifest.get("provenance") or {}).items():
        if info.get("kind") == "blessed-binary" and wasm_src:
            dst = box / box_rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(wasm_src, dst)


def self_test() -> int:
    passed = failed = 0

    def report(label: str, cond: bool) -> None:
        nonlocal passed, failed
        if cond:
            passed += 1
            print(f"  PASS  {label}")
        else:
            failed += 1
            print(f"  FAIL  {label}")

    sys.path.insert(0, str(HERE))
    try:
        import box_selfcheck as bsc
    except Exception as exc:
        # NOT CHECKED rather than skipped: the whole point is that the generator's output is
        # consumable by the real gate, and without the gate nothing here proves that.
        print(f"NOT CHECKED  cannot import box_selfcheck: {exc}")
        return 2

    tmp = Path(tempfile.mkdtemp(prefix="mkinv-"))
    try:
        repo = tmp / "repo"
        repo.mkdir()
        _plant_repo(repo)

        wasm = tmp / "pw.wasm"
        wasm.write_bytes(WASM_MAGIC + b"\x01\x00\x00\x00FRESH-BUILD")
        old_wasm = tmp / "pw-old.wasm"
        old_wasm.write_bytes(WASM_MAGIC + b"\x01\x00\x00\x00JUL-26-BUILD")

        # --- bless, then generate -----------------------------------------------------------
        global BLESSED_PATH
        real_blessed = BLESSED_PATH
        BLESSED_PATH = repo / "deploy" / "blessed-binaries.json"
        try:
            rc = bless(repo, "pw", wasm)
            report("bless: a real wasm is accepted", rc == 0)

            notwasm = tmp / "not.wasm"
            notwasm.write_text("I am not a component\n", encoding="utf-8")
            report("bless: a non-wasm file is REFUSED", bless(repo, "pw", notwasm) == 1)
            # blessed-binaries.json is TRACKED, so nothing recorded in it may name the operator.
            # The wasm above lives OUTSIDE the synthetic repo, which is the leaking case.
            rec = (load_json(BLESSED_PATH) or {})["entries"]["pw"]
            report(
                "bless: an out-of-repo artifact records a BASENAME, not a home path",
                rec["blessed_from"] == "pw.wasm",
            )
            report(
                "bless: no absolute path reached the tracked record",
                not any(
                    isinstance(v, str) and (":" in v[1:3] or v.startswith("/"))
                    for v in rec.values()
                ),
            )
            report(
                "bless: the refusal did not overwrite the good record",
                (load_json(BLESSED_PATH) or {})["entries"]["pw"]["sha256"]
                == sha256_file(wasm),
            )

            blessed = load_json(BLESSED_PATH) or {}
            man, probs, brk, _notes = build_manifest(
                repo, T_TARGETS, blessed, allow_stale=False
            )
            report(
                "generate: a clean tree emits a manifest",
                man is not None and not probs and not brk,
            )
            if man is None:
                print(f"    cannot continue: {probs or brk}")
                return 1

            # --- what got derived ------------------------------------------------------------
            report(
                "derive: merchant parsed out of the enforcing script",
                man["merchant"] == T_MERCHANT,
            )
            report(
                "derive: mint parsed out of the enforcing script", man["mint"] == T_MINT
            )
            report(
                "derive: network follows from the mint, not a declaration",
                man["network"] == "mainnet",
            )
            report(
                "derive: BOTH SOP destinations are pinned, not just one",
                "data/sops/payment-confirmation/SOP.md" in man["files"]
                and "agents/demo/workspace/sops/payment-confirmation/SOP.md"
                in man["files"],
            )
            report(
                "derive: the flattened workspace tools copy is pinned at its own path",
                "agents/demo/workspace/tools/pay_link.py" in man["files"],
            )
            report(
                "derive: the flatten include did NOT sweep the test file into tools/",
                "agents/demo/workspace/tools/test_pay_link.py" not in man["files"],
            )
            report(
                "derive: pinned_scripts found by CONTENT, both pay_link copies",
                sorted(man["pinned_scripts"])
                == [
                    "agents/demo/workspace/tools/pay_link.py",
                    "shared/skills/default/solana-pay/scripts/pay_link.py",
                ],
            )
            report(
                "derive: the binary is pinned at the path the DAEMON loads",
                man["files"].get("plugins/pw/pw.wasm") == sha256_file(wasm),
            )
            test_box = "shared/skills/default/solana-pay/scripts/test_pay_link.py"
            report("scope: the test file IS hash-compared", test_box in man["files"])
            report(
                "scope: the test file is NOT mint-scanned",
                test_box not in man["mint_scan"],
            )
            report(
                "derive: the retired list is DERIVED, so the devnet mint needs no declaration",
                man["retired_mints"] == [T_DEVNET],
            )
            report(
                "derive: the CONFIGURED mint is never in its own prohibition list",
                T_MINT not in man["retired_mints"],
            )

            # --- polarity routing, which is the whole point of the change ----------------------
            deny_targets = json.loads(json.dumps(T_TARGETS))
            deny_targets["mint_scan_extra"] = [
                {"path": "data/memory/brain.db", "enabled": True, "policy": "denylist"}
            ]
            m_deny, p_deny, _b, _n = build_manifest(
                repo, deny_targets, blessed, allow_stale=True
            )
            report(
                "routing: a denylist extra lands in state_scan and NOT in mint_scan",
                m_deny is not None
                and m_deny["state_scan"] == ["data/memory/brain.db"]
                and "data/memory/brain.db" not in m_deny["mint_scan"],
            )

            allow_targets = json.loads(json.dumps(T_TARGETS))
            allow_targets["mint_scan_extra"] = [
                {"path": "data/memory/brain.db", "enabled": True}
            ]
            m_allow, _p, _b, _n = build_manifest(
                repo, allow_targets, blessed, allow_stale=True
            )
            report(
                "routing: an extra with NO policy keeps the old allowlist behaviour",
                m_allow is not None
                and "data/memory/brain.db" in m_allow["mint_scan"]
                and m_allow["state_scan"] == [],
            )

            bad_targets = json.loads(json.dumps(T_TARGETS))
            bad_targets["mint_scan_extra"] = [
                {"path": "data/memory/brain.db", "enabled": True, "policy": "denylst"}
            ]
            m_bad, p_bad, _b, _n = build_manifest(
                repo, bad_targets, blessed, allow_stale=True
            )
            report(
                "routing: a MISSPELLED policy refuses rather than guessing the polarity",
                m_bad is None and any("only 'allowlist'" in p for p in p_bad),
            )

            # A typo'd extra is a prohibition that matches nothing and reports clean forever, so
            # it has to refuse at emit time; the shape is unverifiable once it reaches the box.
            typo_targets = json.loads(json.dumps(T_TARGETS))
            typo_targets["retired_mints_extra"] = ["not-a-base58-address"]
            m_typo, p_typo, _b, _n = build_manifest(
                repo, typo_targets, blessed, allow_stale=True
            )
            report(
                "retired: a non-base58 extra REFUSES the emit",
                m_typo is None and any("matches nothing" in p for p in p_typo),
            )
            self_targets = json.loads(json.dumps(T_TARGETS))
            self_targets["retired_mints_extra"] = [T_MINT]
            m_self, p_self, _b, _n = build_manifest(
                repo, self_targets, blessed, allow_stale=True
            )
            report(
                "retired: retiring the shop's OWN mint REFUSES the emit",
                m_self is None and any("CONFIGURED mint" in p for p in p_self),
            )

            # --- the two incidents, driven through the REAL gate -----------------------------
            box = tmp / "box"
            box.mkdir()
            _plant_box(repo, box, man, wasm)
            bsc.ZC = box

            def manifest_verdict() -> tuple[bool, str]:
                r = bsc.Result()
                bsc.check_manifest(man, r)
                return r.checks[0]["ok"], r.checks[0]["detail"]

            ok, _ = manifest_verdict()
            report("CONTROL: a correct deployment is GREEN", ok is True)

            skill_box = box / "shared/skills/default/solana-pay/SKILL.md"
            good_skill = skill_box.read_bytes()
            skill_box.write_bytes(
                good_skill.replace(b"na mainnet da Solana", b"na devnet da Solana")
            )
            ok, detail = manifest_verdict()
            report(
                "INCIDENT 1: a live skill drifted behind the repo is RED",
                ok is False and "SKILL.md" in detail,
            )
            skill_box.write_bytes(good_skill)
            report(
                "INCIDENT 1: restoring the skill returns to GREEN",
                manifest_verdict()[0] is True,
            )

            wasm_box = box / "plugins/pw/pw.wasm"
            wasm_box.write_bytes(old_wasm.read_bytes())
            ok, detail = manifest_verdict()
            report(
                "INCIDENT 2: deployed binary differs from the blessed one, RED",
                ok is False and "pw.wasm" in detail,
            )

            # The exact shape of incident 2: the FRESH build exists, at the wrong path, and the
            # path the daemon loads holds nothing. A content hash alone cannot see this.
            wasm_box.unlink()
            wrong_dir = box / "zc-shop" / "plugins"
            wrong_dir.mkdir(parents=True)
            shutil.copyfile(wasm, wrong_dir / "pw.wasm")
            ok, detail = manifest_verdict()
            report(
                "INCIDENT 2: fresh build at the WRONG directory is RED as MISSING",
                ok is False and "MISSING" in detail and "plugins/pw/pw.wasm" in detail,
            )
            shutil.copyfile(wasm, wasm_box)
            report(
                "INCIDENT 2: redeploying to the loaded path returns to GREEN",
                manifest_verdict()[0] is True,
            )

            # --- MUTATION CONTROL 1: gut the comparison ---------------------------------------
            # A green suite is equally consistent with a gate that cannot fail, so both incident
            # cases must STOP firing once the comparison is disabled.
            src = Path(bsc.__file__).read_text(encoding="utf-8")
            anchor = "        if got != want:"
            report("mutation 1: the anchor it keys on still exists", anchor in src)
            ns: dict = {"__name__": "bsc_mutant", "__file__": bsc.__file__}
            exec(
                compile(src.replace(anchor, "        if False:"), "bsc_mutant", "exec"),
                ns,
            )
            ns["ZC"] = box
            skill_box.write_bytes(good_skill.replace(b"mainnet", b"devnet"))
            wasm_box.write_bytes(old_wasm.read_bytes())
            mr = ns["Result"]()
            ns["check_manifest"](man, mr)
            report(
                "mutation 1: with the comparison gutted BOTH incidents go green",
                mr.checks[0]["ok"] is True,
            )
            skill_box.write_bytes(good_skill)
            shutil.copyfile(wasm, wasm_box)

            # --- MUTATION CONTROL 2: the test-file exclusion is load-bearing -------------------
            report(
                "CONTROL: the mint scan is GREEN on a correct deployment",
                (lambda r: (bsc.check_mint_prohibition(man, r), r.checks[0]["ok"])[1])(
                    bsc.Result()
                )
                is True,
            )
            leaky = dict(man)
            leaky["mint_scan"] = sorted(set(man["mint_scan"]) | {test_box})
            r2 = bsc.Result()
            bsc.check_mint_prohibition(leaky, r2)
            report(
                "mutation 2: without the test exclusion a CORRECT deploy goes red",
                r2.checks[0]["ok"] is False,
            )

            # --- red-by-construction scan targets ----------------------------------------------
            skill_box_rel = "shared/skills/default/solana-pay/SKILL.md"
            report(
                "validate: a prose file RED on its own correct bytes is DROPPED",
                skill_box_rel not in man["prose_scan"],
            )
            report(
                "validate: the drop is RECORDED with the gate's own words, not silent",
                any(
                    e.get("path") == skill_box_rel
                    and e.get("scan") == "prose_scan"
                    and "devnet" in e.get("gate_said", "")
                    for e in man["not_checked"]
                ),
            )
            report(
                "validate: the OTHER prose files survive, so the check is not disabled",
                len(man["prose_scan"]) == 6
                and all(p.endswith("SOP.md") for p in man["prose_scan"]),
            )
            report(
                "validate: the dropped file is STILL hash-compared, only the scan is narrowed",
                skill_box_rel in man["files"],
            )

            # --- MUTATION CONTROL 4: the validation is load-bearing ----------------------------
            gen_src = Path(__file__).read_text(encoding="utf-8")
            anchor4 = "    gate = import_gate()"
            report("mutation 4: the anchor it keys on still exists", anchor4 in gen_src)
            ns4: dict = {"__name__": "gen_mutant4", "__file__": __file__}
            exec(
                compile(
                    gen_src.replace(
                        anchor4,
                        "    return sorted(mint_scan), sorted(prose_scan), []",
                        1,
                    ),
                    "gen_mutant4",
                    "exec",
                ),
                ns4,
            )
            m11, _p11, _b11, _n11 = ns4["build_manifest"](
                repo, T_TARGETS, blessed, allow_stale=True
            )
            r5 = bsc.Result()
            bsc.check_network_prose(m11, r5)
            report(
                "mutation 4: unvalidated, a CORRECT deployment goes RED forever",
                skill_box_rel in m11["prose_scan"] and r5.checks[0]["ok"] is False,
            )

            # --- the empty-prose floor, which guards an ASYMMETRY in the gate ------------------
            # box_selfcheck fails closed on an empty mint_scan and an empty pinned_scripts, and
            # PASSES an empty prose_scan silently. So a manifest that validated every prose file
            # away would ship a check that reads nothing and reports green.
            sops = sorted((repo / "sops").glob("*/SOP.md"))
            saved = {p: p.read_bytes() for p in sops}
            for p in sops:
                p.write_text(
                    "A customer was quoted a real mainnet charge under a sentence saying\n"
                    "the shop runs on devnet.\n",
                    encoding="utf-8",
                    newline="\n",
                )
            m_floor, p_floor, _b, _n = build_manifest(
                repo, T_TARGETS, blessed, allow_stale=True
            )
            report(
                "floor: every prose target validated away REFUSES rather than shipping green",
                m_floor is None and any("reads nothing" in p for p in p_floor),
            )
            for p, body in saved.items():
                p.write_bytes(body)
            report(
                "floor: restoring the prose files emits again",
                build_manifest(repo, T_TARGETS, blessed, allow_stale=True)[0]
                is not None,
            )

            # --- the rest of the gate consumes it too -----------------------------------------
            r3 = bsc.Result()
            bsc.check_network_prose(man, r3)
            bsc.check_pins(man, r3)
            report(
                "end to end: network-prose and code-pins are GREEN on the generated manifest",
                all(c["ok"] for c in r3.checks),
            )

            # --- stale pins --------------------------------------------------------------------
            (repo / "plugins" / "pw" / "src" / "lib.rs").write_text(
                "// v2\n", encoding="utf-8", newline="\n"
            )
            git(repo, "add", "-A")
            man2, probs2, _brk2, _n2 = build_manifest(
                repo, T_TARGETS, blessed, allow_stale=False
            )
            report(
                "stale: source moved after blessing, the emit is REFUSED",
                man2 is None and any("moved" in p for p in probs2),
            )
            man3, probs3, _brk3, notes3 = build_manifest(
                repo, T_TARGETS, blessed, allow_stale=True
            )
            report(
                "stale: --allow-stale-binaries emits and RECORDS stale:true",
                man3 is not None
                and not probs3
                and man3["provenance"]["plugins/pw/pw.wasm"]["stale"] is True
                and any("STALE" in n for n in notes3),
            )
            report(
                "stale: the manifest carries both hashes so a reader can tell",
                man3["provenance"]["plugins/pw/pw.wasm"]["source_sha256_at_bless"]
                != man3["provenance"]["plugins/pw/pw.wasm"]["source_sha256_now"],
            )

            # --- MUTATION CONTROL 3: the staleness check is load-bearing -----------------------
            anchor3 = 'is_stale = want_src != rec.get("source_sha256")'
            report("mutation 3: the anchor it keys on still exists", anchor3 in gen_src)
            ns3: dict = {"__name__": "gen_mutant", "__file__": __file__}
            exec(
                compile(
                    gen_src.replace(anchor3, "is_stale = False"), "gen_mutant", "exec"
                ),
                ns3,
            )
            m4, p4, _b4, _n4 = ns3["build_manifest"](
                repo, T_TARGETS, blessed, allow_stale=False
            )
            report(
                "mutation 3: with the staleness check gutted the stale case STOPS firing",
                m4 is not None and not p4,
            )

            # --- never blessed -------------------------------------------------------------
            m5, _p5, _b5, _n5 = build_manifest(
                repo, T_TARGETS, {"entries": {}}, allow_stale=False
            )
            report(
                "unblessed: a plugin with no record is NOT CHECKED and named",
                m5 is not None
                and [
                    e["plugin"]
                    for e in m5["not_checked"]
                    if e["kind"] == "unblessed-binary"
                ]
                == ["pw"]
                and "plugins/pw/pw.wasm" not in m5["files"],
            )
        finally:
            BLESSED_PATH = real_blessed

        # --- broken walks: rc != 0 and NOT CHECKED, never a silent pass ---------------------
        bad_map = json.loads(json.dumps(T_TARGETS))
        bad_map["map"][0]["src"] = "skills/renamed-away"
        m6, _p6, b6, _n6 = build_manifest(repo, bad_map, {}, allow_stale=False)
        report(
            "broken map: a prefix matching nothing emits NOTHING",
            m6 is None and bool(b6),
        )
        report("broken map: it says the map is broken", any("broken" in x for x in b6))

        only_one = json.loads(json.dumps(T_TARGETS))
        only_one["map"] = [only_one["map"][1]]
        m7, _p7, b7, _n7 = build_manifest(repo, only_one, {}, allow_stale=False)
        report(
            "floor: a walk that collapses to one file emits NOTHING",
            m7 is None and any("floor" in x for x in b7),
        )

        empty_repo = tmp / "empty"
        empty_repo.mkdir()
        git(empty_repo, "init", "-q")
        m8, _p8, b8, _n8 = build_manifest(empty_repo, T_TARGETS, {}, allow_stale=False)
        report(
            "empty repo: emits NOTHING rather than an empty manifest",
            m8 is None and bool(b8),
        )

        # --- pins gone -----------------------------------------------------------------------
        (repo / "skills" / "solana-pay" / "scripts" / "pay_link.py").write_text(
            "# the pin was removed\n", encoding="utf-8", newline="\n"
        )
        git(repo, "add", "-A")
        m9, p9, _b9, _n9 = build_manifest(repo, T_TARGETS, {}, allow_stale=False)
        report(
            "pins: a removed MERCHANT/MINT constant REFUSES the emit",
            m9 is None and any("MERCHANT" in p for p in p9),
        )

        # --- unknown mint --------------------------------------------------------------------
        (repo / "skills" / "solana-pay" / "scripts" / "pay_link.py").write_text(
            f'MERCHANT = "{T_MERCHANT}"\nMINT = "{T_DEVNET[:-1]}X"\n',
            encoding="utf-8",
            newline="\n",
        )
        git(repo, "add", "-A")
        m10, p10, _b10, _n10 = build_manifest(repo, T_TARGETS, {}, allow_stale=False)
        report(
            "network: an unrecognised mint REFUSES rather than guessing",
            m10 is None and any("no known network" in p for p in p10),
        )
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    # --- the real config on disk parses and is shaped as expected ---------------------------
    real_targets = load_json(TARGETS_PATH)
    report("config: deploy-targets.json parses", isinstance(real_targets, dict))
    report(
        "config: it declares only box facts (a map and units)",
        bool(real_targets and real_targets.get("map") and real_targets.get("units")),
    )
    report(
        "config: blessed-binaries.json parses",
        isinstance(load_json(BLESSED_PATH), dict),
    )

    print(f"\n{passed} passed, {failed} failed")
    return 0 if failed == 0 else 1


# ---------------------------------------------------------------------------------------------


def main() -> int:
    ap = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    ap.add_argument(
        "--out", default=str(DEFAULT_OUT), help="where to write the manifest"
    )
    ap.add_argument(
        "--bless", metavar="PLUGIN", help="record the hash of a built plugin binary"
    )
    ap.add_argument(
        "--wasm", metavar="PATH", help="the built artifact, required with --bless"
    )
    ap.add_argument(
        "--allow-stale-binaries",
        action="store_true",
        help="emit binary pins whose source has moved, recording stale:true in the manifest",
    )
    ap.add_argument(
        "--self-test", action="store_true", help="drive every case both directions"
    )
    args = ap.parse_args()

    if args.self_test:
        return self_test()

    if args.bless:
        if not args.wasm:
            print("NOT CHECKED  --bless needs --wasm <path-to-built.wasm>")
            return 2
        return bless(ROOT, args.bless, Path(args.wasm))

    if git(ROOT, "rev-parse", "--git-dir")[0] != 0:
        print(
            f"NOT CHECKED  {ROOT} is not a git repo, so the file set cannot be derived"
        )
        return 2

    targets = load_json(TARGETS_PATH)
    if not isinstance(targets, dict):
        print(
            f"NOT CHECKED  cannot read {TARGETS_PATH}; nothing was derived and this is NOT a pass"
        )
        return 2
    blessed = load_json(BLESSED_PATH)
    if not isinstance(blessed, dict):
        print(
            f"NOT CHECKED  cannot read {BLESSED_PATH}; binary pins would be silently absent"
        )
        return 2

    manifest, problems, broken, notes = build_manifest(
        ROOT, targets, blessed, allow_stale=args.allow_stale_binaries
    )

    if broken:
        print("NOT CHECKED  the discovery walk is broken, so nothing was written:\n")
        for b in broken:
            print(f"  {b}")
        return 2
    if manifest is None:
        print("REFUSED  emitting would state something known to be wrong:\n")
        for p in problems:
            print(f"  {p}")
        return 1

    out = Path(args.out)
    write_json(out, manifest)

    n_bin = sum(
        1 for v in manifest["provenance"].values() if v["kind"] == "blessed-binary"
    )
    n_stale = sum(1 for v in manifest["provenance"].values() if v.get("stale"))
    print(f"wrote {out}")
    print(
        f"  files pinned      {len(manifest['files'])}  "
        f"({len(manifest['files']) - n_bin} from git, {n_bin} blessed binaries)"
    )
    print(f"  mint scan         {len(manifest['mint_scan'])} target(s) (allowlist)")
    print(
        f"  state scan        {len(manifest['state_scan'])} target(s) against "
        f"{len(manifest['retired_mints'])} retired mint(s) (denylist)"
    )
    print(
        f"  prose scan        {len(manifest['prose_scan'])} file(s) against network="
        f"{manifest['network']}"
    )
    print(f"  pinned scripts    {len(manifest['pinned_scripts'])}")
    print(f"  units             {len(manifest['units'])}")
    if n_stale:
        print(f"  STALE binaries    {n_stale} emitted with stale:true by explicit flag")
    unblessed = [e for e in manifest["not_checked"] if e["kind"] == "unblessed-binary"]
    red_on_ref = [
        e
        for e in manifest["not_checked"]
        if e["kind"] == "scan-target-red-on-reference"
    ]
    if unblessed:
        print(f"  NOT CHECKED       {len(unblessed)} plugin(s) with no blessed hash:")
        for e in unblessed:
            print(f"                      {e['plugin']}")
        print(
            "                    bless each one after building and deploying it, or the"
        )
        print("                    binary that broke the demo is pinned by nothing")
    if red_on_ref:
        print(
            f"  NOT SCANNED       {len(red_on_ref)} file(s) the gate reds on CORRECT bytes:"
        )
        for e in red_on_ref:
            print(f"                      {e['path']}  ({e['scan']})")
            print(f"                        gate said: {e['gate_said'][:88]}")
        print("                    shipping these would pin the box verdict to DRIFTED")
        print("                    forever. They are still hash-compared in files.")
    for n in notes:
        print(f"  note              {n}")

    print("\nNext: copy it to the box and run the gate there.")
    print("  scp/paste to  ~/.zeroclaw/SHOP-INVARIANTS.json")
    print("  python3 deploy/box_selfcheck.py")
    print(
        "A path this map got wrong shows up there as MISSING, naming the exact path it wanted."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
