#!/usr/bin/env python3
"""Prove check-custody-tier.py can FAIL, by giving a component a capability it disclaims.

A checker that has only ever printed PASS has not been shown to work. `check-custody-tier.py`
reports that none of the eight shipped components can touch the filesystem; this is the
control that makes that report worth reading, because it plants a real filesystem read in
the plugin making the strongest claim and requires the gate to catch it.

WHY THE MUTATION IS A SOURCE CHANGE AND NOT A BYTE PATCH. The question is whether the gate
catches a component that genuinely GAINED a capability through the ordinary build, which is
how such a regression would actually arrive: a dependency bump, a convenience `std::fs`
call, a refactor. Corrupting the binary would test a different and easier thing.

TARGET. `solana-pay-request` declares `permissions = []`, `network_reachable = false` and
`filesystem = false`. It is the component with the least to hide, so a capability appearing
there is unambiguous.

SEQUENCE. Rebuild clean, record the pristine import set, plant `std::fs::read_to_string`,
rebuild, require rc=1 with BOTH findings named, restore, rebuild, and require the import
list to come back IDENTICAL. That last assertion is not ceremony: on the first run of this
control the revert appeared to fail, because deleting the wasm is not enough on its own.
Cargo relinks the component from cached dependency artifacts, so two consecutive rebuilds
returned the MUTATED component while `git diff` on the source was empty. `cargo clean -p`
is what forces it, and it is why every build below is preceded by one.

NOT wired into check-all.py or the fast CI path, deliberately and disclosed rather than
omitted: it edits a tracked source file and needs the Rust wasm toolchain, neither of which
belongs in a gate that must run unattended on a clean checkout. Run it yourself:

    python3 scripts/mutation-check-custody-tier.py

Exit 0 the gate caught the planted capability and the tree was restored. Exit 1 otherwise.
"""

import importlib.util
import pathlib
import shutil
import subprocess
import sys
import tomllib

ROOT = pathlib.Path(__file__).resolve().parent.parent
PLUGIN = ROOT / "plugins" / "solana-pay-request"
SRC = PLUGIN / "src" / "lib.rs"
GATE = ROOT / "scripts" / "check-custody-tier.py"
BACKUP = pathlib.Path(str(SRC) + ".mutation-backup")

spec = importlib.util.spec_from_file_location("cct", GATE)
cct = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cct)

WASM = cct.wasm_for(
    PLUGIN, tomllib.loads((PLUGIN / "manifest.toml").read_text(encoding="utf-8"))
)

ANCHOR = "            match pay::parse_and_validate(&args) {"
PLANT = """            // PLANTED BY scripts/mutation-check-custody-tier.py. If you are reading
            // this in a committed file, the control aborted midway: revert it.
            let planted = std::fs::read_to_string("/etc/hostname").unwrap_or_default();
            if planted.len() == 999_999 {
                return Err(planted);
            }
"""


def build() -> None:
    WASM.unlink(missing_ok=True)
    subprocess.run(
        [
            "cargo",
            "clean",
            "-p",
            "solana-pay-request",
            "--target",
            "wasm32-wasip2",
            "--release",
        ],
        cwd=PLUGIN,
        capture_output=True,
    )
    r = subprocess.run(
        ["cargo", "build", "--target", "wasm32-wasip2", "--release"],
        cwd=PLUGIN,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if r.returncode != 0:
        print(r.stdout[-2000:])
        print(r.stderr[-2000:])
        raise SystemExit(f"build failed rc={r.returncode}")


def caps():
    imports = cct.component_imports(WASM.read_bytes())
    return sorted({cct.capability_of(i) for i in imports}), imports


def gate():
    r = subprocess.run(
        [sys.executable, str(GATE)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    return r.returncode, (r.stdout or "") + (r.stderr or "")


def main() -> int:
    if "PLANTED BY" in SRC.read_text(encoding="utf-8"):
        print("MISS  the source already carries a plant; revert it before running")
        return 1

    print("1. pristine baseline")
    build()
    pristine_caps, pristine_imports = caps()
    rc0, out0 = gate()
    print(f"   {len(pristine_imports)} imports, capabilities {pristine_caps}")
    print(f"   gate rc={rc0} (want 0)")
    if rc0 != 0 or "filesystem" in pristine_caps:
        print(out0)
        return 1

    print("\n2. plant a real filesystem read, rebuild")
    text = SRC.read_text(encoding="utf-8")
    if ANCHOR not in text:
        print(f"MISS  anchor not found in {SRC}; the control did not run")
        return 1
    shutil.copy2(SRC, BACKUP)
    # Initialised before the try so a build failure inside it cannot leave these unbound
    # and turn a real failure into a NameError, which would read as a broken control
    # rather than as a caught regression.
    caught_cap = caught_claim = False
    planted_caps: list = []
    rc1 = -1
    try:
        SRC.write_text(
            text.replace(ANCHOR, PLANT + ANCHOR, 1), encoding="utf-8", newline="\n"
        )
        build()
        planted_caps, planted_imports = caps()
        rc1, out1 = gate()
        print(
            f"   {len(pristine_imports)} -> {len(planted_imports)} imports, capabilities {planted_caps}"
        )
        print(f"   gate rc={rc1} (want 1)")
        caught_cap = "imports filesystem which" in out1
        caught_claim = "declares filesystem = False" in out1
        for line in out1.splitlines():
            if "solana-pay-request:" in line:
                print(f"     {line.strip()}")
    finally:
        print("\n3. restore, rebuild")
        shutil.copy2(BACKUP, SRC)
        BACKUP.unlink()
        build()

    restored_caps, restored_imports = caps()
    identical = restored_imports == pristine_imports
    rc2, _ = gate()
    print(f"   capabilities {restored_caps}")
    print(f"   restored import list identical to pristine: {identical}")
    print(f"   gate rc={rc2} (want 0)")

    ok = (
        rc1 == 1
        and caught_cap
        and caught_claim
        and "filesystem" in planted_caps
        and identical
        and rc2 == 0
    )
    print(f"\nCONTROL {'PASSED' if ok else 'FAILED'}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
