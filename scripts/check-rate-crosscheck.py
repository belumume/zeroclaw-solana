#!/usr/bin/env python3
"""Assert the BRL/USD cross-check still refuses everything it is supposed to refuse.

WHY THIS EXISTS. `scripts/rate_crosscheck.py` is the last thing standing between a model-chosen
exchange rate and a customer being asked for money. Its whole value is in what it REFUSES:
sources disagreeing, sources reporting different dates, a rate outside the plausible band, a
malformed response. A refusal path has no output on the happy day, so it can rot for months
without anyone noticing, which is exactly the shape this repo has already reported upstream as
"a control which is claimed and enforced by no runtime path".

OFFLINE, BY CONSTRUCTION. This gate calls only the pure adjudication and parsing functions. It
makes no network call, so a BCB or ECB outage cannot redden a gate that has nothing to do with
either, and a CI runner with no egress still gets a real verdict. Whether the endpoints are
reachable is a separate, live question answered by running the tool itself.

THE CONTROLS ARE THE POINT, not the passes. Two cases exist purely to prove the checks are
load-bearing rather than vacuously green: the real 2026-08-14 values must be ACCEPTED, and the
same values with the band at zero must be REFUSED. Without the second, the first could be
passing because nothing is being compared. Without the first, the band could have been tightened
past reality and the tool would refuse every honest day while this gate stayed green.

Exit codes follow the house convention: 0 all controls hold, 1 a real finding.

Run: python3 scripts/check-rate-crosscheck.py
"""

from __future__ import annotations

import importlib.util
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
TARGET = ROOT / "scripts" / "rate_crosscheck.py"


def load():
    """Exec the SOURCE, never a cached .pyc.

    The sibling gate learned this the hard way: `spec_from_file_location` served a stale
    bytecode file after a mutation control restored the source at the same size inside one
    filesystem tick, and manufactured a disagreement that did not exist. mtime is not a version.
    """
    if not TARGET.is_file():
        print(
            f"FAIL  {TARGET} is missing; the tool this gate protects is gone.",
            file=sys.stderr,
        )
        sys.exit(1)
    spec = importlib.util.spec_from_file_location("_rate_crosscheck_under_test", TARGET)
    if spec is None or spec.loader is None:
        print(f"FAIL  cannot load {TARGET} as a module.", file=sys.stderr)
        sys.exit(1)
    mod = importlib.util.module_from_spec(spec)
    sys.dont_write_bytecode = True
    spec.loader.exec_module(mod)
    return mod


def main() -> int:
    m = load()
    REAL_P, REAL_E, DAY = 5.2236, 5.1762, "2026-08-14"
    checks: list[tuple[str, bool]] = []

    def want(name: str, got: object, expected: object) -> None:
        checks.append((name, got == expected))

    # --- the two controls, first, because everything else is meaningless without them -------
    want(
        "CONTROL real 2026-08-14 values are ACCEPTED",
        m.adjudicate((REAL_P, DAY), (REAL_E, DAY))[0],
        True,
    )
    want(
        "CONTROL same values with band=0 are REFUSED",
        m.adjudicate((REAL_P, DAY), (REAL_E, DAY), max_div=0.0)[0],
        False,
    )

    # --- the refusals the money path depends on ---------------------------------------------
    want("divergent sources refused", m.adjudicate((5.22, DAY), (4.10, DAY))[0], False)
    want(
        "thermometer 30.50 refused", m.adjudicate((30.50, DAY), (30.50, DAY))[0], False
    )
    want(
        "rate below plausible floor refused",
        m.adjudicate((1.5, DAY), (1.5, DAY))[0],
        False,
    )
    want(
        "mismatched dates refused",
        m.adjudicate((REAL_P, DAY), (REAL_P, "2026-08-13"))[0],
        False,
    )
    want("empty PTAX day is None, not zero", m.parse_ptax({"value": []}), None)

    def raises(fn) -> bool:
        try:
            fn()
        except ValueError:
            return True
        except Exception:
            return False
        return False

    want(
        "PTAX bool rate rejected",
        raises(
            lambda: m.parse_ptax(
                {"value": [{"cotacaoVenda": True, "dataHoraCotacao": "2026-08-14 x"}]}
            )
        ),
        True,
    )
    want(
        "PTAX string rate rejected",
        raises(
            lambda: m.parse_ptax(
                {"value": [{"cotacaoVenda": "5.2", "dataHoraCotacao": "2026-08-14 x"}]}
            )
        ),
        True,
    )
    want("ECB missing rates rejected", raises(lambda: m.parse_ecb({"date": DAY})), True)

    # --- the claim the docstring makes about itself ------------------------------------------
    want(
        "no fallback rate constant exists in the tool",
        "last_known" in TARGET.read_text(encoding="utf-8").lower(),
        False,
    )

    failed = [n for n, ok in checks if not ok]
    for name, ok in checks:
        print(f"  {'ok  ' if ok else 'FAIL'} {name}")
    if failed:
        print(
            f"\nFAIL  {len(failed)}/{len(checks)} control(s) broken: {failed}",
            file=sys.stderr,
        )
        return 1
    print(f"\nPASS  {len(checks)}/{len(checks)} rate cross-check controls hold")
    return 0


if __name__ == "__main__":
    sys.exit(main())
