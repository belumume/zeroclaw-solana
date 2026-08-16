#!/usr/bin/env python3
"""Assert docs/video-claims.json still points at things that exist.

WHY THIS EXISTS. The demo video is frozen and submitted, so its claims cannot be corrected. The
claims map is the only remaining way to make them checkable, which means the map itself is now a
judge-facing surface: a claim pointing at a renamed script is worse than no map, because it reads
as a verification route and is a dead end.

WHAT IT CHECKS, all mechanical and none of it a judgement about whether a claim is TRUE:
  - the video and its caption track exist, and are the paths the map names
  - every timestamp falls inside the cut's real duration, read from the caption track rather than
    restated, so a re-cut that shortens the video reddens this instead of silently mispointing
  - every timestamp range is ordered, start before end
  - every repo path named in a `verify` or `note` field exists
  - no `verify` hides a load-bearing path in a trailing comment, since a command needing an
    unstated cd is a dead end for exactly the stranger this map is for
  - every claim carries a kind of `capability` or `recording`, because that distinction is the
    file's whole honesty mechanism and a missing one reads as a stronger claim than intended

WHAT IT DELIBERATELY DOES NOT CHECK. Whether a claim is true, and whether a `verify` command
passes. Several of them take minutes or touch the network, and a gate that runs them would be a
slow flake rather than a guard. Their existence is what rots; their verdicts are checked by their
own gates.

Exit codes follow the house convention: 0 fine, 1 a real problem, 2 could not check.

Run: python3 scripts/check-video-claims.py
     python3 scripts/check-video-claims.py --selftest
"""

from __future__ import annotations

import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
MAP = ROOT / "docs" / "video-claims.json"

CANNOT_CHECK = 2
KINDS = {"capability", "recording"}

# A repo-relative path mentioned anywhere in the prose. Deliberately narrow: it must carry a
# directory separator and a known extension, so ordinary sentences do not read as paths.
PATH_RE = re.compile(
    r"\b((?:docs|scripts|plugins|skills|crates|demo|webshop-pay|sanitizer-microworld)"
    r"/[A-Za-z0-9_./-]+\.(?:py|json|md|vtt|mp4|rs|toml|js|sh))\b"
)
STAMP_RE = re.compile(r"^(\d\d):(\d\d)\.(\d\d)$")


def seconds(stamp: str) -> float | None:
    m = STAMP_RE.match(stamp)
    if not m:
        return None
    return int(m.group(1)) * 60 + int(m.group(2)) + int(m.group(3)) / 100


def caption_end(vtt: pathlib.Path) -> float | None:
    """The last cue's end time, which is the duration the map must fit inside."""
    if not vtt.is_file():
        return None
    last = None
    for line in vtt.read_text(encoding="utf-8", errors="replace").splitlines():
        m = re.search(r"-->\s*(\d\d):(\d\d):(\d\d)\.(\d{3})", line)
        if m:
            h, mi, s, ms = (int(x) for x in m.groups())
            last = h * 3600 + mi * 60 + s + ms / 1000
    return last


def audit(root: pathlib.Path, data: dict) -> list[str]:
    problems: list[str] = []
    vid = data.get("video") or {}

    for key in ("file", "captions"):
        rel = vid.get(key)
        if not rel:
            problems.append(f"video.{key} is missing from the map")
        elif not (root / rel).is_file():
            problems.append(f"video.{key} points at {rel}, which does not exist")

    # The duration is READ from the caption track, never taken from the map's own number, so the
    # map cannot certify itself against a figure it supplies.
    end = caption_end(root / (vid.get("captions") or ""))
    if end is None:
        problems.append("could not read any cue end time from the caption track")

    claims = data.get("claims") or []
    if not claims:
        problems.append("the map lists no claims at all")

    seen_ids = set()
    for c in claims:
        cid = c.get("id") or "<no id>"
        if cid in seen_ids:
            problems.append(f"{cid}: duplicate id")
        seen_ids.add(cid)

        if c.get("kind") not in KINDS:
            problems.append(
                f"{cid}: kind is {c.get('kind')!r}, must be one of {sorted(KINDS)}; that "
                f"distinction is how the map avoids overclaiming"
            )

        at = c.get("at") or ""
        parts = at.split("-")
        a = seconds(parts[0]) if len(parts) == 2 else None
        b = seconds(parts[1]) if len(parts) == 2 else None
        if a is None or b is None:
            problems.append(f"{cid}: 'at' is {at!r}, expected MM:SS.ss-MM:SS.ss")
        else:
            if a >= b:
                problems.append(
                    f"{cid}: 'at' start {parts[0]} is not before end {parts[1]}"
                )
            if end is not None and b > end + 0.5:
                problems.append(
                    f"{cid}: 'at' ends at {parts[1]} but the cut's last cue ends at {end:.2f}s"
                )

        for field in ("verify", "note", "asserts"):
            for rel in PATH_RE.findall(str(c.get(field) or "")):
                if not (root / rel).exists():
                    problems.append(f"{cid}: {field} names {rel}, which does not exist")

        # A LOAD-BEARING PATH MUST NOT HIDE IN A COMMENT. `cargo test --locked  # in
        # plugins/payment-watch` names a real directory and is still not runnable as written,
        # because each plugin is its own workspace and the cd is unstated. Every path a reader
        # needs belongs in the command. A comment that names no path is fine and stays fine.
        # A `#` only opens a comment at the start of a word, which is the shell's own rule. Without
        # that, an explorer URL's fragment (`.../tx/ABC#cluster=mainnet`) reads as a comment and
        # anything after it gets scanned, so the gate would fire on a perfectly good command.
        verify = str(c.get("verify") or "")
        opens = re.search(r"(?:^|\s)#(.*)$", verify)
        if opens:
            comment = opens.group(1)
            hidden = PATH_RE.findall(comment) + re.findall(
                r"\b(?:plugins|crates|skills|demo|scripts)/[A-Za-z0-9_.-]+", comment
            )
            if hidden:
                problems.append(
                    f"{cid}: verify hides {hidden[0]} in a comment, so it is not runnable as "
                    f"written; put the path in the command (cd <dir> && ...)"
                )

    return problems


def selftest() -> int:
    import tempfile

    cases, failures = 0, []

    def check(name, got, want):
        nonlocal cases
        cases += 1
        if got != want:
            failures.append(f"{name}: got {got!r}, want {want!r}")

    vtt = "WEBVTT\n\n1\n00:00:01.000 --> 00:00:10.000\nhi\n"
    good = {
        "video": {"file": "v.mp4", "captions": "c.vtt"},
        "claims": [
            {
                "id": "a",
                "at": "00:01.00-00:09.00",
                "kind": "capability",
                "verify": "python3 scripts/real.py",
            },
        ],
    }

    with tempfile.TemporaryDirectory() as td:
        t = pathlib.Path(td)
        (t / "v.mp4").write_text("x", encoding="utf-8")
        (t / "c.vtt").write_text(vtt, encoding="utf-8")
        (t / "scripts").mkdir()
        (t / "scripts" / "real.py").write_text("x", encoding="utf-8")

        check("a well-formed map is silent", audit(t, good), [])
        check("the duration is read from the cues", caption_end(t / "c.vtt"), 10.0)

        import copy

        # One planted violation per rule, each asserted to fire ALONE so no rule stands in for
        # another. Without the silent case above, a checker that always complained would pass all.
        def one(mutate):
            d = copy.deepcopy(good)
            mutate(d)
            return audit(t, d)

        check(
            "a timestamp past the end fires",
            len(one(lambda d: d["claims"][0].update(at="00:01.00-00:59.00"))),
            1,
        )
        check(
            "a reversed range fires",
            len(one(lambda d: d["claims"][0].update(at="00:09.00-00:01.00"))),
            1,
        )
        check(
            "a malformed stamp fires",
            len(one(lambda d: d["claims"][0].update(at="banana"))),
            1,
        )
        check("a missing kind fires", len(one(lambda d: d["claims"][0].pop("kind"))), 1)
        check(
            "an unknown kind fires",
            len(one(lambda d: d["claims"][0].update(kind="vibes"))),
            1,
        )
        check(
            "a dead path in verify fires",
            len(one(lambda d: d["claims"][0].update(verify="python3 scripts/gone.py"))),
            1,
        )
        check(
            "a dead path in note fires",
            len(one(lambda d: d["claims"][0].update(note="see docs/gone.md"))),
            1,
        )
        check(
            "a missing video file fires",
            len(one(lambda d: d["video"].update(file="nope.mp4"))),
            1,
        )
        check(
            "a duplicate id fires",
            len(one(lambda d: d["claims"].append(dict(d["claims"][0])))),
            1,
        )
        check("no claims at all fires", len(one(lambda d: d.update(claims=[]))), 1)

        # A sentence that merely mentions a word must not be read as a path.
        check(
            "ordinary prose is not treated as a path",
            one(
                lambda d: d["claims"][0].update(note="the terminal and the page agree")
            ),
            [],
        )

        # THE REVIEW FINDING, in its own shape: a real directory hidden in a trailing comment.
        # Every path in it exists, so the path-existence rule above is silent, and the command
        # is still not runnable as written.
        check(
            "a path hidden in a verify comment fires",
            len(
                one(
                    lambda d: d["claims"][0].update(
                        verify="cargo test --locked   # in plugins/payment-watch"
                    )
                )
            ),
            1,
        )
        # OVER-CORRECTION CONTROLS. The corrected form must be silent, or the rule argues against
        # its own remedy; and a comment naming no path must be silent, or it forbids commenting.
        check(
            "the corrected cd form does not fire",
            one(
                lambda d: d["claims"][0].update(
                    verify="cd plugins/payment-watch && cargo test --locked"
                )
            ),
            [],
        )
        check(
            "a comment naming no path does not fire",
            one(
                lambda d: d["claims"][0].update(
                    verify="python3 scripts/real.py   # stdlib only, no network"
                )
            ),
            [],
        )
        # A URL fragment is not a comment. Without the shell's start-of-word rule this fires, and a
        # gate that flags a good command is the shape that gets routed around rather than followed.
        check(
            "a URL fragment is not read as a comment",
            one(
                lambda d: d["claims"][0].update(
                    verify="curl -s https://x.example/tx/ABC#cluster=scripts/real.py"
                )
            ),
            [],
        )

    # The real map must be clean, which is the case a regression breaks.
    if MAP.is_file():
        check(
            "the real map is clean",
            audit(ROOT, json.loads(MAP.read_text(encoding="utf-8"))),
            [],
        )
    else:
        failures.append("the real map is missing")
        cases += 1

    for f in failures:
        print(f"  FAIL  {f}")
    print(f"selftest: {cases - len(failures)}/{cases}")
    return 1 if failures else 0


def main() -> int:
    if "--selftest" in sys.argv:
        return selftest()
    if not MAP.is_file():
        print(f"cannot check: {MAP} is missing")
        return CANNOT_CHECK

    data = json.loads(MAP.read_text(encoding="utf-8"))
    problems = audit(ROOT, data)
    claims = data.get("claims") or []
    kinds = {}
    for c in claims:
        kinds[c.get("kind")] = kinds.get(c.get("kind"), 0) + 1
    print(
        f"{len(claims)} claim(s) mapped: "
        + ", ".join(f"{n} {k}" for k, n in sorted(kinds.items()))
    )
    if problems:
        print(
            "\nFAIL  the claims map offers a verification route that does not work:\n"
            + "\n".join(f"    {p}" for p in problems)
            + "\n  This map is judge-facing. A claim pointing at a renamed script, or naming a\n"
            "  command that is not runnable as written, reads as a verification route and is a\n"
            "  dead end, which is worse than no map.",
            file=sys.stderr,
        )
        return 1
    print("\nPASS  every referenced path exists and every timestamp is inside the cut")
    return 0


if __name__ == "__main__":
    sys.exit(main())
