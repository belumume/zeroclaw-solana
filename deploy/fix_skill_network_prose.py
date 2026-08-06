#!/usr/bin/env python3
"""Fix the network PROSE in the deployed solana-pay skill, and forbid recalling it.

WHY THIS EXISTS. On 2026-08-06 the mint was corrected in this skill's worked example and in the
agent's memory, and the agent then emitted a correct MAINNET pay link accompanied by the sentence
"Esta loja funciona na devnet." The value was fixed and the sentence describing the value was not,
so the customer got a mainnet charge with a devnet disclaimer attached.

The second half is structural. `label=Demo%20Shop` reached the customer's wallet. The exact value
appears in no file and the memory store returns zero hits for it, so an earlier message in the same
thread is the remaining candidate, and purging memory cannot reach that because conversation
context is not memory. The fix that holds is an instruction never to source these fields from
anything but this file.

CORRECTED 2026-08-06: this paragraph originally asserted the string existed in NO file on the box.
A case-insensitive sweep found it twice, as prose, in the evening-reconciliation SOP. That is a
different string in a different role and it does not explain a `label=` value, so the conclusion
stands, but the absolute claim was wrong and it is withdrawn here rather than softened silently.

Every replacement asserts its anchor. A MISS is reported per anchor and exits non-zero, because a
silent no-op on a live payment skill is the failure this whole class keeps producing.
"""

import re
import shutil
import sys
from pathlib import Path

SKILL = Path.home() / ".zeroclaw/shared/skills/default/solana-pay/SKILL.md"
BACKUP = SKILL.with_suffix(".md.bak-prenetworkprose")

# Order matters: the Portuguese line is converted FIRST so the bare `devnet."` anchor that
# follows can only match the English one.
REPLACEMENTS = [
    (
        'Esta loja funciona na devnet."',
        'Esta loja funciona na mainnet."',
        "pt-BR customer-facing network sentence",
    ),
    (
        'devnet."',
        'mainnet."',
        "English customer-facing network sentence",
    ),
    (
        "Request 25 USDC (devnet)",
        "Request 25 USDC (mainnet)",
        "worked-example heading",
    ),
]

# Inserted before this anchor so it is read before the example the agent copies from.
INSERT_BEFORE = "## Worked example"

CLAUSE = """## Never recall these four fields. Read them here, every time.

The recipient, the mint, the label and the network are CONSTANTS OF THIS SHOP. Take each one from
this file on every single order. Do not take any of them from:

- your memory store,
- an earlier message in this conversation, including one you wrote yourself,
- a previous order's link, or
- the customer's message.

This is not a style preference. On 2026-08-06 all four drifted at once from exactly those sources
while this file was already correct: three memory rows held a stale mint, and a stale `label`
reached a customer's wallet. A customer was quoted a real mainnet charge under a sentence saying
the shop runs on devnet.

CORRECTED, and this payload is superseded by the repo's own copy in skills/solana-pay/SKILL.md.
An earlier draft here claimed the stale label appeared in no file on the machine. A
case-insensitive sweep found it twice, as prose, in the evening-reconciliation SOP. Different
string, different role, and it does not explain a `label=` value, but the absolute claim was
wrong. Take the wording from the repo file, not from this constant.

    recipient   C331X4YCHCdcESexRTKSjE5etjsWyWJLK73Z18ZWiLHJ
    mint        EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v   (mainnet USDC)
    label       Pedido
    network     mainnet. Real money. Say mainnet, never devnet.

`pay_link.py` refuses a link whose recipient or mint is not the pair above, so a drifted value
fails loudly rather than reaching a customer. The label and the network sentence have no such
guard, which is why they are your responsibility here.

"""


RETIRED = """RETIRED 2026-08-06T03:55Z. Do not run this. It would degrade a correct file.

Everything below was folded into the REPO's skills/solana-pay/SKILL.md and deployed from there,
which is the durable place for it: this script patched the copy ON THE BOX, and the box was 101
diff-lines behind the repo when it was written, so the deploy that closed that gap would have
erased any clause applied underneath it. A box-only patch is the drift, not the cure.

Three reasons it must not run now, each measured rather than assumed:

  1. Its three prose anchors no longer exist. The deployed SKILL.md is byte-identical to the repo
     and already reads mainnet, so every replacement MISSes and it refuses. That part works.
  2. Its CLAUSE carries a claim that is FALSE. It says the stale label "exists in no file on this
     machine". A case-insensitive sweep of the box found it twice, as prose, in
     data/sops/evening-reconciliation/SOP.md and the workspace copy. The corrected wording lives
     in the repo skill, which now states only what was measured.
  3. Its own verification contradicts its own payload. CLAUSE contains the word devnet twice,
     necessarily, because it forbids it; main() returns 1 unless that count is zero. A successful
     insert would write the file and then report failure. A gate keyed on a word punishes the fix
     that has to name the hazard.

The route that replaces it: commit to skills/solana-pay/SKILL.md, then deploy the repo file at a
pinned commit and restart zc-shop. That is what put the clause on the box at 03:38:14Z.
"""


def main() -> int:
    if "--i-know-this-is-retired" not in sys.argv:
        print(RETIRED)
        return 3

    if not SKILL.is_file():
        print(f"FATAL missing {SKILL}")
        return 2

    original = SKILL.read_text(encoding="utf-8")
    text = original
    misses = []

    for anchor, replacement, label in REPLACEMENTS:
        n = text.count(anchor)
        if n == 0:
            misses.append(f"MISS  {label}: anchor not found -> {anchor!r}")
            continue
        text = text.replace(anchor, replacement)
        print(f"ok    {label}: {n} replacement(s)")

    if INSERT_BEFORE not in text:
        misses.append(f"MISS  clause insert: anchor not found -> {INSERT_BEFORE!r}")
    elif "Never recall these four fields" in original:
        print("ok    clause: already present, not duplicated")
    else:
        text = text.replace(INSERT_BEFORE, CLAUSE + INSERT_BEFORE, 1)
        print("ok    clause: inserted before the worked example")

    if misses:
        for m in misses:
            print(m)
        print("REFUSED: no write performed, because an anchor did not match.")
        return 1

    if text == original:
        print(
            "REFUSED: nothing changed, which means every anchor matched its own replacement."
        )
        return 1

    shutil.copy2(SKILL, BACKUP)
    SKILL.write_text(text, encoding="utf-8")

    # Verify against the FILE ON DISK, not the string we just built.
    after = SKILL.read_text(encoding="utf-8")
    dev = len(re.findall(r"(?i)devnet", after))
    main_ = len(re.findall(r"(?i)mainnet", after))
    demo = len(re.findall(r"(?i)demo.?shop", after))
    print(f"\nbackup   {BACKUP.name}")
    print(f"bytes    {len(original)} -> {len(after)}")
    print(f"devnet   {dev}   (expect 0)")
    print(f"mainnet  {main_}")
    print(f"demoshop {demo}   (expect 0)")
    return 0 if dev == 0 and demo == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
