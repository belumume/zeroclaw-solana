#!/usr/bin/env python3
"""Fix the network PROSE in the deployed solana-pay skill, and forbid recalling it.

WHY THIS EXISTS. On 2026-08-06 the mint was corrected in this skill's worked example and in the
agent's memory, and the agent then emitted a correct MAINNET pay link accompanied by the sentence
"Esta loja funciona na devnet." The value was fixed and the sentence describing the value was not,
so the customer got a mainnet charge with a devnet disclaimer attached.

The second half is structural. `label=Demo%20Shop` reached the customer's wallet while that string
exists in NO file on this box: the agent copied it out of its own earlier message in the same
WhatsApp thread. Purging memory cannot reach that, because conversation context is not memory. The
only fix that holds is an instruction never to source these fields from anything but this file.

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
while this file was already correct: three memory rows held a stale mint, and a stale `label` was
copied out of an earlier reply in the same thread even though that string exists in no file on this
machine. A customer was quoted a real mainnet charge under a sentence saying the shop runs on
devnet.

    recipient   C331X4YCHCdcESexRTKSjE5etjsWyWJLK73Z18ZWiLHJ
    mint        EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v   (mainnet USDC)
    label       Pedido
    network     mainnet. Real money. Say mainnet, never devnet.

`pay_link.py` refuses a link whose recipient or mint is not the pair above, so a drifted value
fails loudly rather than reaching a customer. The label and the network sentence have no such
guard, which is why they are your responsibility here.

"""


def main() -> int:
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
