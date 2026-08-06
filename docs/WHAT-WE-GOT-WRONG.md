# What we got wrong

Eight things this project believed, and the measurement that killed each one. They are here because
every one of them was invisible to a green check, and because the shapes repeat: if you build on
ZeroClaw and Solana you will probably meet at least three of them.

Each entry is what we believed, what killed it, and what it cost.

---

## 1. Every WASM tool plugin had been failing for eleven days, and every test was green

**We believed** the eight plugins were running. They built clean, their unit tests passed, the host
loaded them, and `zeroclaw sop list` showed the SOP that calls one of them as registered.

**What killed it** was reading a full error string instead of a grep of it. The host was emitting:

```
failed to instantiate tool plugin: component imports instance
`zeroclaw:plugin/logging@0.1.0`, but a matching implementation was not found in the linker
```

That sentence sends you to the host's linker registration, which is correct and always was.
`wasmtime` prints the same words for *import absent* and *import present, wrong type*, and the
discriminating detail is in the `Caused by:` chain a truncated log drops.

The type was wrong by **one enum variant**. Our vendored `wit/v0/logging.wit` declares
`plugin-action` with 38 cases. The host binary we build against declares 37. One `memory-audit`
case landed upstream after our host, and component-model interfaces match **nominally**, so 37 and
38 are different types, the whole `logging` instance fails typecheck, and every plugin importing it
dies regardless of what else is correct.

**Cost:** the only tool that had ever executed on that box was `memory_recall`. Eleven days.
Nothing in the build, the tests, or the host's own status commands could see it, because they all
answer *is it loaded* and none answers *did it instantiate*.

**If you hit this:** `demo/check_wit_parity.py` compares your vendored WIT against a host's and
asserts **set equality, not containment**. Ours was a strict superset, so a containment check stayed
green throughout.

---

## 2. A cron in an SOP's frontmatter does not schedule anything

**We believed** the payment-confirmation SOP was running every minute. Its frontmatter says
`cron: * * * * *`. Three separate commands agreed it was fine: `sop list` showed it,
`sop validate` passed it, `sop show` printed it.

**What killed it** was one command nobody had run:

```
$ zeroclaw cron list
No scheduled tasks yet.
```

The daemon keeps its own scheduler table and frontmatter does not populate it. Registration is
`zeroclaw cron add`. The evening reconciliation SOP had never fired either, since the day it was
written.

**Cost:** three green status commands, all answering *is it loaded*, none answering *is it
scheduled*. The same shape as the entry above, in a different subsystem, and we did not recognise
it the second time.

**A rider, because it bit us again an hour later:** the daemon does not re-arm persisted cron jobs
across a restart. After a deploy the job's `next` sat frozen in the past while `last` still looked
healthy. Check `next` against a clock, not `last`.

---

## 3. `api.mainnet-beta.solana.com` returns 403 to any browser

**We believed** the pay page's desktop button worked. It had worked on devnet, the code was
unchanged, and every payment test succeeded.

**What killed it** was measuring the same host twice in the same second:

| | no `Origin` header | with `Origin` |
|---|---|---|
| `api.mainnet-beta.solana.com` | HTTP 200 | **HTTP 403** |
| `solana-rpc.publicnode.com` | HTTP 200 | HTTP 200 |

A browser always sends `Origin`, so every fetch the page made was rejected, and the desktop button
had been dead since the shop moved to mainnet. The 403 is protocol-agnostic; the websocket does the
same thing.

**Why no test caught it:** every successful payment went through the phone, and scanning a QR hands
the `solana:` URL to the wallet, which builds and submits the transaction itself. The phone path
never touches the page's RPC. A feature with two implementations where only one is ever exercised
can have the other completely broken while every observation says healthy.

---

## 4. Our own capture gate was selecting for the result it wanted

**We believed** the demo's terminal captures were verified. A harness runs each command, records the
console, and OCRs the frame for expected strings, re-shooting if one is missing.

**What killed it** was driving a script's own output through its own gate. On the beat carrying our
strongest safety claim the single marker was `ACCEPT`, matched case-insensitively, so the script's
**failure** line `nothing was accepted` satisfied it. The gate was inverted on the most important
beat. Separately, the harness never checked the filmed command's exit code at all, so a command that
genuinely failed could produce a keepable take.

**Cost:** nothing shipped, because this was caught before the shoot. The lesson is that a tool
written to prevent staging had itself become a way to re-roll until the screen looked right.

**The fix, and the control that proves it:** the exit code now decides the take and markers are
demoted to a legibility check. A control beat prints three valid markers and exits 3. Under the old
gate that was a clean pass; it now fails, and it fails on the exit code.

---

## 5. "Every wallet we have is empty"

**We believed** the project held no funds, and planned around needing money before anything could
touch mainnet.

**What killed it** was noticing the claim came from checking eight keys inside **one** artifact.
Two wallets held real mainnet balances the whole time, and their keys were on disk in a directory
whose name says `devnet`.

**Cost:** a funding request that was never needed, and a plan built around a constraint that did not
exist. A quantifier is only as good as the set it was measured over, and nothing about the sentence
said which set that was.

---

## 6. The DePIN feed stays on devnet, for a reason we replaced twice

**Version one:** mainnet would cost real money. Measured: all 790 transactions at that point came to
**$0.58**. Refuted.

**Version two:** eleven days of on-chain history cannot be migrated. True, and it answers a question
nobody asked, because a parallel mainnet feed preserves the old history by existing alongside it.

**Version three, which holds:** the feed account is a PDA **owned by our program**, so a mainnet
feed requires deploying that program to mainnet. Programdata rent is **$111.44** against a wallet
holding $14.44. It is a funding question, not an engineering one.

**Cost:** the verdict never moved and the reason was wrong twice. A decision defended by a false
reason is one refutation away from being reversed for the wrong cause, and the cost reason, applied
anywhere else, would have kept the shop on devnet at a true cost of twenty cents.

---

## 7. Three published documents disagreed about the same number

**We believed** the feed counts on our judge-facing pages were current. Each had been correct when
written.

**What killed it** was reading them side by side. The README was **104 publishes behind** on the
durability claim the whole submission leads with, and the one-pager's table carried no date at all,
so a reader had no way to know how stale it was.

**Cost:** a reader comparing two of our own pages found them contradicting each other about our
strongest claim. Every number on those surfaces now carries the moment it was measured and the
command that re-derives it.

---

## 8. The box is not in a house

**We believed**, and very nearly filmed, that the machine running both use cases was hardware on a
desk. The script had a line about it and a shot planned.

**What killed it** was one control-plane query. The host is `zc-arm-ref`, a `VM.Standard.A1.Flex`
instance in Oracle's `me-jeddah-1` region, on their free tier at a measured 0.00 EUR. An Ampere
Altra is genuinely ARM, which is why "ARM node" was accurate everywhere it appeared and why nobody
questioned it for eleven days. There is no board.

Four judge-facing surfaces had drifted into describing it as owned hardware, and one said outright
that nobody subsidises it, which is false in the most direct way available: Oracle subsidises all of
it.

**Cost:** caught with the shot list already written. Everything downstream survives unchanged, since
the provenance argument was never about owning the metal: the signing key was generated on that box
and has never left it, so this workstation cannot forge a reading for that feed.

---

## What the eight have in common

Six of them were invisible to a passing check, and in four cases the check was passing **because**
it was asking a different question than the one we thought it was asking. Loaded is not scheduled.
Registered is not instantiated. A marker is not an outcome. A count over one artifact is not a count
over the set.

The other recurring shape is a claim that was true when written. Three of these were correct
statements that expired, and none of them announced that they had.
