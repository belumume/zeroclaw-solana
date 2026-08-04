# x402 machine-commerce: one paid read, and the replay that was refused

Driven 2026-07-27 against the gate running on the ARM node in Jeddah under `systemd --user`.
The buyer signed on a separate machine, so this is a remote purchase rather than the seller
paying itself.

The on-chain half of this record lives in `devnet-transactions.json` and is verifiable with no
network by `python3 scripts/verify_proof_offline.py`. This file holds the HTTP half, which has no
on-chain representation: a refusal is a response, not a transaction.

## 1. The challenge

`GET /price` with no payment returns HTTP 402 and the terms, including a single-use memo nonce:

```json
{
  "x402Version": 2,
  "error": "payment required to read this feed",
  "accepts": [
    { "scheme": "exact", "network": "solana-devnet",
      "asset": "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
      "payTo": "C331X4YCHCdcESexRTKSjE5etjsWyWJLK73Z18ZWiLHJ",
      "amount": "1000000", "maxTimeoutSeconds": 60,
      "description": "one feed reading" },
    { "scheme": "exact", "network": "solana-devnet",
      "asset": "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
      "payTo": "C331X4YCHCdcESexRTKSjE5etjsWyWJLK73Z18ZWiLHJ",
      "amount": "5000000", "maxTimeoutSeconds": 60,
      "description": "day pass: unlimited reads this UTC day" }
  ],
  "extra": { "memo": "x402-18c632a32e04eb24-1" }
}
```

## 2. The paid read

The buyer builds a `TransferChecked` carrying that memo, signs it, and presents it as
`X-PAYMENT`. The gate verifies the bytes, settles on chain, and only then serves the reading.

```
HTTP/1.1 200 OK
x-payment-response: eyJuZXR3b3JrIjoic29sYW5hLWRldm5ldCIsInBheWVyIjoiRTM2Tko3RnZGU1F4ZWdGZW1DRUw3
                    NkdyQlZVY1ZTRVd2aWhuZTVXRnhCZGYiLCJzdWNjZXNzIjp0cnVlLCJ0cmFuc2FjdGlvbiI6IkVr
                    Qm1vRGtuRHJ5UXBEdEQ2aG5Mb0NkaGhSakFvM1ZtbjE1Vm1rUWk3bmlxWUhuSzVYWUw4RnB4TGFi
                    RGlRMlMyUXVUZEQzdnNUWE1TcmE3MkxYZ0FwRSJ9
```

Decoded, that receipt reads:

```json
{ "network": "solana-devnet",
  "payer": "E36NJ7FvFSQxegFemCEL76GrBVUcVSEWvihne5WFxBdf",
  "success": true,
  "transaction": "EkBmoDknDryQpDtD6hnLoCdhhRjAo3Vmn15VmkQi7niqYHnK5XYL8FpxLabDiQ2S2QuTdD3vsTXMSra72LXgApE" }
```

Body:

```json
{ "amount": 1000000,
  "paid": true,
  "reading": {
    "feed": "JEtuZkcRzePbbLo8oiM26aqpbt1zJyLP4snvQCjVveg",
    "note": "device-signed on-chain reading; value is fixed-point per the feed's scale",
    "sequence": 177,
    "value_scaled": 4100
  },
  "settlement": "EkBmoDknDryQpDtD6hnLoCdhhRjAo3Vmn15VmkQi7niqYHnK5XYL8FpxLabDiQ2S2QuTdD3vsTXMSra72LXgApE" }
```

The reading served is the node's own feed at sequence 177, value 41.00 C.

## 3. The replay, refused

Presenting the **identical** `X-PAYMENT` header a second time. Nothing about the payment is
invalid: it is a real, settled, on-chain transaction. It is refused because its nonce is spent.

```json
{ "x402Version": 2,
  "error": "payment required to read this feed",
  "rejected": "NonceReused",
  "extra": { "memo": "x402-18c632abb84a275b-2" }
}
```

HTTP 402. The refusal is not a dead end: it carries a fresh challenge, so an honest client that
retried by accident can pay again correctly rather than being left stuck.

This is the property worth reading twice. A settled payment is not a bearer token for unlimited
reads. The seller binds each payment to one challenge, so possession of a valid payment proves
exactly one purchase.

## 4. The earnings ledger

The gate appends one line per settled sale, which is what the node's daily earnings SOP reads:

```json
{"amount":1000000,"day":20661,"is_day_pass":false,
 "payer":"E36NJ7FvFSQxegFemCEL76GrBVUcVSEWvihne5WFxBdf",
 "settlement":"EkBmoDknDryQpDtD6hnLoCdhhRjAo3Vmn15VmkQi7niqYHnK5XYL8FpxLabDiQ2S2QuTdD3vsTXMSra72LXgApE"}
```

## What this does and does not prove

It proves the node sells its own signed reading for a real on-chain payment, and that a replayed
payment is refused by the seller rather than by luck.

It does not prove the daily cap is enforced under load, which is a separate property with its own
tests, and it does not prove anything about mainnet, where none of these accounts hold value.
