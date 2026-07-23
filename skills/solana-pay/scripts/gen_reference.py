#!/usr/bin/env python3
"""Generate a unique Solana Pay reference key: 32 random bytes, base58.

Per the Solana Pay spec, reference accounts need not exist on-chain; they only
need to be unique, valid base58-encoded 32-byte values that settlement lookup
can index. Stdlib only — no dependencies, auditable at a glance.
"""

import secrets

ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58encode(data: bytes) -> str:
    n = int.from_bytes(data, "big")
    out = []
    while n > 0:
        n, rem = divmod(n, 58)
        out.append(ALPHABET[rem])
    pad = 0
    for b in data:
        if b == 0:
            pad += 1
        else:
            break
    return "1" * pad + "".join(reversed(out))


if __name__ == "__main__":
    print(b58encode(secrets.token_bytes(32)))
