#!/usr/bin/env python3
"""Independent reference for the Stap 7d state ratchet (Python stdlib only).

    SK_t = HKDF-SHA256(IKM = SK_{t-1} || I2OSP(t, 8), salt, info, L = 32)   (RFC 5869)
    SK_0 = the same step on the seed (epoch 0)

Writes tests/fixtures/forward_secure/ratchet.json; tests/forward_secure.rs
checks rout_zk::forward_secure against it byte for byte.
"""
import hashlib, hmac, json, pathlib

SALT = b"ROUT-HOST-EPOCH-RATCHET-V1"
INFO = b"rout.v1.host.epoch.state"

def hkdf(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm, t, i = b"", b"", 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
        i += 1
    return okm[:length]

def step(state: bytes, epoch: int) -> bytes:
    return hkdf(state + epoch.to_bytes(8, "big"), SALT, INFO)

seed = bytes(range(1, 33))
states = [step(seed, 0)]
for t in range(1, 8):
    states.append(step(states[-1], t))
# A jump 0 -> 1000 ratchets through every intermediate epoch.
s = states[0]
for t in range(1, 1001):
    s = step(s, t)

out = {
    "source": "tools/forward_secure_vectors.py (Python hashlib/hmac, RFC 5869 HKDF-SHA256)",
    "salt": SALT.decode(),
    "info": INFO.decode(),
    "seed": seed.hex(),
    "states": [x.hex() for x in states],
    "state_1000": s.hex(),
}
path = pathlib.Path(__file__).resolve().parent.parent / "tests" / "fixtures" / "forward_secure" / "ratchet.json"
path.write_text(json.dumps(out, indent=2) + "\n")
print(path)
