#!/usr/bin/env python3

import hashlib

def hash(data: bytes) -> bytes:
    return hashlib.md5(data).digest()

# Set up data
x0 = bytes.fromhex(''.join('00' for i in range(16)))
x1 = bytes.fromhex(''.join('11' for i in range(16)))
x2 = bytes.fromhex(''.join('22' for i in range(16)))
x3 = bytes.fromhex(''.join('33' for i in range(16)))

# Make Merkle Tree
y0 = hash(x0)
# 4ae71336e44bf9bf79d2752e234818a5
y1 = hash(x1)
# 8057b6feaa62d90126274cf9ba31c642
y2 = hash(x2)
# fbc3cf71d993ca7bec2664357ccdac2b
y3 = hash(x3)
# 28bfcf057ec5a48f18c3154c1f2bd324

y4 = hash(y0 + y1)
# b05df6fba6c1c53e8ddb98ffd386ffc8
y5 = hash(y2 + y3)
# 8f7a2a2dcd297872689e177953270f37

y6 = hash(y4 + y5)
# 40c0b71ca488d334d266beecac02a16c
