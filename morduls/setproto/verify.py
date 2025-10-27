#!/usr/bin/env python
from Cryptodome.Hash import SHA256
from Cryptodome.PublicKey import RSA
from Cryptodome.Signature import pss

print("Loading RSA public key")
with open('pubkey.pem', 'rb') as fp:
    key = RSA.import_key(fp.read())

#print(f"{key=}")

verifier = pss.new(key)

print("Loading signature")
with open('sig.bin', 'rb') as fp:
    sig = fp.read()

print(f'{sig.hex()=}')

print("\nMerchant POV: Using OI and PIMD")
with open('OI.txt', 'rb') as fp:
    OI = fp.read()
with open('PIMD.bin', 'rb') as fp:
    PIMD = fp.read()

print(f'{OI=}')
print(f'{PIMD.hex()=}')

OIMD = SHA256.new(OI)

print(f'{OIMD.hexdigest()=}')

POMD = SHA256.new(PIMD + OIMD.digest())

print(f'{POMD.hexdigest()=}')

try:
    verifier.verify(POMD, sig)
    print("Merchant verified signature")
except (ValueError):
    print("Merchant cannot verify signature")






print("\nBANK POV: Using OIMD and PI")

with open('OIMD.bin', 'rb') as fp:
    OIMD = fp.read()
with open('PI.txt', 'rb') as fp:
    PI = fp.read()

print(f'{OIMD.hex()=}')
print(f'{PI=}')

PIMD = SHA256.new(PI)

print(f'{PIMD.hexdigest()=}')

POMD = SHA256.new(PIMD.digest() + OIMD)

print(f'{POMD.hexdigest()=}')

try:
    verifier.verify(POMD, sig)
    print("Bank verified signature")
except (ValueError):
    print("Bank cannot verify signature")


