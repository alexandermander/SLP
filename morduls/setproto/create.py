#!/usr/bin/env python

from Cryptodome.Hash import SHA256
from Cryptodome.PublicKey import RSA
from Cryptodome.Signature import pss

PI = b"Pay 100 DKK to MerchantX"
OI = b"Order #2456: 2 items total 100 DKK"

print(f"{PI=}")
print(f"{OI=}")

with open('PI.txt', 'wb') as fp:
    fp.write(PI)
with open('OI.txt', 'wb') as fp:
    fp.write(OI)

PIMD = SHA256.new(PI)
OIMD = SHA256.new(OI)

print(f"{PIMD.hexdigest()=}")
print(f"{OIMD.hexdigest()=}")

with open('PIMD.bin', 'wb') as fp:
    fp.write(PIMD.digest())
with open('OIMD.bin', 'wb') as fp:
    fp.write(OIMD.digest())

POMD = SHA256.new(PIMD.digest() + OIMD.digest())

print(f"{POMD.hexdigest()=}")

with open('POMD.bin', 'wb') as fp:
    fp.write(POMD.digest())

key = RSA.generate(2048)

#print(f"{key=}")

with open('key.pem', 'wb') as fp:
    fp.write(key.export_key(format='PEM'))

with open('pubkey.pem', 'wb') as fp:
    fp.write(key.public_key().export_key(format='PEM'))

sig = pss.new(key).sign(POMD)

print(f"{sig.hex()=}")

with open('sig.bin', 'wb') as fp:
    fp.write(sig)
