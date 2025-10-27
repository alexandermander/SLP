#!/usr/bin/env python
from os import path
from time import time_ns
from Cryptodome.PublicKey import RSA, DSA, ECC
from Cryptodome.Hash import SHA256
from Cryptodome.Signature import pkcs1_15, DSS

def generate_keys():
    rsa_key = RSA.generate(2048)
    dsa_key = DSA.generate(2048)
    ecc_key = ECC.generate(curve='NIST P-256')
    return rsa_key, dsa_key, ecc_key

def export_keys(rsa_key, dsa_key, ecc_key):
    with open("rsa.pem", "wb") as fp:
        fp.write(rsa_key.export_key())
    with open("dsa.pem", "wb") as fp:
        fp.write(dsa_key.export_key())
    with open("ecc.pem", "wb") as fp:
        fp.write(ecc_key.export_key(format='PEM').encode())

def rsa_sign(data: str, key: RSA.RsaKey) -> bytes:
    h = SHA256.new(data.encode())
    return pkcs1_15.new(key).sign(h)

def dsa_sign(data: str, key) -> bytes:  # DSA or ECC
    h = SHA256.new(data.encode())
    return DSS.new(key, 'fips-186-3').sign(h)

def pretty_print_sig(sig_type: str, sig: bytes) -> None:
    print(f"{sig_type} signature: {sig.hex()}\n")

def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("msg", type=str)
    args = parser.parse_args()

    if not any((path.exists('./rsa.pem'), path.exists('./dsa.pem'), path.exists('./ecc.pem'))):
        rsa_key, dsa_key, ecc_key = generate_keys()
        export_keys(rsa_key, dsa_key, ecc_key)
        print("Generated keys\n")
    else:
        with open("rsa.pem", 'rb') as fp:
            rsa_key = RSA.import_key(fp.read())
        with open("dsa.pem", 'rb') as fp:
            dsa_key = DSA.import_key(fp.read())
        with open("ecc.pem", 'rb') as fp:
            ecc_key = ECC.import_key(fp.read())
        print("Imported keys\n")

    for key_type, key, sign_func in zip(("RSA","DSA","ECDSA"),
                                        (rsa_key,dsa_key,ecc_key),
                                        (rsa_sign,dsa_sign,dsa_sign)):
        print(f"About to generate signature for {key_type}")
        start_time = time_ns()
        sig = sign_func(args.msg, key)
        delta = time_ns() - start_time
        print(f"Signature took {delta} ns ({delta/1e9} s)")
        pretty_print_sig(key_type, sig)

if __name__ == "__main__":
    main()

