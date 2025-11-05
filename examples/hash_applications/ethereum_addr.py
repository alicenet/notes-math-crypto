#!/usr/bin/env python3

from Crypto.Hash import keccak

from eth_keys import keys

def hash_keccak256(data: bytes) -> bytes:
    keccak256 = keccak.new(digest_bits=256)
    keccak256.update(data)
    return keccak256.digest()

def checksum_encode(addr: bytes) -> str: # Takes a 20-byte address as input
    hex_addr = addr.hex()
    checksummed_buffer = ""

    # Treat the hex address as ascii/utf-8 for keccak256 hashing
    hashed_address_bytes = hash_keccak256(hex_addr.encode('utf-8'))
    hashed_address = hashed_address_bytes.hex()

    # Iterate over each character in the hex address
    for nibble_index, character in enumerate(hex_addr):
        if character in "0123456789":
            # We can't upper-case the decimal digits
            checksummed_buffer += character
        elif character in "abcdef":
            # Check if the corresponding hex digit (nibble) in the hash is 8 or higher
            hashed_address_nibble = int(str(hashed_address[nibble_index]), 16)
            if hashed_address_nibble > 7:
                checksummed_buffer += character.upper()
            else:
                checksummed_buffer += character
        else:
            assert 0 == 1, f"Unrecognized hex character {character!r} at position {nibble_index}"

    return "0x" + checksummed_buffer

pk_str = '01' + '00'*30 + '01'
private_key_bytes = bytes.fromhex(pk_str)
private_key = keys.PrivateKey(private_key_bytes)
public_key_bytes = bytes.fromhex(str(private_key.public_key)[2:])
public_key_str = public_key_bytes.hex()

hashed_pk = hash_keccak256(public_key_bytes)
addr = hashed_pk[12:]
encoded_addr = checksum_encode(addr)

true_addr = str(private_key.public_key.to_address())[2:]

print("Computing Ethereum Address")
print("#"*72)
print()
print("Private Key")
print(private_key_bytes.hex())
print()
print("Public Key")
print(public_key_str[0:64])
print(public_key_str[64:])
print()
print("Ethereum Address")
print(addr.hex())
print()
print("Ethereum Address (encoded)")
print(encoded_addr)
print()
print()

assert addr.hex() == true_addr
print("Valid Address")
