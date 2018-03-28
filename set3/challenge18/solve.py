""" Implement CTR, the stream cipher mode - https://cryptopals.com/sets/3/challenges/18
The string:
    L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==

... decrypts to something approximating English in CTR mode,
which is an AES block cipher mode that turns AES into a stream cipher, with the following parameters:
    key=YELLOW SUBMARINE
    nonce=0
    format=64 bit unsigned little endian nonce,
           64 bit little endian block count (byte count / 16)

CTR mode is very simple.

Instead of encrypting the plaintext, CTR mode encrypts a running counter, producing a 16 byte block of keystream,
which is XOR'd against the plaintext.

For instance, for the first 16 bytes of a message with these parameters:
    keystream = AES("YELLOW SUBMARINE",
                "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")

... for the next 16 bytes:
    keystream = AES("YELLOW SUBMARINE",
                "\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00")

... and then:
    keystream = AES("YELLOW SUBMARINE",
                "\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00")

CTR mode does not require padding; when you run out of plaintext, you just stop XOR'ing keystream and
stop generating keystream.

Decryption is identical to encryption. Generate the same keystream, XOR, and recover the plaintext.

Decrypt the string at the top of this function, then use your CTR function to encrypt and decrypt other things.

This is the only block cipher mode that matters in good code.
    Most modern cryptography relies on CTR mode to adapt block ciphers into stream ciphers,
    because most of what we want to encrypt is better described as a stream than as a sequence of blocks.
    Daniel Bernstein once quipped to Phil Rogaway that good cryptosystems don't need the "decrypt" transforms.
    Constructions like CTR are what he was talking about.
"""

import base64
from Crypto.Cipher import AES

BLOCK_SIZE = 16

def xor(string1, string2):
    result_string = ""

    for i in range(len(string1)):
        result_string += chr(string1[i] ^ string2[i])

    return result_string

def encrypt_aes_ecb(plaintext, key, block_size):
    aes = AES.new(key, AES.MODE_ECB)

    return aes.encrypt(plaintext)

def aes_ctr(ciphertext, key, nonce, block_size):
    counter = b'\x00'*8
    blocks = [ciphertext[i:i+16] for i in range(0, len(ciphertext), 16)]
    decrypted_blocks = []

    for block in blocks:
        keystream = encrypt_aes_ecb(nonce + counter, key, BLOCK_SIZE)
        decrypted_blocks.append(xor(block, keystream))
        counter = (int.from_bytes(counter, byteorder='little') + 1).to_bytes(block_size // 2, byteorder='little')

    return ''.join(decrypted_blocks)

if __name__ == "__main__":
    string = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="
    key = b'YELLOW SUBMARINE'
    nonce = b'\x00'*8

    cipher = base64.b64decode(string)

    print (aes_ctr(cipher, key, nonce, BLOCK_SIZE))
