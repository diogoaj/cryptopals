""" Implement CBC mode - https://cryptopals.com/sets/2/challenges/10

CBC mode is a block cipher mode that allows us to encrypt irregularly-sized messages,
despite the fact that a block cipher natively only transforms individual blocks.

In CBC mode, each ciphertext block is added to the next plaintext block before the next call
to the cipher core.

The first plaintext block, which has no associated previous ciphertext block,
is added to a "fake 0th ciphertext block" called the initialization vector, or IV.

Implement CBC mode by hand by taking the ECB function you wrote earlier,
making it encrypt instead of decrypt (verify this by decrypting whatever you encrypt to test),
and using your XOR function from the previous exercise to combine them.

"The file here" is intelligible (somewhat) when CBC decrypted against "YELLOW SUBMARINE"
with an IV of all ASCII 0 (\x00\x00\x00 &c)

Don't cheat.
    Do not use OpenSSL's CBC code to do CBC mode, even to verify your results.
    What's the point of even doing this stuff if you aren't going to learn from it?
"""

import base64
from Crypto.Cipher import AES
from set1.challenge6.solve import open_file

def xor(string1, string2):
    result_string = []

    for i in range(len(string1)):
        result_string.append(string1[i] ^ string2[i])

    return bytes(result_string)


def pad(s, block_size):
    return s + bytes([(block_size - len(s)) % block_size] * ((block_size - len(s)) % block_size))


def unpad(s):
    return s[:-ord(s[len(s) - 1:])]


def encrypt_aes_ecb(plaintext, key, block_size):
    aes = AES.new(key, AES.MODE_ECB)
    plaintext = pad(plaintext, block_size)
    return aes.encrypt(plaintext)


def decrypt_aes_ecb(ciphertext, key):
    aes = AES.new(key, AES.MODE_ECB)
    return aes.decrypt(ciphertext)


def encrypt_aes_cbc(plaintext, key, block_size, IV=None):
    cipher = []
    if IV == None:
        IV = (chr(0)*block_size).encode()

    ciphertext = encrypt_aes_ecb(xor(IV, plaintext[0:block_size].encode()), key, block_size)
    cipher.append(ciphertext)

    for i in range(block_size, len(plaintext), block_size):
        next_block = xor(plaintext[i:i+block_size].encode(), cipher[i//block_size - 1])
        cipher.append(encrypt_aes_ecb(next_block, key, block_size))

    return b"".join(cipher)

def decrypt_aes_cbc(ciphertext, key, block_size, IV=None):
    decipher = []
    if IV == None:
        IV = (chr(0) * block_size).encode()

    plaintext = xor(decrypt_aes_ecb(ciphertext[0:block_size], key), IV)
    decipher.append(plaintext)

    for i in range(block_size, len(ciphertext), block_size):
        next_block = xor(decrypt_aes_ecb(ciphertext[i:i+block_size], key), ciphertext[i-block_size:i])
        decipher.append(next_block)

    return b"".join(decipher)


if __name__ == "__main__":
    contents = open_file("10.txt")

    key = "YELLOW SUBMARINE"

    plaintext = decrypt_aes_cbc(base64.b64decode(contents), key, 16)
    print(unpad(plaintext).decode())

