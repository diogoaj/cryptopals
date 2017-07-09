"""CBC bitflipping attacks - https://cryptopals.com/sets/2/challenges/16

Generate a random AES key.
Combine your padding code and CBC code to write two functions.
The first function should take an arbitrary input string, prepend the string:
    "comment1=cooking%20MCs;userdata="

.. and append the string:
    ";comment2=%20like%20a%20pound%20of%20bacon"

The function should quote out the ";" and "=" characters.
The function should then pad out the input to the 16-byte AES block length and encrypt it under the random AES key.
The second function should decrypt the string and look for the characters ";admin=true;" (or, equivalently, decrypt,
split the string on ";", convert each resulting string into 2-tuples, and look for the "admin" tuple).
Return true or false based on whether the string exists.
If you've written the first function properly, it should not be possible to provide user input to it that will generate
the string the second function is looking for. We'll have to break the crypto to do that.
Instead, modify the ciphertext (without knowledge of the AES key) to accomplish this.
You're relying on the fact that in CBC mode, a 1-bit error in a ciphertext block:
    - Completely scrambles the block the error occurs in
    - Produces the identical 1-bit error(/edit) in the next ciphertext block.

Stop and think for a second.
    Before you implement this attack, answer this question: why does CBC mode have this property?
"""

import os
from set2.challenge10.solve import *

BLOCK_SIZE = 16

pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
unpad = lambda s: s[:-ord(s[len(s) - 1:])]

def parse_string(string, key):
    prefix = "comment1=cooking%20MCs;userdata="
    suffix = ";comment2=%20like%20a%20pound%20of%20bacon"

    parsed = ""
    for char in string:
        if char == ";" or char == "=":
            parsed += "'" + char + "'"
        else:
            parsed += char

    plaintext = pad(prefix + parsed + suffix)

    return encrypt_aes_cbc(plaintext, key, BLOCK_SIZE)


def decrypt_string(ciphertext, key):
    plaintext = unpad(decrypt_aes_cbc(ciphertext, key, BLOCK_SIZE))

    if b";admin=true;" in plaintext:
        return True
    else:
        return False


if __name__ == "__main__":
    key = os.urandom(16)
    ciphertext = parse_string("?admin?true?", key)

    cipher_blocks = [ciphertext[i:i+16] for i in range(0, len(ciphertext), 16)]

    # Flip bits of block before the one we want to change
    # Flipped bits will be carried to the next block
    block = cipher_blocks[1]
    block = list(block)
    # ? -> 111111, 4 -> 000100, ? ^ 4 = ';' -> 111011
    block[0] ^= 4
    block[11] ^= 4
    # ? -> 111111, 2 -> 000010, ? ^ 2 = '=' -> 111101
    block[6] ^= 2

    # Join and decipher block
    cipher_blocks[1] = bytes(block)
    # Returns True
    print(decrypt_string(b"".join(cipher_blocks), key))