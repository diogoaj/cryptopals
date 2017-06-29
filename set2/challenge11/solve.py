""" IAn ECB/CBC detection oracle - https://cryptopals.com/sets/2/challenges/11

Now that you have ECB and CBC working:

Write a function to generate a random AES key; that's just 16 random bytes.

Write a function that encrypts data under an unknown key --- that is, a function that generates a random key and
encrypts under it.

The function should look like:
    encryption_oracle(your-input)
    => [MEANINGLESS JIBBER JABBER]

Under the hood, have the function append 5-10 bytes (count chosen randomly) before the plaintext and 5-10 bytes
after the plaintext.

Now, have the function choose to encrypt under ECB 1/2 the time, and under CBC the other half
(just use random IVs each time for CBC). Use rand(2) to decide which to use.

Detect the block cipher mode the function is using each time. You should end up with a piece of code that,
pointed at a block box that might be encrypting ECB or CBC, tells you which one is happening.
"""

import random
import os
import string
from set2.challenge10.solve import *

def random_char(n):
    return ''.join(random.choice(string.printable) for x in range(n))

def encryption_oracle(string):
    r_key = os.urandom(16)
    r = random.randint(0,1)
    string = random_char(random.randint(5,10)) + string + random_char(random.randint(5,10))
    print(string)

    if r == 0:
        print("Ciphering with ECB mode...")
        return encrypt_aes_ecb(string.encode(), r_key, 16)
    else:
        print("Ciphering with CBC mode...")
        return encrypt_aes_cbc(string, r_key, 16, os.urandom(16))

def detection_oracle(cipher, block_size):
    blocks = [cipher[i:i+block_size] for i in range(0, len(cipher), block_size)]
    if len(blocks) == len(set(blocks)):
        return "CBC"
    else:
        return "ECB"


if __name__ == "__main__":
    cipher = encryption_oracle("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
    print("Oracle says, block mode is:", detection_oracle(cipher, 16))