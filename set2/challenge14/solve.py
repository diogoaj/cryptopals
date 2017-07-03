"""Byte-at-a-time ECB decryption (Harder) - https://cryptopals.com/sets/2/challenges/14

Take your oracle function from #12.
Now generate a random count of random bytes and prepend this string to every plaintext. You are now doing:
    AES-128-ECB(random-prefix || attacker-controlled || target-bytes, random-key)

Same goal: decrypt the target-bytes.

Stop and think for a second.
    What's harder than challenge #12 about doing this? How would you overcome that obstacle?
    The hint is: you're using all the tools you already have; no crazy math is required.

    Think "STIMULUS" and "RESPONSE".
"""
import base64
import random
import os
from set2.challenge10.solve import *
from set2.challenge11.solve import random_char

def encryption_oracle(string):
    prefix = random_char(13)

    s = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg\
        aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq\
        dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg\
        YnkK"

    string = prefix + string + base64.b64decode(s).decode()

    return encrypt_aes_ecb(string.encode(), key, 16)


if __name__ == "__main__":
    key = os.urandom(16)

    # Finding prefix length, assuming length can vary from 1 to 16
    length = 0
    for i in range(16):
        padding = "A"*(32 + i)
        cipher = encryption_oracle(padding)

        block1 = cipher[16:32]
        block2 = cipher[32:48]

        if block1 == block2:
            length = 16 - i
            break

    unknown_string = ""
    # Loop for each block
    for j in range(len(encryption_oracle("")) // 16):
        for i in range(0, 16):
            cipher = encryption_oracle("A" * (15 - i + 16 - length))
            """4. Create dictionary"""
            dictionary = {}

            # Only concerned about the ascii characters
            for char in range(0, 127):
                dictionary[encryption_oracle("A" * (15 - i + 16 - length) + unknown_string + chr(char))[j * 16:(j + 1) * 16]] = \
                    chr(char)

            """5. Get byte"""
            # When we hit the padding, we must break the cycle
            try:
                unknown_string += dictionary[cipher[j * 16:(j + 1) * 16]]
            except:
                break

    # Remove padding
    print(unknown_string[:-1])