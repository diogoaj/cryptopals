"""Byte-at-a-time ECB decryption (Simple) - https://cryptopals.com/sets/2/challenges/12

Copy your oracle function to a new function that encrypts buffers under ECB mode using a consistent but unknown key
(for instance, assign a single random key, once, to a global variable).

Now take that same function and have it append to the plaintext, BEFORE ENCRYPTING, the following string:
    Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
    aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
    dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
    YnkK

Spoiler alert.
    Do not decode this string now. Don't do it.

Base64 decode the string before appending it. Do not base64 decode the string by hand; make your code do it.
The point is that you don't know its contents.

What you have now is a function that produces:
    AES-128-ECB(your-string || unknown-string, random-key)

It turns out: you can decrypt "unknown-string" with repeated calls to the oracle function!
Here's roughly how:
    1. Feed identical bytes of your-string to the function 1 at a time
    --- start with 1 byte ("A"), then "AA", then "AAA" and so on. Discover the block size of the cipher.
    You know it, but do this step anyway.

    2. Detect that the function is using ECB. You already know, but do this step anyways.

    3. Knowing the block size, craft an input block that is exactly 1 byte short (for instance,
    if the block size is 8 bytes, make "AAAAAAA").
    Think about what the oracle function is going to put in that last byte position.

    4. Make a dictionary of every possible last byte by feeding different strings to the oracle; for instance,
    "AAAAAAAA", "AAAAAAAB", "AAAAAAAC", remembering the first block of each invocation.

    5. Match the output of the one-byte-short input to one of the entries in your dictionary.
    You've now discovered the first byte of unknown-string.

    6. Repeat for the next byte.

Congratulations.
    This is the first challenge we've given you whose solution will break real crypto.
    Lots of people know that when you encrypt something in ECB mode, you can see penguins through it.
    Not so many of them can decrypt the contents of those ciphertexts, and now you can.
    If our experience is any guideline, this attack will get you code execution in security tests about once a year.
"""

import base64
import os
from set2.challenge10.solve import *
from set2.challenge11.solve import detection_oracle

def encryption_oracle(string):
    s = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg\
        aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq\
        dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg\
        YnkK"

    string = string + base64.b64decode(s).decode()

    return encrypt_aes_ecb(string.encode(), key, 16)


if __name__ == "__main__":
    key = os.urandom(16)

    """1. Repeats with blocks of 16 bytes as expected"""
    #for i in range(1, 64):
    #    print(str(i), "->", encryption_oracle("A"*i, key))

    """2. ECB mode as expected too"""
    #print(detection_oracle(encryption_oracle("A"*64, key), 16))

    """3. The next byte will be the first byte of the unknown string"""

    """Loop to find the unknown string"""
    unknown_string = ""
    j = 16
    # Loop for each block
    for j in range(len(encryption_oracle("")) // 16):
        for i in range(0, 16):
            cipher = encryption_oracle("A" * (15-i))
            """4. Create dictionary"""
            dictionary = {}

            # Only concerned about the ascii characters
            for char in range(0,127):
                dictionary[encryption_oracle("A"*(15-i) + unknown_string + chr(char))[j*16:(j+1)*16]] = chr(char)

            """5. Get byte"""
            # When we hit the padding, we must break the cycle
            try:
                unknown_string += dictionary[cipher[j*16:(j+1)*16]]
            except:
                break

    # Remove padding
    print(unknown_string[:-1])