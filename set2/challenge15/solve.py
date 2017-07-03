"""PKCS#7 padding validation - https://cryptopals.com/sets/2/challenges/15

Write a function that takes a plaintext, determines if it has valid PKCS#7 padding, and strips the padding off.
The string:
    "ICE ICE BABY\x04\x04\x04\x04"

... has valid padding, and produces the result "ICE ICE BABY".
The string:
    "ICE ICE BABY\x05\x05\x05\x05"

... does not have valid padding, nor does:
    "ICE ICE BABY\x01\x02\x03\x04"

If you are writing in a language with exceptions, like Python or Ruby, make your function throw an exception
on bad padding.
Crypto nerds know where we're going with this. Bear with us.
"""
from string import printable

def validate_padding(plaintext):
    padding_length = ord(plaintext[len(plaintext) - 1:])
    padding = plaintext[-padding_length:]

    for char in padding:
        if char != chr(padding_length):
            raise Exception("Incorrect padding")

    for char in plaintext[:-padding_length]:
        if char not in printable:
            raise Exception("Incorrect padding")

    if len(set(padding)) != 1:
        raise Exception("Incorrect padding")

    return plaintext[:-padding_length]

# Returns stripped string
print(validate_padding("ICE ICE BABY\x04\x04\x04\x04"))

# These two calls raise the exception
#print(validate_padding("ICE ICE BABY\x05\x05\x05\x05"))
#print(validate_padding("ICE ICE BABY\x01\x02\x03\x04"))