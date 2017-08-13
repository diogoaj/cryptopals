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

from struct import pack

def validate_PKCS7_padding(plaintext):
    l_value = plaintext[-1]
    l = pack("B",l_value)

    if l_value == 0 or plaintext[-l_value:] != l * l_value:
        raise ValueError("Incorrect padding")
    return plaintext[0:-l_value]

if __name__ == "__main__":
    # Returns stripped string
    print(validate_PKCS7_padding(b'ICE ICE BABY\x04\x04\x04\x04'))

    # These two calls raise the exception
    #print(validate_PKCS7_padding(b'ICE ICE BABY\x05\x05\x05\x05'))
    #print(validate_PKCS7_padding(b'ICE ICE BABY\x01\x02\x03\x04'))
