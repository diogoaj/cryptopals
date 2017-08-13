""" The CBC padding oracle - https://cryptopals.com/sets/3/challenges/17

This is the best-known attack on modern block-cipher cryptography.

Combine your padding code and your CBC code to write two functions.

The first function should select at random one of the following 10 strings:
    MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=
    MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=
    MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==
    MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==
    MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl
    MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==
    MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==
    MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=
    MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=
    MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93

 ... generate a random AES key (which it should save for all future encryptions),
 pad the string out to the 16-byte AES block size and CBC-encrypt it under that key,
 providing the caller the ciphertext and IV.

The second function should consume the ciphertext produced by the first function,
decrypt it, check its padding, and return true or false depending on whether the padding is valid.

What you're doing here.
    This pair of functions approximates AES-CBC encryption as its deployed serverside in web applications;
    the second function models the server's consumption of an encrypted session token, as if it was a cookie.

It turns out that it's possible to decrypt the ciphertexts provided by the first function.

The decryption here depends on a side-channel leak by the decryption function.
The leak is the error message that the padding is valid or not.

You can find 100 web pages on how this attack works, so I won't re-explain it. What I'll say is this:

The fundamental insight behind this attack is that the byte 01h is valid padding,
and occur in 1/256 trials of "randomized" plaintexts produced by decrypting a tampered ciphertext.

02h in isolation is not valid padding.

02h 02h is valid padding, but is much less likely to occur randomly than 01h.

03h 03h 03h is even less likely.

So you can assume that if you corrupt a decryption AND it had valid padding, you know what that padding byte is.

It is easy to get tripped up on the fact that CBC plaintexts are "padded".
Padding oracles have nothing to do with the actual padding on a CBC plaintext.
It's an attack that targets a specific bit of code that handles decryption.
You can mount a padding oracle on any CBC block, whether it's padded or not.
"""

import os
import random
import array
import base64
from Crypto.Cipher import AES
from set2.challenge15.solve import validate_PKCS7_padding

BLOCK_SIZE = 16

pad = lambda s: s + ((BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)).encode()


strings = ["MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
           "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
           "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
           "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
           "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
           "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
           "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
           "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
           "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
           "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"]


def encrypt(key):
    plaintext = strings[random.randint(0,9)]
    return aes.encrypt(base64.b64decode(plaintext))


def decrypt(ciphertext):
    plaintext = aes.decrypt(ciphertext)
    try:
        s = validate_PKCS7_padding(plaintext)
        return True
    except:
        return False


class AESCipher:
    def __init__(self, key):
        self.key = key
        self.iv = b'\x00'*16

    def encrypt( self, raw ):
        raw = pad(raw)
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        return cipher.encrypt(raw)

    def decrypt( self, enc ):
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv )
        return cipher.decrypt(enc)


def xor(b1, b2, single=False):
    res = []
    if single == False:
        for i in range(len(b1)):
            res.append(b1[i] ^ b2[i])
    else:
        return b1 ^ b2

    return array.array('B', res).tostring()

# Deciphering all blocks including the first one,
# with the assumption that the IV is 0.
if __name__ == "__main__":
    aes_key = os.urandom(BLOCK_SIZE)
    aes = AESCipher(aes_key)

    cipher = encrypt(aes_key)
    decipher = aes.decrypt(cipher)

    cipher_blocks = [cipher[i:i+16] for i in range(0, len(cipher), 16)]
    cipher_blocks = [b'\x00'*16] + cipher_blocks # IV

    deciphered_block = ""
    for index in range(len(cipher_blocks)-1, 0, -1):
        last = cipher_blocks[index]
        last2 = cipher_blocks[index - 1]

        intermidiate_blocks = []

        for j in range(BLOCK_SIZE):
            c1 = j+1
            c2 = [0] * (BLOCK_SIZE - 1 - j)

            # Brute force chars
            for i in range(256):
                c2.append(i)

                for k in range(j):
                    c_ = c1 ^ intermidiate_blocks[k]
                    c2.append(c_)

                cipher_ = bytes(c2) + last

                if decrypt(cipher_) == True:

                    char = xor(i, c1, True)
                    intermidiate_blocks = [char] + intermidiate_blocks

                    ch = xor(last2[BLOCK_SIZE-j-1], char, True)
                    #print("Found char ->", ch, chr(ch))
                    deciphered_block = chr(ch) + deciphered_block
                    break

                c2 = [0] * (BLOCK_SIZE - 1 - j)

        print(deciphered_block.encode())












