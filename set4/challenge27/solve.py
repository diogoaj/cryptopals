""" Recover the key from CBC with IV=Key """

import os
from Crypto.Cipher import AES

class AESCipher(object):

    def __init__(self, key): 
        self.bs = 16
        self.key = key

    def encrypt(self, raw):
        raw = self._pad(raw)
        iv = self.key 
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return cipher.encrypt(raw)

    def decrypt(self, enc):
        iv = self.key
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc))

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]

def xor(string1, string2):
    result_string = []

    for i in range(len(string1)):
        result_string.append(string1[i] ^ string2[i])

    return bytes(result_string)


def parse_string(string, cipher):
    prefix = "comment1=cooking%20MCs;userdata="
    suffix = ";comment2=%20like%20a%20pound%20of%20bacon"

    parsed = ""
    for char in string:
        if char == ";" or char == "=":
            parsed += "'" + char + "'"
        else:
            parsed += char

    plaintext = prefix + parsed + suffix

    return aes.encrypt(plaintext)


def decrypt_string(ciphertext, cipher):
    plaintext = aes.decrypt(ciphertext)

    for c in plaintext:
        if c >= 127:
            print ("ERROR!!")
            print (plaintext)
            return (plaintext)


if __name__ == "__main__":
    key = os.urandom(16)
    aes = AESCipher(key)
    ciphertext = parse_string("random_string", aes)

    cipher_blocks = [ciphertext[i:i+16] for i in range(0, len(ciphertext), 16)]

    cipher_blocks[1] = b'\x00'*16
    cipher_blocks[2] = cipher_blocks[0]

    c = b''.join(cipher_blocks)

    p = decrypt_string(c, aes)

    p_blocks = [p[i:i+16] for i in range(0, len(p), 16)]

    k = xor(p_blocks[0], p_blocks[2])

    print(k == key)