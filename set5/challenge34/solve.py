""" 
    Implement MITM key-fixing attack on Diffie-Hellman with parameter injection 
"""

import random
from hashlib import sha1
import os
import base64
from Crypto.Cipher import AES

class AESCipher(object):

    def __init__(self, key): 
        self.bs = 16
        self.key = sha1(key).digest()[0:16]

    def encrypt(self, raw):
        raw = self._pad(raw)
        iv = os.urandom(self.bs)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw))

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]


if __name__ == "__main__":
    # A -> M
    p = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
    g = 2
    a = random.randint(1, 2**32)
    A = pow(g, a, p)

    # M 
    A = p

    # B
    b = random.randint(1, 2**32)

    # B -> M
    B_original = pow(g, b, p)

    # M -> A
    B = p

    # A
    msg = "abcdefghijklmnopqrstuvwxyz"

    # p ^ a mod p = 0
    s_a = pow(B, a, p)
    shared_key_a = sha1(str(s_a).encode("utf-8")).digest()[0:16]
    aes = AESCipher(shared_key_a)

    # A -> M -> B
    cipher = aes.encrypt(msg)

    # M 
    mitm_key = sha1(str(0).encode("utf-8")).digest()[0:16]
    aes = AESCipher(mitm_key)
    print("[+] MITM decrypted: " + aes.decrypt(cipher))
    
    # B -> M -> A
    s_b = pow(A, b, p)
    shared_key_b = sha1(str(s_b).encode("utf-8")).digest()[0:16]
    aes = AESCipher(shared_key_b)

    # A
    print("[+] echo: " + aes.decrypt(cipher))