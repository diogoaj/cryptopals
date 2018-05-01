"""
	Implement Secure Remote Password (SRP)
"""

import random
import os
import base64
import hmac
from hashlib import sha256
from Crypto.Cipher import AES

class AESCipher(object):

    def __init__(self, key): 
        self.bs = 16
        self.key = sha256(key).digest()[0:16]

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
	# C & S
	N = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
	g = 2
	k = 3

	I = "email@mail.com"
	P = "password"

	# S
	# 1. Generate salt as random integer
	salt = random.randint(1, 2**32)

	# 2. Generate string xH = SHA256(salt|password)
	xH = sha256((str(salt) + P).encode("utf-8")).hexdigest()

	# 3. Convert xH to integer x somehow (put 0x on hexdigest)
	x = int(xH, 16)

	# 4. Generate v = g**x % N
	v = pow(g, x, N)

	# 5. Save everything but x, xH

	# C->S 
	# send I
	a = random.randint(1, 2**32)
	A = pow(g, a, N)

	# S->C
	# send salt
	b = random.randint(1, 2**32)
	B = k*v + pow(g, b, N) % N

	# S, C
	uH = sha256((str(A)+str(B)).encode("utf-8")).hexdigest()
	u = int(uH, 16)

	# C
	xH_client = sha256((str(salt) + P).encode("utf-8")).hexdigest()
	x_client = int(xH_client, 16)

	S = pow(B-k*pow(g, x_client, N), a+u*x, N) % N
	K1 = sha256(str(S).encode("utf-8")).hexdigest()

	# S
	S_server = pow(A*pow(v,u,N), b, N) % N
	K2 = sha256(str(S_server).encode("utf-8")).hexdigest()

	# C->S
	h = hmac.new(str.encode(K1), str(salt).encode("utf-8"), sha256).hexdigest()

	# S->C
	if hmac.new(str.encode(K2), str(salt).encode("utf-8"), sha256).hexdigest() == h:
		print ("OK")
	else:
		print ("Not OK")