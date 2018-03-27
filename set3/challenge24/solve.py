#!/usr/bin/python3.6

import sys
sys.path.insert(0, '../')

""" Create the MT19937 stream cipher and break it """

import random
import string
import time
from challenge21.solve import MarsenneTwisterMT19937

def xor(a, b):
    res = ""

    for i in range(len(a)):
        res += chr(ord(a[i]) ^ b[i])

    return res


class MT19937Cipher:
	def __init__(self, key):
		self.rng = MarsenneTwisterMT19937(key)
		self.keystream = []

	def mt_encrypt(self, plaintext):
		for i in range(0, len(plaintext), 4):
			n = self.rng.generateNumber()
			self.keystream.append(n & 0xff)
			self.keystream.append(n >> 8 & 0xff)
			self.keystream.append(n >> 16 & 0xff)
			self.keystream.append(n >> 24 & 0xff)
		return xor(plaintext, self.keystream)


def recoverKey(ciphertext):
	m = 2**16
	for key in range(m):
		cipher = MT19937Cipher(key)
		if 'A'*14 in cipher.mt_encrypt(ciphertext):
			return key


def generateToken(bits=16):
	token = []
	k = int(time.time())
	rng = MarsenneTwisterMT19937(k)
	for i in range(0, bits, 4):
		n = rng.generateNumber()
		token.append(chr(n & 0xff))
		token.append(chr(n >> 8 & 0xff))
		token.append(chr(n >> 16 & 0xff))
		token.append(chr(n >> 24 & 0xff))
	return ''.join(token)


def detectToken(token, bits=16):
	tk = []
	for t in range(3600*24):
		k = int(time.time() - t)
		rng = MarsenneTwisterMT19937(k)
		for i in range(0, bits, 4):
			n = rng.generateNumber()
			tk.append(chr(n & 0xff))
			tk.append(chr(n >> 8 & 0xff))
			tk.append(chr(n >> 16 & 0xff))
			tk.append(chr(n >> 24 & 0xff))
		tk = ''.join(tk)
		if tk == token:
			return True
	return False


""" Recover key from cipher

cipher = MT19937Cipher(random.randint(1, 2**16))

plaintext = ''.join(random.choices(string.ascii_letters, 
					k=random.randint(1, 10)))
plaintext += 'A'*14

ciphertext = cipher.mt_encrypt(plaintext)

print(recoverKey(ciphertext))"""



""" Password reset token funcs
token = generateToken()

print(detectToken(token))