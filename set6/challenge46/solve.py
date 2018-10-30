""" RSA parity oracle

Generate a 1024 bit RSA key pair.

Write an oracle function that uses the private key to answer the question "is the plaintext of this message even or odd" (is the last bit of the message 0 or 1). Imagine for instance a server that accepted RSA-encrypted messages and checked the parity of their decryption to validate them, and spat out an error if they were of the wrong parity.

Anyways: function returning true or false based on whether the decrypted plaintext was even or odd, and nothing else.

Take the following string and un-Base64 it in your code (without looking at it!) and encrypt it to the public key, creating a ciphertext:

	VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ==

With your oracle function, you can trivially decrypt the message.

Here's why:

    * RSA ciphertexts are just numbers. You can do trivial math on them. You can for instance multiply a ciphertext by the RSA-encryption of another number; the corresponding plaintext will be the product of those two numbers.
    * If you double a ciphertext (multiply it by (2**e)%n), the resulting plaintext will (obviously) be either even or odd.
    * If the plaintext after doubling is even, doubling the plaintext didn't wrap the modulus --- the modulus is a prime number. That means the plaintext is less than half the modulus.

You can repeatedly apply this heuristic, once per bit of the message, checking your oracle function each time.

Your decryption function starts with bounds for the plaintext of [0,n].

Each iteration of the decryption cuts the bounds in half; either the upper bound is reduced by half, or the lower bound is.

After log2(n) iterations, you have the decryption of the message.

Print the upper bound of the message as a string at each iteration; you'll see the message decrypt "hollywood style".

Decrypt the string (after encrypting it to a hidden private key) above. 
"""

from binascii import hexlify, unhexlify
import gmpy2
import base64

class RSA:
	def __init__(self, primes):
		self.p = primes[0]
		self.q = primes[1]
		
		self.n = self.p*self.q
		self.phi = (self.p-1)*(self.q-1)

		self.e = 65537
		self.d = gmpy2.invert(self.e, self.phi)

	def encrypt(self, m):
		m = int(hexlify(m).decode(), 16)
		return pow(m, self.e, self.n)

	def decrypt(self, c):
		m = pow(c, self.d, self.n)
		return m


def oracle(cipher):
	m = rsa.decrypt(cipher)
	if m & 1 == 0:
		return True 
	else:
		return False

if __name__ == "__main__":
	encoded_cipher = "VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ=="

	cipher = base64.b64decode(encoded_cipher)

	# Private
	primes = [10953339029280395697974696773647967862795480222910930479849459772930649581431337779769944200222560822778461472831797484180703344870223759941205120258949569,
			  11085467181994361322733460707522139380985886539043947367352298723693754914538557893749286188323093207348857408277911403759583563274093556951283755584430877]

	# Public
	n = primes[0]*primes[1]
	e = 65537

	rsa = RSA(primes)
	c = rsa.encrypt(cipher)

	# Binary Search
	low = 0
	high = n
	while low < high:
		mid = (high + low) // 2
		c = c * pow(2, e, n) 
		if oracle(c):
			high = mid
		else:
			low = mid

		print ("[+]", high)

	print ("----------------------")
	print (unhexlify(hex(high)[2:]))