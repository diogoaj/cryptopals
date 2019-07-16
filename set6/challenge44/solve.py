""" DSA nonce recovery from repeated nonce """

from Crypto.Util.number import inverse
import hashlib
import random


def get_sha1(string):
	sha1 = hashlib.sha1(string)
	return int(sha1.hexdigest(), 16)


class DSA:
	def __init__(self):
		self.p = 0x800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1
		self.q = 0xf4f47f05794b256174bba6e9b396a7707e563c5b
		self.g = 0x5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291
		self.x = random.randint(1, self.q - 1) # private key
		self.y = pow(self.g, self.x, self.p)   # public key


	def sign(self, message, k):
		r = (pow(self.g, k, self.p) % self.q)
		s = (inverse(k, self.q)*(get_sha1(message) + self.x*r)) % self.q

		return (r, s)


	def verify(self, original_message, signature):
		r, s = signature
		if r > 0 and r < self.q and s > 0 and s < self.q:
			w = inverse(s, self.q)
			u1 = (get_sha1(original_message)*w) % self.q
			u2 = (r*w) % self.q
			v = ((pow(self.g, u1, self.p)*pow(self.y, u2, self.p)) % self.p) % self.q

			return v == r
		return False


def discover_k(m1, m2, s1, s2, q):
	inv = inverse((s1 - s2), q)
	return ((m1 - m2) * inv) % q


def recover_private_key(r, s, q, k, message):
	r_inv = inverse(r, q)
	return (((s*k) - message) * r_inv) % q


if __name__ == "__main__":
	dsa = DSA()

	# Challenge 
	y = 0x2d026f4bf30195ede3a088da85e398ef869611d0f68f0713d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b85519b1c23cc3ecdc6062650462e3063bd179c2a6581519f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d32971c3de5084cce04a2e147821

	# Messages with the same k
	msg1 = "Listen for me, you better listen for me now.\n"
	r1 = 1105520928110492191417703162650245113664610474875
	s1 = 1267396447369736888040262262183731677867615804316
	m1 = 0xa4db3de27e2db3e5ef085ced2bced91b82e0df19

	msg2 = "Pure black people mon is all I mon know.\n"
	r2 = 1105520928110492191417703162650245113664610474875
	s2 = 1021643638653719618255840562522049391608552714967
	m2 = 0xd22804c4899b522b23eda34d2137cd8cc22b9ce8

	k = discover_k(m1, m2, s1, s2, dsa.q)

	x = recover_private_key(r1, s1, dsa.q, k, m1)

	print(hex(get_sha1(hex(x).encode()[2:]))[2:])