""" Implement the MT19937 Marsenne Twister RNG """

"""
From wikipedia.org/Marsenne_Twister

w: word size (in number of bits)
n: degree of recurrence
m: middle word, an offset used in recurrence relation definining the series x, 1 <= m < n
r: separation point of one word, or the number of bits of the lower bitmask, 0 <= r <= w - 1
a: coefficients of the rational normal form twist matrix
b, c: TGFSR(R) tempering bitmasks
s, t: TGFSR(R) tempering bit shifts
u, d, l: additional Marsenne Twister tempering bit shifts/masks
"""
import time

upper_bits = 1 << 31
lower_bits = (1 << 31) - 1

class MarsenneTwisterMT19937:
	def __init__(self, seed=int(time.time())):
		self.w = 32
		self.n = 624
		self.m = 397
		self.r = 31
		self.a = 0x9908b0df
		self.u = 11
		self.d = 0xffffffff
		self.s = 7
		self.b = 0x9d2c5680
		self.t = 15
		self.c = 0xefc60000
		self.l = 18
		self.f = 1812433253
		self.index = 0
		self.x = [0]*self.n

		self.x[0] = seed
		for i in range(1, self.n):
			self.x[i] = (self.f * (self.x[i-1] ^ (self.x[i-1] >> (self.w-2))) + i) & self.d

	def setState(self, x):
		self.x = x

	def twist(self):
		for i in range(self.n):
			y = (self.x[i] & upper_bits) + (self.x[(i+1) % self.n] & lower_bits)
			self.x[i] = self.x[(i+self.m) % self.n] ^ (y >> 1)
			if y % 2 != 0:
				self.x[i] ^= self.a

	def generateNumber(self):
		if self.index == 0:
			self.twist()

		y = self.x[self.index] ^ ((self.x[self.index] >> self.u) & self.d)
		y = y ^ ((y << self.s) & self.b)
		y = y ^ ((y << self.t) & self.c)
		z = (y ^ (y >> self.l)) & self.d
		self.index = (self.index + 1) % self.n
		return z