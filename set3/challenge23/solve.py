import sys
sys.path.insert(0, '../')

""" Clone an MT19937 RNG from its output """

from challenge21.solve import MarsenneTwisterMT19937

def untemper(rng, y):
	y = y ^ (y >> rng.l)
	y = y ^ ((y << rng.t) & rng.c)
	for i in range(7):
		y = y ^ ((y << rng.s) & rng.b)
	y = y ^ ((y >> rng.u) ^ (y >> rng.u * 2))
	return y

original = MarsenneTwisterMT19937()
state = []
for i in range(624):
	state.append(untemper(original, original.generateNumber()))

new = MarsenneTwisterMT19937()
new.setState(state)

# Predicting the original rng
for i in range(10):
	print("Original rng output " + str(original.generateNumber()))
	print("Spliced rng output " + str(new.generateNumber()))