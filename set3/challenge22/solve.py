import sys
sys.path.insert(0, '../')

""" Crack an MT19937 seed """

from challenge21.solve import MarsenneTwisterMT19937
import random
import time

# Generate output
time.sleep(random.randint(40, 1000))
rng = MarsenneTwisterMT19937()
time.sleep(random.randint(40, 1000))

output = rng.generateNumber()
print("Output " + str(output))

# Crack Seed
t = int(time.time())

while True:
	rng = MarsenneTwisterMT19937(t)
	if rng.generateNumber() == output:
		print ("Found seed: " + str(t))
		break
	t -= 1