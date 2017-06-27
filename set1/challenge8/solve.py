""" Detect AES in ECB mode - https://cryptopals.com/sets/1/challenges/8

"In this file" are a bunch of hex-encoded ciphertexts.

One of them has been encrypted with ECB.

Detect it.

Remember that the problem with ECB is that it is stateless and deterministic; 
the same 16 byte plaintext block will always produce the same 16 byte ciphertext. 
"""

from codecs import decode
from set1.challenge4.solve import read_file_lines

BLOCK_SIZE = 16

def is_mode_ecb(ciphertext, block_size):
	ciphertext = decode(ciphertext.replace("\n", ""), "hex")
	blocks = [ciphertext[i:i+block_size] for i in range(0, len(ciphertext), block_size)]

	return len(blocks) != len(set(blocks))

if __name__ == "__main__":
	lines = read_file_lines("8.txt")

	# Line 132 is in ECB mode
	for i in range(len(lines)):
		print("Line", str(i), "->", is_mode_ecb(lines[i], BLOCK_SIZE))