""" Break repeating-key XOR - https://cryptopals.com/sets/1/challenges/6

It is officially on, now.
	This challenge isn't conceptually hard, but it involves actual error-prone coding. 
	The other challenges in this set are there to bring you up to speed. 
	This one is there to qualify you. If you can do this one, you're probably just fine up to Set 6. 

"There's a file here". It's been base64'd after being encrypted with repeating-key XOR.

Decrypt it.

Here's how: 
	1. Let KEYSIZE be the guessed length of the key; try values from 2 to (say) 40. 
	2. Write a function to compute the edit distance/Hamming distance between two strings. 
	    The Hamming distance is just the number of differing bits. The distance between: 
	   		this is a test
	    and
	   		wokka wokka!!!
	    is 37. Make sure your code agrees before you proceed.
	3. For each KEYSIZE, take the first KEYSIZE worth of bytes, and the second KEYSIZE worth of bytes, 
	   and find the edit distance between them. Normalize this result by dividing by KEYSIZE. 
	4. The KEYSIZE with the smallest normalized edit distance is probably the key. 
	   You could proceed perhaps with the smallest 2-3 KEYSIZE values. 
	   Or take 4 KEYSIZE blocks instead of 2 and average the distances. 
	5. Now that you probably know the KEYSIZE: break the ciphertext into blocks of KEYSIZE length. 
	6. Now transpose the blocks: make a block that is the first byte of every block,
	   and a block that is the second byte of every block, and so on.
	7. Solve each block as if it was single-character XOR. You already have code to do this. 
	8. For each block, the single-byte XOR key that produces the best looking histogram is the 
	   repeating-key XOR key byte for that block. Put them together and you have the key. 

This code is going to turn out to be surprisingly useful later on. 
Breaking repeating-key XOR ("Vigenere") statistically is obviously an academic exercise, 
a "Crypto 101" thing. But more people "know how" to break it than can actually break it, 
and a similar technique breaks something much more important. 

No, that's not a mistake.
	We get more tech support questions for this challenge than any of the other ones. We promise, 
	there aren't any blatant errors in this text. In particular: the "wokka wokka!!!" edit distance really is 37. 

"""
import bitarray
import base64
from set1.challenge2.solve import xor
from set1.challenge3.solve import brute_force_char
from set1.challenge5.solve import calculate_xor_key


def open_file(filename):
	with open(filename, "r") as f:
		return f.read().replace("\n", "")


def arraytobits(array):
	res = ""
	for i in range(len(array)):
		if array[i]:
			res += "1"
		else:
			res += "0"

	return res


def hamming_distance(string1, string2):
	ba1 = bitarray.bitarray()
	ba2 = bitarray.bitarray()

	ba1.fromstring(string1)
	ba2.fromstring(string2)

	bin1 = arraytobits(ba1)
	bin2 = arraytobits(ba2)

	counter = 0

	for i in range(len(bin1)):
		if bin1[i] != bin2[i]:
			counter += 1

	return counter


def get_candidate_distances(string, lower_bound=2, higher_bound=41):
	distances = []
	for i in range(lower_bound, higher_bound+1):
		string1 = string[0:i]
		string2 = string[i:i*2]
		string3 = string[i*2:i*3]

		distance1 = hamming_distance(string1, string2) / i
		distance2 = hamming_distance(string2, string3) / i

		avg = (distance1 + distance2) / 2

		distances.append([i, avg])

	return distances


def get_top_candidates(candidates, top=3):
	return sorted(candidates, key=lambda x: x[1])[:top]


def divide_ciphertext_blocks(ciphertext, keysize, b64=True):
	blocks = []
	if b64 == True:
		ciphertext = base64.b64decode(ciphertext)

	for i in range(0, len(ciphertext), keysize):
		blocks.append(ciphertext[i:i+keysize])

	return blocks


def transpose_blocks(blocks, keysize):
	transposed_blocks = []

	for i in range(keysize):
		block = ""
		for j in range(len(blocks)):
			try:
				block += chr(blocks[j][i])
			except:
				continue

		transposed_blocks.append(block)

	return transposed_blocks


if __name__  == "__main__":

    text = open_file("6.txt")
    top_candidates = get_top_candidates(get_candidate_distances(text), 5)

    # After experimenting, the keysize is 29
    blocks = transpose_blocks(divide_ciphertext_blocks(text, 29), 29)

    deciphered_list = [brute_force_char(block.encode()) for block in blocks]

    key = ""
    for deciphered_obj in deciphered_list:
        key += deciphered_obj[1]

    text = base64.b64decode(text)
    print(xor(text, calculate_xor_key(text, key).encode()))