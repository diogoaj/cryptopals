""" Implement and break HMAC-SHA1 with an artificial timing leak 
	
	and

	Break HMAC-SHA1 with a slightly less artificial timing leak

"""


import requests
import time

chars = "0123456789abcdef"


# Challenge 31
"""
def find_hmac(filename):
	max_time = 0.05
	hmac = ""
	for _ in range(40):
		for c in chars:
			hmac += c
			before = time.time()
			r = requests.get("http://127.0.0.1:5000/test?filename=" + filename + \
							 "&signature=" + hmac)

			after = time.time()
			if after - before >= max_time:
				max_time += 0.05
				print(hmac)
				break
			else:
				hmac = hmac[:-1]

	return hmac
"""

# Challenge 32 ( With average )
def find_hmac(filename):
	avg_list = []
	hmac = ""
	for _ in range(40):
		for c in chars:
			avg = 0
			hmac += c
			for _ in range(5):
				before = time.time()
				r = requests.get("http://127.0.0.1:5000/test?filename=" + filename + \
								 "&signature=" + hmac)

				after = time.time()
				avg += (after - before)

			avg_list.append(avg / 5)
			hmac = hmac[:-1]

		hmac += chars[avg_list.index(max(avg_list))]
		print(hmac)
		avg_list = []

	return hmac


if __name__ == "__main__":
	find_hmac("file")