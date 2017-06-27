""" Fixed XOR - https://cryptopals.com/sets/1/challenges/2

Write a function that takes two equal-length buffers and produces their XOR combination. 

If your function works properly, then when you feed it the string: 	
	1c0111001f010100061a024b53535009181c

... after hex decoding, and when XOR'd against: 
	686974207468652062756c6c277320657965

... should produce:
	746865206b696420646f6e277420706c6179

"""
from codecs import decode, encode

def xor(string1, string2, single=False):
    result_string = ""

    if single == True:
        for i in range(len(string1)):
            result_string += chr(string1[i] ^ string2)
    else:
        for i in range(len(string1)):
            result_string += chr(string1[i] ^ string2[i])
    return result_string

if __name__ == "__main__":
	string1 = decode("1c0111001f010100061a024b53535009181c", "hex")
	string2 = decode("686974207468652062756c6c277320657965", "hex")

	print (encode(xor(string1, string2).encode(), "hex").decode())