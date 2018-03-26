""" Break fixed-nonce CTR mode using substitutions - https://cryptopals.com/sets/3/challenges/19"""


import base64
from Crypto.Cipher import AES


f = open("cipher.txt", "r")
ciphertexts = f.readlines()
f.close()

