""" AES in ECB mode - https://cryptopals.com/sets/1/challenges/7

The Base64-encoded content "in this file" has been encrypted via AES-128 in ECB mode under the key:
	"YELLOW SUBMARINE".
	
(case-sensitive, without the quotes; exactly 16 characters;
I like "YELLOW SUBMARINE" because it's exactly 16 bytes long, and now you do too).

Decrypt it. You know the key, after all.

Easiest way: use OpenSSL::Cipher and give it AES-128-ECB as the cipher. 

Do this with code.
	You can obviously decrypt this using the OpenSSL command-line tool,
	 but we're having you get ECB working in code for a reason.
	You'll need it a lot later on, and not just for attacking ECB. 
"""

import base64
from Crypto.Cipher import AES
from set1.challenge6.solve import open_file

BLOCK_SIZE = 16

pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
unpad = lambda s: s[:-ord(s[len(s) - 1:])]


def decrypt_aes_ecb(ciphertext, key):
    aes = AES.new(key, AES.MODE_ECB)
    return unpad(aes.decrypt(ciphertext).decode())

if __name__ == "__main__":
    key = 'YELLOW SUBMARINE'
    ciphertext = base64.b64decode(open_file("7.txt"))

    print(decrypt_aes_ecb(ciphertext, key, BLOCK_SIZE))