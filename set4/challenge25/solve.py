""" Break "random access read/write" AES CTR """

# Copied code from challenge 18

import base64
import os
from Crypto.Cipher import AES

BLOCK_SIZE = 16

def xor(string1, string2):
    result_string = ""
    for i in range(len(string1)):
        if isinstance(string1[i], int) and isinstance(string2[i], int):
            result_string += chr(string1[i] ^ string2[i])
        elif not isinstance(string1[i], int) and isinstance(string2[i], int):
            result_string += chr(ord(string1[i]) ^ string2[i])
        elif not isinstance(string2[i], int) and isinstance(string1[i], int):
            result_string += chr(string1[i] ^ ord(string2[i]))
        else:
            result_string += chr(ord(string1[i]) ^ ord(string2[i]))     
   
    return result_string

def decrypt_aes_ecb(ciphertext, key, block_size):
    aes = AES.new(key, AES.MODE_ECB)

    return aes.decrypt(ciphertext)

def encrypt_aes_ecb(plaintext, key, block_size):
    aes = AES.new(key, AES.MODE_ECB)

    return aes.encrypt(plaintext)

def aes_ctr(ciphertext, key, nonce, block_size):
    counter = b"\x00"*8
    blocks = [ciphertext[i:i+16] for i in range(0, len(ciphertext), 16)]
    decrypted_blocks = []

    for block in blocks:
        keystream = encrypt_aes_ecb(nonce + counter, key, BLOCK_SIZE)
        decrypted_blocks.append(xor(block, keystream))
        counter = (int.from_bytes(counter, byteorder='little') + 1).to_bytes(block_size // 2, byteorder='little')

    return ''.join(decrypted_blocks)

# Attacker controls this function
def editAPI(ciphertext, offset, newtext):
    return edit(ciphertext, key, offset, newtext)


def edit(ciphertext, key, offset, newtext):
    plaintext = aes_ctr(ciphertext, key, nonce, BLOCK_SIZE)
    blocks = [plaintext[i:i+16] for i in range(0, len(plaintext), 16)]

    blocks[offset] = newtext

    return aes_ctr(''.join(blocks), key, nonce, BLOCK_SIZE)
    
def attackCTR(ciphertext):
    key = ""
    cycles = len(ciphertext) // 16

    for i in range(cycles):
        new_ciphertext = editAPI(ciphertext, i, "A"*16)
        blocks = [new_ciphertext[i:i+16] for i in range(0, len(new_ciphertext), 16)]
        key += xor("A"*16, blocks[i])

    return xor(ciphertext, key)

if __name__ == "__main__":
    f = open("25.txt", "r")
    encrypted = f.read()
    f.close()

    plaintext = decrypt_aes_ecb(base64.b64decode(encrypted), "YELLOW SUBMARINE", BLOCK_SIZE)

    key = os.urandom(16)
    nonce = b"\x00"*8

    ciphertext = aes_ctr(plaintext, key, nonce, BLOCK_SIZE)

    print(attackCTR(ciphertext))