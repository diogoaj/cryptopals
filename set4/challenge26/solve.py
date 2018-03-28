""" CTR bitfipping """

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

def encrypt_aes_ecb(plaintext, key, block_size):
    aes = AES.new(key, AES.MODE_ECB)

    return aes.encrypt(plaintext)

def aes_ctr(ciphertext, key, nonce, block_size):
    counter = b'\x00'*8
    blocks = [ciphertext[i:i+16] for i in range(0, len(ciphertext), 16)]
    decrypted_blocks = []

    for block in blocks:
        keystream = encrypt_aes_ecb(nonce + counter, key, BLOCK_SIZE)
        decrypted_blocks.append(xor(block, keystream))
        counter = (int.from_bytes(counter, byteorder='little') + 1).to_bytes(block_size // 2, byteorder='little')

    return ''.join(decrypted_blocks)


def parse_string(string, key, nonce):
    prefix = "comment1=cooking%20MCs;userdata="
    suffix = ";comment2=%20like%20a%20pound%20of%20bacon"

    parsed = ""
    for char in string:
        if char == ";" or char == "=":
            parsed += "'" + char + "'"
        else:
            parsed += char

    return aes_ctr(prefix + parsed + suffix, key, nonce, BLOCK_SIZE)


def decrypt_string(ciphertext, key, nonce):
    plaintext = aes_ctr(ciphertext, key, nonce, BLOCK_SIZE)

    if "admin=true" in plaintext:
        return True
    else:
        return False


if __name__ == "__main__":
    key = os.urandom(16)
    nonce = b"\x00"*8

    ciphertext = parse_string("admin?true", key, nonce)

    cipher_blocks = [ciphertext[i:i+16] for i in range(0, len(ciphertext), 16)]

    block = list(cipher_blocks[2])
 
    for i in range(len(block)):
        try:
            block[i] = ord(block[i])
        except:
            pass

    t = block[5]
    t ^= ord('?') # key

    block[5] = ord('=') ^ t

    for i in range(len(block)):
        block[i] = chr(block[i])

    cipher_blocks[2] = ''.join(block)

    print(decrypt_string(''.join(cipher_blocks), key, nonce))