""" Break an MD4 keyed MAC using length extension """


# MD4 code from https://github.com/FiloSottile/crypto.py/blob/master/3/md4.py

import os

import struct
import binascii

lrot = lambda x, n: (x << n) | (x >> (32 - n))


class MD4():

    buf = [0x00] * 64

    _F = lambda self, x, y, z: ((x & y) | (~x & z))
    _G = lambda self, x, y, z: ((x & y) | (x & z) | (y & z))
    _H = lambda self, x, y, z: (x ^ y ^ z)

    def __init__(self, message, A=0x67452301, B=0xefcdab89, C=0x98badcfe, D=0x10325476, l=None):
    	self.A, self.B, self.C, self.D = A, B, C, D

    	if l is None:
    		l = len(message)*8

    	length = struct.pack('<Q', l)

    	while len(message) > 64:
    		self._handle(message[:64])
    		message = message[64:]

    	message += b'\x80'
    	message += bytes((56 - len(message) % 64) % 64)
    	message += length

    	while len(message):
            self._handle(message[:64])
            message = message[64:]

    def _handle(self, chunk):
        X = list(struct.unpack('<' + 'I' * 16, chunk))
        A, B, C, D = self.A, self.B, self.C, self.D

        for i in range(16):
            k = i
            if i % 4 == 0:
                A = lrot((A + self._F(B, C, D) + X[k]) & 0xffffffff, 3)
            elif i % 4 == 1:
                D = lrot((D + self._F(A, B, C) + X[k]) & 0xffffffff, 7)
            elif i % 4 == 2:
                C = lrot((C + self._F(D, A, B) + X[k]) & 0xffffffff, 11)
            elif i % 4 == 3:
                B = lrot((B + self._F(C, D, A) + X[k]) & 0xffffffff, 19)

        for i in range(16):
            k = (i // 4) + (i % 4) * 4
            if i % 4 == 0:
                A = lrot((A + self._G(B, C, D) + X[k] + 0x5a827999) & 0xffffffff, 3)
            elif i % 4 == 1:
                D = lrot((D + self._G(A, B, C) + X[k] + 0x5a827999) & 0xffffffff, 5)
            elif i % 4 == 2:
                C = lrot((C + self._G(D, A, B) + X[k] + 0x5a827999) & 0xffffffff, 9)
            elif i % 4 == 3:
                B = lrot((B + self._G(C, D, A) + X[k] + 0x5a827999) & 0xffffffff, 13)

        order = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15]
        for i in range(16):
            k = order[i]
            if i % 4 == 0:
                A = lrot((A + self._H(B, C, D) + X[k] + 0x6ed9eba1) & 0xffffffff, 3)
            elif i % 4 == 1:
                D = lrot((D + self._H(A, B, C) + X[k] + 0x6ed9eba1) & 0xffffffff, 9)
            elif i % 4 == 2:
                C = lrot((C + self._H(D, A, B) + X[k] + 0x6ed9eba1) & 0xffffffff, 11)
            elif i % 4 == 3:
                B = lrot((B + self._H(C, D, A) + X[k] + 0x6ed9eba1) & 0xffffffff, 15)

        self.A = (self.A + A) & 0xffffffff
        self.B = (self.B + B) & 0xffffffff
        self.C = (self.C + C) & 0xffffffff
        self.D = (self.D + D) & 0xffffffff

    def digest(self):
        return struct.pack('<4I', self.A, self.B, self.C, self.D)

    def hexdigest(self):
    	return binascii.hexlify(self.digest()).decode()

def compute_mac(key, message):
	return MD4(key + message).hexdigest()


def compute_padding(message):
	length = len(message) * 8
	message += b'\x80'
	message += bytes((56 - (len(message) % 64)) % 64)
	message += struct.pack('<Q', length)
	
	return message

def forge_message(message, digest, key_len, new_message):
	forged_message = compute_padding(b"A"*key_len + message)[key_len:] + new_message

	h = struct.unpack("<4I", binascii.unhexlify(digest))

	forged_mac = MD4(new_message, h[0], h[1], h[2], h[3],
					   (key_len + len(forged_message)) * 8).hexdigest()

	return forged_message, forged_mac

if __name__ == "__main__":
	key = os.urandom(16)

	original_message = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
	new_message = b";admin=true"

	mac = compute_mac(key, original_message)
	forged_message, forged_mac = forge_message(original_message, mac, 16, new_message)

	print(compute_mac(key, forged_message) == forged_mac)
