""" Break a SHA-1 keyed MAC using length extension """

# From: https://github.com/FiloSottile/crypto.py/blob/master/3/sha1.py

import os
import struct
import binascii

lrot = lambda x, n: (x << n) | (x >> (32 - n))


class SHA1():
    def __init__(self, message, l=None, h0=0x67452301, h1=0xefcdab89, h2=0x98badcfe, h3=0x10325476, h4=0xc3d2e1f0):
        self._h0, self._h1, self._h2, self._h3, self._h4 = h0, h1, h2, h3, h4

        if l == None:
            l = len(message)*8

        length = struct.pack('>Q', l)

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
        w = list(struct.unpack('>' + 'I' * 16, chunk))

        for i in range(16, 80):
            w.append(lrot(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1)
                     & 0xffffffff)

        a = self._h0
        b = self._h1
        c = self._h2
        d = self._h3
        e = self._h4

        for i in range(80):

            if i <= i <= 19:
                f, k = d ^ (b & (c ^ d)), 0x5a827999
            elif 20 <= i <= 39:
                f, k = b ^ c ^ d, 0x6ed9eba1
            elif 40 <= i <= 59:
                f, k = (b & c) | (d & (b | c)), 0x8f1bbcdc
            elif 60 <= i <= 79:
                f, k = b ^ c ^ d, 0xca62c1d6

            temp = lrot(a, 5) + f + e + k + w[i] & 0xffffffff
            a, b, c, d, e = temp, a, lrot(b, 30), c, d

        self._h0 = (self._h0 + a) & 0xffffffff
        self._h1 = (self._h1 + b) & 0xffffffff
        self._h2 = (self._h2 + c) & 0xffffffff
        self._h3 = (self._h3 + d) & 0xffffffff
        self._h4 = (self._h4 + e) & 0xffffffff

    def digest(self):
        return struct.pack('>IIIII', self._h0, self._h1,
                           self._h2, self._h3, self._h4)

    def hexdigest(self):
        return binascii.hexlify(self.digest()).decode()


def compute_mac(key, message):
    return SHA1(key + message).hexdigest()

def compute_padding(message):
    ml = len(message) * 8
    message += b'\x80'
    while(len(message) * 8) % 512 != 448:
        message += b'\x00'
    message += struct.pack('>Q', ml)
    return message


def forge_message(message, digest, key_len, new_message):
    forged_message = compute_padding(b'A'*key_len + message)[key_len:] + new_message

    h = struct.unpack(">5I", binascii.unhexlify(digest))

    forged_digest = SHA1(new_message, (key_len + len(forged_message)) * 8, 
                         h[0], h[1], h[2], h[3], h[4]).hexdigest()

    return forged_message, forged_digest


if __name__ == "__main__":
    key = os.urandom(16)

    original_message = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
    new_message = b";admin=true"

    mac = compute_mac(key, original_message)
    forged_message, forged_mac = forge_message(original_message, mac, 16, new_message)

    print(compute_mac(key, forged_message) == forged_mac)

    print(SHA1(b'sha1').hexdigest())

