""" Break a SHA-1 keyed MAC using length extension """

# From: https://github.com/pcaro90/Python-SHA1
import os

class SHA1:
    def __init__(self):
        self.__H = [
            0x67452301,
            0xEFCDAB89,
            0x98BADCFE,
            0x10325476,
            0xC3D2E1F0
            ]

    def __str__(self):
        return ''.join((hex(h)[2:]).rjust(8, '0') for h in self.__H)

    # Private static methods used for internal operations.
    @staticmethod
    def __ROTL(n, x, w=32):
        return ((x << n) | (x >> w - n))

    @staticmethod # length arg for the extension attack
    def __padding(stream, length):
        if length == 0:
            l = len(stream)*8
        else:
            l = length

        hl = [int((hex(l)[2:]).rjust(16, '0')[i:i+2], 16)
              for i in range(0, 16, 2)]

        l0 = (56 - l) % 64
        if not l0:
            l0 = 64

        if isinstance(stream, str):
            stream += chr(0b10000000)
            stream += chr(0)*(l0-1)
            for a in hl:
                stream += chr(a)
        elif isinstance(stream, bytes):
            stream += bytes([0b10000000])
            stream += bytes(l0-1)
            stream += bytes(hl)

        return stream

    @staticmethod
    def __prepare(stream):
        M = []
        n_blocks = len(stream) // 64

        stream = bytearray(stream)

        for i in range(n_blocks):  # 64 Bytes per Block
            m = []

            for j in range(16):  # 16 Words per Block
                n = 0
                for k in range(4):  # 4 Bytes per Word
                    n <<= 8
                    n += stream[i*64 + j*4 + k]

                m.append(n)

            M.append(m[:])

        return M


    # Private instance methods used for internal operations.
    def __process_block(self, block):
        MASK = 2**32-1

        W = block[:]
        for t in range(16, 80):
            W.append(SHA1.__ROTL(1, (W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16]))
                     & MASK)

        a, b, c, d, e = self.__H[:]

        for t in range(80):
            if t <= 19:
                K = 0x5a827999
                f = (b & c) ^ (~b & d)
            elif t <= 39:
                K = 0x6ed9eba1
                f = b ^ c ^ d
            elif t <= 59:
                K = 0x8f1bbcdc
                f = (b & c) ^ (b & d) ^ (c & d)
            else:
                K = 0xca62c1d6
                f = b ^ c ^ d

            T = ((SHA1.__ROTL(5, a) + f + e + K + W[t]) & MASK)
            e = d
            d = c
            c = SHA1.__ROTL(30, b) & MASK
            b = a
            a = T

        self.__H[0] = (a + self.__H[0]) & MASK
        self.__H[1] = (b + self.__H[1]) & MASK
        self.__H[2] = (c + self.__H[2]) & MASK
        self.__H[3] = (d + self.__H[3]) & MASK
        self.__H[4] = (e + self.__H[4]) & MASK

    # Method to break keyed MAC
    def setState(self, new_state):
        self.__H = new_state

    # Public methods for class use.
    def update(self, stream, length=0):
        stream = SHA1.__padding(stream, length)
        stream = SHA1.__prepare(stream)

        for block in stream:
            self.__process_block(block)

    def digest(self):
        pass

    def hexdigest(self):
        s = ''
        for h in self.__H:
            s += (hex(h)[2:]).rjust(8, '0')
        return s


def compute_mac(key, message, sha1):
	sha1.update(key + message)
	return sha1.hexdigest()

def compute_padding(stream):
    l = len(stream)  # Bytes
    hl = [int((hex(l*8)[2:]).rjust(16, '0')[i:i+2], 16)
          for i in range(0, 16, 2)]

    l0 = (56 - l) % 64
    if not l0:
        l0 = 64

    if isinstance(stream, str):
        stream += chr(0b10000000)
        stream += chr(0)*(l0-1)
        for a in hl:
            stream += chr(a)
    elif isinstance(stream, bytes):
        stream += bytes([0b10000000])
        stream += bytes(l0-1)
        stream += bytes(hl)

    return stream

def generate_state(int_message):
    a = int_message >> 128
    b = (int_message >> 96) & 0xffffffff
    c = (int_message >> 64) & 0xffffffff
    d = (int_message >> 32) & 0xffffffff
    e = int_message & 0xffffffff

    return [a, b, c, d, e]


def forge_message(message, digest, key_len, new_message, sha1):
    forged_message = compute_padding(b'A'*key_len + message) + new_message

    forged_message = forged_message[key_len:]

    int_message = int(digest, 16)
    state = generate_state(int_message)

    sha1.setState(state)
    sha1.update(new_message, (key_len + len(forged_message)) * 8)

    return forged_message, sha1.hexdigest()


if __name__ == "__main__":
    sha1 = SHA1()
    key = os.urandom(16)

    original_message = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
    new_message = b";admin=true"

    mac = compute_mac(key, original_message, sha1)
    print("Original message mac:", mac)

    forged_message, forged_mac = forge_message(original_message, mac, 16, new_message, sha1)
    
    print("Forged mac?", mac == forged_mac)

    print("Forged message:", forged_message)
    print("Forged mac", forged_mac)
