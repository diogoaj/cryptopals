"""ECB cut-and-paste - https://cryptopals.com/sets/2/challenges/13

Write a k=v parsing routine, as if for a structured cookie. The routine should take:
    foo=bar&baz=qux&zap=zazzle
... and produce:
    {
      foo: 'bar',
      baz: 'qux',
      zap: 'zazzle'
    }
 (you know, the object; I don't care if you convert it to JSON).

Now write a function that encodes a user profile in that format, given an email address.
You should have something like:
    profile_for("foo@bar.com")

... and it should produce:
    {
      email: 'foo@bar.com',
      uid: 10,
      role: 'user'
    }

... encoded as:
    email=foo@bar.com&uid=10&role=user

Your "profile_for" function should not allow encoding metacharacters (& and =).
Eat them, quote them, whatever you want to do, but don't let people set their email address to
"foo@bar.com&role=admin".

Now, two more easy functions. Generate a random AES key, then:
    A. Encrypt the encoded user profile under the key; "provide" that to the "attacker".
    B. Decrypt the encoded user profile and parse it.

Using only the user input to profile_for() (as an oracle to generate "valid" ciphertexts)
and the ciphertexts themselves, make a role=admin profile.
"""

import os
import random
from set2.challenge10.solve import *

def parse(string):
    object = {}
    parts = string.split("&")

    for s in parts:
        try:
            s_parts = s.split("=")
            object[s_parts[0]] = s_parts[1]
        except:
            continue

    return object

def profile_for(email):
    encoded_string = ""
    if "&" in email or "=" in email:
        raise ValueError("Wrong character in email string!")

    encoded_string += "email=" + email + "&uid=" + str(random.randint(1,100)) + "&role=user"

    encrypted_profile = encrypt_profile(encoded_string, aes_key)
    decrypted_profile = decrypt_profile(encrypted_profile, aes_key)

    return encrypted_profile, decrypted_profile

def gen_key(block_size):
    return os.urandom(16)

def encrypt_profile(plaintext, key):
    return encrypt_aes_ecb(plaintext.encode(), key, 16)

def decrypt_profile(ciphertext, key):
    plaintext = decrypt_aes_ecb(ciphertext, key)
    return parse(plaintext.decode())


if __name__ == "__main__":
    # Test
    aes_key = gen_key(16)
    #encrypted_profile, profile = profile_for("foo@bar.com")
    #print(profile)

    # Goal: Creating user with role: admin
    # Gathering multiple aes ciphers

    # email=AAAAAAAAAA
    block1, profile = profile_for("A"*10)
    block1 = block1[0:16]

    # admin&uid=3&role
    block2, profile = profile_for("A"*10 + "admin")
    block2 = block2[16:32]

    # AAA&uid=39&role=
    block3, profile = profile_for("A"*13)
    block3 = block3[16:32]

    # block1 + block3 + block2 -> admin
    cipher_list = [block1, block3, block2]
    admin_ciphertext = b"".join(cipher_list)
    print(decrypt_profile(admin_ciphertext, aes_key))

    # Done [Example]
    #{'email': 'AAAAAAAAAAAAA', 'role': 'admin', 'uid': '62'}