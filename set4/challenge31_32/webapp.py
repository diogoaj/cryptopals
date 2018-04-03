from flask import Flask
from flask import request
from flask import abort
import hashlib
import time

secrey_key = b'hmac:key:so:secret'

def xor(s1, s2):
	return str.encode(''.join([chr(a ^ b) for a,b in zip(s1, s2)]))


# From wikipedia.org/wiki/HMAC
def hmac(key, message):
	sha1 = hashlib.sha1()

	if len(key) > 64:
		sha1.update(key)
		key = sha1.digest()

	if len(key) < 64:
		key += b'\x00'*(64 - len(key))

	o_key_pad = xor(key, b'\x5c' * 64)
	i_key_pad = xor(key, b'\x36' * 64)

	sha1 = hashlib.sha1() # clear state
	sha1.update(i_key_pad + message)
	m = sha1.digest()

	sha1 = hashlib.sha1() # clear state
	sha1.update(o_key_pad + m)
	return sha1.hexdigest()


def check_signature(filename, signature):
	f = open(filename, "r")
	content = str(f.read()).encode()
	f.close()

	return insecure_compare(hmac(secrey_key, content), signature)


def insecure_compare(hmac, signature):
	for i in range(len(hmac)):
		if hmac[i] != signature[i]:
			return False

		time.sleep(0.005) # challenge 31 time = 0.05

	return True



app = Flask(__name__)

@app.route("/")
def hello():
	return ("Sample application to solve Cryptopals Challenge 31")


@app.route("/test")
def test():
	args = request.args
	if 'filename' in args and 'signature' in args:
		if check_signature(args['filename'], args['signature']):
			return ("OK")
	abort(500)