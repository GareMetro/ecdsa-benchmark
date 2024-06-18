from Crypto.Random import random
from Crypto.Hash import SHA
from Crypto.PublicKey import DSA
from Crypto.Math.Numbers import Integer

from ecdsa_key_recovery import DsaSignature, EcDsaSignature, SignatureParameter, ecdsa, bignum_to_hex, bytes_fromhex

import ecdsa
from ecdsa import SigningKey
import time
import string

from ScriptBaseDeDonnes import ScriptBd

global_nonce_counter = 0

def sigencode(r, s, order):
	return SignatureParameter(r, s)

def curve_to_length(curve):
	match curve:
		case ecdsa.SECP256k1:
			return 256
		case ecdsa.NIST256p:
			return 256
		case ecdsa.BRAINPOOLP384t1:
			return 384
		case ecdsa.NIST384p:
			return 384
		case ecdsa.NIST192p:
			return 192
		case ecdsa.NIST224p:
			return 224
		case ecdsa.NIST521p:
			return 521

#Signe un message DSA 
def signMessageDSA(privkey, msg, k):

	# generate msg hash
	# sign the messages using privkey
	h = SHA.new(msg).digest()
	r, s = privkey._sign(Integer.from_bytes(h), k)
	return h, (r, s), privkey.publickey()


#Effectue un essaie de récupération de clef privée (devrait toujours réussir)
def single_test_DSA(msgA, msgB, secret_key, k, key_size, seed):
	# sign two messages using the same k
	samples = (signMessageDSA(secret_key, msgA.encode("utf-8"), k), 
	signMessageDSA(secret_key, msgB.encode("utf-8"), k))
	signatures = [DsaSignature(sig, h, pubkey) for h, sig, pubkey in samples]

	two_sigs = []
	for sig in signatures:
		two_sigs.append(sig)
		if not len(two_sigs) == 2:
			continue
		sample = two_sigs.pop(0)
		time_start = time.perf_counter()
		sample.recover_nonce_reuse(two_sigs[0])
		time_end = time.perf_counter()
		duration = time_end - time_start
		if sample.x is not None and sample.privkey == secret_key:
			return ("DSA", len(msgA), key_size, seed, True, duration)
		else:
			return ("DSA", len(msgA), key_size, seed, False, duration)

#Teste une même paire de message avec différents nonces d'une taille donnée
def test_nonces_DSA(msgA, msgB, secret_key, key_size, test_number):
	global global_nonce_counter

	success_number = 0
	duration_sum = 0
	res = []
	for i in range(test_number):
		k = random.StrongRandom().randint(1, secret_key.q - 1)
		global_nonce_counter += 1
		test = single_test_DSA(msgA, msgB, secret_key, k, key_size, global_nonce_counter)
		res.append(test)
		if test[4]:
			success_number += 1
			duration_sum += test[5]
	print("Success rate : " + str(success_number/test_number))
	print("Avg recovery duration : " + str(float(duration_sum)/success_number) + "s")
	return res

# Génération d'une chaîne de caractères aléatoires de taille size
def randomString(size, chars = string.ascii_uppercase + string.ascii_lowercase + string.digits):
	return ''.join(random.choice(chars) for _ in range(size))

#Teste un même nonce avec différentes paires de messages d'une taille donnée
def test_msg_size_DSA(secret_key, k, key_size, msg_size, test_number):
	success_number = 0
	duration_sum = 0
	res = []
	for i in range(test_number):
		msgA = randomString(msg_size)
		msgB = randomString(msg_size)
		test = single_test_DSA(msgA, msgB, secret_key, k, key_size, global_nonce_counter)
		res.append(test)
		if test[4]:
			success_number += 1
			duration_sum += test[5]
	print("Success rate : " + str(success_number/test_number))
	print("Avg recovery duration : " + str(float(duration_sum)/success_number) + "s")
	return res


def single_test_ECDSA(msgA, msgB, secret_key, k, curve, seed):
	hashA = SHA.new(msgA.encode("utf-8")).digest()
	hashB = SHA.new(msgB.encode("utf-8")).digest()
	sigA = secret_key.sign_digest(hashA, sigencode = sigencode, k = k)
	sigB = secret_key.sign_digest(hashB, sigencode = sigencode, k = k)

	sampleA = EcDsaSignature(sigA, hashA, secret_key.verifying_key.pubkey, curve)
	sampleB = EcDsaSignature(sigB, hashB, secret_key.verifying_key.pubkey, curve)
	
	time_start = time.perf_counter()
	sampleA.recover_nonce_reuse(sampleB)
	time_end = time.perf_counter()
	duration = time_end - time_start
	if sampleA.x is not None and sampleA.privkey == secret_key.privkey:
		return("ECDSA", len(msgA), curve_to_length(curve), seed, True, duration)
	else:
		return("ECDSA", len(msgA), curve_to_length(curve), seed, False, duration)

def test_nonces_ECDSA(msgA, msgB, secret_key, curve, test_number):
	global global_nonce_counter

	success_number = 0
	duration_sum = 0
	res = []
	order = secret_key.verifying_key.pubkey.generator.order()
	for i in range(test_number):
		k = random.StrongRandom().randint(1, order - 1)
		global_nonce_counter += 1
		test = single_test_ECDSA(msgA, msgB, secret_key, k, curve, global_nonce_counter)
		res.append(test)
		if test[4]:
			success_number += 1
			duration_sum += test[5]
	print("Success rate : " + str(success_number/test_number))
	print("Avg recovery duration : " + str(float(duration_sum)/success_number) + "s")
	return res

def test_msg_size_ECDSA(secret_key, k, curve, msg_size, test_number):
	success_number = 0
	duration_sum = 0
	res = []
	for i in range(test_number):
		msgA = randomString(msg_size)
		msgB = randomString(msg_size)
		test = single_test_ECDSA(msgA, msgB, secret_key, k, curve, global_nonce_counter)
		res.append(test)
		if test[4]:
			success_number += 1
			duration_sum += test[5]
	print("Success rate : " + str(success_number/test_number))
	print("Avg recovery duration : " + str(float(duration_sum)/success_number) + "s")
	return res


ScriptBd.clearTable()
ScriptBd.createTable()
test_res = []
#Test de différents nonces taille 1024
test_res.extend(test_nonces_DSA("Secret Message 1", "Another very secret message", DSA.generate(1024), 1024, 100))
#Test de différents nonces taille 2048
test_res.extend(test_nonces_DSA("Secret Message 1", "Another very secret message", DSA.generate(2048), 2048, 100))
#Test de différents nonces taille 3072
test_res.extend(test_nonces_DSA("Secret Message 1", "Another very secret message", DSA.generate(3072), 3072, 100))
#Tests de différents messages taille 128
key = DSA.generate(1024)
k = random.StrongRandom().randint(1, key.q - 1)
global_nonce_counter += 1
test_res.extend(test_msg_size_DSA(key, k, 1024, 128, 100))
#Tests de différents messages taille 256
test_res.extend(test_msg_size_DSA(key, k, 1024, 256, 100))
#Tests de différents messages taille 512
test_res.extend(test_msg_size_DSA(key, k, 1024, 512, 100))
#Tests de différents messages taille 1024
test_res.extend(test_msg_size_DSA(key, k, 1024, 1024, 100))

test_res.extend(test_nonces_ECDSA("Secret Message 1", "Another very secret message", ecdsa.keys.SigningKey.generate(ecdsa.NIST384p), ecdsa.NIST384p, 100))
test_res.extend(test_nonces_ECDSA("Secret Message 1", "Another very secret message", ecdsa.keys.SigningKey.generate(ecdsa.NIST256p), ecdsa.NIST256p, 100))
test_res.extend(test_nonces_ECDSA("Secret Message 1", "Another very secret message", ecdsa.keys.SigningKey.generate(ecdsa.NIST192p), ecdsa.NIST192p, 100))
test_res.extend(test_nonces_ECDSA("Secret Message 1", "Another very secret message", ecdsa.keys.SigningKey.generate(ecdsa.NIST224p), ecdsa.NIST224p, 100))
test_res.extend(test_nonces_ECDSA("Secret Message 1", "Another very secret message", ecdsa.keys.SigningKey.generate(ecdsa.NIST521p), ecdsa.NIST521p, 100))
secret_key = ecdsa.keys.SigningKey.generate(ecdsa.BRAINPOOLP384t1)
order = secret_key.verifying_key.pubkey.generator.order()
k = random.StrongRandom().randint(1, order - 1)
test_res.extend(test_msg_size_ECDSA(secret_key, k, ecdsa.BRAINPOOLP384t1, 128, 100))
test_res.extend(test_msg_size_ECDSA(secret_key, k, ecdsa.BRAINPOOLP384t1, 256, 100))
test_res.extend(test_msg_size_ECDSA(secret_key, k, ecdsa.BRAINPOOLP384t1, 512, 100))
test_res.extend(test_msg_size_ECDSA(secret_key, k, ecdsa.BRAINPOOLP384t1, 1024, 100))
ScriptBd.addManyTests(test_res)