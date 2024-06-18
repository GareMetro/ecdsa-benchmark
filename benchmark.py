from Crypto.Random import random
from Crypto.Hash import SHA
from Crypto.PublicKey import DSA
from Crypto.Math.Numbers import Integer

from ecdsa_key_recovery import DsaSignature, EcDsaSignature, ecdsa, bignum_to_hex, bytes_fromhex

import time
import string

from ScriptBaseDeDonnes import ScriptBd

global_nonce_counter = 0

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
		time_start = time.time()
		sample.recover_nonce_reuse(two_sigs[0])
		duration = time.time() - time_start
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

ScriptBd.clearTable()
ScriptBd.createTable()
#Test de différents nonces taille 1024
test_nonces_res1 = test_nonces_DSA("Secret Message 1", "Another very secret message", DSA.generate(1024), 100, 1024) 
#Test de différents nonces taille 2048
test_nonces_res2 = test_nonces_DSA("Secret Message 1", "Another very secret message", DSA.generate(2048), 10, 2048)
#Tests de différents messages taille 128
key = DSA.generate(1024)
k = random.StrongRandom().randint(1, key.q - 1)
global_nonce_counter += 1
test_size1 = test_msg_size_DSA(key, k, 1024, 128, 100)
#Tests de différents messages taille 256
test_size2 = test_msg_size_DSA(key, k, 1024, 256, 100)
ScriptBd.addManyTests(test_nonces_res1 + test_nonces_res2 test_size1 + test_size2)