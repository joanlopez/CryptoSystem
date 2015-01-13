#!/usr/bin/env python
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from ecdsa import SigningKey
from ecdsa import VerifyingKey
from ecdsa import BadSignatureError
from ecdsa import NIST256p
from ecdsa import NIST384p
from ecdsa import NIST521p
from os import system
from os import path
from os import urandom
from io import StringIO
import binascii
import hashlib

# Initializations & Definitions #
curves = {
	"secp256":NIST256p,
	"secp384":NIST384p,
	"secp521":NIST521p
}

#Function that encrypts a file with AES 128 CBC & PKCS7
def xifrar():
	if len(inputs) != 3:
		print("\n")
		print("No has posat els parametres correctament\n")
	else:
		#Input to encrypt
		if not path.isfile(inputs[1]):
			print("El fitxer "+inputs[1]+" no existeix\n")
			return
		file_i = open(inputs[1],'rb')

		#Output encrypted
		file_o = open(inputs[1]+'.enc','wb')

		#Input key
		if not path.isfile(inputs[2]):
			print("El fitxer "+inputs[2]+" no existeix\n")
			return
		file_key = open(inputs[2],'rb')
		
		#Initializations
		iv = Random.new().read(AES.block_size)
		file_o.write(iv)
		cipher = AES.new(file_key.read(),AES.MODE_CBC,iv) 
		chunksize = 1024 #Multiple of BS

		#Crypting
		while True:
			chunk = file_i.read(chunksize)
			#End of file
			if len(chunk) == 0:
				break
			#Chunk multiple of BS
			elif len(chunk) == chunksize:
				file_o.write(cipher.encrypt(chunk))
			#Chunk no multiple of BS, must add padding PKCS7
			else:	
				padding_bytes = 16 - len(chunk) % AES.block_size
				padding = StringIO()
				for _ in range(padding_bytes):
					padding.write('%02x' % padding_bytes)
				padded_chunk = chunk + binascii.unhexlify(padding.getvalue())
				file_o.write(cipher.encrypt(padded_chunk))

		file_i.close()
		file_key.close()
		file_o.close()

		print("Arxiu xifrat: "+file_o.name+"\n")

#Function that decrypts a file encrypted with AES 128 CBC & PKCS7
def desxifrar():
	if len(inputs) != 3:
		print("\n")
		print("No has posat els parametres correctament\n")
	else:
		#Input to decrypt
		if not path.isfile(inputs[1]):
			print("El fitxer "+inputs[1]+" no existeix\n")
			return
		file_i = open(inputs[1],'rb')
		
		#Output decrypted
		file_o = open(inputs[1][:-4]+".dec",'wb')

		#Input key
		if not path.isfile(inputs[1]):
			print("El fitxer "+inputs[1]+" no existeix\n")
			return
		file_key = open(inputs[2],'rb')
		
		#Initializations
		data = file_i.read()
		iv = data[:16]
		data = data[16:]
		cipher = AES.new(file_key.read(),AES.MODE_CBC,iv)
		chunksize = 1024

		#Decrypting
		while True:
			chunk = data[:chunksize]
			data = data[chunksize:]
			decrypted_chunk = cipher.decrypt(chunk)
			#End of file
			if len(data) == 0:
				#Remove padding
				padding_length = decrypted_chunk[-1]
				decrypted_chunk = decrypted_chunk[:-padding_length]
				file_o.write(decrypted_chunk)
				break
			file_o.write(decrypted_chunk)

		file_i.close()
		file_o.close()
		file_key.close()

		print("Arxiu desxifrat: "+file_o.name+"\n")

#Function that generates RSA keys (private & public pems)
def generarRSAkeys():
	if len(inputs) != 2:
		print("\n")
		print("No has posat els parametres correctament\n")
	else:
		#Generating keys
		keys = RSA.generate(int(inputs[1]))

		#Saving public key
		file_public = open("RSA_pub_key.pem","wb")
		file_public.write(keys.publickey().exportKey("PEM"))
		file_public.close()

		#Saving private key
		file_private = open("RSA_priv_key.pem","wb")
		file_private.write(keys.exportKey("PEM"))
		file_private.close()

		print("Claus exportades:\n")
		print("\t"+file_public.name+"\n")
		print("\t"+file_private.name+"\n")

#Function that generates ECC keys (private & public pems)
def generarECCkeys():
	if len(inputs) != 2:
		print("\n")
		print("No has posat els parametres correctament\n")
	else:
		#Test available curve
		if inputs[1] not in curves:
			print("Corba no disponible, prova amb: secp256 secp384 o secp521\n")	
			return

		#Generating sign key
		sk = SigningKey.generate(curve=curves[inputs[1]])
		open("EC_priv_key.pem","wb").write(sk.to_pem())

		#Generating verify key
		vk = sk.get_verifying_key()
		open("EC_pub_key.pem","wb").write(vk.to_pem())

		print("Claus exportades:\n")
		print("\tEC_pub_key.pem\n")
		print("\tEC_priv_key.pem\n")

#Function that signs a file
def signarFitxer():
	if len(inputs) != 3:
		print("\n")
		print("No has posat els parametres correctament\n")
	else:
		#Input file to sign
		if not path.isfile(inputs[1]):
			print("El fitxer "+inputs[1]+" no existeix\n")
			return
		file_i = open(inputs[1],'rb')

		#Output file signed
		file_o = open(inputs[1]+'.signature','wb') 

		#Input key file to sign
		if not path.isfile(inputs[2]):
			print("El fitxer "+inputs[2]+" no existeix\n")
			return
		file_key = open(inputs[2],'rb') 

		#Reading key from file & initializations
		sk = SigningKey.from_pem(file_key.read())
		data = file_i.read()
		
		#Signing & writing output
		file_o.write(sk.sign(data,hashfunc=hashlib.sha256))
		
		file_i.close()
		file_o.close()
		file_key.close()

		print("Fitxer signat")
		print("\t"+inputs[1]+".signature\n")

#Function that verifies a sign
def verificarSigna():
	if len(inputs) != 4:
		print("\n")
		print("No has posat els parametres correctament\n")
	else:
		#Input file to sign
		if not path.isfile(inputs[1]):
			print("El fitxer "+inputs[1]+" no existeix\n")
			return
		file_i = open(inputs[1],'rb') #Input file to sign

		#Input signed file to verify the signature
		if not path.isfile(inputs[2]):
			print("El fitxer "+inputs[2]+" no existeix\n")
			return
		file_i_s = open(inputs[2],'rb')

		#Input key file to verify the signature
		if not path.isfile(inputs[3]):
			print("El fitxer "+inputs[3]+" no existeix\n")
			return
		file_key = open(inputs[3],'rb')
		
		#Reading key from file & initializations
		vk = VerifyingKey.from_pem(file_key.read())
		data = file_i.read()
		sig = file_i_s.read()

		try:
			vk.verify(sig,data,hashfunc=hashlib.sha256)
			print("Signa verificada correctament\n")
		except BadSignatureError:
			print("Signa no verificada\n")

		file_i.close()
		file_i_s.close()
		file_key.close()

#Function that makes all process to send a message
def enviarMissatge():
	if not (len(inputs) == 4) and not (len(inputs) == 5):
		print("\n")
		print("No has posat els parametres correctament\n")
	else:
		#Input message to send
		if not path.isfile(inputs[1]):
			print("El fitxer "+inputs[1]+" no existeix\n")
			return
		file_m = open(inputs[1],'rb')

		#Input key for signing
		if not path.isfile(inputs[2]):
			print("El fitxer "+inputs[2]+" no existeix\n")
			return	
		file_sign_key = open(inputs[2],'rb')

		#Input key for encrypt
		if not path.isfile(inputs[3]):
			print("El fitxer "+inputs[3]+" no existeix\n")
			return	
		file_pub_key = open(inputs[3],'rb')

		#Output message to send
		file_o = open(inputs[1]+'.bin','wb')
		
		#1. Sign M with private EC key and concatenate M||F
		sk = SigningKey.from_pem(file_sign_key.read())
		message = file_m.read()
		msg_sign = message+sk.sign(message,hashfunc=hashlib.sha256)
		
		#2. Generate a KS and determine KSE (info to generate KS)
		aes_key = urandom(AES.block_size)
		
		#3. Encrypt M||F with KS (PK algorithm) getting E(M||F)
		iv = Random.new().read(AES.block_size)
		e_msg_sign = iv
		aes_cipher = AES.new(aes_key,AES.MODE_CBC,iv)
		chunksize = 1024 #Multiple of BS
		while True:
			chunk = msg_sign[:chunksize]
			msg_sign = msg_sign[chunksize:]
			if len(chunk) == 0:
				break
			elif len(chunk) == chunksize:
				e_msg_sign += aes_cipher.encrypt(chunk)
			else:	
				padding_bytes = 16 - len(chunk) % AES.block_size
				padding = StringIO()
				for _ in range(padding_bytes):
					padding.write('%02x' % padding_bytes)
				padded_chunk = chunk + binascii.unhexlify(padding.getvalue())
				e_msg_sign += aes_cipher.encrypt(padded_chunk)
		
		#4. Concatenate KSE with E(M||F) getting KSE||E(M||F)
		rsa_key = RSA.importKey(file_pub_key.read())
		rsa_cipher = PKCS1_OAEP.new(rsa_key)
		e_aes_key = rsa_cipher.encrypt(aes_key)

		#Final output message ready to be sent
		file_o.write(e_aes_key+e_msg_sign)

		file_m.close()
		file_sign_key.close()
		file_pub_key.close()
		file_o.close()

		print("Missatge enviat correctament\n")

#Function that makes all process to receive a message
def rebreMissatge():
	if not (len(inputs) == 4) and not (len(inputs) == 5):
		print("\n")
		print("No has posat els parametres correctament\n")
	else:
		#Input message to receive
		if not path.isfile(inputs[1]):
			print("El fitxer "+inputs[1]+" no existeix\n")
			return
		file_c = open(inputs[1],'rb')

		#Input key for verifying sign
		if not path.isfile(inputs[2]):
			print("El fitxer "+inputs[2]+" no existeix\n")
			return	
		file_signature = open(inputs[2],'rb')

		#Input key for decrypt
		if not path.isfile(inputs[3]):
			print("El fitxer "+inputs[3]+" no existeix\n")
			return	
		file_priv_key = open(inputs[3],'rb')

		#Output message received
		file_m = open(inputs[1]+'.message','wb')

		#Output message received
		file_s = open(inputs[1]+'.signature','wb')

		#1. Split KSE and E(M||F) from the input
		data = file_c.read()
		e_aes_key = data[:256]
		e_msg_sign = data[256:]
		
		#2. Generate KS with KSE (info to generate KS)
		rsa_key = RSA.importKey(file_priv_key.read())
		rsa_cipher = PKCS1_OAEP.new(rsa_key)
		aes_key = rsa_cipher.decrypt(e_aes_key)

		#3. Decrypt E(M||F) with KS getting M||F
		iv = e_msg_sign[:16]
		e_msg_sign = e_msg_sign[16:]
		aes_cipher = AES.new(aes_key,AES.MODE_CBC,iv)
		chunksize = 1024
		msg_sign = b''
		while True:
			chunk = e_msg_sign[:chunksize]
			e_msg_sign = e_msg_sign[chunksize:]
			decrypted_chunk = aes_cipher.decrypt(chunk)
			if len(e_msg_sign) == 0:
				padding_length = decrypted_chunk[-1]
				decrypted_chunk = decrypted_chunk[:-padding_length]
				msg_sign += decrypted_chunk
				break
			msg_sign += decrypted_chunk

		#4. Split M and F and verify it
		message = msg_sign[:-64]
		signature = msg_sign[-64:]

		vk = VerifyingKey.from_pem(file_signature.read())
		try:
			vk.verify(signature,message,hashfunc=hashlib.sha256)
			file_m.write(message)
			file_s.write(signature)
			print("Firma verificada: missatge rebut correctament\n")
		except BadSignatureError:
			print("Firma no verificada: Missatge NO rebut\n")

		file_c.close()
		file_signature.close()
		file_priv_key.close()
		file_m.close()
		file_s.close()

		print("Missatge rebut correctament\n")

opcions = {
	"Xifrar":xifrar,
	"Desxifrar":desxifrar,
	"RSAkey":generarRSAkeys,
	"ECCkey":generarECCkeys,
	"Signar":signarFitxer,
	"Verificar":verificarSigna,
	"enviarMissatge":enviarMissatge,
	"rebreMissatge":rebreMissatge
}

# Main Program #
print("\n")
print("Benvingut al Sistema Criptografic d'en Joan Lopez\n")
print("Escriu una de les opcions:\n\n")
print("· Xifrar fitxer clauXifrat\n")
print("· Desxifrar fitxer.enc clauXifrat\n")
print("· RSAkey n\n")
print("· ECCkey corba\n")
print("· Signar fitxer clauSignatura\n")
print("· Verificar fitxer fitxer.signature clauVerificacio\n")
print("· enviarMissatge M clauDeFirma clauPublica clauPrivada*\n")
print("· rebreMissatge C clauVerificacioDeFirma clauPrivada clauPublica*\n")

user_input = input()
inputs = user_input.split(" ")
if inputs[0] in opcions:
	opcions[inputs[0]]()
else:
	print("\n")
	print("Has escollit una opcio no reconeguda\n")

