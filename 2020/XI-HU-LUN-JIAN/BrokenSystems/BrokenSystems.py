from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from secret import flag
import os
rsa = RSA.generate(2048)
public_key = rsa.publickey().exportKey()
f=open("public.key","w")
f.write(public_key.decode())
f.close()

rsakey=RSA.importKey(open("public.key","r").read())
rsa = PKCS1_OAEP.new(rsakey)
msg=rsa.encrypt(flag.encode())
f=open("message","wb")
f.write(msg)
f.close()
