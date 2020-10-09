#!/usr/bin/env python
# -*- coding:utf-8 -*-
from socketserver import BaseRequestHandler, TCPServer, ThreadingTCPServer
from threading import Thread
import os
import random
import string
from hashlib import sha256
from DragonKing import dragonKing
from secret import flag
from sm4_encryption import *
from sm4_decryption import *
BUFSIZE = 1024
banner='''
__        __   _                            _____      
\ \      / /__| | ___ ___  _ __ ___   ___  |_   _|__   
 \ \ /\ / / _ \ |/ __/ _ \| '_ ` _ \ / _ \   | |/ _ \  
  \ V  V /  __/ | (_| (_) | | | | | |  __/   | | (_) |
   \_/\_/ \___|_|\___\___/|_| |_| |_|\___|   |_|\___/  
                                                            

__        __        _     _          _               
\ \      / /__  ___| |_  | |    __ _| | _____        
 \ \ /\ / / _ \/ __| __| | |   / _` | |/ / _ \       
  \ V  V /  __/\__ \ |_  | |__| (_| |   <  __/       
   \_/\_/ \___||___/\__| |_____\__,_|_|\_\___|       
                                              
                                              
  ____      _                                        _ _         
 / ___|   _| |__   ___ _ __ ___  ___  ___ _   _ _ __(_) |_ _   _ 
| |  | | | | '_ \ / _ \ '__/ __|/ _ \/ __| | | | '__| | __| | | |
| |__| |_| | |_) |  __/ |  \__ \  __/ (__| |_| | |  | | |_| |_| |
 \____\__, |_.__/ \___|_|  |___/\___|\___|\__,_|_|  |_|\__|\__, |
      |___/                                                |___/ 


  ____             __                                     
 / ___|___  _ __  / _| ___ _ __ ___ _ __   ___ ___        
| |   / _ \| '_ \| |_ / _ \ '__/ _ \ '_ \ / __/ _ \       
| |__| (_) | | | |  _|  __/ | |  __/ | | | (_|  __/       
 \____\___/|_| |_|_|  \___|_|  \___|_| |_|\___\___|              

'''
class Task(BaseRequestHandler):
    def hash(self,proof):
        return sha256(proof.encode()).hexdigest()
    def valid_proof(self,xxxx,last_proof,last_hash):
        guess = xxxx+last_proof[4:]
        guess_hash = sha256(guess.encode()).hexdigest()
        return guess_hash==last_hash
    def proof_of_work(self):
        random.seed(os.urandom(8))
        last_proof = ''.join([random.choice(string.ascii_letters+string.digits) for _ in range(20)])
        last_hash = self.hash(last_proof)
        self.request.send((("sha256(XXXX+%s) == %s\n" % (last_proof[4:],last_hash))).encode())
        self.request.send('Give me XXXX:'.encode())
        xxxx=self.request.recv(10).decode().strip("\n")
        if len(xxxx) != 4 or not self.valid_proof(xxxx,last_proof,last_hash): 
            return False
        return True
    def DragonKing(self,rand):
        self.request.send(dragonKing[rand%4].encode("utf-8"))
    def recvline(self,BUFSIZE):
        return self.request.recv(BUFSIZE).decode().split("\n")[0].strip()
    def sendflag(self):
        sm = sm4_encryption(self.key)
        sm.__key__expand__()
        en_flag=sm.encrypt_cbc(flag,self.key)
        self.request.send("This is what you want:".encode()+en_flag.encode())

    def encryption(self,message):
        sm = sm4_encryption(self.key)
        sm.__key__expand__()
        en_message=sm.encrypt_cbc(message,self.key)
        self.c=en_message
        return en_message
    def decryption(self,iv):
        if self.c =="":
            return "Please encrypt first".encode()
        sm = sm4_decryption(self.key)
        sm.__key__expand__()
        message=sm.decrypt_cbc(self.c,iv)
        return message
        
    def handle(self):
        self.key=os.urandom(16)
        self.c=""
        menu = '''
1. Dragon King
2. encryption
3. decryption
4. getflag
5. exit
'''
        if not self.proof_of_work():
       		return
        self.request.send(banner.encode())
        try:
            while True:
                self.request.send(menu.encode())
                choice=self.recvline(BUFSIZE)
                if choice=="1":
                    rand=random.randint(0,10)
                    self.DragonKing(rand)
                    continue
                if choice=="2":
                    self.request.send("What message do you want to encrypt:".encode())
                    message=self.recvline(BUFSIZE)
                    en_message=self.encryption(message)
                    self.request.send("My encrypted message is absolutely secure, maybe~:".encode()+en_message.encode())
                    continue
                if choice=="3":
                    self.request.send("please input iv to decrypt:".encode())
                    iv=self.recvline(BUFSIZE)
                    iv=long_to_bytes(eval('0x'+iv))
                    message=self.decryption(iv)
                    self.request.send("Is this your message?~:".encode()+hex(bytes_to_long(message))[2:].encode())
                    continue
                if choice=="4":
                    self.sendflag()
                    continue
                if choice=="5":
                    self.request.send("Bye!".encode())
                    return
        except:
            return False

if __name__ == '__main__':
    HOST, PORT = "0.0.0.0", 9999
    server = ThreadingTCPServer((HOST, PORT), Task)
    server.allow_reuse_address = True
    server.serve_forever()
