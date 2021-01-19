#!/usr/bin/python3

from Crypto.Util.number import *
from Crypto.Cipher import AES
from hashlib import sha256
from os import urandom
from base64 import *
from flag import FLAG

FLAG += (16 - (len(FLAG) % 16))*b'\x00'


class Rng:
  def __init__(self, seed):
    self.seed = seed
    self.generated = b""
    self.num = 0

  def more_bytes(self):
    self.generated += sha256(self.seed).digest()
    self.seed = long_to_bytes(bytes_to_long(self.seed) + 1, 32)
    self.num += 256


  def getbits(self, num=64):
    while (self.num < num):
      self.more_bytes()
    x = bytes_to_long(self.generated)
    self.num -= num
    self.generated = b""
    if self.num > 0:
      self.generated = long_to_bytes(x >> num, self.num // 8)
    return x & ((1 << num) - 1)


class DiffieHellman:
  def gen_prime(self):
    prime = self.rng.getbits(512)
    _iter = 0
    while not isPrime(prime):
      _iter += 1
      prime = self.rng.getbits(512)
    #print("Generated after", _iter, "iterations")
    return prime,_iter

  def __init__(self, seed, prime=None):
    self.rng = Rng(seed)
    self._iter=0
    if prime is None:
      prime,_iter = self.gen_prime()
      self._iter=_iter

    self.prime = prime
    self.my_secret = self.rng.getbits()
    self.my_number = pow(5, self.my_secret, prime)
    self.shared = 1337
    #rint('Complete one loop init work!')

  def send_iter(self):
    return self._iter

  def set_other(self, x):
    self.shared ^= pow(x, self.my_secret, self.prime)

def pad32(x):
  return (b"\x00"*32+x)[-32:]

def xor32(a, b):
  return bytes(x^y for x, y in zip(pad32(a), pad32(b)))

def bit_flip(x):
  print("bit-flip str:")
  flip_str = b64decode(input().strip())
  return xor32(flip_str, x)

if __name__=='__main__':
    alice_seed = urandom(16)
    
    while 1:
      alice = DiffieHellman(bit_flip(alice_seed))
      bob = DiffieHellman(urandom(16), alice.prime)
    
      alice.set_other(bob.my_number)
      print("bob number", bob.my_number)
      bob.set_other(alice.my_number)
      iv = urandom(16)
      print(b64encode(iv).decode())
      cipher = AES.new(long_to_bytes(alice.shared, 16)[:16], AES.MODE_CBC, IV=iv)
      enc_flag = cipher.encrypt(FLAG)
      print(b64encode(enc_flag).decode())
