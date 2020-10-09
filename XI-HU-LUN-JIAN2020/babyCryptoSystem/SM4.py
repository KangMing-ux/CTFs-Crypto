from os import urandom
import hashlib
import binascii
from Crypto.Util.number import *

def pad(msg):
    return msg+hex((32-len(msg)%32)//2)[2:].zfill(2)*((32-len(msg)%32)//2)

class Sm4:
      CK = [0x00070F15,0x1c232a31,0x383f464d,0x545b6269,
            0x70777e85,0x8c939aa1,0xa8afb6bd,0xc4cbd2d9,
            0xe0e7eef5,0xfc030a11,0x181f262d,0x343b4249,
            0x50575e65,0x6c737a81,0x888f969d,0xa4abb2b9,
            0xc0c7ced5,0xdce3eaf1,0xf8ff060d,0x141b2229,
            0x30373e45,0x4c535a61,0x686f767d,0x848b9299,
            0xa0a7aeb5,0xbcc3cad1,0xd8dfe6ed,0xf4fb0209,
            0x10171e25,0x2c333a41,0x484f565d,0x646b7279]

      FK = [0xa3b1bac6,0x56aa3350,0x677d9197,0xb27022dc]

      SboxTable = [
      0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
      0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
      0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
      0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
      0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
      0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
      0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
      0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
      0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
      0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
      0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
      0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
      0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
      0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
      0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
      0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48]

      K = []
      MK = []
      key = 0
      X = []
      Y = []
      txtstream = []
      lenth = 0

      def __init__(self,key):
            self.key = key
            self.K = []
            self.MK = []
            self.X = []
            self.Y = []
            self.txtstream = []
            self.lenth = 0
            pass

      def __key__expand__(self):
            for i in range(0,13,4):
                  self.MK.append(self.__union__hex__(self.key[i:i+4]))
            for i in range(4):
                  self.K.append(self.MK[i] ^ self.FK[i])
            for i in range(32):
                  a = self.K[i+1] ^ self.K[i+2] ^ self.K[i+3] ^ self.getCK(i)
                  b = self.__apart__hex__(a)
                  c = [self.getSbox(i) for i in b]
                  d = self.__union__hex__(c)
                  e = d ^ (d <<13) ^ (d << 23)
                  self.K.append(self.K[i] ^ e)

      def __union__hex__(self,data):
          return int((data[0] << 24) | (data[1] << 16) | (data[2] << 8) | (data[3]))

      def __apart__hex__(self,data):
            return [int((data >> 24) & 0xff), int((data >> 16) & 0xff), int((data >> 8) & 0xff), int((data) & 0xff)]

      def getSbox(self,i):
            return self.SboxTable[i]

      def getCK(self,i):
            return self.CK[i]

      def encrypt(self,bits,mk,model):
            self.X = []
            self.Y = []
            for p in range(0, len(bits), 16):
                  plaintxt = bits[p:p+16]
                  self.X = []
                  for i in range(0,13,4):
                        self.X.append(self.__union__hex__(plaintxt[i:i+4]))
                  if model:
                      j = 4
                  else:
                      j=35
                  for i in range(0,32):
                        a = self.X[i+1] ^ self.X[i+2] ^ self.X[i+3] ^ self.K[j]
                        if model:
                            j+=1
                        else:
                            j-=1
                        b = self.__apart__hex__(a)
                        c = [self.getSbox(i) for i in b]
                        d = self.__union__hex__(c)
                        e = d ^ (d << 2) ^ (d << 10) ^ (d << 18) ^ (d << 24)
                        self.X.append(self.X[i] ^ e)
                  t = self.X[35]
                  self.X[35] = self.X[32]
                  self.X[32] = t
                  t =self.X[34]
                  self.X[34] = self.X[33]
                  self.X[33] = t
                  for i in range(32,36):
                        self.Y.append(self.X[i])
                  byte=[]
                  for i in self.Y:
                        a = self.__apart__hex__(i)
                        for j in a:
                              byte.append(j)
                  return byte
      def encrypt_cbc(self,Plaintext,Key):
            mk=bytes_to_long(Key)

            Plaintext_bytes=binascii.hexlify(bytes(Plaintext.encode('utf-8')))
            Plaintext_str = str(Plaintext_bytes)[2:-1]
            iv=mk

            if len(Plaintext_str)%32!=0:
                  Plaintext_str=pad(Plaintext_str)
            Ciphertext=''
            for i in range(0,len(Plaintext_str),32):
                  tmp=eval('0x'+Plaintext_str[i:i+32])^iv
                  res=self.encrypt(long_to_bytes(tmp),mk,1)
                  Ciphertext+=self.list_to_hex(res)
                  iv=eval('0x'+self.list_to_hex(res))
            return Ciphertext
      
      def decrypt_cbc(self,Ciphertext,Key):
          mk=bytes_to_long(Key)
          Plaintext=''
          iv=mk
          for i in range(0,len(Ciphertext),32):
              tmp=self.encrypt(binascii.unhexlify(Ciphertext[i:(i+32)]),mk,0)
              tmp=self.list_to_hex(tmp)
              tmp=bytes_to_long(bytes(binascii.unhexlify(tmp)))
              tmp^=iv
              Plaintext+=str(long_to_bytes(tmp))[2:-1]
              iv=bytes_to_long(bytes(binascii.unhexlify(Ciphertext[i:(i+32)])))
          return Plaintext

      def list_to_hex(self,arr):
            hex_re=""
            for i in arr:
                  hex_re+=hex(i)[2:].zfill(2)
            return hex_re


def test():
    key=urandom(16)
    sm4=Sm4(key)
    sm4.__key__expand__()
    msg='xxxxxxxxxxxxxxxx'
    print(msg)
    cip=sm4.encrypt_cbc(msg,key)
    return sm4.decrypt_cbc(cip,key)

if __name__=='__main__':
    print(test())
