from secret import e1,e2,flag
from Crypto.Util.number import *

msg = bytes_to_long("=========Hint:e1="+str(e1)+"=============")
p = getPrime(512)
q = getPrime(512)
N = p*q
print N
print pow(msg,3,N)

msg = bytes_to_long(flag)
p = getPrime(1024)
q = getPrime(1024)
N = p*q
c = pow(msg, e2, N)
print N,e2
print c
print(pow(p+q,e1,N ))
print(pow(p+e1, q, N))
