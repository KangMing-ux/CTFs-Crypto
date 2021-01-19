from pwn import pwnlib
from pwnlib.tubes.remote import remote
from pwnlib.util.iters import mbruteforce
from hashlib import sha256
from string import ascii_letters,digits
from math import sqrt
from Crypto.Util.number import *
from gmpy2 import next_prime

r=remote('182.92.153.117',30101)
re1=r.recvline()
nonce=re1[8:16]

def check(s):
    mes=(str(nonce)[2:-1]+s).encode('Latin-1')
    return sha256(mes).digest().hex().startswith("00000")

def get_NC(delta=16):
    Ns=[0]*32
    Cs=[0]*32
    ed=pow(2,delta)
    point=int(sqrt(1.1)*pow(2,32))
    count=0
    flag=0
    for ii in range(63):
        N=next_prime(getRandomRange(point-ed,point+ed))
        r.sendline('god')
        r.sendline(str(N))
        re2=r.recvline()
        C=int(re2)
        if C%N:
            Ns[count]=N
            Cs[count]=N-C%N
            count+=1
            if count>31:
                flag=1
                break
    if flag:
        print('success!')
        return Ns,Cs
    else:
        print('try again!')
    return

def crt(As,Ms):
    Mod=1
    for m in Ms:
        Mod*=m
    MS=[Mod//m for m in Ms]
    Ts=[inverse(M,m) for M,m in zip(MS,Ms)]
    ret=0
    for a,t,M in zip(As,Ts,MS):
        ret+=(a*t*M)
        ret%=Mod
    return ret

def get_flag(secret):
    r.sendline('bless')
    r.sendline(str(secret))
    re3=r.recvline()
    return re3

def solve():
    base=ascii_letters+digits
    suffix=mbruteforce(check,base,12)
    r.sendline(suffix)
    r.recvline()
    try:
        Ns,Cs=get_NC()
        #print(Ns)
        #print(Cs)
    except TypeError:
        return
    secret=crt(Cs,Ns)
    print(str(secret))
    return get_flag(secret)

if __name__=='__main__':
    print(solve())
    r.close()
