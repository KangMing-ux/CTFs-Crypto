from pwn import pwnlib
from pwnlib.tubes.remote import remote
from pwnlib.util.iters import mbruteforce
from string import ascii_letters,digits
from hashlib import sha256

r=remote('81.68.174.63',8631)
da=r.recvn(97)

def solve_proof(x):
    assert len(x)==3
    global da
    msg=da[11:28]
    dig=da[33:97]
    return sha256((x+msg).encode()).hexdigest()==dig

def get_data():
    x=mbruteforce(solve_proof,ascii_letters+digits,3,method='fixed')
    global r
    r.sendline(x)
    r.recvuntil('choice?')
    r.sendline('1')
    r.recvuntil('\n')
    r.recvuntil('\n')
    re=r.recvuntil(' ')[:-1]
    q=long(re)
    print q
    re=r.recvuntil(' ')[:-1]
    h=long(re)
    print h
    re=r.recvuntil('\n')[:-1]
    c=long(re)
    print c
    re=r.recvuntil('\n')[:-1]
    N=long(re)
    print N
    re=r.recvuntil('\n')[:-1]
    cip=long(re)
    print cip
    return q,h,c

def solve():
	q,h,c=get_data()
	M=Matrix(ZZ,[[1,h],[0,q]])
	f,g=M.LLL()[0]
	tmp=(f*c)%q
	tmp%=g
	cake=(tmp*inverse_mod(f,g))%g
	global r
	r.sendline(str(cake))
	print r.recv()

if __name__=='__main__':
    solve()
