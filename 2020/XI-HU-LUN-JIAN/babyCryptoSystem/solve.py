from pwn import pwnlib
from pwnlib.util.iters import mbruteforce
from pwnlib.tubes.remote import remote
from SM4 import Sm4
from hashlib import sha256
from string import ascii_letters,digits
from binascii import hexlify,unhexlify

r=remote('183.129.189.61',54600)
re1=r.recvline().strip()
dig=str(re1[-64:])[2:-1]
rpart=re1[12:28]
base=ascii_letters+digits
r.recvuntil(':')

def check(lpart):
    msg=lpart+str(rpart)[2:-1]
    return sha256(msg.encode()).hexdigest()==dig

def solve():
    proof_part=mbruteforce(check,base,4,method='fixed')
    send_data=proof_part+'\n'*6
    r.send(send_data.encode())
    r.recvuntil('exit\n')
    r.sendline('4')
    re2=r.recv().strip()
    print(re2)
    en_flag=re2[22:]
    print(en_flag)
    msg='xxxxxxxxxxxxxxxx'
    r.recvuntil('exit\n')
    r.sendline('2')
    r.recvuntil(':')
    r.sendline(msg)
    re3=r.recv().strip()
    cip=re3[50:]
    r.recvuntil('exit\n')
    r.sendline('3')
    r.recvuntil(':')
    hexmsg=hexlify(bytes(msg.encode()))
    r.sendline(hexmsg)
    re4=r.recv().strip()
    key=unhexlify(re4[23:])
    sm4=Sm4(key)
    sm4.__key__expand__()
    return sm4.decrypt_cbc(en_flag,key)

if __name__=='__main__':
    print(solve())
    r.close()
