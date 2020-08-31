from pwn import pwnlib
from pwnlib.tubes.remote import remote

def solve():
    r=remote('124.71.145.165',9999)
    rr=r.recv()
    rr=r.recv()
    Mr=[]
    times=100
    for _ in range(times):
        r.sendline('2')
        rr=r.recv()
        m=[float(x) for x in rr[:-3].split(',')]
        if len(m)<47:
            r.sendline('2')
            rr=r.recv()
            m.extend([float(x) for x in rr[:-3].split(',')])
        Mr.append(m[:])
    r.close()
    col=47
    ret=[0]*col
    for ii in range(col):
        ret[ii]=round(sum([Mr[x][ii] for x in range(times)])/times)
    iret=[int(x) for x in ret]
    return ''.join([chr(x) for x in iret])

if __name__=='__main__':
    print solve()
