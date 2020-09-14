from Crypto.Util.number import long_to_bytes
from hashlib import sha256
from binascii import unhexlify
from Crypto.Cipher import AES

p=108848362000185157098908557633810357240367513945191048364780883709439999L

def unpad(S):
	return S[:-ord(S[-1])]

def add_points(P,Q):
    return ((P[0]*Q[0]-P[1]*Q[1])%p,(P[0]*Q[1]+P[1]*Q[0])%p)


def multiply(P,n):
    Q=(1,0)
    while n>0:
        if n%2==1:
            Q=add_points(Q,P)
        P=add_points(P,P)
        n=n//2
    return Q

def cal_b(p,g,B):
    K.<w>=PolynomialRing(GF(p))
    K.<w>=GF(p).extension(w^2+1)
    g_K=g[0]+g[1]*w
    B_K=B[0]+B[1]*w
    return discrete_log(B_K,g_K)

def solve():
    g=(29223879291878505213325643878338189297997503744039619988987863719655098L,32188620669315455017576071518169599806490004123869726364682284676721556L)
    A=(68279847973010227567437241690876400434176575735647388141445319082120661L,36521392659318312718307506287199839545959127964141955928297920414981390L)
    B=(84698630137710906531637499064120297563999383201108850561060383338482806L,10975400339031190591877824767290004140780471215800442883565278903964109L)
    b=cal_b(p,g,B)
    shared=multiply(A,b)[0]
    key=sha256(long_to_bytes(shared)).digest()
    aes = AES.new(key, AES.MODE_ECB)
    cip='26b1b05962d188f1f2abdfad2cef049d45cfc27d9e46f40ebe52e367941bcfa05dd0ef698f528375be2185759e663431'
    return unpad(aes.decrypt(unhexlify(cip)))


if __name__=='__main__':
    print solve()
