from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

def wiener_attack(n,e):
    hi_1,hi_2=1,0
    ki_1,ki_2=0,1
    a,b=e,n
    R.<t> = PolynomialRing(QQ)
    r=1
    while r:
        p,r=divmod(a,b)
        hi=p*hi_1+hi_2
        ki=p*ki_1+ki_2
        #print hi,ki
        hi_1,hi_2=hi,hi_1
        ki_1,ki_2=ki,ki_1
        a,b=b,r
        if hi==0:
            continue
        f=t^2-(n-(ki*e-1)/hi+1)*t+n
        rts=f.roots()
        flag=0
        for ii in xrange(len(rts)):
            flag+=rts[ii][0] in ZZ
        if flag==2:
            break
    p,q=rts[0][0],rts[1][0]
    if p<q:
        return p,q
    else:
        return q,p

def solve():
    with open('public.key','rb') as f:
        pubkey=RSA.importKey(f.read())
    n,e=pubkey.n,pubkey.e
    p,q=wiener_attack(n,e)
    assert n==p*q
    d=inverse_mod(e,(p-1)*(q-1))
    rsa_key=RSA.construct((n,e,long(d),long(p),long(q)))
    key=PKCS1_OAEP.new(rsa_key)
    with open('message','rb') as f:
        flag=key.decrypt(f.read()).decode()
    return flag

if __name__=='__main__':
    print solve()
