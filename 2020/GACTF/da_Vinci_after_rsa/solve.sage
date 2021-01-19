from itertools import product
from Crypto.Util.number import long_to_bytes
from string import printable

def solve():
    N=0x1d42aea2879f2e44dea5a13ae3465277b06749ce9059fd8b7b4b560cd861f99144d0775ffffffffffff
    c=421363015174981309103786520626603807427915973516427836319727073378790974986429057810159449046489151
    e=5
    p1,p2,p3=9749,11237753507624591,9127680453986244150392840833873266696712898279308227257525736684312919750469261
    G1,G2,G3=GF(p1),GF(p2),GF(p3)
    ms1,ms2,ms3=G1(c).nth_root(5,all=True),G2(c).nth_root(5,all=True),G3(c).nth_root(5,all=True)
    flag=''
    for m1,m2,m3 in product(ms1,ms2,ms3):
        m=crt([ZZ(m1),ZZ(m2),ZZ(m3)],[p1,p2,p3])
        assert power_mod(m,e,N)==c
        flag=long_to_bytes(ZZ(m))
        if all(x in printable for x in flag):
            break
    rep=list(flag[(flag.find('{')+1):flag.rfind('}')])
    enc=[1,28657,2,1,3,17711,5,8,13,21,46368,75025,34,55,89,610,377,144,233,1597,2584,4181,6765,10946,987]
    s_enc=sorted(enc)
    dec=[s_enc.index(x) for x in enc]
    assert len(rep)==len(dec)
    return ''.join([rep[x] for x in dec])

if __name__=='__main__':
    print 'flag{'+solve()+'}'
