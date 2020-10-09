from secret import *
from Crypto.Util.number import *

print "N is : ",N
print "C is : ",C
F = IntegerModRing(N)

E1 = EllipticCurve(F, [A, C])
E2 =  EllipticCurve(F, [A, B])
P1 = (40868726519566019162794925971370501749760105301423309229554,54687980868371628310908123178978977864897123871328723)
P2 = (235149117685317066108245267690004572936544028030457002179126,1289371238921298371232163781261298731812137628190)
P1 = E1(P1)
P2 = E2(P2)
msg = flag
msg1 = msg[:19]
msg2 = msg[19:]
m1 = bytes_to_long(msg1)
m2 = bytes_to_long(msg2)
assert m1 < n
assert m2 < n
P3 = m1 * P2
P4 = m2 * P2
print(P1)
print(P2)
print(P3)
print(P4)
