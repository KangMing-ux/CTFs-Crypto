from Crypto.Util.number import getPrime

def eat_cake():
	BITS = 512
	e=getPrime(int(447))
	p,q = getPrime(int(BITS)),getPrime(int(BITS))
	ph = (p - 1) * (q + 1)
	N = p * q
	d = inverse_mod(e, ph)
	#768 bits
	cake = getPrime(int(BITS >> 1 | BITS))
	#1536 bits
	q = getPrime(int(BITS << 1 | BITS))
	f = d
	g = getPrime(int(len(bin(q))-len(bin(f))-1))
	f_inv_q = inverse_mod(f, q)
	h = f_inv_q * g % q
	r = getPrime(int(BITS))
	c = (r * h + cake) % q
	return q,h,c,cake

def solve():
	q,h,c,cake=eat_cake()
	M=Matrix(ZZ,[[1,h],[0,q]])
	M=M.BKZ()
	f,g=M[0]
	tmp=(f*c)%q
	tmp%=g
	solve_cake=(tmp*inverse_mod(f,g))%g
	return solve_cake==cake

if __name__=='__main__':
	ret=0
	cnt=0
	while not ret:
		ret=solve()
		cnt+=1
	print 'success! '+str(cnt)+' -th'
