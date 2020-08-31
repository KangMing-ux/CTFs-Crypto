from json import load
from multiprocessing import Pool
from functools import partial
from random import Random
from time import time
from datetime import timedelta

def solve(s,A,k,id):
	rand=Random(x=id)
	lA=len(A)
	N=ceil(sqrt(lA))
	Lm=[[]]*(lA)
	for ind in xrange(lA):
		Lm[ind]=[0]*(lA+2)
		Lm[ind][ind]=1
		Lm[ind][lA]=A[ind]*N
		Lm[ind][lA+1]=N
	top=[0]*(lA+2)
	top[lA]=-s*N
	top[lA+1]=-k*N
	while 1:
		Lt=Lm[:]
		Lt.insert(0,top)
		M=Matrix(ZZ,Lt)
		shuffle(Lm,random=rand.random)
		M=M.BKZ(block_size=22)
		for vec in M.rows():
			if all(b==0 or b==1 for b in vec) and sum(vec)==20 and sum([a*b for a,b in zip(A,vec)])==s:
				print vec
				return True

if __name__=='__main__':
	t0=time()
	with open('data','r') as f:
		s,A=load(f)
	mul_solve=partial(solve,s,A,20)
	pool=Pool(6)
	mulres=pool.imap_unordered(mul_solve,xrange(6))
	for res in mulres:
		if res:
			pool.terminate()
			break
	pool.close()
	print 'cost time: ',timedelta(seconds=long(time()-t0))
