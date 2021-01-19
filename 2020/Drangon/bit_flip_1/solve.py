from task import *
from time import sleep
from string import printable

def server():
    alice_seed=urandom(16)
    print(alice_seed)
    guess='0'
    #hack s1
    cnt=0
    while 1:
        flip_str=long_to_bytes(cnt<<128)
        seed=xor32(alice_seed,flip_str)
        alice=DiffieHellman(seed)
        _iter_1=alice.send_iter()
        flip_str=long_to_bytes((cnt<<128)^2)
        seed=xor32(flip_str,alice_seed)
        alice=DiffieHellman(seed)
        _iter_2=alice.send_iter()
        if _iter_1*_iter_2:
            delta_iter=_iter_1-_iter_2
            assert abs(delta_iter)==1
            #NOTE:Actually,delta_iter=1 => delta_iter!=-1
            # => s1!=1 => s1=0 and
            # delta_iter=-1 => delta_iter!=1
            # => s1!=0 => s1=1
            guess=str(int(delta_iter==-1))+guess
            break                
        cnt+=1
    #hack s_{j} by s_{j-1}...s_{1},j=2,...,127
    for j in range(2,128):
        cnt&=0
        while 1:
            flip_str=long_to_bytes((cnt<<128)^((1<<j)-2)^int(guess,2))
            seed=xor32(flip_str,alice_seed)
            alice=DiffieHellman(seed)
            _iter_1=alice.send_iter()
            flip_str=long_to_bytes((cnt<<128)^(1<<j)^int(guess,2))
            seed=xor32(flip_str,alice_seed)
            alice=DiffieHellman(seed)
            _iter_2=alice.send_iter()
            flip_str=long_to_bytes((cnt<<128)^((1<<j+1)-2)^int(guess,2))
            seed=xor32(flip_str,alice_seed)
            alice=DiffieHellman(seed)
            _iter_3=alice.send_iter()
            flip_str=long_to_bytes((cnt<<128)^int(guess,2))
            seed=xor32(flip_str,alice_seed)
            alice=DiffieHellman(seed)
            _iter_4=alice.send_iter()
            delta_iter_12=_iter_1-_iter_2
            delta_iter_34=_iter_3-_iter_4
            if _iter_1*_iter_3*(delta_iter_12*delta_iter_34-1):
                #NOTE:owing to s_{j}=0 => delta_iter_12=1,so
                #delta_iter_12!=1 => s_{j}!=0 => s_{j}=1
                #In the same way,delta_iter_34!=1 => s_{j}!=1
                #which is means s_{j}=0
                #what's more,delta_iter_12!=1 => s_{j}=1
                # => delta_iter_34=1,which means either delta_iter_12
                #or delta_iter_34 must be equal to 1
                #however,only there is either delta_iter_12 or delta_iter_34
                #unequal 1,I can find s_{j}!
                try:
                    assert (delta_iter_12-1)*(delta_iter_34-1)==0
                except AssertionError:
                    print(j)
                guess=str(int(delta_iter_34==1))+guess
                break
            cnt+=1
    #Here,|alice_seed-guess|<=1.
    guess=int(guess,2)            
    assert bytes_to_long(alice_seed)-guess<2
    #this seed only has 2 value: 32*'\0x00',31*'\0x00'+'\x01'
    alice=DiffieHellman(xor32(alice_seed,long_to_bytes(guess)))
    bob = DiffieHellman(urandom(16), alice.prime)
    alice.set_other(bob.my_number)
    iv = urandom(16)
    cipher = AES.new(long_to_bytes(alice.shared, 16)[:16], AES.MODE_CBC, IV=iv)
    enc_flag = cipher.encrypt(FLAG)
    return (bob.my_number,b64encode(iv).decode(),b64encode(enc_flag).decode())

if __name__=='__main__':
    bnum,iv,enc_flag=server()
    for seed in [b'\x00',b'\x01']:
        alice=DiffieHellman(pad32(seed))
        alice.set_other(bnum)
        cipher = AES.new(long_to_bytes(alice.shared, 16)[:16], AES.MODE_CBC, IV=b64decode(iv.encode()))
        dec_flag=cipher.decrypt(b64decode(enc_flag.encode()))
        if all(chr(x) in printable for x in dec_flag if x):
            solve_flag=''.join([chr(x) for x in dec_flag if x])
            break
    assert all(chr(x) in printable for x in dec_flag if x)
    print(solve_flag)
