# -*- coding: utf-8 -*-

from random import randint, seed
from ecpy.curves import Curve
from Crypto.Hash import SHA3_256
from Crypto import Random   # a bit better secure random number generation 
import math

E = Curve.get_curve('secp256k1')
n = E.order
p = E.field
P = E.generator
a = E.a
b = E.b
print("Base point:\n", P)
print("p :", p)
print("a :", a)
print("b :", b)
print("n :", n)

k = Random.new().read(int(math.log(n,2)))
k = int.from_bytes(k, byteorder='big')%n

Q = k*P
print("\nQ:\n", Q)
print("Q on curve?", E.is_on_curve(Q))
   
#generate public-private key pair, 

#identity public key of the server.
Iks_Pub = (93223115898197558905062012489877327981787036929201444813217704012422483432813, 8985629203225767185464920094198364255740987346743912071843303975587695337619)
#%%
### FUNCTIONS #############################################
def egcd(a, b):
    x,y, u,v = 0,1, 1,0
    while a != 0:
        q, r = b//a, b%a
        m, n = x-u*q, y-v*q
        b,a, x,y, u,v = a,r, u,v, m,n
    gcd = b
    return gcd, x, y

def modinv(a, m):
    if a < 0:
        a = a+m
    gcd, x, y = egcd(a, m)
    if gcd != 1:
        return None  # modular inverse does not exist
    else:
        return x % m
    
    # eger p ve q esitse  y sifirsa 0,0 dondur.
    # ve p  q esit degilse, px qx aynisya 0,0 dondur.
    # https://www.nayuki.io/page/elliptic-curve-point-addition-in-projective-coordinates


def Add(P,Q,p,a):
    slope = 0
    px, py = P[0], P[1]
    qx, qy = Q[0], Q[1]
    if(P==Q):
        
        if(P==(0,0)):
            return(0,0)
        else:
            if(py==0):
                return (0,0)
            else:
                slope = ((3*pow(px,2)+a) * modinv((2*py),p))% p

    if(P!=Q):
        if(P==(0,0)):
            return Q
        elif(Q==(0,0)):
            return P
        else:
            if(px==qx):
                return(0,0)
            else:
                slope = (((py - qx)) * modinv((px - qx),p)) % p
    
    rx = (pow(slope,2)-px-qx) % p
    ry = (-py + slope*(px-rx)) %p
    
    return (rx,ry)

def Multiply(k:int,P,p,a):
    Result = P
    for i in range(0,k-1):
        print(i, Result)
        Result = Addition(Result,P,p,a)
    
    return Result

def GenerateSignature(P,M,S_a,n,p,a):
    #generate a random k : 0<k<n-1
    k= randint(1,n-2)
    #compute R = k*P
    R = Multiply(k,P,p,a)
    #compute r, x coordinate of R
    rx,ry = R[0], R[1]
    r = rx % n
    
    #concatenate M & r
    M_ = (M << r.bit_length()) + r
    #calculate h
    #change the line below if M is not given as string
    hash = SHA3_256.new(M_.encode('utf-8')) # hash it
    digest = int.from_bytes(hash.digest(), byteorder='big') 
    h = h % n
    #calculate s
    s =(k-S_a*h) % n
    # the signature is h, s tuple.
    return (h,s)
    
### END FUNCTIONS #############################################
 #%%
#generate public-private key pair,

#Random secret key generation:
S_a = randint(1,n-2)
#Compute the public key:
Q_a = Mult(S_a, P,p,a)
#Signature Generation

Ika.Pri
Ika_Pub