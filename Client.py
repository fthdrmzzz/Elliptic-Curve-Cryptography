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
def Addition(P,Q,p,a):
    slope = 0
    
    if(P==Q):
        slope = ((3*pow(P[0],2)+a) * modinv((2*P[1]),p))% p
    #elif P[0] == Q[0]:
       #    return Addition(P,P,p,a)
    if(P!=Q):
        slope = (((P[1] - Q[1])) * modinv((P[0] - Q[0]),p)) % p
    
    xr = (pow(slope,2)-P[0]-Q[0]) % p
    yr = (-P[1] + slope*(P[0]-xr)) %p
    
    return (xr,yr)

def Mult(k:int,P,p,a):
    Result = P
    for i in range(0,k-1):
        print(i, Result)
        Result = Addition(Result,P,p,a)
    
    return Result



 #%%
Addition((5,0),(5,0),7,1)       
 #%%
        print(Mult(8,(1,3),5,2))
        #%%
#generate public-private key pair,

#Random secret key generation:
S_a = randint(1,n-2)
#Compute the public key:
Ika.Pri
Ika_Pub