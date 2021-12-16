# -*- coding: utf-8 -*-

from random import randint, seed
from ecpy.curves import Curve
from Crypto.Hash import SHA3_256
from Crypto import Random   # a bit better secure random number generation 
import math
# kanka, test 'i true yapince bu fonksiyonlar slayttaki 
# curve degerlerini returnliyor. 
# gecen aksam beraber baktigimiz ornegi test etmek icin 
# bunu True olarak isaretkle.
test = False
__E__ = Curve.get_curve('secp256k1')

#asagidaki degerleri yanlislikla modifiye etmeyelim die fonksiyon
#icine aldim. pythonda constant variable yokmus.
# bir de her fonksiyonda parametre olarak n p a P vermek istemedim artik
# onun yerine direkt bunlari kullaniyim diye
# ama farkli curve gerekirse sictik

def _n_():
    if(test):
        return 7
    else:
        ret = __E__.order
        return ret
def _p_():
    if(test):
        return 101
    else:
        ret =__E__.field
        return ret
def _P_():
    if(test):
        return (1,3)
    else:
        ret =__E__.generator
        return tuple((ret.x,ret.y))
def _a_():
    if(test):
        return 1
    else:
        ret =__E__.a
        return ret
def _b_():
    if(test):
        return 57
    else:
        ret =__E__.b
        return ret
print("Base point:\n", _P_())
print("p :", _p_())
print("a :", _a_())
print("b :", _b_())
print("n :", _n_())

"""
k = Random.new().read(int(math.log(n,2)))
k = int.from_bytes(k, byteorder='big')%n

Q = k*P
print("\nQ:\n", Q)
print("Q on curve?", E.is_on_curve(Q))
"""
   


### FUNCTIONS #############################################
def printProgressBar (iteration, total, prefix = '', suffix = '', decimals = 1, length = 100, fill = '█', printEnd = "\r"):
    """
    Call in a loop to create terminal progress bar
    @params:\
        iteration   - Required  : current iteration (Int)
        total       - Required  : total iterations (Int)
        prefix      - Optional  : prefix string (Str)
        suffix      - Optional  : suffix string (Str)
        decimals    - Optional  : positive number of decimals in percent complete (Int)
        length      - Optional  : character length of bar (Int)
        fill        - Optional  : bar fill character (Str)
        printEnd    - Optional  : end character (e.g. "\r", "\r\n") (Str)
    """
    percent = ("{0:." + str(decimals) + "f}").format(100 * (iteration / float(total)))
    filledLength = int(length * iteration // total)
    bar = fill * filledLength + '-' * (length - filledLength)
    print(f'\r{prefix} |{bar}| {percent}% {suffix}', end = printEnd)
    # Print New Line on Complete
    if iteration == total: 
        print()
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


def Add(P,Q):
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
                slope = ((3*pow(px,2)+_a_()) * modinv((2*py),_p_()))% _p_()
    if(P!=Q):
        if(P==(0,0)):
            return Q
        elif(Q==(0,0)):
            return P
        else:
            if(px==qx):
                return(0,0)
            else:
                slope = (((py - qy)) * modinv((px - qx),_p_())) % _p_()
    
    rx = (pow(slope,2)-px-qx) % _p_()
    ry = (-py + slope*(px-rx)) % _p_()
    
    return (rx,ry)

def Multiply(k:int,P):
    Result = P
    for i in range(0,k-1):
        #printProgressBar(i,k-1,)
        
        Result = Add(Result,P)
        print(i,Result)
    return Result

# bu fonksiyon yazildi ama test edilmedi. 
#ACCEPTS M AS INTEGER
def GenerateSignature(P,M,S_a):
    # STEP BY STEP
    
    # STEP 1
    k= randint(1,_n_()-2)
    
    # STEP 2
    R = Multiply(k,_P_())
    
    # STEP 3
    rx,ry = R[0], R[1]
    r = rx % _n_()
    
    # STEP 4    
    #concatenate M & r
    RM = (r << M.bit_length()) + M
    #calculate h
    RM_bytes = RM.to_bytes((RM.bit_length() + 7) // 8, byteorder='big')
    hash = SHA3_256.new(RM_bytes) # hash it
    digest = int.from_bytes(hash.digest(), byteorder='big') 
    h = digest % _n_()
    
    # STEP 5
    s =(k-S_a*h) % _n_()
    
    # STEP 6
    # the signature is h, s tuple.
    return (h,s)

def VerifySignature(Signature,M,Q_a):
    
    h,s = Signature[0],Signature[1]
    # STEP 1    
    V = Add(Multiply(s,_P_()),Multiply(h,Q_a))
    
    # STEP 2
    vx, vy = V[0], V[1]
    v = vx % _n_()
    
    # STEP 3   
    #concatenate v||M
    VM = (v << M.bit_length()) + M
    #calculate h
    VM_bytes = VM.to_bytes((VM.bit_length() + 7) // 8, byteorder='big')
    hash = SHA3_256.new(VM_bytes) # hash it
    digest = int.from_bytes(hash.digest(), byteorder='big') 
    h_ = digest % _n_()
    
    return h == h_
        
### END FUNCTIONS #############################################
 #%%
 #teste true yap ve slaytlardan kontrol et, dogru calisiyor
pointP = (1,3)
print(Multiply(5,pointP))
 #%%
#server's public identity key
ServPubIK= (93223115898197558905062012489877327981787036929201444813217704012422483432813, 8985629203225767185464920094198364255740987346743912071843303975587695337619)

#generate public-private key pair,
#Random secret key generation:
PrivIK = randint(1,_n_()-2)
#Compute the public key:
print("Generating Public Identity Key")
PubIK = Multiply(PrivIK, _P_())


