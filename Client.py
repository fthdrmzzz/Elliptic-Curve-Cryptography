# -- coding: utf-8 --

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
_E_ = Curve.get_curve('secp256k1')

#asagidaki degerleri yanlislikla modifiye etmeyelim die fonksiyon
#icine aldim. pythonda constant variable yokmus.
def n():
    if(test):
        return 7
    else:
        ret = _E_.order
        return ret
def p():
    if(test):
        return 5
    else:
        ret =_E_.field
        return ret
def P():
    if(test):
        return (1,3)
    else:
        ret =_E_.generator
        return tuple((ret.x,ret.y))
def a():
    if(test):
        return 2
    else:
        ret =_E_.a
        return ret
def b():
    if(test):
        return 1
    else:
        ret =_E_.b
        return ret
print("Base point:\n", P())
print("p :", p())
print("a :", a())
print("b :", b())
print("n :", n())

"""
k = Random.new().read(int(math.log(n,2)))
k = int.from_bytes(k, byteorder='big')%n
Q = k*P
print("\nQ:\n", Q)
print("Q on curve?", E.is_on_curve(Q))
"""
   


### FUNCTIONS #############################################
def printProgressBar (iteration, total, prefix = '', suffix = '', decimals = 1, length = 100, fill = '?', printEnd = "\r"):
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
                slope = ((3*pow(px,2)+a()) * modinv((2*py),p()))% p()
    if(P!=Q):
        if(P==(0,0)):
            return Q
        elif(Q==(0,0)):
            return P
        else:
            if(px==qx):
                return(0,0)
            else:
                slope = (((py - qy)) * modinv((px - qx),p())) % p()
    
    rx = (pow(slope,2)-px-qx) % p()
    ry = (-py + slope*(px-rx)) % p()
    
    return (rx,ry)

def Multiply(k:int,P):
    Result = P
    for i in range(0,k-1):
        #printProgressBar(i,k-1,)
        
        Result = Add(Result,P)
        #print(i,Result)
    return Result


def KeyGenration(Public):
    #Random secret key generation:
    print("\nPublic KEY generation")
    #s_A= randint(1,n()-2)
    s_A= randint(1,10000)
    print("Random number s_A is ",s_A)

    #Compute the public key:
    #Q_A is the public key
    Q_A = Multiply(s_A, Public)
    print("Q_A is ",Q_A)

    return Q_A

# bu fonksiyon yazildi ama test edilmedi. 
#ACCEPTS M AS INTEGER
def GenerateSignature(P,M,S_a):
    # STEP BY STEP
    
    # STEP 1
    #k is s_A
    k= randint(1,n()-2)
    
    # STEP 2
    #R is Q_A
    R = Multiply(k,P)
    
    # STEP 3
    rx,ry = R[0], R[1]
    r = rx % n()
    
    # STEP 4    
    #concatenate M & r
    RM = (r << M.bit_length()) + M
    #calculate h
    RM_bytes = RM.to_bytes((RM.bit_length() + 7) // 8, byteorder='big')
    hash = SHA3_256.new(RM_bytes) # hash it
    digest = int.from_bytes(hash.digest(), byteorder='big') 
    h = digest % n()
    
    # STEP 5
    s =(k-S_a*h) % n()
    
    # STEP 6
    # the signature is h, s tuple.
    return (h,s)

def VerifySignature(Signature,M,Q_a):
    
    h,s = Signature[0],Signature[1]
    # STEP 1    
    V = Add(Multiply(s,P()),Multiply(h,Q_a))
    
    # STEP 2
    vx, vy = V[0], V[1]
    v = vx % n()
    
    # STEP 3   
    #concatenate v||M
    VM = (v << M.bit_length()) + M
    #calculate h
    VM_bytes = VM.to_bytes((VM.bit_length() + 7) // 8, byteorder='big')
    hash = SHA3_256.new(VM_bytes) # hash it
    digest = int.from_bytes(hash.digest(), byteorder='big') 
    h_ = digest % n()
    
    return h == h_
        
### END FUNCTIONS #############################################
 #%%
 #teste true yap ve slaytlardan kontrol et, dogru calisiyor
pointP = (1,3)
print(Multiply(5,pointP))
 #%%
#server's public identity key
ServPubIK= (93223115898197558905062012489877327981787036929201444813217704012422483432813, 8985629203225767185464920094198364255740987346743912071843303975587695337619)
"""
Public KEY generation
Random number s_A is  7546
Q_A is  (87535894158095520824325068259954455295733891190513406969582947246123914785959, 48028079269525428442804774157116932826724800026095805835175339939845548587240)
"""
#generate public-private key pair,
#Knk fonksiyonda fake random rangei kullandim,
#multiplication cok uzun suruyor hesaplayamadi
Q_A_publicKey = KeyGenration(P())

"""
Public KEY generation
Random number s_A is  5950
Q_A is  (57391636622241864249838054409219857161376422046440955917844129896230831707812, 39884903221139359768339999990120438978496065562591711856782560734682241297942)
"""