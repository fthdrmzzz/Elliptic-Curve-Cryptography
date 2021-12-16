# -*- coding: utf-8 -*-
import math
import time
import sympy
import warnings
from random import randint, seed
import sys
from ecpy.curves import Curve, Point
from Crypto.Hash import SHA3_256
from Crypto import Random  # a bit better secure random number generation
import requests

API_URL = 'http://10.92.52.175:5000/'

stuID = 25119  ## Change this to your ID number


def IKRegReq(h, s, x, y):
    mes = {'ID': stuID, 'H': h, 'S': s, 'IKPUB.X': x, 'IKPUB.Y': y}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "IKRegReq"), json=mes)
    if ((response.ok) == False): print(response.json())


# Send the verification code
def IKRegVerify(code):
    mes = {'ID': stuID, 'CODE': code}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "IKRegVerif"), json=mes)
    if ((response.ok) == False): raise Exception(response.json())
    print(response.json())


# Send SPK Coordinates and corresponding signature
def SPKReg(h, s, x, y):
    mes = {'ID': stuID, 'H': h, 'S': s, 'SPKPUB.X': x, 'SPKPUB.Y': y}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "SPKReg"), json=mes)
    if ((response.ok) == False):
        print(response.json())
    else:
        res = response.json()
        return res['SPKPUB.X'], res['SPKPUB.Y'], res['H'], res['S']


# kanka, test 'i true yapince bu fonksiyonlar slayttaki
# curve degerlerini returnliyor. 
# gecen aksam beraber baktigimiz ornegi test etmek icin 
# bunu True olarak isaretle.
test = False
__E__ = Curve.get_curve('secp256k1')


# asagidaki degerleri yanlislikla modifiye etmeyelim die fonksiyon
# icine aldim. pythonda constant variable yokmus.
# bir de her fonksiyonda parametre olarak n p a P vermek istemedim artik
# onun yerine direkt bunlari kullaniyim diye
# ama farkli curve gerekirse sictik

def _n_():
    if (test):
        return 7
    else:
        ret = __E__.order
        return ret


def _p_():
    if (test):
        return 101
    else:
        ret = __E__.field
        return ret


def _P_():
    if (test):
        return (1, 3)
    else:
        ret = __E__.generator
        return ret  # BURAYI DEGISTIRDIM, BU SEKILDE RETURN EDINCE DAHA RAHAT ISLEMLERI GOREBILIYORUZ


def _a_():
    if (test):
        return 1
    else:
        ret = __E__.a
        return ret


def _b_():
    if (test):
        return 57
    else:
        ret = __E__.b
        return ret

"""
print("Base point:\n", _P_())
print("p :", _p_())
print("a :", _a_())
print("b :", _b_())
print("n :", _n_())
"""

"""
k = Random.new().read(int(math.log(n,2)))
k = int.from_bytes(k, byteorder='big')%n
Q = k*P
print("\nQ:\n", Q)
print("Q on curve?", E.is_on_curve(Q))
"""


### FUNCTIONS #############################################
def printProgressBar(iteration, total, prefix='', suffix='', decimals=1, length=100, fill='█', printEnd="\r"):
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
    print(f'\r{prefix} |{bar}| {percent}% {suffix}', end=printEnd)
    # Print New Line on Complete
    if iteration == total:
        print()


def egcd(a, b):
    x, y, u, v = 0, 1, 1, 0
    while a != 0:
        q, r = b // a, b % a
        m, n = x - u * q, y - v * q
        b, a, x, y, u, v = a, r, u, v, m, n
    gcd = b
    return gcd, x, y


def modinv(a, m):
    if a < 0:
        a = a + m
    gcd, x, y = egcd(a, m)
    if gcd != 1:
        return None  # modular inverse does not exist
    else:
        return x % m

    # eger p ve q esitse  y sifirsa 0,0 dondur.
    # ve p  q esit degilse, px qx aynisya 0,0 dondur.
    # https://www.nayuki.io/page/elliptic-curve-point-addition-in-projective-coordinates


def Add(P, Q):
    slope = 0
    px, py = P[0], P[1]
    qx, qy = Q[0], Q[1]
    if (P == Q):
        if (P == (0, 0)):
            return (0, 0)
        else:
            if (py == 0):
                return (0, 0)
            else:
                slope = ((3 * pow(px, 2) + _a_()) * modinv((2 * py), _p_())) % _p_()
    if (P != Q):
        if (P == (0, 0)):
            return Q
        elif (Q == (0, 0)):
            return P
        else:
            if (px == qx):
                return (0, 0)
            else:
                slope = (((py - qy)) * modinv((px - qx), _p_())) % _p_()

    rx = (pow(slope, 2) - px - qx) % _p_()
    ry = (-py + slope * (px - rx)) % _p_()

    return (rx, ry)


def KeyGeneration(Public):
    # Random secret key generation:
    print("\nPublic KEY generation")
    s_A = randint(1, _n_() - 2)
    # print("Random number s_A is ",s_A)

    # Compute the public key:
    # Q_A is the public key
    Q_A = s_A * Public
    # print("Q_A is ",Q_A)

    return s_A, Q_A


def GenerateSignature(P, M, S_a):
    # STEP BY STEP

    # STEP 1
    k = randint(1, _n_() - 2)

    # STEP 2
    R = k * P

    # STEP 3
    r = R.x % _n_()

    # STEP 4    
    r_byte = r.to_bytes((r.bit_length() + 7) // 8, byteorder='big')
    M_byte = M.to_bytes((M.bit_length() + 7) // 8, byteorder='big')

    hash_byte = r_byte + M_byte
    hash = SHA3_256.new(hash_byte)  # hash it
    digest = int.from_bytes(hash.digest(), byteorder='big')
    h = digest % _n_()

    # STEP 5
    s = (k - (S_a * h)) % _n_()

    # STEP 6
    # the signature is h, s tuple.
    return (h, s)


def VerifySignature(Signature, M, Q_a):
    h, s = Signature[0], Signature[1]
    # STEP 1    
    V = s * _P_() + h * Q_a

    # STEP 2
    v = V.x % _n_()

    # STEP 3   
    # concatenate v||M
    v_bytes = v.to_bytes((v.bit_length() + 7) // 8, byteorder='big')
    M_bytes = M.to_bytes((M.bit_length() + 7) // 8, byteorder='big')

    # calculate h
    hash_bytes = v_bytes + M_bytes
    hash = SHA3_256.new(hash_bytes)  # hash it
    digest = int.from_bytes(hash.digest(), byteorder='big')
    h_ = digest % _n_()

    return h == h_


### END FUNCTIONS #############################################

#######################SECTION 2.1#############################
print("Section 2.1 Started")
# server's public identity key
ServPubIK = Point(93223115898197558905062012489877327981787036929201444813217704012422483432813,
             8985629203225767185464920094198364255740987346743912071843303975587695337619,
            __E__
             )

# generate public-private key pair,
"""
#Already generated
private,ikpub = KeyGeneration(_P_())
print("IKPUB ", ikpub)
print("Private key is ",private)
print("IKPUB.x is ",ikpub.x)
print("IKPUB.y is ",ikpub.y)
privKey = private
IKPUB_x =  ikpub.x
IKPUB_y =  ikpub.y
"""
# REGISTRATION TO THE SERVER

# FATIH
privKey = 94521801300613165484736014372466820435205348304503106962012705151542008931493
IKPUB_x = 13454045804951041800861425145260473887575795168349084317631689200742197438891
IKPUB_y = 51371775992988002345874638731955426408534503596147761006521551843585840068683
IKPUB = Point(IKPUB_x, IKPUB_y, __E__)
# IKRegReq(h,s,IKPUB_x,IKPUB_y)
ID = 25119
CODE = 172135
RESET = 239795
# IKRegVerify(CODE)
# END OF FATIH

"""
#MELIH
privKey = 50653728290329342968310403098566478579527388781281943577810245277141300700776
IKPUB_x = 23633173257570318923110869411227090891322101986741458964833457092812117061900
IKPUB_y = 47163067102607020505397555018876217270029402871572808817630261534980589863261
IKPUB = Point(IKPUB_x , IKPUB_y, __E__)
#IKRegReq(h,s,IKPUB_x,IKPUB_y)
ID= 25132 
CODE= 612303 
#IKRegVerify(CODE)
#END OF MELIH
"""

signature = GenerateSignature(_P_(), stuID, privKey)
h, s = signature[0], signature[1]

# VERIFICATION EXAMPLE CODE FOR LATER USAGE
if (VerifySignature(signature, stuID, IKPUB) == True):
    print("Verified")
else:
    print("NOT Verified")
print("Section 2.1 passed.\n#\n")


#######################SECTION 2.2#############################
print("Section 2.2 started.")
def SPK_Message(SPKPUB_x, SPKPUB_y):
    SPKPUB_x_bytes = SPKPUB_x.to_bytes((SPKPUB_x.bit_length() + 7) // 8, byteorder='big')
    SPKPUB_y_bytes = SPKPUB_y.to_bytes((SPKPUB_y.bit_length() + 7) // 8, byteorder='big')
    concat_bytes = SPKPUB_x_bytes + SPKPUB_y_bytes
    message = int.from_bytes(concat_bytes, byteorder='big')

    return message


"""
#Already generated 
private,ikpub = KeyGeneration(_P_())
print("IKPUB ", ikpub)
print("Private key is ",private)
print("IKPUB.x is ",ikpub.x)
print("IKPUB.y is ",ikpub.y)
privKey = private
"""

# FATIH
privKeySPK = 23709468699399012413335949851631185403239900516201749468972818471145787539442
SPKPUB_x = 114590600750797444225622024358886468950692822297300139584690340022315922294658
SPKPUB_y = 3783880007329682945558395094014369807590612988422275924802569666898674922684
SPKPUB = Point(SPKPUB_x, SPKPUB_y, __E__)
# END OF FATIH

"""
#MELIH
privKeySPK = 22677646434295206042315781975106516886874077659674676715265076980993252012419
SPKPUB_x = 66741554407868132438414242495415239856795791414364983712084644345825229511801
SPKPUB_y =  110275591324510446373768651084057740272103593984944753850742989363408791019218
SPKPUB = Point(SPKPUB_x , SPKPUB_y, __E__)
#END OF MELIH
"""

message = SPK_Message(SPKPUB_x, SPKPUB_y)
signature2 = GenerateSignature(_P_(), message, privKey)
h2, s2 = signature2[0], signature2[1]


"""
(85040781858568445399879179922879835942032506645887434621361669108644661638219, 
46354559534391251764410704735456214670494836161052287022185178295305851364841, 
107338514472014150452119982252950151955827304841981384723418296022276000650967, 
49579867550559644093052410637290403102612534910465663433948531076103167174828)
"""
# Burası da calisti galiba. Server bisey returnledi
result = SPKReg(h2, s2, SPKPUB_x, SPKPUB_y)
serverSPKPUB_x, serverSPKPUB_y, h, s = result
serverSPKPUB = Point(serverSPKPUB_x, serverSPKPUB_y, __E__)
signature = (h, s)
M = SPK_Message(serverSPKPUB_x, serverSPKPUB_y)
if VerifySignature(signature, M, ServPubIK):
    print("Verified")
else:
    print("NOT Verified")
print("Section 2.2 passed.")

# Section 2.3
def GenerateHMACKey():
    T = privKeySPK * serverSPKPUB
    Tx_bytes = T.x.to_bytes((T.x.bit_length() + 7) // 8, byteorder='big')
    Ty_bytes = T.x.to_bytes((T.y.bit_length() + 7) // 8, byteorder='big')
    U = Tx_bytes + Ty_bytes + b'NoNeedToRideAndHide'
    hash = SHA3_256(U)
    digest = int.from_bytes(hash.digest(), byteorder='big')
    return digest

