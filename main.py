# -*- coding: utf-8 -*-
import math
import time
import sympy
import warnings
from random import randint, seed
import sys
from ecpy.curves import Curve, Point
from Crypto.Hash import HMAC, SHA3_256,SHA256
from Crypto import Random  # a bit better secure random number generation
import requests
# DO NOT FORGET TO INSTALL PICK
# pip install pick
from pick import pick
import json
import sys

API_URL = 'http://10.92.52.175:5000/'

title = 'Who are you? (press SPACE to mark, ENTER to continue): '
options = ['Fatih', 'Melih']
selected = pick(options, title, multiselect=False)
if(selected[1]==0): # if the person is fatih
    stuID = 25119
else:
    stuID = 25132   # if melih
print("{}'s student number is: {}".format(selected[0],stuID))

with open('database.json', 'r') as myfile:
    data=myfile.read()
obj = json.loads(data)

person = obj["people"][selected[1]]

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
#Send OTK Coordinates and corresponding hmac
def OTKReg(keyID,x,y,hmac):
    mes = {'ID':stuID, 'KEYID': keyID, 'OTKI.X': x, 'OTKI.Y': y, 'HMACI': hmac}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "OTKReg"), json = mes)
    print(response.json())
    if((response.ok) == False): return False
    else: return True
#
def ResetOTK(h,s):
    mes = {'ID':stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.delete('{}/{}'.format(API_URL, "ResetOTK"), json = mes)
    if((response.ok) == False): print(response.json())
# Reset Code is sent when you first registered
def ResetIK(rcode):
    mes = {'ID': stuID, 'RCODE': rcode}
    print("Sending message is: ", mes)
    response = requests.delete('{}/{}'.format(API_URL, "ResetIK"), json=mes)
    print(response.json())
    if ((response.ok) == False):
        return False
    else:
        return True
# Sign your ID  number and send the signature to delete your SPK
def ResetSPK(h, s):
    mes = {'ID': stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.delete('{}/{}'.format(API_URL, "ResetSPK"), json=mes)
    print(response.json())
    if ((response.ok) == False):
        return False
    else:
        return True

# kanka, test 'i true yapinca bu fonksiyonlar slayttaki
# curve degerlerini returnliyor.
# gecen aksam beraber baktigimiz ornegi test etmek icin
# bunu True olarak isaretle.
test = False
__E__ = Curve.get_curve('secp256k1')


# asagidaki degerleri yanlislikla modifiye etmeyelim die fonksiyon
# icine aldim. pythonda constant variable yokmus.
# bir de her fonksiyonda parametre olarak n p a P vermek istemedim artik
# onun yerine direkt bunlari kullaniyim diye

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
        return ret
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
    #print("\nPublic KEY generation")
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

def GenerateHMACKey():
    T = privKeySPK * serverSPKPUB
    Tx_bytes = T.x.to_bytes((T.x.bit_length() + 7) // 8, byteorder='big')
    Ty_bytes = T.y.to_bytes((T.y.bit_length() + 7) // 8, byteorder='big')
    U = Tx_bytes + Ty_bytes + b'NoNeedToRideAndHide'

    hash = SHA3_256.new(U)  # hash it
    HMACkey_int = int.from_bytes(hash.digest(), byteorder='big') % _n_()
    return HMACkey_int

def GenerateOTKArray():
    OTK= []
    for i in range(0,10):
        #generate public, private key pair
        OTKprivate, OTKpub = KeyGeneration(_P_())
        OTKpair = (OTKprivate, (OTKpub.x,OTKpub.y))
        OTK.append(OTKpair)
    return OTK

def GenerateHMACArray(OTK,HMACkey):
    HMACarray = []
    for OTKpair in OTK:
        OTKprivate, OTKpub = OTKpair
        concatOTKpub = concatenateIntPair(OTKpub[0],OTKpub[1])
        concatOTKpub_bytes = concatOTKpub.to_bytes((concatOTKpub.bit_length() + 7) // 8, byteorder='big')

        HMACkey_bytes = HMACkey.to_bytes((HMACkey.bit_length() + 7) // 8, byteorder='big')
        hash = HMAC.new(key=HMACkey_bytes, msg=concatOTKpub_bytes, digestmod=SHA256)
        digest = hash.hexdigest()
        HMACarray.append(digest)
    return HMACarray
### END FUNCTIONS #############################################

#######################SECTION 2.1#############################
print("\nSection 2.1 Started")
# server's public identity key
ServPubIK = Point(93223115898197558905062012489877327981787036929201444813217704012422483432813,
             8985629203225767185464920094198364255740987346743912071843303975587695337619,
            __E__
             )

# generate public-private key pair,
#if not generated.
privKey = 0
IKPUB_x = 0
IKPUB_y = 0
IKPUB =0
h=0
s=0
if(person["IKprivate"]==0):
    title = "{}, you do not have IK, want to create?".format(str(selected[0]))
    options = ['Yes', 'No']
    IKcreation = pick(options, title, multiselect=False)
    if(IKcreation[1]==0):
        private, ikpub = KeyGeneration(_P_())
        print("IK generated.")
        print("Private key is ", private)
        print("IKPUB.x is ", ikpub.x)
        print("IKPUB.y is ", ikpub.y)
        privKey = private
        IKPUB_x = ikpub.x
        IKPUB_y = ikpub.y
        print("Registering with IK.")

        signature = GenerateSignature(_P_(), stuID, privKey)
        h, s = signature[0], signature[1]

        IKRegReq(h, s, IKPUB_x, IKPUB_y)
        CODE = int(input("Please enter the code that is send by mail: "))
        IKRegVerify(CODE)
        RESET = int(input("Please enter the reset code: "))
        person["IKprivate"] = privKey
        person["IKpublic"] = [IKPUB_x, IKPUB_y]
        person["CODE"] = CODE
        person["RESET"] = RESET
        obj["people"][selected[1]] = person
        with open('database.json', 'w', encoding='utf-8') as f:
            json.dump(obj, f, ensure_ascii=False, indent=4)
    else:
        sys.exit();
else:
    title = '{}, you already have IK whats next?'.format(str(selected[0]))
    options = ['Continue to section 2.2', 'Reset IK']
    IKreset = pick(options, title, multiselect=False)
    if(IKreset[1]==0):
        privKey = person["IKprivate"]
        IKPUB_x = person["IKpublic"][0]
        IKPUB_y = person["IKpublic"][1]
        IKPUB = Point(IKPUB_x, IKPUB_y, __E__)
    else:
        ResetIK(person["RESET"])
        person["IKprivate"] = 0
        person["IKpublic"] = 0
        person["SPKprivate"] = 0
        person["SPKpublic"] = 0
        person["OTKarray"] = 0
        person["HMACarray"] = 0
        person["HMACkey"] = 0
        person["RESET"] = 0
        person["CODE"] = 0
        obj["people"][selected[1]] = person
        with open('database.json', 'w', encoding='utf-8') as f:
            json.dump(obj, f, ensure_ascii=False, indent=4)
        sys.exit()

# REGISTRATION TO THE SERVER

# VERIFICATION EXAMPLE CODE FOR LATER USAGE
        if (VerifySignature(signature, stuID, IKPUB) == True):
            print("Verified")
        else:
            print("NOT Verified")
print("Section 2.1 passed.\n#\n")


#######################SECTION 2.2#############################
print("Section 2.2 started.")
def concatenateIntPair(SPKPUB_x, SPKPUB_y):
    SPKPUB_x_bytes = SPKPUB_x.to_bytes((SPKPUB_x.bit_length() + 7) // 8, byteorder='big')
    SPKPUB_y_bytes = SPKPUB_y.to_bytes((SPKPUB_y.bit_length() + 7) // 8, byteorder='big')
    concat_bytes = SPKPUB_x_bytes + SPKPUB_y_bytes
    message = int.from_bytes(concat_bytes, byteorder='big')

    return message

privKeySPK = 0
SPKPUB_x = 0
SPKPUB_y = 0
SPKPUB = 0
if person["SPKprivate"] == 0:
    title = '{}, you do not have SPK, want to create?'.format(selected[0])
    options = ['Yes', 'No']
    picked = pick(options, title, multiselect=False)
    if(picked[1]==0):
        privKeySPK, SPKPUB = KeyGeneration(_P_())
        SPKPUB_x = SPKPUB.x
        SPKPUB_y = SPKPUB.y
        person["SPKprivate"] = privKeySPK
        person["SPKpublic"] = [SPKPUB_x, SPKPUB_y]
        obj["people"][selected[1]] = person
        with open('database.json', 'w', encoding='utf-8') as f:
            json.dump(obj, f, ensure_ascii=False, indent=4)
    else:
        sys.exit()
else:
    title = '{}, you already have SPK whats next?'.format(selected[0])
    options = ['Continue to section 2.3', 'Reset SPK']
    picked = pick(options, title, multiselect=False)
    if (picked[1] == 0):
        privKeySPK = person["SPKprivate"]
        SPKPUB_x = person["SPKpublic"][0]
        SPKPUB_y = person["SPKpublic"][1]
        SPKPUB = Point(IKPUB_x, IKPUB_y, __E__)
    else:
        h, s = GenerateSignature(_P_(), stuID, privKey)
        ResetSPK(h, s)
        person["SPKprivate"] = 0
        person["SPKpublic"] = 0
        person["OTKarray"] = 0
        person["HMACarray"] = 0
        person["HMACkey"] = 0
        obj["people"][selected[1]] = person
        with open('database.json', 'w', encoding='utf-8') as f:
            json.dump(obj, f, ensure_ascii=False, indent=4)
        sys.exit()




message = concatenateIntPair(SPKPUB_x, SPKPUB_y)
signature2 = GenerateSignature(_P_(), message, privKey)
h2, s2 = signature2[0], signature2[1]


# Burası da calisti galiba. Server bisey returnledi
result = SPKReg(h2, s2, SPKPUB_x, SPKPUB_y)
serverSPKPUB_x, serverSPKPUB_y, h, s = result
serverSPKPUB = Point(serverSPKPUB_x, serverSPKPUB_y, __E__)
signature = (h, s)
M = concatenateIntPair(serverSPKPUB_x, serverSPKPUB_y)
if VerifySignature(signature, M, ServPubIK):
    print("Verified")
else:
    print("NOT Verified")
print("Section 2.2 passed.\n#\n")

# Section 2.3
print("Section 2.3 started.")



HMACkey =0
OTKarray =0
HMACarray =0
if person["OTKarray"] == 0:
    title = '{}, you do not have OTK, want to create?'.format(selected[0])
    options = ['Yes', 'No']
    picked = pick(options, title, multiselect=False)
    if(picked[1]==0):
        HMACkey = GenerateHMACKey()
        OTKarray = GenerateOTKArray()
        HMACarray = GenerateHMACArray(OTKarray, HMACkey)

        for i in range(0, len(OTKarray)):
            OTKpair = OTKarray[i]
            OTKpub = OTKpair[1]
            OTKReg(i, OTKpub[0], OTKpub[1], HMACarray[i])

        person["OTKarray"] = OTKarray
        person["HMACarray"] = HMACarray
        person["HMACkey"] = HMACkey
        obj["people"][selected[1]] = person
        with open('database.json', 'w', encoding='utf-8') as f:
            json.dump(obj, f, ensure_ascii=False, indent=4)
    else:
        sys.exit()
else:
    title = '{}, you already have OTK whats next?'.format(selected[0])
    options = ['Continue', 'Reset OTK']
    picked = pick(options, title, multiselect=False)
    if (picked[1] == 0):
        HMACkey = person["HMACkey"]
        OTKarray = person["OTKarray"]
        HMACarray = ["HMACarray"]
        print("condinued")
    else:
        h,s = GenerateSignature(_P_(), stuID, privKey)
        ResetOTK(h,s)
        person["OTKarray"]=0
        person["HMACarray"] = 0
        person["HMACkey"] = 0

        obj["people"][selected[1]] = person
        with open('database.json', 'w', encoding='utf-8') as f:
            json.dump(obj, f, ensure_ascii=False, indent=4)

print("Section 2.3 passed.\n#\n")


