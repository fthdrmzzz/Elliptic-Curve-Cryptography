# -*- coding: utf-8 -*-
import math
import time
import sympy
import warnings
from random import randint, seed
import sys
from ecpy.curves import Curve, Point
from Crypto.Hash import HMAC, SHA3_256,SHA256
from Crypto.Cipher import AES

from Crypto import Random  # a bit better secure random number generation
import requests
# DO NOT FORGET TO INSTALL PICK
# pip install pick
from pick import pick
import json
import sys

"""
Before execute the program run pip install pick
We used a json database for the project 
Therefore please do not delete database.json file
database.json will keep the client key informations 
Since we (Fatih and Melih) are team members, we created 2 profiles for us.
When we run the program firstly, the program asks the user (Melih or Fatih)
After that if we did not have Identity Key informations in database.json it will create one for us.
If we have already Identity Key informations in database.json we can reset it, or we can move section 2.2 in the documnentation
In section 2.2 if we did not have SPK we can generate one for us.
               if we have we can move to section 2.3 or reset our SPK
In section 2.3 if we did not have OTK, we can generate. If we have it we can reset.
All the data generated each step will be written into database.json. In this way, in each round we will not lose any information.
"""





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

#Send Public Identitiy Key Coordinates and corresponding signature
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
#Send the reset code to delete your Identitiy Key
#Reset Code is sent when you first registered
def ResetIK(rcode):
    mes = {'ID': stuID, 'RCODE': rcode}
    print("Sending message is: ", mes)
    response = requests.delete('{}/{}'.format(API_URL, "ResetIK"), json=mes)
    print(response.json())
    if ((response.ok) == False):
        return False
    else:
        return True
#Sign your ID  number and send the signature to delete your SPK
def ResetSPK(h, s):
    mes = {'ID': stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.delete('{}/{}'.format(API_URL, "ResetSPK"), json=mes)
    print(response.json())
    if ((response.ok) == False):
        return False
    else:
        return True
#Send the reset code to delete your Identitiy Key
def ResetOTK(h,s):
    mes = {'ID':stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.delete('{}/{}'.format(API_URL, "ResetOTK"), json = mes)
    if((response.ok) == False): print(response.json())
#Pseudo-client will send you 5 messages to your inbox via server when you call this function
def PseudoSendMsg(h,s):
    mes = {'ID':stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "PseudoSendMsg"), json = mes)
    print(response.json())

#get your messages. server will send 1 message from your inbox
def ReqMsg(h,s):
    mes = {'ID':stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.get('{}/{}'.format(API_URL, "ReqMsg"), json = mes)
    print(response.json())
    if((response.ok) == True):
        res = response.json()
        return res["IDB"], res["OTKID"], res["MSGID"], res["MSG"], res["EK.X"], res["EK.Y"]

#If you decrypted the message, send back the plaintext for grading
def Checker(stuID, stuIDB, msgID, decmsg):
    mes = {'IDA':stuID, 'IDB':stuIDB, 'MSGID': msgID, 'DECMSG': decmsg}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "Checker"), json = mes)
    print(response.json())


def PseudoSendMsgPH3(h, s):
    mes = {'ID': stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "PseudoSendMsgPH3"), json=mes)
    print(response.json())

def SendMsg(idA, idB, otkid, msgid, msg, ekx, eky):
    mes = {"IDA": idA, "IDB": idB, "OTKID": int(otkID), "MSGID": msgid, "MSG": msg, "EK.X": ekx, "EK.Y": eky}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "SendMSG"), json=mes)
    print(response.json())


def reqOTKB(stuID, stuIDB, h, s):
    OTK_request_msg = {'IDA': stuID, 'IDB': stuIDB, 'S': s, 'H': h}
    print("Requesting party B's OTK ...")
    response = requests.get('{}/{}'.format(API_URL, "ReqOTK"), json=OTK_request_msg)
    print(response.json())
    if ((response.ok) == True):
        print(response.json())
        res = response.json()
        return res['KEYID'], res['OTK.X'], res['OTK.Y']
    else:
        return -1, 0, 0


def Status(stuID, h, s):
    mes = {'ID': stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.get('{}/{}'.format(API_URL, "Status"), json=mes)
    print(response.json())
    if (response.ok == True):
        res = response.json()
        return res['numMSG'], res['numOTK'], res['StatusMSG']


__E__ = Curve.get_curve('secp256k1')


def _n_():
    ret = __E__.order
    return ret
def _p_():
    ret = __E__.field
    return ret
def _P_():
    ret = __E__.generator
    return ret
def _a_():
    ret = __E__.a
    return ret
def _b_():
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

#Key generation function defined in section 2.4
def KeyGeneration(Public):
    # Random secret key generation:
    s_A = randint(1, _n_() - 2)
    # Compute the public key:
    # Q_A is the public key
    Q_A = s_A * Public

    return s_A, Q_A
#Signature generation function defined in section 2.4
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
    #concatenation
    hash_byte = r_byte + M_byte
    hash = SHA3_256.new(hash_byte)  # hash it
    digest = int.from_bytes(hash.digest(), byteorder='big')
    h = digest % _n_()

    # STEP 5
    s = (k - (S_a * h)) % _n_()

    # STEP 6
    # the signature is h, s tuple.
    return (h, s)

#Signature verification function defined in section 2.4
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
#Concatenate two integer as bytes and return as an integer
def concatenateIntPair(SPKPUB_x, SPKPUB_y):
    SPKPUB_x_bytes = SPKPUB_x.to_bytes((SPKPUB_x.bit_length() + 7) // 8, byteorder='big')
    SPKPUB_y_bytes = SPKPUB_y.to_bytes((SPKPUB_y.bit_length() + 7) // 8, byteorder='big')
    concat_bytes = SPKPUB_x_bytes + SPKPUB_y_bytes
    message = int.from_bytes(concat_bytes, byteorder='big')

    return message

def GenerateHMACKey(SPKprivate,ServSPKpublic):
    T = SPKprivate * ServSPKpublic
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
ServIKpublic = Point(93223115898197558905062012489877327981787036929201444813217704012422483432813,
             8985629203225767185464920094198364255740987346743912071843303975587695337619,
            __E__
             )

# generate public-private key pair,
#if not generated.
IKprivate = 0
IKpublic_x = 0
IKpublic_y = 0
IKpublic =0
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
        print("IKpublic.x is ", ikpub.x)
        print("IKpublic.y is ", ikpub.y)
        IKprivate = private
        IKpublic_x = ikpub.x
        IKpublic_y = ikpub.y
        print("Registering with IK.")

        signature = GenerateSignature(_P_(), stuID, IKprivate)
        h, s = signature[0], signature[1]

        IKRegReq(h, s, IKpublic_x, IKpublic_y)
        CODE = int(input("Please enter the code that is send by mail: "))
        IKRegVerify(CODE)
        RESET = int(input("Please enter the reset code: "))
        person["IKprivate"] = IKprivate
        person["IKpublic"] = [IKpublic_x, IKpublic_y]
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
        IKprivate = person["IKprivate"]
        IKpublic_x = person["IKpublic"][0]
        IKpublic_y = person["IKpublic"][1]
        IKpublic = Point(IKpublic_x, IKpublic_y, __E__)
    else:
        #Reset IK will be called
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
        if (VerifySignature(signature, stuID, IKpublic) == True):
            print("Verified")
        else:
            print("NOT Verified")
print("Section 2.1 passed.\n#\n")


#######################SECTION 2.2#############################
print("Section 2.2 started.")


SPKprivate = 0
SPKpublic_x = 0
SPKpublic_y = 0
SPKpublic = 0
if person["SPKprivate"] == 0:
    title = '{}, you do not have SPK, want to create?'.format(selected[0])
    options = ['Yes', 'No']
    picked = pick(options, title, multiselect=False)
    if(picked[1]==0):
        SPKprivate, SPKpublic = KeyGeneration(_P_())
        SPKpublic_x = SPKpublic.x
        SPKpublic_y = SPKpublic.y
        person["SPKprivate"] = SPKprivate
        person["SPKpublic"] = [SPKpublic_x, SPKpublic_y]
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
        SPKprivate = person["SPKprivate"]
        SPKpublic_x = person["SPKpublic"][0]
        SPKpublic_y = person["SPKpublic"][1]
        SPKpublic = Point(IKpublic_x, IKpublic_y, __E__)
    else:
        h, s = GenerateSignature(_P_(), stuID, IKprivate)
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

message = concatenateIntPair(SPKpublic_x, SPKpublic_y)
signature2 = GenerateSignature(_P_(), message, IKprivate)
h2, s2 = signature2[0], signature2[1]


result = SPKReg(h2, s2, SPKpublic_x, SPKpublic_y)
ServSPKpublic_x, ServSPKpublic_y, h, s = result
ServSPKpublic = Point(ServSPKpublic_x, ServSPKpublic_y, __E__)
signature = (h, s)
M = concatenateIntPair(ServSPKpublic_x, ServSPKpublic_y)
if VerifySignature(signature, M, ServIKpublic):
    print("Verified")
else:
    print("NOT Verified")
print("Section 2.2 passed.\n#\n")

#######################SECTION 2.3#############################
print("Section 2.3 started.")

HMACkey =0
OTKarray =0
HMACarray =0
if person["OTKarray"] == 0:
    title = '{}, you do not have OTK, want to create?'.format(selected[0])
    options = ['Yes', 'No']
    picked = pick(options, title, multiselect=False)
    if(picked[1]==0):
        HMACkey = GenerateHMACKey(SPKprivate, ServSPKpublic)
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
    else:
        h,s = GenerateSignature(_P_(), stuID, IKprivate)
        ResetOTK(h,s)
        person["OTKarray"]=0
        person["HMACarray"] = 0
        person["HMACkey"] = 0

        obj["people"][selected[1]] = person
        with open('database.json', 'w', encoding='utf-8') as f:
            json.dump(obj, f, ensure_ascii=False, indent=4)

print("Section 2.3 passed.\n#\n")

#######################SECTION 3.1.1#############################
print("Section 3.1.1 started.")

# Rec = receiver
# this function takes receivers otk as parameter
# and generates a session key for the communication
# practices diffie hellman in some way.
def GenerateSessionKey(OTK,EK,receiver = True):
    if receiver:
        OTKprivate = OTK
        EKpublic = EK
        #STEP1
        T = OTKprivate * EKpublic
    else: # if sender
        OTKpublic =OTK
        EKprivate = EK
        T = OTKpublic * EKprivate
    Tx, Ty = T.x, T.y

    #STEP2
    Tx_bytes = Tx.to_bytes((Tx.bit_length() + 7) // 8, byteorder='big')
    Ty_bytes = Ty.to_bytes((Ty.bit_length() + 7) // 8, byteorder='big')
    # concatenation
    U = Tx_bytes + Ty_bytes + b'MadMadWorld'

    #STEP3
    hash = SHA3_256.new(U)  # hash it
    digest = int.from_bytes(hash.digest(), byteorder='big')
    #h = digest % _n_()
    return digest #hash.digest() #h #session key
 

print("Section 3.1.1 passed.\n#\n")

#######################SECTION 3.1.2#############################

#this is key chaining function for
# multiple messages between users
# for each message this function shold be called and
# new key should be generated.
def KeyDerivation(K_KDF):
    #STEP1
    K_KDFkey_byte = K_KDF.to_bytes((K_KDF.bit_length() + 7) // 8, byteorder='big')
    # concatenation
    toHash = K_KDFkey_byte + b'LeaveMeAlone'
    hash = SHA3_256.new(toHash)
    digest = int.from_bytes(hash.digest(), byteorder='big')
    K_ENC = digest #% _n_()

    #STEP2
    K_ENC_byte = K_ENC.to_bytes((K_ENC.bit_length() + 7) // 8, byteorder='big')
    toHash = K_ENC_byte + b'GlovesAndSteeringWheel'
    hash = SHA3_256.new(toHash)
    digest = int.from_bytes(hash.digest(), byteorder='big')
    K_HMAC = digest #% _n_()

    #STEP3
    K_HMAC_byte = K_HMAC.to_bytes((K_HMAC.bit_length() + 7) // 8, byteorder='big')
    toHash = K_HMAC_byte + b'YouWillNotHaveTheDrink'
    hash = SHA3_256.new(toHash)
    digest = int.from_bytes(hash.digest(),byteorder ='big')
    K_KDFnext = digest #% _n_()

    return K_ENC, K_HMAC,K_KDFnext

#this function takes index and
# generate ith key for the key chain
def KDFatIndex(index:int,KDFkey):
    K_ENC, K_HMAC, K_KDFnext = KeyDerivation(KDFkey)
    for i in range(1,index):
        K_ENC, K_HMAC, K_KDFnext= KeyDerivation(K_KDFnext)

    return K_ENC, K_HMAC, K_KDFnext
KDFkey = 0

#Session key generated for both parties

#it is used as kdf and KENC KHMAC created.


#IDK how encryption will be done,
#KENC KHMAC used for message1, recreated for following messages.
def EncryptMessage(Message,K_ENC, K_HMAC, K_KDFnext):
    print("TODO: Encryption is done")
    #next chain of kdf. next encryption will be done accordingly.
    K_ENC, K_HMAC, K_KDFnext= KeyDerivation(K_KDFnext)


#######################SECTION 3.2#############################
#This function will decrypt the message that will send by the server
def Decryption(ciphertext_byte,nonce_byte, k_enc):
    cipher = AES.new(k_enc, AES.MODE_CTR, nonce = nonce_byte)
    decryptedtext_byte = cipher.decrypt(ciphertext_byte)
    decryptedtext = decryptedtext_byte.decode('utf-8')
    return decryptedtext

import time
while True:
    signature = GenerateSignature(_P_(), stuID, IKprivate)
    h, s = signature
    title = '{}, what do you want to do next?'.format(selected[0])
    options = ['Check my mailbox', 'Ask server to send messages','Send Messages','Check OTKs','sleep','quit']
    picked = pick(options, title, multiselect=False)
    if(picked[1]==0):
        messages = []
        counter = 0
        #FOR 5 MESSAGES, THIS RUNS
        for i in range(5):
            signature = GenerateSignature(_P_(), stuID, IKprivate)
            h, s = signature
            try:
                #GET THE RESPONSE FROM SERVER. IF CANT, THE MAILBOX IS EMPTY
                IDB, OTKID, MSGID,MSG, EKx,EKy = ReqMsg(h,s)
                """
                print("IDK: ",IDB)
                print("OTKID: ",OTKID)
                print("MSGID: ",MSGID)
                print("MSG: ",MSG)
                print("EKx: ",EKx)
                print("EKy: ",EKy)
                """
            except:
                print("Empty Mailbox")
                break

            #Configuration
            #GENERATE SESSION KEY AND CHAIN KEYS ACCORDING TO MESSAGE ID.
            CurrentOTK = OTKarray[OTKID][0]#private OTK
            CurrentEKpublic = Point(EKx, EKy,__E__) # public EK
            SessionKey = GenerateSessionKey(CurrentOTK,CurrentEKpublic)
            K_ENC, K_HMAC, K_KDFnext = KDFatIndex(MSGID,SessionKey)

            #Message is in form:
            # nonce (8 bytes) - msg - mac (32 bytes)
            MSG_bytes = MSG.to_bytes((MSG.bit_length() + 7) // 8, byteorder='big')
            #extracted hmac for verification
            MAC_bytes = MSG_bytes[len(MSG_bytes) - 32:]
            #extracted raw encrypted message for verification
            MSGraw_bytes = MSG_bytes[8:-32]

            #HMAC IS CALCULATED.
            K_HMAC_bytes = K_HMAC.to_bytes((K_HMAC.bit_length() + 7) // 8, byteorder='big')
            HMACnew_hash = HMAC.new(msg=MSGraw_bytes, digestmod=SHA256, key=K_HMAC_bytes)
            HMACnew_int = int.from_bytes(HMACnew_hash.digest(), byteorder='big') %_n_()
            HMACnew_bytes = HMACnew_int.to_bytes((HMACnew_int.bit_length() + 7) // 8, byteorder='big')

            #HMAC VERIFICATION
            if HMACnew_bytes == MAC_bytes:
                counter+=1
                print("VERIFIED")
                #IF VERIFIED DECRYPT THE MESSAGE
                # first 8 byte of the message.
                NONCE_bytes = MSG_bytes[0:8]
                # message without nonce to get the MAC of the message
                CIPHERTEXT_bytes = MSG_bytes[8:-32]
                # message in int format to decrypt it
                MSG_int = int.from_bytes(MSG_bytes[:len(MSG_bytes) - 32], byteorder='big')

                K_ENC_bytes = K_ENC.to_bytes((K_ENC.bit_length() + 7) // 8, byteorder='big')
                CIPHER = AES.new(K_ENC_bytes, AES.MODE_CTR, nonce=NONCE_bytes)
                PLAINTEXT_bytes = CIPHER.decrypt(CIPHERTEXT_bytes)

                messages.append(str(PLAINTEXT_bytes))
                decrypt_text = PLAINTEXT_bytes.decode('utf-8')
                #AFTER DECRYPTION SEND IT TO SERVER.
                Checker(stuID,IDB,MSGID,(decrypt_text))
            else:
                print("NOT VERIFIED")
                #SEND INVALID TO SERVER
                Checker(stuID, IDB, MSGID, "INVALIDHMAC")

        print("{} out of {} messages are verified\n\n".format(counter,5))
        print("Messages: ")
        for i in range(0,5):
            if len(messages)<i+1:break
            print(messages[i])
        time.sleep(5)
    elif (picked[1]==1):
        PseudoSendMsg(h,s)
        time.sleep(3)
    elif picked[1]==4:
        time.sleep(15)
    #MELIH BURASI KALDI KANKA ##############################################
    elif picked[1]==2:
        stuIDB = input("Please enter ID of receiver to get OTK: ")
        OTKID, OTKx, OTKy = 0,0,0

        #here server returns internal server error,
        #therefore I couldnt test rest of the code.
        try:
            OTKID, OTKx, OTKy = reqOTKB(stuID,stuIDB,h,s)
        except:
            print("problem in otkB request")

        print(OTKx,OTKy)
        OTKpublic = Point(OTKx,OTKy,__E__)
        EKprivate, EKpublic = KeyGeneration(_P_())
        SessionKey= GenerateSessionKey(OTKpublic,EKprivate,receiver=False)


        Messages = [b'Selamlar',b'Bonjour',b'selamualeykum',b'hola',b'koniciva']
        MSGID=1
        for MSG in Messages:
            K_ENC, K_HMAC, K_KDFnext = KDFatIndex(MSGID, SessionKey)



            #CALCULATING CIPHERTEXT
            K_ENC_bytes = K_ENC.to_bytes((K_ENC.bit_length() + 7) // 8, byteorder='big')
            CIPHER = AES.new(K_ENC_bytes, AES.MODE_CTR)
            NONCE_bytes = CIPHER.nonce

            PLAINTEXT_bytes = MSG
            CIPHERTEXT_bytes = cipher.encrypt(PLAINTEXT_bytes)

            K_HMAC_bytes = K_HMAC.to_bytes((K_HMAC.bit_length() + 7) // 8, byteorder='big')
            HMAC_hash = HMAC.new(msg=CIPHERTEXT_bytes, digestmod=SHA256, key=K_HMAC_bytes)
            HMAC_int = int.from_bytes(HMAC_hash.digest(), byteorder='big') % _n_()
            HMAC_bytes = HMAC_int.to_bytes((HMAC_int.bit_length() + 7) // 8, byteorder='big')

            MSGBLOCK = NONCE_bytes+CIPHERTEXT_bytes+HMAC_bytes

            SendMsg(stuID,stuIDB,OTKID,MSGID,MSGBLOCK,EKpublic.x,EKpublic.y)
            MSGID+=1
    # MELIH BURASI KALDI KANKA END ##############################################
    elif picked[1]==3:
        numMSG,numOTK,statusMSG =Status(stuID,h,s)
        print(numMSG,numOTK,statusMSG)

        choice = input("Do you want to register new OTKs? (y/n): ")
        if choice =="y":
            print("generating otks")
            HMACkey = GenerateHMACKey(SPKprivate, ServSPKpublic)
            OTKarray = GenerateOTKArray()
            HMACarray = GenerateHMACArray(OTKarray, HMACkey)

            OTKoffset = input("What is first id of newcoming OTKs: ")
            for i in range(0, len(OTKarray)):
                OTKpair = OTKarray[i]
                OTKpub = OTKpair[1]
                OTKReg(i+int(OTKoffset), OTKpub[0], OTKpub[1], HMACarray[i])

            person["OTKarray"] = OTKarray
            person["HMACarray"] = HMACarray
            person["HMACkey"] = HMACkey
            obj["people"][selected[1]] = person
            with open('database.json', 'w', encoding='utf-8') as f:
                json.dump(obj, f, ensure_ascii=False, indent=4)
    else:
        break
    print("#\n#\n")
    #time.sleep(15)
