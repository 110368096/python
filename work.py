import math
from PySSSS import *
from io import BytesIO
from os import curdir
from numpy import string_
import pandas as pd
from datetime import date, datetime
import random
from mini_ecdsa import *
from Crypto.Cipher import AES
import base64
import secrets
import sys


a = 2 
b = 6 
q = 17321
Generator_P_x= 1
Generator_P_y= 3
n = 17564





def point_add(N_x, N_y, Q_x, Q_y, p):
    m = (Q_y - N_y) * pow((Q_x-N_x), p-2, p)
    ret_x = (m ** 2 - N_x - Q_x) % p
    ret_y = (m*(N_x - ret_x) - N_y) % p
    return ret_x, ret_y

def add_calculator():
    N_x=int(input('Enter the value of x_1 : '))
    N_y=int(input('Enter the value of y_1 : '))
    Q_x=int(input('Enter the value of x_2 : '))
    Q_y=int(input('Enter the value of y_2 : '))
    p=int(input('Enter the value of p : '))
    print(point_add(N_x, N_y, Q_x, Q_y, p))

def isPrime(p):
    if(p <= 1): return False
    if(p == 2): return True
    if(p%2 == 0): return False

    for i in range(3, int(math.sqrt(p))):
        if(p%i == 0): return False
        i += 2

    return True


def point_double(N_x, N_y, a, p):
    m = (3*(N_x ** 2)+a) * pow(2*N_y, p-2, p)
    ret_x = (m ** 2 - N_x - N_x) % p
    ret_y = (m*(N_x - ret_x) - N_y) % p
    return ret_x, ret_y

def multiplication_calculator(k, x, y, a, b, p):
    k = format(k, "b")
    binary = list(k)
    P = [x, y]
    P1 = [x, y]

    for i in range(1, len(k)):
        if binary[i] == '1':
            P = point_double(P[0], P[1], a, p)
            P = point_add(P[0], P[1], P1[0], P1[1], p)
            
        elif binary[i] == '0':
            P = point_double(P[0], P[1], a, p)
    return P

def multiplication():
    k = int(input("Enter the value of k : "))
    x = int(input("Enter the value of x : "))
    y = int(input("Enter the value of y : "))
    a = int(input("Enter value of a : "))
    b = int(input("Enter value of b : "))
    p = int(input("Enter value of p : "))
    print("Point is: ", multiplication_calculator(k, x, y, a, b, p))

def order_curve(a, b, p):
    points = []
    X = []
    Y = []
    order = 1
    for n in range(p):
        #For X
        X.append(dict({'index': n, 'value': (((n * n * n) + (a * n) + (b % p)) % p)}))
        
        #For y
        Y.append(dict({'index': n, 'value': ((n * n) % p)}))
    
    for Px in X:
        for Py in Y:
            if Px['value'] == Py['value']:
                order += 1
    return order

def order_c():
    a = int(input("Enter value of a : "))
    b = int(input("Enter value of b : "))
    p = int(input("Enter value of p : "))
    print("Order is:", order_curve(a, b, p))

def order_finder(x, y, a, b, p):

    Xc = (((x * x * x) + (a * x) + (b % p)) % p)
    Yc = ((y * y) % p)
    if(Xc != Yc):
        print("Given point doesnt lie on curve")
        return 

    order  = 2
    curve = order_curve(a, b, p)

    while True and order <= curve:

        X = multiplication_calculator(order, x, y, a, b, p)

        if X[0] == x and X[1] == y: break

        order += 1
    
    # if(order >= curve): order = curve
    return order-1

def order():
    x = int(input("Enter the value of x : "))
    y = int(input("Enter the value of y : "))
    a = int(input("Enter value of a : "))
    b = int(input("Enter value of b : "))
    p = int(input("Enter value of p : "))
    print("\nOrder is: ", order_finder(x, y, a, b, p))

def order_finder_points(curve, x, y, a, b, p):

    Xc = (((x * x * x) + (a * x) + (b % p)) % p)
    Yc = ((y * y) % p)
    if(Xc != Yc):
        print("Given point doesnt lie on curve")
        return 

    order  = 2
    
    while True and order <= curve:
        print ("currently checking for", order, end="\r")

        X = multiplication_calculator(order, x, y, a, b, p)

        if X[0] == x and X[1] == y: break

        order += 1
    
    # if(order >= curve): order = curve
    return order-1

def points_finder_order(a, b, p):
    curve = order_curve(a, b, p)
    points = []
    X = []
    Y = []
    for n in range(p):
        #For X
        X.append(dict({'index': n, 'value': (((n * n * n) + (a * n) + (b % p)) % p)}))
        
        #For y
        Y.append(dict({'index': n, 'value': ((n * n) % p)}))
    
    for Px in X:
        for Py in Y:
            if Px['value'] == Py['value']:
                points.append(dict({'x': Px['index'], 'y': Py['index'], 'order': order_finder_points(curve, Px['index'], Py['index'],a, b, p)}))
                print("  (", Px['index'], ", ", Py['index'], ")  ")

    print("Order of curve is: ", (len(points) +1))

def points_order():
    a = int(input("Enter value of a : "))
    b = int(input("Enter value of b : "))
    p = int(input("Enter value of p : "))
    points_finder_order(a, b, p)

def points_finder(a, b, p):
    points = []
    X = []
    Y = []
    for n in range(p):
        #For X
        X.append(dict({'index': n, 'value': (((n * n * n) + (a * n) + (b % p)) % p)}))
        
        #For y
        Y.append(dict({'index': n, 'value': ((n * n) % p)}))
    
    for Px in X:
        for Py in Y:
            if Px['value'] == Py['value']:
                points.append(dict({'x': Px['index'], 'y': Py['index']}))
                print("  (", Px['index'], ", ", Py['index'], ")  ")

    print("Order of curve is: ", (len(points) +1))

def points():
    a = int(input("Enter value of a : "))
    b = int(input("Enter value of b : "))
    p = int(input("Enter value of p : "))
    points_finder(a, b, p)

def squareroot_cal(a, p):
    roots = []
    if(a < 0 or p < 0):
        print("Square Root does not exists for given values")
        return roots

    if(p == 2 or not(isPrime(p))):
        print("Square exists only for odd primes")
        return roots

    for i in range(p):
        if((a%p) == ((i**2)%p)):
            roots.append(i)
            break
    
    print(len(roots))
    if(len(roots) <= 0):
        print("Square Root does not exists for given values")
        return roots
    
    roots.append(p-roots[0])
    return roots

def ecdsa_sig(a,b,p,n,P_x,P_y,pk,sig_data):
    P= Point(P_x,P_y)  #generator P
    curve=CurveOverFp(0,a,b,p) #曲線
    Q=curve.mult(P,pk)  #公鑰
    temp_1=str(sig_data[0])
    temp_2=str(sig_data[1])
    temp=(temp_1,temp_2)
    dot=','
    mes= dot.join(temp)
    K=(pk,Q)    #用於 lib 無其他含意
    sig=sign(mes,curve,P,n,K)   #簽章
    r=sig[1]
    s=sig[2]    
    return(r,s)
    
def ecdsa_verf(a,b,p,n,Generator_P_x,Generator_P_y,Q_x,Q_y,sig,mes):
    r=sig[0]
    s=sig[1]
    P= Point(int(Generator_P_x),int(Generator_P_y))
    curve=CurveOverFp(0,a,b,p)
    Q=Point(int(Q_x),int(Q_y))
    temp_1=str(mes[0])
    temp_2=str(mes[1])
    temp=(temp_1,temp_2)
    dot=','
    mes1= dot.join(temp)
    sign=(Q,r,s)
    print(verify(mes1, curve , P , n , sign))
    
def AES_Encrypt(key, data):
    vi = '0102030405060708'
    pad = lambda s: s + (16 - len(s)%16) * chr(16 - len(s)%16)
    data = pad(data)
    cipher = AES.new(key.encode('utf8'), AES.MODE_CBC, vi.encode('utf8'))
    encryptedbytes = cipher.encrypt(data.encode('utf8'))
    encodestrs = base64.b64encode(encryptedbytes)
    enctext = encodestrs.decode('utf8')
    return enctext

def AES_Decrypt(key, data):
    vi = '0102030405060708'
    data = data.encode('utf8')
    encodebytes = base64.decodebytes(data)
    cipher = AES.new(key.encode('utf8'), AES.MODE_CBC, vi.encode('utf8'))
    text_decrypted = cipher.decrypt(encodebytes)
    unpad = lambda s: s[0:-s[-1]]
    text_decrypted = unpad(text_decrypted)
    text_decrypted = text_decrypted.decode('utf8')
    return text_decrypted
    
def ECDH(a,b,p,pk,Q_x,Q_y):
    #pk for  self Q for others public key
    
    
    return(multiplication_calculator(pk,Q_x,Q_y,a,b,p))
    
def ECDH_E(session_key,data):
  
    session_key=str(session_key)
    pad = lambda s: s + (16 - len(s)%16) * chr(16 - len(s)%16)
    session_key=pad(session_key)
    AES_Encrypt(session_key,data)
    enctext=AES_Encrypt(session_key,data)

    return(enctext)

def ECDH_D(session_key,encrypted_data):

    session_key=str(session_key)
    pad = lambda s: s + (16 - len(s)%16) * chr(16 - len(s)%16)
    session_key=pad(session_key)
    text_decrypted = AES_Decrypt(session_key, encrypted_data)

    return(text_decrypted)

def sss_depart(secret,n,k):
    a = BytesIO(secret.encode('UTF-8'))
    shares = []
    n = int(n)
    k = int(k)
    for i in range(n):
        shares.append(BytesIO())

    encode(a,shares,k)

    #for i in range(n):
        #print(binascii.hexlify(shares[i].getvalue()).decode('UTF-8'))
    #share_secret=[]
    #for i in range(n):        
    #    share_secret.append(binascii.hexlify(shares[i].getvalue()).decode('UTF-8'))
    
    print('shares size=',sys.getsizeof(shares))
    print(shares[0])
    
    return(shares)



def sss_recovery(shares):

    k=5
    try:
        inputs = []
        for i in range(k):
            inputs.append(shares[i+1])

        for i in range(k):
            inputs[i].seek(0)

        output = BytesIO()
        print(output)
        decode(inputs,output)  

        return(output.getvalue().decode('UTF-8'))
    except:
        print('piece not enough')







def elgamal_E(a,b,p,n,P_x,P_y,Q_x,Q_y,M_x,M_y):
    #P for generator P
    #Q for others public key
    #M for key wnat to encrypt
    r=random.randint(1,n)
    M=(M_x,M_y)
    rQ=multiplication_calculator(r,Q_x,Q_y,a,b,p)
    rQ_x=rQ[0]
    rQ_y=rQ[1]
    c_1=point_add(M_x,M_y,rQ_x,rQ_y,p)
    c_2=multiplication_calculator(r,P_x,P_y,a,b,p)
    return(c_1,c_2)

def elgamal_D(a,b,p,pk,c_1,c_2):
    pkc2=multiplication_calculator(pk,c_2[0],c_2[1],a,b,p)
    inv_pkc2_x=pkc2[0]
    inv_pkc2_y=pkc2[1]
    inv_pkc2_y=-1*inv_pkc2_y
    inv_pkc2_y=inv_pkc2_y%p
    inv_pkc2=[inv_pkc2_x,inv_pkc2_y]
    M=point_add(c_1[0],c_1[1],inv_pkc2[0],inv_pkc2[1],p)
    return(M)

def squareroot():
    a = int(input("Enter value of a : "))
    p = int(input("Enter value of p : "))
    print("Roots are: ", squareroot_cal(a, p))


m = (secrets.randbits(256))
s = (secrets.randbits(256))
gk = (secrets.randbits(32))
Q_TA = multiplication_calculator(m*s,Generator_P_x,Generator_P_y,a,b,q)
Q_x=Q_TA[0]
Q_y=Q_TA[1]



def v_authcode(id):
    r_r = (secrets.randbits(32)) % n
    Ind =  ((m*s)+(id*r_r)) % n
    R=multiplication_calculator(r_r,Generator_P_x,Generator_P_y,a,b,q)
    
    return(Ind,R,id)

v_1authcode = v_authcode(secrets.randbits(256))

def id_check(v_authcode):
    
    Ind = v_authcode[0]
    R = v_authcode[1]
    R_x=R[0]
    R_y=R[1]
    id = v_authcode[2]
    N=multiplication_calculator(id,R_x,R_y,a,b,q)
    N_x=N[0]
    N_y=N[1]
    print(multiplication_calculator(Ind,Generator_P_x,Generator_P_y,a,b,q) == point_add(N_x,N_y,Q_x,Q_y,q))


def v_parameter(v_authcode):
    r_k=secrets.randbits(32)
    pk=r_k * v_authcode[0]
    Q=multiplication_calculator(pk,Generator_P_x,Generator_P_y,a,b,q)

    return(pk,Q,v_authcode)

v_1parameter=v_parameter(v_1authcode)


def Q_sss(AES_Q):
    n=15
    k=5
    shares=sss_depart(AES_Q,n,k)
    return(shares)


def Q_check(auth_bc):
    shares=auth_bc[2:]
    Q=AES_Decrypt(sss_recovery(shares))
    id_check(auth_bc[0])
    ecdsa_verf(auth_bc[1],Q)

def AEs_work(key,data):
    key=str(key)
    data_1=str(data[0])
    data_2=str(data[1])
    temp=(data_1,data_2)
    dot=','
    data3= dot.join(temp)
    data = ''.join(map(str, data3))
    pad = lambda s: s + (16 - len(s)%16) * chr(16 - len(s)%16)
    key=pad(key)
    enctext = AES_Encrypt(key, data)
    return(enctext)

def AEs_de_work(key,data):
    key=str(key)
    data = ''.join(map(str, data))
    pad = lambda s: s + (16 - len(s)%16) * chr(16 - len(s)%16)
    key=pad(key)
    output=AES_Decrypt(key,data)
    return(output)

def v_broadcast(v_parameter):
    v_1parameter=v_parameter
    print('v_para_size =',sys.getsizeof(v_1parameter))
    pk=v_1parameter[0]          #pk
    print('pk_size =',sys.getsizeof(pk))
    Q=v_1parameter[1]           #Q
    print('Q size =',sys.getsizeof(Q))
    v_authcode=v_parameter[2]  #(Ind,R,id)
    print('auth size =',sys.getsizeof(v_authcode))


    while(True):
        try:
            
            sign=ecdsa_sig(a,b,q,n,Generator_P_x,Generator_P_y,pk,Q)
            print(sign)
            ecdsa_verf(a,b,q,n,Generator_P_x,Generator_P_y,Q[0],Q[1],sign,Q)
            
            
            
            break

        except:
            pass
    
    aes_gk=AEs_work(gk,v_1parameter[1])
    print('Q_AES size =',sys.getsizeof(aes_gk))
    shares=Q_sss(aes_gk)
    print('shares_size=',sys.getsizeof(shares))


    print(sys.getsizeof((v_authcode,shares,sign)))
    return(v_authcode,shares,sign)



def got_broadcast(broadcast):
    
    authcode=broadcast[0]
    print('auth code = ',authcode)
    shares=broadcast[1]
    sign=broadcast[2]
    print('sign = ',sign)
    print('id auth check : ')
    id_check(authcode)
    recover=sss_recovery(shares)
    print('E[Q] = ',recover)
    
    
    Q_recover=AEs_de_work(gk,recover)
    Q_sp=Q_recover.split(',')
    Q_tp=tuple(Q_sp) 

    print('Q_ecdsa check : ')
    ecdsa_verf(a,b,q,n,Generator_P_x,Generator_P_y,Q_tp[0],Q_tp[1],sign,Q_tp)
    print('Q = ',Q_tp)


v=v_broadcast(v_1parameter)
print('v=',v)


s=sys.getsizeof(v[1])
print('size of v =',s)

print('')

got_broadcast(v)










"""
v_1 = v_authcode(1283857)
print('Ind,R,id = ',v_1)
v_1para=v_parameter(v_1)
print('v_1_parameter = pk , Q , Ind , R , id = ' ,v_1para)
aes_gk=AEs_work(gk,v_1para[1])
aes_gk_recover=AEs_de_work(gk,aes_gk)
print(aes_gk_recover)
shares=Q_sss(aes_gk)
recover=sss_recovery(shares)
Q_AEs_de_work=AEs_de_work(gk,recover)
print(Q_AEs_de_work)
                

#v=v_broadcast(v_1parameter)

#got_broadcast(v)


pk=v_1parameter[0]
Q=v_1parameter[1]

while(True):
    try:
        sig=ecdsa_sig(a,b,q,n,Generator_P_x,Generator_P_y,pk,Q)
        #Q_sign
        break

    except:
        pass

ecdsa_verf(a,b,q,n,Generator_P_x,Generator_P_y,Q[0],Q[1],sig,Q)

def v_broadcast(v_parameter):
    v_1parameter=v_parameter
    pk=v_1parameter[0]          #pk
    Q=v_1parameter[1]           #Q
    v_authcode=v_parameter[2]  #(Ind,R,id)

    while(True):
        try:
            sig=ecdsa_sig(a,b,q,n,Generator_P_x,Generator_P_y,pk,Q)
            #Q_sign
            break

        except:
            pass
    
    
    print(sig)
    return(sig)

Q=v_1parameter[1]  
sign=v_broadcast(v_1parameter)

ecdsa_verf(a,b,q,n,Generator_P_x,Generator_P_y,Q[0],Q[1],sign,Q)
"""