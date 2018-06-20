# !/usr/bin/env python3
# coding:utf-8

from socket import *
import sys
import urllib.request
import ssl
from uuid import uuid4
from fractions import gcd
import json
import threading
import time
import random
from datetime import datetime



HOST = "0.0.0.0"
NOMAL_PORT = 33844
VALID_PORT = 33845
NODE_ADDRESS = 'localhost'
NODE_PORT = 5000

# To vender server
SERVER_PORT = 33846
TIME = 300 # 5min

# For test
VER = "1"
HASH = "f52d885484f1215ea500a805a86ff443"
URL = 'git@github.com:ertlnagoya/Update_Test.git'
FILE_NAME = 'Update_Test'
METADATA = FILE_NAME + ";" + HASH + ";" + "len" + ";" + HOST
# "file_name+file_hash+piece_length+valid_node_URL"
DOWNLOAD = URL + ";" + HASH  # "file_URL+file_hash+len"


# Generate a globally unique address for this
sender = str(uuid4()).replace('-', '')

# Oreore certificate
# requests.get("https://8.8.8.8", verify = False)
ssl._create_default_https_context = ssl._create_unverified_context


def recv_until(c, delim="\n"):
    res = c.recv(1024)
    if len(res) == 0:
        return ""
    while not res[-1] == delim:
        data = c.recv(1024)
        if len(data) == 0:
            return res
        res += data
    return res


def lcm(p, q):
    return (p * q) // gcd(p, q)


def generate_keys(p, q):
    N = p * q
    L = lcm(p - 1, q - 1)
    for i in range(2, L):
        if gcd(i, L) == 1:
            E = i
            break
    for i in range(2, L):
        if (E * i) % L == 1:
            D = i
            break
    return (E, N), (D, N)


def encrypt(plain_text, public_key):
    E, N = public_key
    plain_integers = [ord(char) for char in plain_text]
    encrypted_integers = [i ** E % N for i in plain_integers]
    encrypted_text = ''.join(chr(i) for i in encrypted_integers)
    return encrypted_text


def decrypt(encrypted_text, private_key):
    D, N = private_key
    encrypted_integers = [ord(char) for char in encrypted_text]
    decrypted_intergers = [i ** D % N for i in encrypted_integers]
    decrypted_text = ''.join(chr(i) for i in decrypted_intergers)
    return decrypted_text


def tuple_key(payload):
    '''
    return public_key from payload
    '''
    data = []
    key = []
    public_client_key = ''
    data = payload.split("-")
    data[0] = data[0].replace('(', '')
    data[0] = data[0].replace(')', '')
    key = data[0].split(",")
    key[0] = int(key[0])
    key[1] = int(key[1])
    return tuple(key)


def randam(payload, r_before):
    '''
    return randam nuber from payload
    '''
    data = []
    data = payload.split("-")
    r = int(data[4])
    if (r_before + 2 - r) != 0:
        print("Error: Rundam nuber. It may be Reply Attack!!", r, r_before)
    # print(r)
    return r + 1


def randam_ini(payload):
    '''
    return randam nuber from payload
    '''
    data = []
    data = payload.split("-")
    r = data[4]
    return int(r) + 1


def make_payload(public_key, sender, NODE, INFO, r):
    payload = (str(public_key) + '-' + sender + '-' + NODE + '-'
                + str(INFO) + '-' + str(r))
    return payload

# For HTTPS conection
# sslctx = ssl.create_default_context()
# sslctx.load_cert_chain('cert.crt', 'server_secret.key')


def new_transaction(address):
    address_nt = 'https://' + address + '/transactions/new'
    data_nt = {
        "counter": 1,
        # "merkle tree": ,
        "sender": sender,
        "recipient": "someone-other-address",
        # "digital signature": ,
        "verifier": HASH
    }
    headers_nt = {
        'Content-Type': 'application/json',
    }

    req = urllib.request.Request(
        address_nt, json.dumps(data_nt).encode(), headers_nt)
    try:
        with urllib.request.urlopen(req) as res:
            body = res.read()
            print(body)
    except urllib.error.HTTPError as err:
        print(err.code)
    except urllib.error.URLError as err:
        print(err.reason)


def mine(address):
    address_m = 'https://' + address + '/mine'
    req = urllib.request.Request(address_m)
    try:
        with urllib.request.urlopen(req) as res:
            body = res.read()
            print(body)
    except urllib.error.HTTPError as err:
        print(err.code)
    except urllib.error.URLError as err:
        print(err.reason)


def chain(address):
    address_c = 'https://' + address + '/chain'
    req = urllib.request.Request(address_c)
    try:
        with urllib.request.urlopen(req) as res:
            body = res.read()
            # print(body)
            return body
    except urllib.error.HTTPError as err:
        print(err.code)
        return -1
    except urllib.error.URLError as err:
        print(err.reason)
        return -1


def resolve(address):
    address_r = 'https://' + address + '/nodes/resolve'
    req = urllib.request.Request(address_r)
    try:
        with urllib.request.urlopen(req) as res:
            body = res.read()
            print(body)
    except urllib.error.HTTPError as err:
        print(err.code)
    except urllib.error.URLError as err:
        print(err.reason)


def transaction(address):
    print("Transaction start.")
    new_transaction(address)
    mine(address)
    # print(chain(address))
    print("Transaction finish!!")


def search_version(address):
    ver = 0
    print("[*] Search start.")
    data = json.loads(chain(address))
    print(json.dumps(data, sort_keys=True, indent=4))
    keylist = data.keys()
    # print()
    print(keylist)
    for key in data['chain']:
        count = key['index']
        for key_next in key['transactions']:
            if key_next != "[]":
                if key_next['sender'] == sender:
                    # print(key_next)
                    # print(key_next['url'])
                    # index = count
                    # print(index)
                    ver = key_next['ver']
                    # print(key_next['ver'])
    # print(ver)
    return ver

    print("[*] Search finish.")


def verify(address):
    # search
    ver = search_version(address)
    print("[*] Blockchain version: " + str(ver))


def client():
    # open csv
    dict = open_csv()
    # print(dict)
    for key in dict['data']:
        VER = key['ver']
        HASH = key['hash']

    # client to vender server
    # print("現在のスレッドの数: ", str(threading.activeCount()))
    print(threading.currentThread().getName())
    r = random.randrange(1000)

    # conection
    soc = socket(AF_INET)
    soc.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    soc.connect((HOST, SERVER_PORT))
    print("[*] Connecting to %s:%s" % (HOST, SERVER_PORT))
    #verbose_ping(sys.argv[12)

    # req_vercheck c1-1-1
    payload = make_payload(public_key, sender, "nomalnode", VER, r)
    soc.sendall(payload.encode("UTF-8"))
    print("[*] Send to server 1: ", payload)

    # Generates verifier H(fv) after checking res_verchk message c1-1-4
    payload = soc.recv(1024)
    payload = payload.decode("UTF-8")
    payload = decrypt(payload, private_key)
    print("[*] Receive from server 1: ", payload)
    public_server_key = tuple_key(payload)
    # print("[*] public_server_key", public_server_key)

    data = payload.split("-")
    r = randam(payload, r - 1)
    comp = int(data[3])

    if int(VER) == comp:
        # req_verification c1-1-5
        print("[*] Version check: req = res!")
        payload = make_payload(public_key, sender, "nomalnode", HASH, r)
        print("[*] Send to server 2: ", payload)
        payload = encrypt(payload, tuple(public_server_key))
        # print(payload)
        payload = payload.encode("UTF-8")
        soc.sendall(payload)

        # Verifies and decrypts res_verification message,
        # and compares H(fv) and H(fvnew c1-1-8
        payload = soc.recv(1024)
        payload = payload.decode("UTF-8")
        payload = decrypt(payload, private_key)
        print("[*] Receive from server 2: ", payload)
        data = payload.split("-")
        # print("c1-1-8: " + data[3])

        if str(HASH) == str(data[3]):
            print("[*] SAME!!")
        else:
            print("[*] The hash is not latest! Download start!")
            git_pull()
            #VER = comp
            write_csv(dict, comp, URL, HASH)

    else:
        print("[*] It is not latest! Download start!")

        # req_download c1-2-5
        r = randam(payload, r - 3)
        payload = make_payload(public_key, sender, "nomalnode", 'Download', r)
        print("[*] Send to server 2: ", payload)
        payload = encrypt(payload, tuple(public_server_key))
        payload = payload.encode("UTF-8")
        soc.sendall(payload)

        # Downloads and installs the latest firmware file 
        # after checking res_download message c1-2-8
        payload = soc.recv(1024)
        payload = payload.decode("UTF-8")
        payload = decrypt(payload, private_key)
        print("[*] Receive from server 2: " + str(payload))
        data = payload.split("-")
        soc.close()

        git_pull()
        #VER = comp
        write_csv(dict, ccomp, URL, HASH)

    
    soc.close()
    print("[*] Finish!!")
    t=threading.Timer(TIME, client)
    t.start()


def open_csv():
    file = open("Access_point.csv", 'r')
    dict = json.load(file)
    # print(dict)
    file.close()
    return dict


def write_csv(dict, VER, URL, HASH):
    # dict.update(dict_add)
    dict_add = {
        "ver": VER,
        "url": URL, 
        "hash": HASH,
        "time": datetime.now().strftime("%Y/%m/%d %H:%M:%S")
    }
    dict['data'].append(dict_add)
    file = open("Access_point.csv", 'w')
    print(dict)
    json.dump(dict, file, indent=4)
    file.close()

while True:
    data = []
    key = []
    public_client_key = ''

    if len(sys.argv) == 2:
        VALID_PORT = argv[1]
        print("[*] Port: ", VALID_PORT)
    else:
        print("[*] Default port:", VALID_PORT)
        # sys.exit()

    # open csv
    dict = open_csv()
    # print(dict)
    for key in dict['data']:
        VER = key['ver']
        HASH = key['hash']


    # RSA
    public_key, private_key = generate_keys(101, 3259)
    print("public_key:", public_key)
    print("private_key:", private_key)

    t=threading.Thread(target=client)
    t.start()

    # conection
    s = socket(AF_INET)
    s.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    print("[*] waiting for connection at %s:%s" % (HOST, VALID_PORT))
    s.bind((HOST, VALID_PORT))
    s.listen(1)
    conn, addr = s.accept()
    print("[*] connection from: %s:%s" % addr)



    while True:
        # open csv
        dict = open_csv()
        # print(dict)
        for key in dict['data']:
            VER = key['ver']
            HASH = key['hash']
        # Obtains vnew and Mvnew from its database c1-1-2
        payload = conn.recv(1024)
        if len(payload) == 0:
            break
        print("[*] Reception1: " + str(payload))
        payload = payload.decode("UTF-8")

        public_client_key = tuple_key(payload)
        print("public_client_key", public_client_key)
        # print(type(key))
        # print(tuple(public_key))
        # print(type(public_key))

        r = randam_ini(payload)
        data = payload.split("-")

        if str(data[2]) == "nomalnode":
            #  res_verchk c1-1-3
            payload = make_payload(public_key, sender, 'validnode', VER, r)
            payload = encrypt(payload, tuple(public_client_key))
            payload = payload.encode("UTF-8")
            conn.sendall(payload)

            # Verifies and decrypts req_download message, and checks H(fvnew) c1-1-6
            payload = conn.recv(1024)
            if len(payload) == 0:
                break
            payload = payload.decode("UTF-8")
            payload = decrypt(payload, private_key)
            print("[*] Reception: c1-1-6", payload)

            # es_download c1-1-7
            r = randam(payload, r-1)
            payload = make_payload(public_key, sender, 'validnode', HASH, r)
            payload = encrypt(payload, tuple(public_client_key))
            payload = payload.encode("UTF-8")
            conn.sendall(payload)

            # version & hash compare

            address = NODE_ADDRESS + ':' + str(NODE_PORT)
            # verify(address)
            # mine(address)
            transaction(address)
            print("waiting...")

        print("[*] Finish!!")

    conn.close()
