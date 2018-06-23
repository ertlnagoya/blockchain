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
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256


HOST = "0.0.0.0"
VALID_PORT = 33845
NODE_ADDRESS = 'localhost'
NODE_PORT = 5000

# To vender server
SERVER_PORT = 33846
TIME = 300 # 5min

# For test
VER = "3.0"
HASH = "f52d885484f1215ea500a805a86ff443"
URL = 'git@github.com:ertlnagoya/Update_Test.git'
FILE_NAME = 'Update_Test'
METADATA = FILE_NAME + ";" + HASH + ";" + "len" + ";" + HOST
# "file_name+file_hash+piece_length+valid_node_URL"
DOWNLOAD = URL + ";" + HASH  # "file_URL+file_hash+len"


# Generate a globally unique address for this
sender = str(uuid4()).replace('-', '')

# RSA
start = time.time()*1000
random_func = Random.new().read
rsa = RSA.generate(2048, random_func)
private_key = rsa.exportKey(format='PEM')
public_key = rsa.publickey().exportKey()
cipher = PKCS1_OAEP.new(RSA.importKey(public_key))

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


def randam(payload, r_before):
    '''
    return randam nuber from payload
    '''
    data = []
    payload = str(payload).replace("b'", "").replace("'", "")
    data = payload.split("-")
    r = int(data[3])
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
    r = data[3]
    return int(r) + 1

def make_payload(sender, NODE, INFO, r):
    payload = (str(sender) + '-' + str(NODE) + '-' + str(INFO) + '-' + str(r))
    return payload.encode("UTF-8")


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




while True:
    data = []
    key = []
    public_client_key = ''

    if len(sys.argv) == 2:
        SERVER_PORT = argv[1]
        print("[*] Port: ", SERVER_PORT)
    else:
        print("[*] Default port:", SERVER_PORT)
        # sys.exit()

    # conection
    s = socket(AF_INET)
    s.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    print("[*] waiting for connection at %s:%s" % (HOST, SERVER_PORT))
    s.bind((HOST, SERVER_PORT))
    s.listen(1)
    conn, addr = s.accept()
    print("[*] connection from: %s:%s" % addr)

    while True:
        payload = conn.recv(1024)
        if len(payload) == 0:
            break
        print("[*] Reception0: ", str(payload))
        conn.sendall(public_key)
        public_client_key = payload  # tuple_key(payload)
        print("public_client_key", public_client_key)

        # Obtains vnew and Mvnew from its database c1-1-2
        payload = conn.recv(1024)
        if len(payload) == 0:
            break
        print("[*] Reception1: ", str(payload))
        cipher = PKCS1_OAEP.new(RSA.importKey(private_key))
        payload = cipher.decrypt(payload)

        payload = payload.decode("UTF-8")
        r = randam_ini(payload)
        data = payload.split("-")

        if str(data[1]) == "nomalnode":
            #  res_verchk c1-1-3
            payload = make_payload(sender, 'validnode', VER, r)
            cipher = PKCS1_OAEP.new(RSA.importKey(public_client_key))
            payload = cipher.encrypt(payload)
            conn.sendall(payload)

            # Verifies and decrypts req_download message, and checks H(fvnew) c1-1-6
            payload = conn.recv(1024)
            if len(payload) == 0:
                break
            cipher = PKCS1_OAEP.new(RSA.importKey(private_key))
            payload = cipher.decrypt(payload)
            print("[*] Reception: c1-1-6", payload)

            # es_download c1-1-7
            r = randam(payload, r-1)
            payload = make_payload(sender, 'validnode', HASH, r)
            cipher = PKCS1_OAEP.new(RSA.importKey(public_client_key))
            payload = cipher.encrypt(payload)
            conn.sendall(payload)

            # version & hash compare

            # address = NODE_ADDRESS + ':' + str(NODE_PORT)
            # verify(address)
            # mine(address)
            # transaction(address)
            print("waiting...")

        print("[*] Finish!!")

    conn.close()
