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
import threading
from tqdm import tqdm
from time import sleep


HOST = "0.0.0.0"
NODE_ADDRESS = 'localhost'
NODE_PORT = 5000

# vender server
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

class pycolor:
    BLACK = '\033[30m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    PURPLE = '\033[35m'
    CYAN = '\033[36m'
    WHITE = '\033[37m'
    END = '\033[0m'
    BOLD = '\038[1m'
    UNDERLINE = '\033[4m'
    INVISIBLE = '\033[08m'
    REVERCE = '\033[07m'

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

    print(pycolor.CYAN, "[*] Search finish.", pycolor.END)


def verify(address):
    # search
    ver = search_version(address)
    print(pycolor.CYAN, "[*] Blockchain version: ", pycolor.YELLOW, ver, pycolor.END)


def server(clientsock, addr):
    print(pycolor.CYAN, "[*] connection from: %s:%s" % addr, pycolor.END)

    while True:
        try:
            # receive public key
            payload = conn.recv(1024)
            if len(payload) == 0:
                break
            conn.sendall(public_key)
            public_client_key = payload
            print(pycolor.CYAN, "Receive public key of client", pycolor.YELLOW, public_client_key, pycolor.END)

            # receive version info
            payload = conn.recv(1024)
            if len(payload) == 0:
                break
            print(pycolor.CYAN, "[*] receive version: ", pycolor.YELLOW, payload, pycolor.END)
            cipher = PKCS1_OAEP.new(RSA.importKey(private_key))
            payload = cipher.decrypt(payload)

            payload = payload.decode("UTF-8")
            r = randam_ini(payload)
            data = payload.split("-")

            # send verion info
            payload = make_payload(sender, 'validnode', VER, r)
            cipher = PKCS1_OAEP.new(RSA.importKey(public_client_key))
            payload = cipher.encrypt(payload)
            conn.sendall(payload)

            # receive hash info
            payload = conn.recv(1024)
            if len(payload) == 0:
                break
            cipher = PKCS1_OAEP.new(RSA.importKey(private_key))
            payload = cipher.decrypt(payload)
            print(pycolor.CYAN, "[*] Reception: c1-1-6", pycolor.YELLOW, payload, pycolor.END)

            # send hash info
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
            print(pycolor.CYAN, "waiting...", pycolor.END)

            print(pycolor.CYAN, "[*] Finish!!", pycolor.END)

        except OSError as e:
            print(pycolor.RED, "[server] socket error.(demo)", pycolor.END)

    conn.close()

while True:
    data = []
    key = []
    public_client_key = ''

    # conection
    s = socket(AF_INET)
    s.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    print(pycolor.CYAN, "[*] waiting for connection at %s:%s" % (HOST, SERVER_PORT), pycolor.END)
    s.bind((HOST, SERVER_PORT))
    s.listen(1)

    while True:
        conn, addr = s.accept()
        print(pycolor.CYAN, "[server] connection from: %s:%s" % addr, pycolor.END)
        handle_thread = threading.Thread(target=server,
                                         args=(conn, addr),
                                         daemon=True)
        handle_thread.start()
 
    conn.close()


