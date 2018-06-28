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
import random
from datetime import datetime
import git
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import time
import subprocess

# label = subprocess.check_output(["git", "describe"]).strip()
def get_git_revision_hash():
    return subprocess.check_output(['git', 'rev-parse', 'HEAD'])

def get_git_revision_short_hash():
    return subprocess.check_output(['git', 'rev-parse', '--short', 'HEAD'])
print(get_git_revision_hash())
print(get_git_revision_short_hash())

HOST = "0.0.0.0"
NOMAL_PORT = 33844
VALID_PORT = 33845
NODE_ADDRESS = 'localhost'
NODE_PORT = 5000

# To vender server
SERVER_PORT = 33846
TIME = 300  # 5min

# For git
URL = 'git@github.com:ertlnagoya/Update_Test.git'
DIRECTORY = 'repo'

# For test
VER = "0"
HASH = "f52d885484f1215ea500a805a86ff443"
URL = 'git@github.com:ertlnagoya/Update_Test.git'
FILE_NAME = 'Update_Test'
METADATA = FILE_NAME + ";" + HASH + ";" + "len" + ";" + HOST
# "file_name+file_hash+piece_length+valid_node_URL"
DOWNLOAD = URL + ";" + HASH  # "file_URL+file_hash+len"


# Generate a globally unique address
sender = str(uuid4()).replace('-', '')

# RSA
start = time.time()*1000
random_func = Random.new().read
rsa = RSA.generate(2048, random_func)
private_key = rsa.exportKey(format='PEM')
public_key = rsa.publickey().exportKey()
cipher = PKCS1_OAEP.new(RSA.importKey(public_key))

# *Oreore certificate
# requests.get("https://8.8.8.8", verify = False)
ssl._create_default_https_context = ssl._create_unverified_context


def git_clone():
    _repo_path = os.path.join('./', DIRECTORY)
    # clone from remote
    git_repo = git.Repo.clone_from(
        URL, _repo_path, branch='master')


def git_pull():
    repo = git.Repo(DIRECTORY)
    o = repo.remotes.origin
    o.pull()
    print(o)


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

    soc.sendall(public_key)
    payload = soc.recv(1024)
    print("[*] public_key:", payload)
    public_server_key = payload

    # req_vercheck c1-1-1
    payload = make_payload(sender, "nomalnode", VER, r)
    cipher = PKCS1_OAEP.new(RSA.importKey(public_server_key))
    print("[*] c1-1-1:send", payload)
    payload = cipher.encrypt(payload)
    soc.sendall(payload)

    # Generates verifier H(fv) after checking res_verchk message c1-1-4
    payload = soc.recv(1024)
    cipher = PKCS1_OAEP.new(RSA.importKey(private_key))
    payload = str(cipher.decrypt(payload))
    print("[*] Receive from server 1: ", payload)

    data = payload.split("-")
    r = randam(payload, r - 1)
    comp = float(data[2])

    if float(VER) == comp:
        # req_verification c1-1-5
        print("[*] Version check: req = res!")
        payload = make_payload(sender, "nomalnode", HASH, r)
        cipher = PKCS1_OAEP.new(RSA.importKey(public_server_key))
        print("[*] c1-1-5:send", payload)
        payload = cipher.encrypt(payload)
        soc.sendall(payload)

        # Verifies and decrypts res_verification message,
        # and compares H(fv) and H(fvnew c1-1-8
        payload = soc.recv(1024)
        payload = payload.decode("UTF-8")
        payload = decrypt(payload, private_key)
        print("[*] Receive from server 2: ", payload)
        data = payload.split("-")
        # print("c1-1-8: " + data[3])

        if str(HASH) == str(data[2]):
            print("[*] SAME!!")
        else:
            print("[*] The hash is not latest! Download start!")

            # Download from Github & data store
            git_pull()
            # VER = comp
            write_csv(dict, comp, URL, HASH)
            address = NODE_ADDRESS + ':' + str(NODE_PORT)
            # verify(address)
            # mine(address)
            transaction(address)

    else:
        print("[*] It is not latest! Download start!")

        # req_download c1-2-5
        r = randam(payload, r - 3)
        payload = make_payload(sender, "nomalnode", 'Download', r)
        cipher = PKCS1_OAEP.new(RSA.importKey(public_server_key))
        print("[*] c1-2-5:send", payload)
        payload = cipher.encrypt(payload)
        soc.sendall(payload)

        # Downloads and installs the latest firmware file 
        # after checking res_download message c1-2-8
        payload = soc.recv(1024)
        cipher = PKCS1_OAEP.new(RSA.importKey(private_key))
        payload = str(cipher.decrypt(payload))
        print("[*] Receive from server 2: " + str(payload))
        data = payload.split("-")
        soc.close()

        # Download from Github & data store
        git_pull()
        write_csv(dict, comp, URL, HASH)
        address = NODE_ADDRESS + ':' + str(NODE_PORT)
        # verify(address)
        # mine(address)
        transaction(address)

    
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
    # public_key, private_key = generate_keys(101, 3259)
    # print("public_key:", public_key)
    # print("private_key:", private_key)

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
        print("[*] Reception0: " + str(payload))
        conn.sendall(public_key)
        public_client_key = payload  # tuple_key(payload)
        print("public_client_key", public_client_key)

        payload = conn.recv(1024)
        if len(payload) == 0:
            break
        cipher = PKCS1_OAEP.new(RSA.importKey(private_key))
        payload = cipher.decrypt(payload)
        print("[*] Reception1: " + str(payload))
        payload = payload.decode("UTF-8")


        # print(type(key))
        # print(tuple(public_key))
        # print(type(public_key))

        r = randam_ini(payload)
        data = payload.split("-")

        if str(data[1]) == "nomalnode":
            #  res_verchk c1-1-3
            payload = make_payload(sender, 'validnode', VER, r)
            cipher = PKCS1_OAEP.new(RSA.importKey(public_client_key))
            payload = cipher.encrypt(payload)  # encrypt(payload, tuple(public_client_key))
            #payload = payload.encode("UTF-8")
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

            address = NODE_ADDRESS + ':' + str(NODE_PORT)
            # verify(address)
            # mine(address)
            transaction(address)

        print("[*] Finish!!")

    conn.close()
