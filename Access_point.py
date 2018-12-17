# !/usr/bin/env python3
# coding:utf-8

from socket import *
import sys
import urllib.request
import ssl
from uuid import uuid4
import json
import threading
import random
from datetime import datetime
import git
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Cipher import PKCS1_OAEP
# from Crypto.Signature import pkcs1_15
# from Crypto.Hash import SHA256
import time
import os
import subprocess
from argparse import ArgumentParser
from tqdm import tqdm
from time import sleep

# Default address
HOST = "0.0.0.0"
VALID_PORT = 33845
NODE_ADDRESS = 'localhost'  # blockchain node
NODE_PORT = 5000

# To vender server
SERVER_PORT = 33846
TIME = 300  # =5min, 86400 = a day
TIMEOUT = 29

# For git. Default URL.
URL = 'git@github.com:ertlnagoya/Update_Test.git'
DIRECTORY = 'repo'

# For test.
VER = "3.0"

HASH = "f52d885484f1215ea500a805a86ff443"
FILE_NAME = 'Update_Test'

# Generate a globally unique address(ID).
sender = str(uuid4()).replace('-', '')

# RSA for client-server connection.
start = time.time()*1000
random_func = Random.new().read
rsa = RSA.generate(2048, random_func)
private_key = rsa.exportKey(format='PEM')
public_key = rsa.publickey().exportKey()
cipher = PKCS1_OAEP.new(RSA.importKey(public_key))

# *Oreore certificate
# requests.get("https://8.8.8.8", verify = False)
ssl._create_default_https_context = ssl._create_unverified_context

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
#print(pycolor.RED + "RED TEXT" + pycolor.END)

# For github
def git_clone():
    '''
    git clone from URL in DIRECTORY.
    '''
    _repo_path = os.path.join('./', DIRECTORY)
    # clone from remote
    git_repo = git.Repo.clone_from(
        URL, _repo_path, branch='master')
    return git_repo


def git_pull():
    '''
    git pull in DIRECTORY.
    '''
    repo = git.Repo(DIRECTORY)
    o = repo.remotes.origin
    o.pull()
    print("git pull:", o)


def get_git_revision_hash(dir):
    '''
    get hash of existing DIRECTORY.
    '''
    dir_name = "./" + dir
    os.chdir(dir_name)
    hash = subprocess.check_output(['git', 'rev-parse', 'HEAD'])
    os.chdir("./..")
    return hash


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
    verify randam number. return randam nuber from payload.
    '''
    data = []
    payload = str(payload).replace("b'", "").replace("'", "")
    data = payload.split("-")
    r = int(data[3])
    if (r_before + 2 - r) != 0:
        print(pycolor.RED, "Error: Rundam nuber. It may be Reply Attack!!", r, r_before, pycolor.END)
    # print(r)
    return r + 1


def randam_ini(payload):
    '''
    return randam nuber from payload.
    '''
    data = []
    data = payload.split("-")
    r = data[3]
    return int(r) + 1


def make_payload(sender, NODE, INFO, r):
    payload = (str(sender) + '-' + str(NODE) + '-' + str(INFO) + '-' + str(r))
    return payload.encode("UTF-8")


def new_transaction(address, state, sender_IoT):
    address_nt = 'https://' + address + '/transactions/new'
    data_nt = {
        # "counter": 1,  # TODO
        # "merkle tree": 
        "state": state, #random.randrange(3),
        "sender": sender_IoT, # IoT
        "recipient": sender, # Access_point
        # "digital signature": ,
        "ver": VER,
        "verifier": HASH
    }
    headers_nt = {
        'Content-Type': 'application/json',
    }
    # print(pycolor.YELLOW + json.dumps(data_nt, sort_keys = True, indent = 4) + pycolor.END)

    req = urllib.request.Request(
        address_nt, json.dumps(data_nt).encode(), headers_nt)
    try:
        with urllib.request.urlopen(req) as res:
            body = json.loads(res.read())
            print(pycolor.YELLOW, json.dumps(body, sort_keys = True, indent = 4), pycolor.END)
    except urllib.error.HTTPError as err:
        print(err.code)
    except urllib.error.URLError as err:
        print(err.reason)


def mine(address):
    address_m = 'https://' + address + '/mine'
    req = urllib.request.Request(address_m)
    try:
        with urllib.request.urlopen(req) as res:
            body = json.loads(res.read())
            print(pycolor.GREEN, json.dumps(body, sort_keys = True, indent = 4), pycolor.END)

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
            body = json.loads(res.read())
            print(pycolor.YELLOW, json.dumps(body, sort_keys = True, indent = 4), pycolor.END)
    except urllib.error.HTTPError as err:
        print(err.code)
    except urllib.error.URLError as err:
        print(err.reason)


def transaction(address, state, sender_IoT):
    print(pycolor.CYAN, "[server] Transaction: ", pycolor.END)
    new_transaction(address, state, sender_IoT)
    # print(pycolor.BLUE, "[server] Transaction finish!!", pycolor.END)
    print(pycolor.CYAN, "[server] Mining: ", pycolor.END)
    # demo (Probably management server instract mining)
    mine(address)
    # print(pycolor.BLUE, "[server] Transaction finish!!", pycolor.END)
    # print(chain(address))
    


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
    '''
    It is client function to connect management server.
    '''

    print("------------------------------------------------------------------------------------------------------------")
    try:
        # open csv
        dict = open_csv()
        # print(dict)
        for key in dict['data']:
            VER = key['ver']
            #HASH = key['hash']

        # client to vender server
        # print("現在のスレッドの数: ", str(threading.activeCount()))
        print(pycolor.CYAN, "[client]", threading.currentThread().getName(), pycolor.END)

        # random number for countermeasure to reply attack.
        r = random.randrange(1000)

        # conection
        soc = socket(AF_INET)
        # timeout
        soc.settimeout(TIMEOUT)
        soc.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        soc.connect((HOST, SERVER_PORT))
        print(pycolor.CYAN, "[client] Connecting to %s:%s" % (HOST, SERVER_PORT), pycolor.END)
        # verbose_ping(sys.argv[12)

        soc.sendall(public_key)
        payload = soc.recv(1024)
        print(pycolor.CYAN, "[client] send public_key: ", pycolor.YELLOW, payload, pycolor.END)
        public_server_key = payload

        # req_vercheck
        payload = make_payload(sender, "nomalnode", VER, r)
        cipher = PKCS1_OAEP.new(RSA.importKey(public_server_key))
        print(pycolor.CYAN, "[client] First send: ", pycolor.YELLOW, payload, pycolor.END)
        payload = cipher.encrypt(payload)
        soc.sendall(payload)

        # Generates verifier H(fv) after checking res_verchk message c1-1-4
        payload = soc.recv(1024)
        cipher = PKCS1_OAEP.new(RSA.importKey(private_key))
        payload = str(cipher.decrypt(payload))
        print(pycolor.CYAN, "[client] First payload receive from server: ", pycolor.YELLOW, payload, pycolor.END)

        data = payload.split("-")
        r = randam(payload, r - 1)
        comp = float(data[2])

        if float(VER) == comp:
            # req_verification
            print(pycolor.CYAN, "[client] Version check: req = res!", pycolor.END)
            payload = make_payload(sender, "nomalnode", HASH, r)
            cipher = PKCS1_OAEP.new(RSA.importKey(public_server_key))
            print(pycolor.CYAN, "[client] Second payload send: ", pycolor.YELLOW, payload, pycolor.END)
            payload = cipher.encrypt(payload)
            soc.sendall(payload)

            # Verifies and decrypts res_verification message,
            # and compares H(fv) and H(fvnew c1-1-8
            payload = soc.recv(1024)
            cipher = PKCS1_OAEP.new(RSA.importKey(private_key))
            payload = str(cipher.decrypt(payload))
            print(pycolor.CYAN, "[client] Second payload receive from server: ", pycolor.YELLOW, payload, pycolor.END)
            data = payload.split("-")
            # print("c1-1-8: " + data[3])

            if str(HASH) == str(data[2]):
                print(pycolor.CYAN, "[client] Hash is same!! Download is unnecessary.", pycolor.END)
            else:
                print(pycolor.CYAN, "[client] The hash is not latest! Download start!", pycolor.END)

                # Download from Github & data store
                git_pull()
                # VER = comp
                write_csv(dict, comp, URL, HASH)
                address = NODE_ADDRESS + ':' + str(NODE_PORT)
                # verify(address)
                #transaction(address, state)
                #ine(address)

        else:
            print(pycolor.CYAN, "[client] It is not latest! Download start!", pycolor.END)

            # Reqest for download
            r = randam(payload, r - 3)
            payload = make_payload(sender, "nomalnode", 'Download', r)
            cipher = PKCS1_OAEP.new(RSA.importKey(public_server_key))
            print(pycolor.CYAN, "[client] First send: ", pycolor.YELLOW, payload, pycolor.END)
            payload = cipher.encrypt(payload)
            soc.sendall(payload)

            # Downloads and installs the latest firmware file
            # after checking res_download message]
            payload = soc.recv(1024)
            cipher = PKCS1_OAEP.new(RSA.importKey(private_key))
            payload = str(cipher.decrypt(payload))
            print(pycolor.CYAN, "[client] Second receive from server: ", pycolor.YELLOW, str(payload), pycolor.CYAN)
            data = payload.split("-")
            soc.close()

            # Download from Github & data store
            # git_pull()
            write_csv(dict, comp, URL, HASH)
            address = NODE_ADDRESS + ':' + str(NODE_PORT)
            # verify(address)
            # transaction(address, state)
            # mine(address)
    except OSError as e:
        print(pycolor.RED, "[*] clientsock error.", pycolor.END)

    soc.close()
    print(pycolor.CYAN, "[client] Client function: Finish!!", pycolor.END)

    # Thread
    t = threading.Timer(TIME, client)
    t.start()
    print("------------------------------------------------------------------------------------------------------------")
            


def open_csv():
    '''
    Read data from csv file.
    '''
    file = open("Access_point.csv", 'r')
    dict = json.load(file)
    # print(dict)
    file.close()
    return dict


def write_csv(dict, VER, URL, HASH):
    '''
    Write data to csv file.
    '''
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


# For HTTPS conection (password:pass)
sslctx = ssl.create_default_context()
sslctx.load_cert_chain('cert.crt', 'server_secret.key')

# define
HASH = str(get_git_revision_hash(DIRECTORY)).replace("b'", "").replace("'", "")
print(pycolor.BLUE, "HASH: ", get_git_revision_hash(DIRECTORY), pycolor.END)
METADATA = FILE_NAME + ";" + HASH + ";" + "len" + ";" + HOST
# "file_name+file_hash+piece_length+valid_node_URL"
DOWNLOAD = URL + ";" + HASH  # "file_URL+file_hash+len"

def visualize(address):
    data = json.loads(chain(address))
    #data = data[1:]
    #data =data[:-1]
    print(pycolor.YELLOW, json.dumps(data, sort_keys = True, indent = 4), pycolor.END)


def server(clientsock, addr):
    # print(clientsock, addr)
    while True:
        try:
            # open csv file
            dict = open_csv()
            # print(dict)
            for key in dict['data']:
                VER = key['ver']
                HASH = key['hash']

            # first receive
            payload = clientsock.recv(1024)
            if len(payload) == 0:
                break
            print(pycolor.CYAN, "[server] Key reception: ", pycolor.YELLOW, payload, pycolor.END)
            public_client_key = payload

            # send public key to client
            clientsock.sendall(public_key)
            print(pycolor.CYAN, "[server] public_client_key: ", pycolor.YELLOW, public_client_key, pycolor.END)

            # second receive
            payload = clientsock.recv(1024)
            if len(payload) == 0:
                break
            cipher = PKCS1_OAEP.new(RSA.importKey(private_key))
            payload = cipher.decrypt(payload)
            print(pycolor.CYAN, "[server] Version info reception: ", pycolor.YELLOW, payload, pycolor.END)
            payload = payload.decode("UTF-8")


            # make rundom number
            r = randam_ini(payload)
            
            data = payload.split("-")
            sender_IoT = data[0]
            # print("sender(IoT):", sender_IoT)

            comp_ver = float(data[2])
            # print(payload, comp_ver)

            if random.randrange(3) == random.randrange(3) :
                raise OSError("Error.")
            
            # response of version check
            payload = make_payload(sender, "Access_point", VER, r)
            print(pycolor.CYAN, "[server] send version: ", pycolor.YELLOW, payload, pycolor.END)
            cipher = PKCS1_OAEP.new(RSA.importKey(public_client_key))
            payload = cipher.encrypt(payload)
            clientsock.sendall(payload)

            # hash info receive
            payload = clientsock.recv(1024)
            if len(payload) == 0:
                break
            cipher = PKCS1_OAEP.new(RSA.importKey(private_key))
            payload = cipher.decrypt(payload)
            print(pycolor.CYAN, "[server] Reception:", pycolor.YELLOW, payload, pycolor.END)
            payload = payload.decode("UTF-8")
            data = payload.split("-")
            comp_hash = data[2]

            # response of hash check
            r = randam(payload, r-1)
            payload = make_payload(sender, "Access_point", HASH, r)
            print(pycolor.CYAN, "[server] send hash: ", pycolor.YELLOW, payload, pycolor.END)
            cipher = PKCS1_OAEP.new(RSA.importKey(public_client_key))
            payload = cipher.encrypt(payload)
            clientsock.sendall(payload)

            # version & hash compare
            # : TODO


            if float(VER) == comp_ver:
                if HASH == comp_hash:
                    print(pycolor.CYAN, "[server] Version is same!! Download is unnecessary.", pycolor.END)
                    state = "unnecessary"
                else:
                    # update(demo)
                    print(pycolor.CYAN, "[server] The hash is not latest! Download start!", HASH, comp_hash, pycolor.END)
                    print(pycolor.CYAN, "[server] Updating(demo): ", pycolor.END)
                    for i in tqdm(range(50)):
                        sleep(0.1)
                    state = "success"
            else:
                # update(demo)
                print(pycolor.CYAN, "[server] The version is not latest! Download start!", pycolor.END)
                print(pycolor.CYAN, "[server] Updating(demo): ", pycolor.END)
                for i in tqdm(range(50)):
                    sleep(0.1)
                state = "success"

        except OSError as e:
            print(pycolor.RED, "[server] socket error.(demo)", pycolor.END)
            state = "false"

        # write blockchain node
        address = NODE_ADDRESS + ':' + str(NODE_PORT)
        # verify(address)
        # mine(address)
        transaction(address, state, sender_IoT)
        # visualize(address)
     
    clientsock.close()
    print(pycolor.CYAN, "[server] Finish!!", pycolor.END)

    # output for demo
    print("------------------------------------------------------------------------------------------------------------")
    print()
    print()
    print()
    print()
    print()
    print()



if __name__ == '__main__':
    data = []
    key = []
    public_client_key = ''
    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=33846, type=int, help='port of server')
    parser.add_argument('-a', '--address', default="0.0.0.0", type=str, help='address of server')
    args = parser.parse_args()
    SERVER_PORT = args.port
    HOST = args.address

    while True:
        # open csv
        dict = open_csv()
        # print(dict)
        for key in dict['data']:
            VER = key['ver']
            HASH = key['hash']

        # client thread
        t=threading.Thread(target=client)
        t.start()

        # conection
        s = socket(AF_INET)
        s.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        print(pycolor.CYAN, "[server] waiting for connection at %s:%s" % (HOST, VALID_PORT), pycolor.END)
        s.bind((HOST, VALID_PORT))
        s.listen(1)

        # server thread
        while True:
            conn, addr = s.accept()
            # sys.stdout.write("\r{}".format("[server] connection from: %s:%s" % addr))
            # sys.stdout.flush()

            # output for demo
            print("------------------------------------------------------------------------------------------------------------")
            
            print(pycolor.CYAN, "[server] connection from: %s:%s" % addr, pycolor.END)
            handle_thread = threading.Thread(target=server,
                                             args=(conn, addr),
                                             daemon=True)
            handle_thread.start()
