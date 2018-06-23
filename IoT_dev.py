# !/usr/bin/env python3
# coding:utf-8

import sys
import os
import git
from sys import argv
from socket import *
import socket as Socket
from uuid import uuid4
from fractions import gcd
import random
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import time


HOST = "0.0.0.0"
VALID_PORT = 33845


# For git
URL = 'git@github.com:ertlnagoya/Update_Test.git'
DIRECTORY = 'repo'

# For test
VER = "3.0"
HASH = "f52d885484f1215ea500a805a86ff443"
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
    payload = payload.replace("b'", "").replace("'", "")
    data = payload.split("-")
    r = int(data[3])
    if (r_before + 2 - r) != 0:
        print("Error: Rundam nuber. It may be Reply Attack!!", r, r_before)
    # print(r)
    return r + 1


def make_payload(sender, NODE, INFO, r):
    payload = (str(sender) + '-' + str(NODE) + '-' + str(INFO) + '-' + str(r))
    return payload.encode('UTF-8')


def client(HOST, public_key, private_key):
    # Randam number
    r = random.randrange(1000)

    # conection
    soc = socket(AF_INET)
    soc.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    #soc.connect((HOST, NOMAL_PORT))
    #print("[*] connecting to %s:%s" % (HOST, NOMAL_PORT))
    soc.connect((HOST, VALID_PORT))
    print("[*] connecting to %s:%s" % (HOST, VALID_PORT))
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
    print("[*] payload decode & decrypt: c1-1-4", payload)
    # public_server_key = tuple_key(payload)
    # print("[*] public_server_key", public_server_key)

    data = payload.split("-")
    r = randam(payload, r - 1)
    comp = float(data[2])

    if str(data[1]) == "validnode":
        print("[*] Server is valid node")
        if float(VER) == comp:
            # req_verification c1-1-5
            print("[*] Version check: req = res!")
            payload = make_payload(sender, "nomalnode", HASH, r)
            cipher = PKCS1_OAEP.new(RSA.importKey(public_server_key))
            print("[*] c1-1-1:send", payload)
            payload = cipher.encrypt(payload)
            soc.sendall(payload)
            print("[*] c1-1-5:send", data)

            # Verifies and decrypts res_verification message,
            # and compares H(fv) and H(fvnew c1-1-8
            payload = soc.recv(1024)
            cipher = PKCS1_OAEP.new(RSA.importKey(private_key))
            payload = str(cipher.decrypt(payload))
            print("[*] Reception: " + str(payload))
            data = payload.split("-")
            # print("c1-1-8: " + data[3])

            if str(HASH) == str(data[2]):
                print("[*] SAME!!")
            else:
                print("[*] Download start!")
                git_pull()

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
            print("[*] Reception: " + str(payload))
            data = payload.split("-")
            soc.close()

            git_pull()

    
    soc.close()
    print("[*] Finish!!")


if __name__ == '__main__':
    data = []
    if len(sys.argv) == 2:
        HOST = argv[1]
    else:
        if len(sys.argv) == 3:
            NOMAL_PORT = int(argv[2])
            print("[*] Port: ", VALID_PORT)
        else:
            print("[*] Default port:", VALID_PORT)
            # sys.exit()
            print("Error: ")
            sys.exit()

    if os.path.isdir("./repo"):
        print("[*] already exist.")
    else:
        print("[*] make repo")
        git_clone()

    # RSA: generate
    # public_key, private_key = generate_keys(107, 3259)
    # print(public_key)
    # print(private_key)

    client(HOST, public_key, private_key)
