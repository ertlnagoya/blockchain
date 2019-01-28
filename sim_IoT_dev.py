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
from argparse import ArgumentParser
import threading
import time
import concurrent.futures
from tqdm import tqdm
from time import sleep

HOST = "0.0.0.0"
VALID_PORT = 33845
TIMEOUT = 29

# For git
URL = 'git@github.com:ertlnagoya/Update_Test.git'
DIRECTORY = 'repo'

# For test
name = "home_camera_01"
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

# Degital signature
#message = b"hello world!"
#key = RSA.importKey(private_key)
#h = SHA256.new(message)
#signature = pkcs1_15.new(key).sign(h)
#print("署名作成", signature, int(time.time()*1000-start), 'mSec')

#try:
#    key = RSA.importKey(public_key)
#    pkcs1_15.new(key).verify(h, signature)
#    print("署名OK", int(time.time()*1000-start), 'mSec')
#except (ValueError, TypeError):
#    print("署名NG！", int(time.time()*1000-start), 'mSec')


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
    # Randam number generation
    try:
        r = random.randrange(1000)
        if random.randrange(2) == random.randrange(2) :
            VER = "3.0"
        else: 
            VER = "4.0"

        # conection to server
        soc = socket(AF_INET)
        # timeout
        soc.settimeout(TIMEOUT)
        soc.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        soc.connect((HOST, VALID_PORT))
        print(pycolor.CYAN, "[*] connecting to %s:%s" % (HOST, VALID_PORT), pycolor.END)
        # verbose_ping(sys.argv[12)

        soc.sendall(public_key)
        payload = soc.recv(1024)
        print(pycolor.CYAN, "[*] send public_key:", pycolor.YELLOW, payload, pycolor.END)
        public_server_key = payload

        # send vercsion info
        payload = make_payload(sender, "", VER, r)
        cipher = PKCS1_OAEP.new(RSA.importKey(public_server_key))
        print(pycolor.CYAN, "[*] send version: ", pycolor.YELLOW, payload, pycolor.END)
        payload = cipher.encrypt(payload)
        soc.sendall(payload)

        # receive version infp
        payload = soc.recv(1024)
        cipher = PKCS1_OAEP.new(RSA.importKey(private_key))
        payload = str(cipher.decrypt(payload))
        print(pycolor.CYAN, "[*] receive, decode & decrypt payload: ", pycolor.YELLOW, payload, pycolor.END)
        # raise OSError("Error.")
        data = payload.split("-")
        r = randam(payload, r - 1)
        comp = float(data[2])

        if float(VER) == comp:
            # send hash info
            print(pycolor.CYAN, "[*] Version check: req = res!", pycolor.END)
            payload = make_payload(sender, name, HASH, r)
            print(pycolor.CYAN, "[*] send hash: ", pycolor.YELLOW, payload, pycolor.END)
            cipher = PKCS1_OAEP.new(RSA.importKey(public_server_key))
            payload = cipher.encrypt(payload)
            soc.sendall(payload)

            # receive hash info
            payload = soc.recv(1024)
            cipher = PKCS1_OAEP.new(RSA.importKey(private_key))
            payload = str(cipher.decrypt(payload))
            print(pycolor.CYAN, "[*] receive hash: ", pycolor.YELLOW, payload, pycolor.END)
            data = payload.split("-")

            if str(HASH) == str(data[2]):
                print(pycolor.CYAN, "[*] SAME!! Download is unnecessary.", pycolor.END)
            else:
                print(pycolor.CYAN, "[*] The hash is not latest! Download start!", pycolor.END)
                # git_pull()
                # update(demo)
                print(pycolor.CYAN, "[server] Updating(demo): ", pycolor.END)
                for i in tqdm(range(50)):
                    sleep(0.1)

        else:
            print(pycolor.CYAN, "[*] It is not latest! Download start!", pycolor.END)

            # send download info
            r = randam(payload, r - 3)
            payload = make_payload(sender, name, 'Download', r)
            cipher = PKCS1_OAEP.new(RSA.importKey(public_server_key))
            print(pycolor.CYAN, "[*] send infomation to download: ", pycolor.YELLOW, payload, pycolor.END)
            payload = cipher.encrypt(payload)
            soc.sendall(payload)

            # receive download info
            payload = soc.recv(1024)
            cipher = PKCS1_OAEP.new(RSA.importKey(private_key))
            payload = str(cipher.decrypt(payload))
            print(pycolor.CYAN, "[*] Reception: ", pycolor.YELLOW, str(payload), pycolor.END)
            data = payload.split("-")
            soc.close()

            # git_pull()
            # update(demo)
            print(pycolor.CYAN, "[server] Updating(demo): ", pycolor.END)
            for i in tqdm(range(50)):
                sleep(0.1)

    except OSError as e:
        print(pycolor.RED, "[*] clientsock error.", pycolor.END)
        
    soc.close()
    print(pycolor.CYAN, "[*] Finish!!", pycolor.END)


if __name__ == '__main__':
    data = []

    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=33845, type=int, help='port to listen on')
    parser.add_argument('-a', '--address', default="0.0.0.0", type=str, help='address of server')
    parser.add_argument('-s', '--simulation', default="1", type=int, help='interval(s) of simulation')
    args = parser.parse_args()
    SERVER_PORT = args.port
    HOST = args.address

    if os.path.isdir("./repo"):
        print(pycolor.CYAN, "[*] Git repository already exist.", pycolor.END)
    else:
        print(pycolor.CYAN, "[*] make git repository", pycolor.END)
        git_clone()


    # simulation
    def schedule(interval, wait=True):
        base_time = time.time()
        next_time = 0
        while True:
            t = threading.Thread(target=client(HOST, public_key, private_key))
            t.start()
            if wait:
                t.join()
            next_time = ((base_time - time.time()) % interval) or interval
            time.sleep(next_time)
    schedule(args.simulation*30)
    # client(HOST, public_key, private_key)



