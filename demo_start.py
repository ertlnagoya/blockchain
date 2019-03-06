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
import time
import os
import subprocess
from argparse import ArgumentParser

ssl._create_default_https_context = ssl._create_unverified_context
# For HTTPS conection (password:pass)
sslctx = ssl.create_default_context()
sslctx.load_cert_chain('cert.crt', 'private.key')


def request_crete(address):
    address_nt = 'https://' + address + '/api/management/v1/deployments/deployments/next?artifact_name=mender-image-1.5.0&device_type=qemux86-64'
    data_nt = {
        "application/json" : [ {
            "name" : "qemux86-64",
            "artifact_name" : "mender-image-2.5.0",
            "devices" : [ "5ba4bd3d04da8a0001952e01" ]
        } ]
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

def request_auth(address):
    address_nt = 'https://' + address + ':443/api/management/v1/useradm/auth/login'  # '/api/devices/v1/authentication/auth_requests'
    data_nt = {
    "application/json" : {
    "id_data" : "{\"mac\":\"00:01:02:03:04:05\"}",
    "pubkey" : "-----BEGIN PRIVATE KEY-----MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg/VN910Au7qVoLAS1j0GUEGZoENuGkirkGoHQw6ocSkehRANCAASF1Sse8ls90h4ffoS8giWnKyRiiQRqf6trcewcYtzftD0O1dEeqPLi+NEiiPMEq6hid79aNZ+C+S3dyKt8S4jM-----END PRIVATE KEY-----\n"
    }
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

def setup_basic_auth(base_uri, user, password):
    password_mgr = urllib.request.HTTPPasswordMgrWithDefaultRealm()
    password_mgr.add_password(
            realm=None,
            uri=base_uri,
            user=user,
            passwd=password)
    auth_handler = urllib.request.HTTPBasicAuthHandler(password_mgr)
    opener = urllib.request.build_opener(auth_handler)
    #print(auth_handler)
    urllib.request.install_opener(opener)

setup_basic_auth('https://localhost/api/management/v1/deployments/', 'nagara@ertl.jp', 'mysecretpassword')

if __name__ == '__main__':
    address = "192.168.11.17"
    print("start")
    request_auth(address)
    print("start")
    request_crete(address)


