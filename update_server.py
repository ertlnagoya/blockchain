# !/usr/bin/env python3

from socket import *
import os
import git
import json
import urllib.request

HOST = "0.0.0.0"
PORT = 33844


def git_clone():
    _repo_path = os.path.join('./', 'repo')
    # clone from remote
    git_repo = git.Repo.clone_from(
        'git@github.com:ertlnagoya/Update_Test.git', _repo_path, branch='master')


def git_pull():
    repo = git.Repo('repo')
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


def new_transaction(address):
    address_nt = 'http://' + address + '/transactions/new'
    data_nt = {
        "sender": "d4ee26eee15148ee92c6cd394edd974e",
        "recipient": "someone-other-address",
        "ver": 2,
        "url": "http://version.2"
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
    address_m = 'http://' + address + '/mine'
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
    address_c = 'http://' + address + '/chain'
    req = urllib.request.Request(address_c)
    try:
        with urllib.request.urlopen(req) as res:
            body = res.read()
            return body
    except urllib.error.HTTPError as err:
        print(err.code)
        return -1
    except urllib.error.URLError as err:
        print(err.reason)
        return -1


def transaction(address):
    print("Transaction start.")
    new_transaction(address)
    mine(address)
    print(chain(address))
    print("Transaction finish!!")


def search(arg, cond):
    res = []
    if cond(arg):
        res.append(arg)
    if isinstance(arg, list):
        for item in arg:
            res += search(item, cond)
            print(res)
    elif isinstance(arg, dict):
        for value in arg.values():
            res += search(value, cond)
            print(res)
    return res


def has_star_key(arg):
    if isinstance(arg, dict):
        return arg.keys() == {"chain"}


def get_star(arg):
    return search(arg, has_star_key)


def search_version(address):
    sender = "d4ee26eee15148ee92c6cd394edd974e"
    ver = 0
    print("Search start.")
    data = json.loads(chain(address))
    # print(json.dumps(data, sort_keys = True, indent = 4))
    keylist = data.keys()
    print()
    print(keylist)
    for key in data['chain']:
        count = key['index']
        for key_next in key['transactions']:
            if key_next != "[]":
                if key_next['sender'] == sender:
                    # print(key_next)
                    # print(key_next['url'])
                    index = count
                    print(index)
                    ver = key_next['ver']
                    print(key_next['ver'])
    print(ver)
    return ver

    # print(key['transactions'])
    # namelist.sort()
    # print(get_star(data))
    # for attr in data:
    # print(attr)
    # print('chain：{}'.format(data['chain']['transaction']))
    print("Search finish.")


while True:
    if os.path.isdir("./repo"):
        print("already exist.")
    else:
        print("make repo")
        # git_clone()
    s = socket(AF_INET)
    s.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    print("[*] waiting for connection at %s:%s" % (HOST, PORT))
    s.bind((HOST, PORT))
    s.listen(1)
    conn, addr = s.accept()
    print("[*] connection from: %s:%s" % addr)
    while True:
        payload = recv_until(conn)
        if len(payload) == 0:
            break
        git_pull()
        address = 'localhost' + ':' + '5000'
        # mine(address)
        transaction(address)
        # search
        search_version(address)
        # print("waiting...")
    conn.close()
