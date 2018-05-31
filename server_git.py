#!/usr/bin/env python3

from socket import *
import sys
import os
import time
import git

HOST = "0.0.0.0"
PORT = 33844 


def git_clone(out):
    _repo_path = os.path.join('./', 'repo')
    # clone from remote
    git_repo = git.Repo.clone_from('git@github.com:ertlnagoya/Update_Test.git', _repo_path, branch='master')

def git_pull():
    repo = git.Repo('repo')
    o = repo.remotes.origin
    o.pull()
    print o

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

while True:
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
        #print("waiting...")
    conn.close() 



