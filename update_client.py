# coding:utf-8

import sys
from sys import argv
from socket import *
import socket as Socket


MONI_PORT = 33844


if __name__ == '__main__':
    if len(sys.argv) == 3:
        HOST = argv[2]
    else:
        print("Error: ")
        sys.exit()
    soc = socket(AF_INET)
    soc.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    # print("[*] connecting to %s:%s" % (HOST, TIME_PORT))
    soc.connect((HOST, MONI_PORT))
    # FIXME: Add a real CLI
    print("[*] connecting to %s:%s" % (HOST, MONI_PORT))
    # verbose_ping(sys.argv[1])
    soc.sendall(b' ' + b'\n')
