import os, sys, time, signal, datetime, struct
import time
from sys import argv
from socket import * 
import socket as Socket

if sys.platform == "win32":
    # On Windows, the best timer is time.clock()
    default_timer = time.clock
else:
    # On most other platforms the best timer is time.time()
    default_timer = time.time

# ICMP parameters
ICMP_ECHOREPLY = 0 # Echo reply (per RFC792)
ICMP_ECHO = 8 # Echo request (per RFC792)
ICMP_MAX_RECV = 2048 # Max size of incoming buffer
MAX_SLEEP = 1000

TIME_PORT = 37133
MONI_PORT = 33844

if __name__ == '__main__':
    #time synchronization
    if len(sys.argv) == 3:
        HOST = argv[2]
    else:
        print "Error: "
        sys.exit()
   

    soc = socket(AF_INET)
    soc.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    print("[*] connecting to %s:%s" % (HOST, TIME_PORT))
    soc.connect((HOST, MONI_PORT))
    # FIXME: Add a real CLI
    print("[*] connecting to %s:%s" % (HOST, MONI_PORT))
    # verbose_ping(sys.argv[1])
    soc.sendall(' '+ "\n")