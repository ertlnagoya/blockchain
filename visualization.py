# !/usr/bin/env python3
# coding:utf-8

from socket import *
import sys
import os
import struct
import select
import time
import signal
import json
import datetime
import math
import requests
import urllib.request
import urllib.error
import ssl
from elasticsearch import Elasticsearch
from elasticsearch import helpers


NODE_ADDRESS = 'localhost'
NODE_PORT = 5000

# For HTTPS conection
# Oreore certificate
# requests.get("https://8.8.8.8", verify = False)
ssl._create_default_https_context = ssl._create_unverified_context
sslctx = ssl.create_default_context()
sslctx.load_cert_chain('cert.crt', 'server_secret.key')


# elasticsearch
packet_que = list()
es = Elasticsearch("localhost:9200")
URL = "http://localhost:9200"
INDEX_URL = URL + "/blockchain"
TYPE_URL = INDEX_URL + "/block"

def delete_index():
    """Delete an index in elastic search."""
    requests.delete(INDEX_URL)

def create_index():
    """Create an index in elastic search with timestamp enabled."""
    try:
        print("[*] creating an index in elasticsearch")
        r = requests.put(INDEX_URL)
        if "index_already_exists_exception" in r.text:
            print("[*] index already exists")
            return
        mapping = {
		    "index": "date",
		    "message": "string",
		    "previous_hash":  "string",
		    "proof": "date",
		    "transactions": [
		        {
                    "counter": "data",  # TODO
                    # "merkle tree": 
                    "state": "data", 
                    "sender": "string",
                    "recipient":  "string",
                    # "digital signature": ,
                    "ver": "float",
                    "verifier": "date"
		        }
		    ]
		}
        r = requests.put(TYPE_URL + "/_mapping", data=json.dumps(mapping))
        print("r: " + r.text)
    except:
        raise Exception("Elasticsearch is not running")

def add(address):
    data = json.loads(chain(address))
    #data = data[1:]
    #data =data[:-1]
    print(json.dumps(data, sort_keys = True, indent = 4))
    '''
    try:
        timestamp, capture = data.split(" ", 1)
    except Exception as e:
        return

    timestamp = float(timestamp)
	'''
    for k in data:
        # try:
        # row_timestamp=datetime.datetime.fromtimestamp(timestamp) - datetime.timedelta(hours=9)
        # timestamp = row_timestamp.strftime("%Y-%m-%dT%H:%M:%SZ")
        print("[*]write")
        
        res = es.index(index="blockchain", doc_type="block", body=k)
        print(res)

        res = es.search(index="captures", body={"query": {"match_all": {}}})
        print("Got %d Hits:" % res['hits']['total'])
        # except Exception as e:
            # print(e)
            # time.sleep(1)
        # return 

def chain(address):
    address_c = 'https://' + address + '/chain_visualize'
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

delete_index()
create_index()

address = NODE_ADDRESS + ':' + str(NODE_PORT)
add(address)
