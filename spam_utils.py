import random
import string
from ipaddress import IPv4Address
from random import getrandbits
import requests
import socks
import socket
from stem import Signal
from stem.control import Controller

fileFirstnames = "first-names.txt"
fileLastnames = "last-names.txt"
tor_password = "MyStr0n9P#D"

def get_current_ip():
    session = requests.session()
    session.proxies = {}
    session.proxies['http']='socks5h://localhost:9050'

    try:
        r = session.get('http://ipinfo.io/ip')
    except Exception as e:
        print("Error while getting IP: " + str(e))
    else:
        return r.text


# Please check README to make this work!
def renew_tor_ip():
    with Controller.from_port(port=9051) as controller:
        controller.authenticate(password=tor_password)
        controller.signal(Signal.NEWNYM)


def test_tor():
    try:
        tor_c = socket.create_connection(('127.0.0.1', 9051))
        payload = 'AUTHENTICATE "{}"\r\nGETINFO status/circuit-established\r\nQUIT\r\n'.format(tor_password)
        tor_c.send(payload.encode())

        response = tor_c.recv(1024)
        tor_c.close()
        if 'circuit-established=1' not in str(response):
            return False
        else:
            return True

    except Exception as e:
        print("Could not connect to Tor: " + str(e))
        print("Please make sure Tor is installed!")
        return False


def get_tor_session():
    session = requests.session()
    # Tor uses the 9050 port as the default socks port
    session.proxies = {'http':  'socks5h://127.0.0.1:9050',
                       'https': 'socks5h://127.0.0.1:9050'}
    return session


def create_fake_private_ip():
    ip = ""
    class_net = random.randint(0,2)

    if class_net == 0:
        ip = "10."
        ip += ".".join(map(str, (random.randint(0, 255) 
        for _ in range(3))))
    elif class_net == 1:
        ip = "172."
        ip = ip + str(random.randint(16,35)) + "."
        ip += ".".join(map(str, (random.randint(0, 255) 
        for _ in range(2))))
    elif class_net == 2: 
        ip = "192.168."
        ip += ".".join(map(str, (random.randint(0, 255) 
        for _ in range(2))))
    return(ip)


def create_hostname():
    prefixes = ['WIN-', 'Dev-', 'SRV', '', 'PC', 'PC-', 'SRV_', 'SRVWIN-']
    rand_prefix = random.randint(0, len(prefixes) - 1)

    min_length = 4
    max_length = 12

    actual_length = random.randint(min_length, max_length)

    x = ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in range(actual_length))

    glob_hostname = prefixes[rand_prefix] + x
    return glob_hostname


def create_username():
    with open(fileFirstnames) as fName:
        firstnames = fName.read().splitlines()

    with open(fileLastnames) as lName:
        lastnames = lName.read().splitlines()

    rand_firstname = random.randint(0, len(firstnames) - 1)
    rand_lastname = random.randint(0, len(lastnames) - 1)

    rand_username_format = random.randint(0,2)

    if rand_username_format == 0:
        glob_username = firstnames[rand_firstname] + "." + lastnames[rand_lastname]
    elif rand_username_format == 1:
        glob_username = firstnames[rand_firstname][0] + lastnames[rand_lastname]
    elif rand_username_format == 2:
        glob_username = lastnames[rand_lastname] + firstnames[rand_firstname][0]
    return glob_username


def create_fakeip():
    bits = getrandbits(32)  # generates an integer with 32 random bits
    addr = IPv4Address(bits)  # instances an IPv4Address object from those bits
    addr_str = str(addr)  # get the IPv4Address object's string representation

    return addr_str.encode('ascii')
