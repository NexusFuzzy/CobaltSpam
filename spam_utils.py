import random
import string
from ipaddress import IPv4Address
from random import getrandbits

fileFirstnames = "first-names.txt"
fileLastnames = "last-names.txt"

def create_hostname():
    prefixes = ['WIN-', 'Dev-', 'SRV', '', 'PC', 'PC-', 'SRV_', 'SRVWIN-']
    rand_prefix = random.randint(0,3)

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
