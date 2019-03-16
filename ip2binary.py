#!/usr/bin/env python3

"""
Convert a presentation format IP address to its binary representation.

Examples:

$ ip2binary.py 128.91.2.13
10000000010110110000001000001101

$ ip2binary.py 2001:4860:4860::8844
00100000000000010100100001100000010010000110000000000000000000000000000000000000000000000000000000000000000000001000100001000100

"""

import sys, socket


def ip2binary(address):
    if address.find('.') != -1:
        packed = socket.inet_pton(socket.AF_INET, address)
    elif address.find(':') != -1:
        packed = socket.inet_pton(socket.AF_INET6, address)
    else:
        raise ValueError("{} isn't an IP address".format(address))

    binary_string = ''
    for i in packed:
        binary_string += "{:08b}".format(i)
    return binary_string


if __name__ == '__main__':

    address = sys.argv[1]
    print(ip2binary(address))
