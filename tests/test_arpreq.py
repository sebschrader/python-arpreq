import sys
from socket import htonl, inet_ntoa
from struct import pack

import pytest

from arpreq import arpreq


def test_localhost():
    assert arpreq('127.0.0.1') == '00:00:00:00:00:00'


def decode_address(value):
    return inet_ntoa(pack(">I", htonl(int(value, base=16))))


def decode_flags(value):
    return int(value, base=16)


def get_default_gateway():
    with open("/proc/net/route") as f:
        next(f)
        for line in f:
            fields = line.strip().split()
            destination = decode_address(fields[1])
            mask = decode_address(fields[7])
            gateway = decode_address(fields[2])
            flags = decode_flags(fields[3])
            if destination == '0.0.0.0' and mask == '0.0.0.0' and flags & 0x2:
                return gateway
    return None


def test_default_gateway():
    gateway = get_default_gateway()
    if not gateway:
        pytest.skip("No default gateway present.")
    assert arpreq(gateway) is not None
