import sys
from socket import htonl, inet_ntoa
from struct import pack

import ipaddress
import netaddr
import pytest

from arpreq import arpreq

localhost_values = [
    0x7F000001,
    b'127.0.0.1',
    u'127.0.0.1',
    netaddr.IPAddress('127.0.0.1'),
    ipaddress.IPv4Address(u'127.0.0.1'),
]

if sys.version_info < (3,):
    import ipaddr
    localhost_values.extend([
        long(0x7F000001),
        ipaddr.IPv4Address('127.0.0.1'),
    ])


@pytest.mark.parametrize("value", localhost_values)
def test_localhost(value):
    assert arpreq(value) == '00:00:00:00:00:00'


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


def get_arp_cache():
    with open("/proc/net/arp") as f:
        next(f)
        for line in f:
            ip_address, hw_type, flags, hw_address, mask, device = line.split()
            if decode_flags(flags) & 0x2:
                yield ip_address, hw_address


def test_cached_entries():
    for ip, mac in get_arp_cache():
        assert arpreq(ip) == mac


def test_default_gateway():
    gateway = get_default_gateway()
    if not gateway:
        pytest.skip("No default gateway present.")
    assert arpreq(gateway) is not None


@pytest.mark.parametrize("value", [
    "Foobar",
    -1,
    1 << 32,
    1 << 64,
    u"\u201c\ufffd\u201d"
])
def test_illegal_argument(value):
    with pytest.raises(ValueError):
        arpreq(value)


@pytest.mark.parametrize("value", [None, object(), [], ()])
def test_illegal_type(value):
    with pytest.raises(TypeError):
        arpreq(value)
