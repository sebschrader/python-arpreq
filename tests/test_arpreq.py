import sys
from socket import htonl, inet_ntoa
from struct import pack

import netaddr
import pytest

if sys.version_info >= (3,):
    import ipaddress
    from unittest.mock import Mock
    ipaddr = Mock()
    long = Mock()
else:
    import ipaddr
    from mock import Mock
    ipaddress = Mock()

from arpreq import arpreq


python2 = pytest.mark.skipif(sys.version_info >= (3,),
                             reason='Requires Python 2')
python3 = pytest.mark.skipif(sys.version_info < (3,),
                             reason='Requires Python 3')


@pytest.mark.parametrize("value", [
    0x7F000001,
    python2(long(0x7F000001)),
    '127.0.0.1',
    netaddr.IPAddress('127.0.0.1'),
    python2(ipaddr.IPv4Address('127.0.0.1')),
    python3(ipaddress.IPv4Address('127.0.0.1')),
])
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
            fields = line.strip().split()
            yield fields[0], fields[3]


def test_cached_entries():
    for ip, mac in get_arp_cache():
        assert arpreq(ip) == mac


def test_default_gateway():
    gateway = get_default_gateway()
    if not gateway:
        pytest.skip("No default gateway present.")
    assert arpreq(gateway) is not None


@pytest.mark.parametrize("value", ["Foobar", -1, 1 << 32, 1 << 64])
def test_illegal_argument(value):
    with pytest.raises(ValueError):
        arpreq(value)


def test_illegal_type():
    with pytest.raises(TypeError):
        arpreq(None)
