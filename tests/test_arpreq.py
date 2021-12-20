import contextlib
import errno
import re
import sys
import socket
from struct import pack

import pytest
import _pytest.outcomes

from arpreq import arpreq

localhost = {
    "int": 0x7F000001,
    "bytes": b"127.0.0.1",
    "unicode": u"127.0.0.1",
}

try:
    localhost["long"] = long(0x7F000001)
except NameError as e:
    localhost["long"] = pytest.param(None, marks=[pytest.mark.skip(str(e))])

try:
    import ipaddress
except ImportError as e:
    localhost["ipaddress"] = pytest.param(
        None,
        marks=[pytest.mark.skip(str(e))],
    )
else:
    localhost["ipaddress"] = ipaddress.IPv4Address(u"127.0.0.1")

try:
    import ipaddr
except ImportError as e:
    localhost["ipaddr"] = pytest.param(None, marks=[pytest.mark.skip(str(e))])
else:
    localhost["ipaddr"] = ipaddr.IPv4Address("127.0.0.1")

try:
    import netaddr
except ImportError as e:
    localhost["netaddr"] = pytest.param(None, marks=[pytest.mark.skip(str(e))])
else:
    localhost["netaddr"] = netaddr.IPAddress("127.0.0.1")


@pytest.mark.parametrize(
    "value",
    localhost.values(),
    ids=tuple(localhost.keys()),
)
def test_localhost(value):
    assert arpreq(value) == '00:00:00:00:00:00'


def decode_address(value):
    return socket.inet_ntoa(pack(">I", socket.htonl(int(value, base=16))))


def decode_flags(value):
    return int(value, base=16)


def icmp_socket():
    try:
        return socket.socket(socket.AF_INET, socket.SOCK_DGRAM,
                             socket.IPPROTO_ICMP)
    except IOError as e:
        if e.errno != errno.EACCES:
            raise
        pytest.skip("Can't use unprivileged ICMP. Allow with sysctl "
                    "net.ipv4.ping_group_range='0 2147483647'")


def ping(address):
    with contextlib.closing(icmp_socket()) as sock:
        sock.connect((address, 0))
        sock.settimeout(1)
        request = pack(
            '>BBHHH32s',
            8, # ICMP Type 8 (ECHO Request)
            0, # Sub-Code 0
            0, # Checksum,
            0, # Identifier
            0, # Sequence No
            b'\x00' * 32 # Payload
        )
        sock.send(request)
        reply = sock.recv(65536)


def get_gateways():
    """Get all gateways of routes"""
    with open("/proc/net/route") as f:
        # Skip header
        next(f)
        for line in f:
            fields = line.strip().split()
            destination = decode_address(fields[1])
            mask = decode_address(fields[7])
            gateway = decode_address(fields[2])
            flags = decode_flags(fields[3])
            # Check if RTF_UP and RTF_GATEWAY flags are set
            if flags & 0x3 == 0x3:
                yield gateway


@pytest.fixture(scope="session")
def gateways():
    """Sends an ICMP Echo-Request to all gateways to fill ARP cache"""
    ips = set(get_gateways())
    for ip in ips:
        try:
            ping(ip)
        except socket.timeout:
            pass
    return ips


def get_arp_cache():
    """Get all complete ARP entries"""
    with open("/proc/net/arp") as f:
        # Skip header
        next(f)
        for line in f:
            ip_address, hw_type, flags, hw_address, mask, device = line.split()
            # Check if ATF_COM flag is set
            if decode_flags(flags) & 0x2:
                yield ip_address, hw_address


@pytest.fixture(scope="session")
def arp_cache(request):
    # Request gateways during runtime to handle if skipped
    try:
        request.getfixturevalue("gateways")
    except _pytest.outcomes.Skipped:
        pass
    return tuple(get_arp_cache())


def test_cached_entries(arp_cache):
    for ip, mac in arp_cache:
        assert arpreq(ip) == mac


mac_pattern = re.compile(
    r"\A([0-9a-f]{2}):([0-9-af]{2}):([0-9a-f]{2}):"
    r"([0-9a-f]{2}):([0-9a-f]{2}):([0-9a-f]{2})\Z"
)


def test_gateways(gateways):
    for gateway in gateways:
        assert mac_pattern.match(arpreq(gateway))



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
