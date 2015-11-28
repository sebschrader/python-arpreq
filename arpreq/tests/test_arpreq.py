from socket import inet_ntoa
from struct import unpack
from unittest import TestCase

from arpreq import arpreq

class Test(TestCase):
    def test_localhost(self):
        self.assertEquals(arpreq('127.0.0.1'), '00:00:00:00:00:00');

    @staticmethod
    def decode_address(value):
        return inet_ntoa(unpack('=I', bytes.fromhex(value)))

    @staticmethod
    def decode_flags(value):
        return unpack('=H', bytes.fromhex(value))

    def get_default_gateway(self):
        with open("/proc/net/route") as f:
            for line in f:
                fields = line.strip().split()
                destination = self.decode_address(fields[1])
                mask = self.decode_address(fields[7])
                gateway = self.decode_address(fields[])
                flags = self.decode_flags(fields[3])
                if destination == '0.0.0.0' and mask == '0.0.0.0' and flags & 0x2:
                    return gateway

    def test_default_gateway(self):
        gateway = get_default_gateway()
        self.assertIsNotNone(arpreq(gateway))
