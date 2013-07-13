
from __future__ import division, absolute_import
import struct

from twisted.python.compat import iterbytes
from twisted.trial import unittest
from twisted.test import proto_helpers
from twisted.protocols.test.test_basic import LPTestCaseMixin
from twisted.internet import error


from parseproto.basic.protocol import LineOnlyReceiver, IntNStringReceiver
from parseproto.basic.protocol import (
    Int8StringReceiver, Int16StringReceiver, Int32StringReceiver)


class LineOnlyTester(LineOnlyReceiver):
    """
    A buffering line only receiver.
    """
    def connectionMade(self):
        """
        Create/clean data received on connection.
        """
        self.received = []


    def lineReceived(self, line):
        """
        Save received data.
        """
        self.received.append(line)


class LineOnlyReceiverTestCase(unittest.SynchronousTestCase):
    """
    Tests for L{parserproto.basic.protocol.LineOnlyReceiver}.
    """
    buffer = b"foo\r\nbleakness\r\ndesolation\r\nplastic forks\r\n"

    def test_buffer(self):
        """
        Test buffering over line protocol: data received should match buffer.
        """
        t = proto_helpers.StringTransport()
        a = LineOnlyTester()
        a.makeConnection(t)
        for c in iterbytes(self.buffer):
            a.dataReceived(c)
        self.assertEqual(a.received, self.buffer.split(b'\r\n')[:-1])


    def test_lineTooLong(self):
        """
        Test sending a line too long: it should close the connection.
        """
        t = proto_helpers.StringTransport()
        a = LineOnlyTester()
        a.makeConnection(t)
        res = a.dataReceived(b'x' * 2000 + '\r\n')
        # need further modification here
        self.assertIsInstance(res, error.ConnectionLost)
    test_lineTooLong.skip = 'Cannot return error under parsley.'


    def test_lineReceivedNotImplemented(self):
        """
        When L{LineOnlyReceiver.lineReceived} is not overridden in a subclass,
        calling it raises C{NotImplementedError}.
        """
        proto = LineOnlyReceiver()
        self.assertRaises(NotImplementedError, proto.lineReceived, 'foo')


class TestMixin:
    def connectionMade(self):
        self.received = []

    def stringReceived(self, s):
        self.received.append(s)

    MAX_LENGTH = 50



class IntNTestCaseMixin(LPTestCaseMixin):
    """
    TestCase mixin for int-prefixed protocols.
    """
    protocol = None
    strings = None
    illegalStrings = None
    partialStrings = None

    def test_receive(self):
        """
        Test receiving data find the same data send.
        """
        r = self.getProtocol()
        for s in self.strings:
            for c in iterbytes(struct.pack(r.structFormat,len(s)) + s):
                r.dataReceived(c)
        self.assertEqual(r.received, self.strings)


    def test_partial(self):
        """
        Send partial data, nothing should be definitely received.
        """
        for s in self.partialStrings:
            r = self.getProtocol()
            for c in iterbytes(s):
                r.dataReceived(c)
            self.assertEqual(r.received, [])


    def test_send(self):
        """
        Test sending data over protocol.
        """
        r = self.getProtocol()
        r.sendString(b"b" * 16)
        self.assertEqual(r.transport.value(),
            struct.pack(r.structFormat, 16) + b"b" * 16)


    def test_lengthLimitExceeded(self):
        """
        When a length prefix is received which is greater than the protocol's
        C{MAX_LENGTH} attribute, the C{lengthLimitExceeded} method is called
        with the received length prefix.
        """
        length = []
        r = self.getProtocol()
        r.lengthLimitExceeded = length.append
        r.MAX_LENGTH = 10
        r.dataReceived(struct.pack(r.structFormat, 11))
        self.assertEqual(length, [11])


    def test_longStringNotDelivered(self):
        """
        If a length prefix for a string longer than C{MAX_LENGTH} is delivered
        to C{dataReceived} at the same time as the entire string, the string is
        not passed to C{stringReceived}.
        """
        r = self.getProtocol()
        r.MAX_LENGTH = 10
        r.dataReceived(
            struct.pack(r.structFormat, 11) + b'x' * 11)
        self.assertEqual(r.received, [])


    def test_stringReceivedNotImplemented(self):
        """
        When L{IntNStringReceiver.stringReceived} is not overridden in a
        subclass, calling it raises C{NotImplementedError}.
        """

        proto = IntNStringReceiver()
        self.assertRaises(NotImplementedError, proto.stringReceived, 'foo')


class TestInt32(TestMixin, Int32StringReceiver):
    """
    A L{basic.Int32StringReceiver} storing received strings in an array.

    @ivar received: array holding received strings.
    """



class Int32TestCase(unittest.SynchronousTestCase, IntNTestCaseMixin):
    """
    Test case for int32-prefixed protocol
    """
    protocol = TestInt32
    strings = [b"a", b"b" * 16]
    illegalStrings = [b"\x10\x00\x00\x00aaaaaa"]
    partialStrings = [b"\x00\x00\x00", b"hello there", b""]

    def test_data(self):
        """
        Test specific behavior of the 32-bits length.
        """
        r = self.getProtocol()
        r.sendString(b"foo")
        self.assertEqual(r.transport.value(), b"\x00\x00\x00\x03foo")
        r.dataReceived(b"\x00\x00\x00\x04ubar")
        self.assertEqual(r.received, [b"ubar"])



class TestInt16(TestMixin, Int16StringReceiver):
    """
    A L{Int16StringReceiver} storing received strings in an array.

    @ivar received: array holding received strings.
    """



class Int16TestCase(unittest.SynchronousTestCase, IntNTestCaseMixin):
    """
    Test case for int16-prefixed protocol
    """
    protocol = TestInt16
    strings = [b"a", b"b" * 16]
    illegalStrings = [b"\x10\x00aaaaaa"]
    partialStrings = [b"\x00", b"hello there", b""]

    def test_data(self):
        """
        Test specific behavior of the 16-bits length.
        """
        r = self.getProtocol()
        r.sendString(b"foo")
        self.assertEqual(r.transport.value(), b"\x00\x03foo")
        r.dataReceived(b"\x00\x04ubar")
        self.assertEqual(r.received, [b"ubar"])


    def test_tooLongSend(self):
        """
        Send too much data: that should cause an error.
        """
        r = self.getProtocol()
        tooSend = b"b" * (2**(r.prefixLength * 8) + 1)
        self.assertRaises(AssertionError, r.sendString, tooSend)


class TestInt8(TestMixin, Int8StringReceiver):
    """
    A L{Int8StringReceiver} storing received strings in an array.

    @ivar received: array holding received strings.
    """



class Int8TestCase(unittest.SynchronousTestCase, IntNTestCaseMixin):
    """
    Test case for int8-prefixed protocol
    """
    protocol = TestInt8
    strings = [b"a", b"b" * 16]
    illegalStrings = [b"\x00\x00aaaaaa"]
    partialStrings = [b"\x08", b"dzadz", b""]


    def test_data(self):
        """
        Test specific behavior of the 8-bits length.
        """
        r = self.getProtocol()
        r.sendString(b"foo")
        self.assertEqual(r.transport.value(), b"\x03foo")
        r.dataReceived(b"\x04ubar")
        self.assertEqual(r.received, [b"ubar"])


    def test_tooLongSend(self):
        """
        Send too much data: that should cause an error.
        """
        r = self.getProtocol()
        tooSend = b"b" * (2**(r.prefixLength * 8) + 1)
        self.assertRaises(AssertionError, r.sendString, tooSend)