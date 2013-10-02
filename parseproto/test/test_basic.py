
from __future__ import division, absolute_import
import struct
import sys

from twisted.python.compat import iterbytes
from twisted.trial import unittest
from twisted.test import proto_helpers
from twisted.protocols.test.test_basic import LPTestCaseMixin
from twisted.internet import protocol, error, task


from parseproto.basic.protocol import (
    LineOnlyReceiver, LineReceiver, IntNStringReceiver)
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


class FlippingLineTester(LineReceiver):
    """
    A line receiver that flips between line and raw data modes after one byte.
    """

    delimiter = b'\n'

    def __init__(self):
        self.lines = []


    def lineReceived(self, line):
        """
        Set the mode to raw.
        """
        self.lines.append(line)
        self.setRawMode()


    def rawDataReceived(self, data):
        """
        Set the mode back to line.
        """
        self.setLineMode(data[1:])


class LineTester(LineReceiver):
    """
    A line receiver that parses data received and make actions on some tokens.

    @type delimiter: C{bytes}
    @ivar delimiter: character used between received lines.
    @type MAX_LENGTH: C{int}
    @ivar MAX_LENGTH: size of a line when C{lineLengthExceeded} will be called.
    @type clock: L{twisted.internet.task.Clock}
    @ivar clock: clock simulating reactor callLater. Pass it to constructor if
        you want to use the pause/rawpause functionalities.
    """

    delimiter = b'\n'
    MAX_LENGTH = 64

    def __init__(self, clock=None):
        """
        If given, use a clock to make callLater calls.
        """
        self.clock = clock


    def connectionMade(self):
        """
        Create/clean data received on connection.
        """
        self.received = []


    def lineReceived(self, line):
        """
        Receive line and make some action for some tokens: pause, rawpause,
        stop, len, produce, unproduce.
        """
        self.received.append(line)
        if line == b'':
            self.setRawMode()
        elif line == b'pause':
            self.pauseProducing()
            self.clock.callLater(0, self.resumeProducing)
        elif line == b'rawpause':
            self.pauseProducing()
            self.setRawMode()
            self.received.append(b'')
            self.clock.callLater(0, self.resumeProducing)
        elif line == b'stop':
            self.stopProducing()
        elif line[:4] == b'len ':
            self.length = int(line[4:])
        elif line.startswith(b'produce'):
            self.transport.registerProducer(self, False)
        elif line.startswith(b'unproduce'):
            self.transport.unregisterProducer()


    def rawDataReceived(self, data):
        """
        Read raw data, until the quantity specified by a previous 'len' line is
        reached.
        """
        data, rest = data[:self.length], data[self.length:]
        self.length = self.length - len(data)
        self.received[-1] = self.received[-1] + data
        if self.length == 0:
            self.setLineMode(rest)


    def lineLengthExceeded(self, line):
        """
        Adjust line mode when long lines received.
        """
        if len(line) > self.MAX_LENGTH + 1:
            self.setLineMode(line[self.MAX_LENGTH + 1:])

class LineReceiverTestCase(unittest.SynchronousTestCase):
    """
    Test L{twisted.protocols.basic.LineReceiver}, using the C{LineTester}
    wrapper.
    """
    buffer = b'''\
len 10

0123456789len 5

1234
len 20
foo 123

0123456789
012345678len 0
foo 5

1234567890123456789012345678901234567890123456789012345678901234567890
len 1

a'''

    output = [b'len 10', b'0123456789', b'len 5', b'1234\n',
              b'len 20', b'foo 123', b'0123456789\n012345678',
              b'len 0', b'foo 5', b'', b'67890', b'len 1', b'a']

    def test_buffer(self):
        """
        Test buffering for different packet size, checking received matches
        expected data.
        """
        for packet_size in range(1, 10):
            t = proto_helpers.StringIOWithoutClosing()
            a = LineTester()
            a.makeConnection(protocol.FileWrapper(t))
            for i in range(len(self.buffer) // packet_size + 1):
                s = self.buffer[i * packet_size:(i + 1) * packet_size]
                a.dataReceived(s)
            self.assertEqual(self.output, a.received)


    pauseBuf = b'twiddle1\ntwiddle2\npause\ntwiddle3\n'

    pauseOutput1 = [b'twiddle1', b'twiddle2', b'pause']
    pauseOutput2 = pauseOutput1 + [b'twiddle3']


    def test_pausing(self):
        """
        Test pause inside data receiving. It uses fake clock to see if
        pausing/resuming work.
        """
        for packet_size in range(1, 10):
            t = proto_helpers.StringIOWithoutClosing()
            clock = task.Clock()
            a = LineTester(clock)
            a.makeConnection(protocol.FileWrapper(t))
            for i in range(len(self.pauseBuf) // packet_size + 1):
                s = self.pauseBuf[i * packet_size:(i + 1) * packet_size]
                a.dataReceived(s)
            self.assertEqual(self.pauseOutput1, a.received)
            clock.advance(0)
            self.assertEqual(self.pauseOutput2, a.received)

    rawpauseBuf = b'twiddle1\ntwiddle2\nlen 5\nrawpause\n12345twiddle3\n'

    rawpauseOutput1 = [b'twiddle1', b'twiddle2', b'len 5', b'rawpause', b'']
    rawpauseOutput2 = [b'twiddle1', b'twiddle2', b'len 5', b'rawpause',
                       b'12345', b'twiddle3']


    def test_rawPausing(self):
        """
        Test pause inside raw date receiving.
        """
        for packet_size in range(1, 10):
            t = proto_helpers.StringIOWithoutClosing()
            clock = task.Clock()
            a = LineTester(clock)
            a.makeConnection(protocol.FileWrapper(t))
            for i in range(len(self.rawpauseBuf) // packet_size + 1):
                s = self.rawpauseBuf[i * packet_size:(i + 1) * packet_size]
                a.dataReceived(s)
            self.assertEqual(self.rawpauseOutput1, a.received)
            clock.advance(0)
            self.assertEqual(self.rawpauseOutput2, a.received)
    test_rawPausing.skip = "pausing implementation undecided."

    stop_buf = b'twiddle1\ntwiddle2\nstop\nmore\nstuff\n'

    stop_output = [b'twiddle1', b'twiddle2', b'stop']


    def test_stopProducing(self):
        """
        Test stop inside producing.
        """
        for packet_size in range(1, 10):
            t = proto_helpers.StringIOWithoutClosing()
            a = LineTester()
            a.makeConnection(protocol.FileWrapper(t))
            for i in range(len(self.stop_buf) // packet_size + 1):
                s = self.stop_buf[i * packet_size:(i + 1) * packet_size]
                a.dataReceived(s)
            self.assertEqual(self.stop_output, a.received)
    test_stopProducing.skip = "pausing implementation undecided."

    def test_lineReceiverAsProducer(self):
        """
        Test produce/unproduce in receiving.
        """
        a = LineTester()
        t = proto_helpers.StringIOWithoutClosing()
        a.makeConnection(protocol.FileWrapper(t))
        a.dataReceived(b'produce\nhello world\nunproduce\ngoodbye\n')
        self.assertEqual(a.received,
                         [b'produce', b'hello world', b'unproduce', b'goodbye'])


    def test_clearLineBuffer(self):
        """
        L{LineReceiver.clearLineBuffer} removes all buffered data and returns
        it as a C{bytes} and can be called from beneath C{dataReceived}.
        """
        class ClearingReceiver(LineReceiver):
            def lineReceived(self, line):
                self.line = line
                self.rest = self.clearLineBuffer()

        protocol = ClearingReceiver()
        protocol.dataReceived(b'foo\r\nbar\r\nbaz')
        self.assertEqual(protocol.line, b'foo')
        self.assertEqual(protocol.rest, b'bar\r\nbaz')

        # Deliver another line to make sure the previously buffered data is
        # really gone.
        protocol.dataReceived(b'quux\r\n')
        self.assertEqual(protocol.line, b'quux')
        self.assertEqual(protocol.rest, b'')
    test_clearLineBuffer.skip = "Currently not supported."


    def test_stackRecursion(self):
        """
        Test switching modes many times on the same data.
        """
        proto = FlippingLineTester()
        transport = proto_helpers.StringIOWithoutClosing()
        proto.makeConnection(protocol.FileWrapper(transport))
        limit = sys.getrecursionlimit()
        proto.dataReceived(b'x\nx' * limit)
        self.assertEqual(b'x' * limit, b''.join(proto.lines))


    def test_maximumLineLength(self):
        """
        C{LineReceiver} disconnects the transport if it receives a line longer
        than its C{MAX_LENGTH}.
        """
        proto = LineReceiver()
        transport = proto_helpers.StringTransport()
        proto.makeConnection(transport)
        proto.dataReceived(b'x' * (proto.MAX_LENGTH + 1) + b'\r\nr')
        self.assertTrue(transport.disconnecting)


    def test_maximumLineLengthRemaining(self):
        """
        C{LineReceiver} disconnects the transport it if receives a non-finished
        line longer than its C{MAX_LENGTH}.
        """
        proto = LineReceiver()
        transport = proto_helpers.StringTransport()
        proto.makeConnection(transport)
        proto.dataReceived(b'x' * (proto.MAX_LENGTH + 1))
        self.assertTrue(transport.disconnecting)
    test_maximumLineLengthRemaining.skip = ("I think max_len support should be"
                                            "built in parsley")


    def test_rawDataError(self):
        """
        C{LineReceiver.dataReceived} forwards errors returned by
        C{rawDataReceived}.
        """
        proto = LineReceiver()
        proto.rawDataReceived = lambda data: RuntimeError("oops")
        transport = proto_helpers.StringTransport()
        proto.makeConnection(transport)
        proto.setRawMode()
        why = proto.dataReceived(b'data')
        self.assertIsInstance(why, RuntimeError)
    test_rawDataError.skip = ("dataReceived currently is not able to return that"
                             "in parsley")


    def test_rawDataReceivedNotImplemented(self):
        """
        When L{LineReceiver.rawDataReceived} is not overridden in a
        subclass, calling it raises C{NotImplementedError}.
        """
        proto = LineReceiver()
        self.assertRaises(NotImplementedError, proto.rawDataReceived, 'foo')


    def test_lineReceivedNotImplemented(self):
        """
        When L{LineReceiver.lineReceived} is not overridden in a subclass,
        calling it raises C{NotImplementedError}.
        """
        proto = LineReceiver()
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