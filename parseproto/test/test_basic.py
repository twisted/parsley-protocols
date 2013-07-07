
from __future__ import division, absolute_import

from twisted.python.compat import iterbytes
from twisted.trial import unittest
from twisted.internet import error
from twisted.test import proto_helpers


from parseproto.basic.protocol import LineOnlyReceiver

class LineOnlyTester(LineOnlyReceiver):
    """
    A buffering line only receiver.
    """
    delimiter = b'\n'
    MAX_LENGTH = 64

    def connectionMade(self):
        """
        Create/clean data received on connection.
        """
        self.received = []
        # twisted.internet.protcol.BaseProtcol is an old-style class
        LineOnlyReceiver.connectionMade(self)


    def lineReceived(self, line):
        """
        Save received data.
        """
        self.received.append(line)


class LineOnlyReceiverTestCase(unittest.SynchronousTestCase):
    """
    Tests for L{parserproto.basic.protocol.LineOnlyReceiver}.
    """
    buffer = b"""foo\r\nbleakness\r\ndesolation\r\nplastic forks"""
    buffer = b'asdfsadf\r\n'
    buffer = 'aabc'

    def test_buffer(self):
        """
        Test buffering over line protocol: data received should match buffer.
        """
        t = proto_helpers.StringTransport()
        a = LineOnlyTester()
        a.makeConnection(t)
        for c in iterbytes(self.buffer):
            a.dataReceived(c)
        self.assertEqual(a.received, self.buffer.split(b'\n')[:-1])


    def test_lineTooLong(self):
        """
        Test sending a line too long: it should close the connection.
        """
        t = proto_helpers.StringTransport()
        a = LineOnlyTester()
        a.makeConnection(t)
        res = a.dataReceived(b'x' * 200)
        self.assertIsInstance(res, error.ConnectionLost)


    def test_lineReceivedNotImplemented(self):
        """
        When L{LineOnlyReceiver.lineReceived} is not overridden in a subclass,
        calling it raises C{NotImplementedError}.
        """
        proto = LineOnlyReceiver()
        self.assertRaises(NotImplementedError, proto.lineReceived, 'foo')
