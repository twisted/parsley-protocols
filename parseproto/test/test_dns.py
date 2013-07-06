# -*- test-case-name: parseproto.test.test_dns -*-
# Copyright (c) Twisted Matrix Laboratories.
# See LICENSE for details.

"""
Tests for parseproto.dns.protocol.
"""

from __future__ import absolute_import


from io import BytesIO
import struct


# Twisted imports
from twisted.names import dns
from twisted.trial import unittest
from twisted.internet import address, task
from twisted.internet.error import CannotListenError, ConnectionDone
from twisted.test import proto_helpers
from twisted.python.failure import Failure

# dns import from parsley-protocols
from parseproto.dns import protocol


class DNSParserTests(unittest.TestCase):
    """
    Tests of parseproto.dns.protocol.DNSParser
    """

    names = [b"example.org", b"go-away.fish.tv", b"23strikesback.net"]


    def setUp(self):
        self.parser = protocol.DNSParser()


    def test_name(self):
        """
        L{DNSparser.parser.name} populates the L{Name} instance with name information read
        from the file-like object passed to it.
        """
        self.parser.updateData(b"\x07example\x03com\x00")
        self.assertEqual(dns.Name(b"example.com"), self.parser.name())


    def test_unknown(self):
        """
        A resource record of unknown type and class is parsed into an
        L{UnknownRecord} instance with its data preserved, and an
        L{UnknownRecord} instance is serialized to a string equal to the one it
        was parsed from.
        """
        wire = (
            b'\x01\x00' # Message ID
            b'\x00' # answer bit, opCode nibble, auth bit, trunc bit, recursive
                    # bit
            b'\x00' # recursion bit, empty bit, empty bit, empty bit, response
                    # code nibble
            b'\x00\x01' # number of queries
            b'\x00\x01' # number of answers
            b'\x00\x00' # number of authorities
            b'\x00\x01' # number of additionals

            # query
            b'\x03foo\x03bar\x00'    # foo.bar
            b'\xde\xad'              # type=0xdead
            b'\xbe\xef'              # cls=0xbeef

            # 1st answer
            b'\xc0\x0c'              # foo.bar - compressed
            b'\xde\xad'              # type=0xdead
            b'\xbe\xef'              # cls=0xbeef
            b'\x00\x00\x01\x01'      # ttl=257
            b'\x00\x08somedata'      # some payload data

            # 1st additional
            b'\x03baz\x03ban\x00'    # baz.ban
            b'\x00\x01'              # type=A
            b'\x00\x01'              # cls=IN
            b'\x00\x00\x01\x01'      # ttl=257
            b'\x00\x04'              # len=4
            b'\x01\x02\x03\x04'      # 1.2.3.4
            )
        self.parser.updateData(wire)
        msg = self.parser.message()
        self.assertEqual(msg.queries, [
                dns.Query(b'foo.bar', type=0xdead, cls=0xbeef),
                ])
        self.assertEqual(msg.answers, [
                dns.RRHeader(b'foo.bar', type=0xdead, cls=0xbeef, ttl=257,
                             payload=dns.UnknownRecord(b'somedata', ttl=257)),
                ])
        self.assertEqual(msg.additional, [
                dns.RRHeader(b'baz.ban', type=dns.A, cls=dns.IN, ttl=257,
                             payload=dns.Record_A('1.2.3.4', ttl=257)),
                ])
        enc = msg.toStr()
        self.assertEqual(enc, wire)


    def test_nameRejectCompressionLoop(self):
        """
        L{DNSParser.parser.name} raises an L{ValueError} if the name contains
        compression loop.
        """
        self.parser.updateData(b"\xc0\x00")
        self.assertRaises(ValueError, self.parser.name)


    def test_nameRoundTrip(self):
        """
        Encoding and then parsing the object.
        """
        for n in self.names:
            f = BytesIO()
            dns.Name(n).encode(f)
            f.seek(0, 0)
            self.parser.updateData(f.read1(-1))
            self.assertEqual(self.parser.name().name, n)


    def test_queryRoundTrip(self):
        """
        Encoding and then parsing the object.
        """
        for n in self.names:
            for dnstype in range(1, 17):
                for dnscls in range(1, 5):
                    f = BytesIO()
                    dns.Query(n, dnstype, dnscls).encode(f)
                    f.seek(0, 0)
                    self.parser.updateData(f.read1(-1))
                    query = self.parser.query()
                    self.assertEqual(query.name.name, n)
                    self.assertEqual(query.type, dnstype)
                    self.assertEqual(query.cls, dnscls)


    def _recordRoundtripTest(self, record, name, ttl=None):
        """
        Assert that encoding C{record} and then parsing the resulting bytes
        creates a record which compares equal to C{record}.
        """
        stream = BytesIO()
        record.encode(stream)
        length = stream.tell()
        stream.seek(0, 0)
        data = stream.read1(-1)
        self.parser.updateData(data)
        self.assertEqual(record, getattr(self.parser, 'payload')(name, ttl, length))


    def test_SOA(self):
        record = dns.Record_SOA(mname=b'foo', rname=b'bar', serial=12, refresh=34,
                                retry=56, expire=78, minimum=90)
        self._recordRoundtripTest(record, 'SOA')


    def test_A(self):
        self._recordRoundtripTest(dns.Record_A('1.2.3.4'), 'A')


    def test_NULL(self):
        self._recordRoundtripTest(dns.Record_NULL(b'foo bar'), 'NULL')


    def test_WKS(self):
        self._recordRoundtripTest(dns.Record_WKS('1.2.3.4', 3, b'xyz'), 'WKS')


    def test_AAAA(self):
        self._recordRoundtripTest(dns.Record_AAAA('::1'), 'AAAA')


    def test_A6(self):
        self._recordRoundtripTest(dns.Record_A6(8, '::1:2', b'foo'), 'A6')


    def test_SRV(self):
        self._recordRoundtripTest(dns.Record_SRV(
                priority=1, weight=2, port=3, target=b'example.com'), 'SRV')


    def test_NAPTR(self):
        naptrs = [
            (100, 10, b"u", b"sip+E2U",
             b"!^.*$!sip:information@domain.tld!", b""),
            (100, 50, b"s", b"http+I2L+I2C+I2R",
             b"", b"_http._tcp.gatech.edu")]

        for (order, preference, flags, service, regexp, replacement) in naptrs:
            rin = dns.Record_NAPTR(order, preference, flags, service, regexp,
                                   replacement)
            e = BytesIO()
            rin.encode(e)
            length = e.tell()
            e.seek(0, 0)
            self.parser.updateData(e.read1(-1))
            rout = getattr(self.parser, 'payload')('NAPTR', None, length)
            self.assertEqual(rin.order, rout.order)
            self.assertEqual(rin.preference, rout.preference)
            self.assertEqual(rin.flags, rout.flags)
            self.assertEqual(rin.service, rout.service)
            self.assertEqual(rin.regexp, rout.regexp)
            self.assertEqual(rin.replacement.name, rout.replacement.name)
            self.assertEqual(rin.ttl, rout.ttl)


    def test_AFSDB(self):
        self._recordRoundtripTest(dns.Record_AFSDB(
                subtype=3, hostname=b'example.com'), 'AFSDB')


    def test_RP(self):
        self._recordRoundtripTest(dns.Record_RP(
                mbox=b'alice.example.com', txt=b'example.com'), 'RP')


    def test_HINFO(self):
        self._recordRoundtripTest(dns.Record_HINFO(cpu=b'fast', os=b'great'), 'HINFO')


    def test_MINFO(self):
        self._recordRoundtripTest(dns.Record_MINFO(
                rmailbx=b'foo', emailbx=b'bar'), 'MINFO')


    def test_MX(self):
        self._recordRoundtripTest(dns.Record_MX(
                preference=1, name=b'example.com'), 'MX')


    def test_TXT(self):
        self._recordRoundtripTest(dns.Record_TXT(b'foo', b'bar'), 'TXT')


    def test_emptyQuery(self):
        """
        Test that bytes representing an empty query message can be parsed
        as such.
        """
        data = (
            b'\x01\x00' # Message ID
            b'\x00' # answer bit, opCode nibble, auth bit, trunc bit, recursive bit
            b'\x00' # recursion bit, empty bit, empty bit, empty bit, response code nibble
            b'\x00\x00' # number of queries
            b'\x00\x00' # number of answers
            b'\x00\x00' # number of authorities
            b'\x00\x00' # number of additionals
        )
        self.parser.updateData(data)
        msg = self.parser.message()
        self.assertEqual(msg.id, 256)
        self.failIf(msg.answer, "Message was not supposed to be an answer.")
        self.assertEqual(msg.opCode, dns.OP_QUERY)
        self.failIf(msg.auth, "Message was not supposed to be authoritative.")
        self.failIf(msg.trunc, "Message was not supposed to be truncated.")
        self.assertEqual(msg.queries, [])
        self.assertEqual(msg.answers, [])
        self.assertEqual(msg.authority, [])
        self.assertEqual(msg.additional, [])


    def test_NULLRecordMessage(self):
        """
        A I{NULL} record with an arbitrary payload can be encoded and parsed as
        part of a L{dns.Message}.
        """
        bytes = b''.join([dns._ord2bytes(i) for i in range(256)])
        rec = dns.Record_NULL(bytes)
        rr = dns.RRHeader(b'testname', dns.NULL, payload=rec)
        msg1 = dns.Message()
        msg1.answers.append(rr)
        s = BytesIO()
        msg1.encode(s)
        s.seek(0, 0)
        self.parser.updateData(s.read1(-1))
        msg2 = self.parser.message()
        self.failUnless(isinstance(msg2.answers[0].payload, dns.Record_NULL))
        self.assertEqual(msg2.answers[0].payload.payload, bytes)


    def test_nonAuthoritativeMessage(self):
        """
        The L{RRHeader} instances created by L{Message} from a non-authoritative
        message are marked as not authoritative.
        """
        buf = BytesIO()
        answer = dns.RRHeader(payload=dns.Record_A('1.2.3.4', ttl=0))
        answer.encode(buf)
        data = (
            b'\x01\x00' # Message ID
            # answer bit, opCode nibble, auth bit, trunc bit, recursive bit
            b'\x00'
            # recursion bit, empty bit, empty bit, empty bit, response code
            # nibble
            b'\x00'
            b'\x00\x00' # number of queries
            b'\x00\x01' # number of answers
            b'\x00\x00' # number of authorities
            b'\x00\x00' # number of additionals
            + buf.getvalue()
            )
        self.parser.updateData(data)
        message = self.parser.message()
        self.assertEqual(message.answers, [answer])
        self.assertFalse(message.answers[0].auth)


    def test_authoritativeMessage(self):
        """
        The L{RRHeader} instances created by L{Message} from an authoritative
        message are marked as authoritative.
        """
        buf = BytesIO()
        answer = dns.RRHeader(payload=dns.Record_A('1.2.3.4', ttl=0))
        answer.encode(buf)
        data = (
            b'\x01\x00' # Message ID
            # answer bit, opCode nibble, auth bit, trunc bit, recursive bit
            b'\x04'
            # recursion bit, empty bit, empty bit, empty bit, response code
            # nibble
            b'\x00'
            b'\x00\x00' # number of queries
            b'\x00\x01' # number of answers
            b'\x00\x00' # number of authorities
            b'\x00\x00' # number of additionals
            + buf.getvalue()
            )
        answer.auth = True
        self.parser.updateData(data)
        message = self.parser.message()
        self.assertEqual(message.answers, [answer])
        self.assertTrue(message.answers[0].auth)


class TestController(object):
    """
    Pretend to be a DNS query processor for a DNSDatagramProtocol.

    @ivar messages: the list of received messages.
    @type messages: C{list} of (msg, protocol, address)
    """

    def __init__(self):
        """
        Initialize the controller: create a list of messages.
        """
        self.messages = []


    def messageReceived(self, msg, proto, addr):
        """
        Save the message so that it can be checked during the tests.
        """
        self.messages.append((msg, proto, addr))



class DNSDatagramProtocolTestCases(unittest.TestCase):
    """
    Test various aspects of L{protocol.DNSDatagramProtocol}.
    """

    def setUp(self):
        """
        Create a L{protocol.DNSDatagramProtocol} with a deterministic clock.
        """
        self.clock = task.Clock()
        self.controller = TestController()
        self.proto = protocol.DNSDatagramProtocol(self.controller)
        transport = proto_helpers.FakeDatagramTransport()
        self.proto.makeConnection(transport)
        self.proto.callLater = self.clock.callLater


    def test_truncatedPacket(self):
        """
        Test that when a short datagram is received, datagramReceived does
        not raise an exception while processing it.
        """
        self.proto.datagramReceived(
            b'', address.IPv4Address('UDP', '127.0.0.1', 12345))
        self.assertEqual(self.controller.messages, [])


    def test_simpleQuery(self):
        """
        Test content received after a query.
        """
        d = self.proto.query(('127.0.0.1', 21345), [dns.Query(b'foo')])
        self.assertEqual(len(self.proto.liveMessages.keys()), 1)
        m = dns.Message()
        m.id = next(iter(self.proto.liveMessages.keys()))
        m.answers = [dns.RRHeader(payload=dns.Record_A(address='1.2.3.4'))]
        def cb(result):
            self.assertEqual(result.answers[0].payload.dottedQuad(), '1.2.3.4')
        d.addCallback(cb)
        self.proto.datagramReceived(m.toStr(), ('127.0.0.1', 21345))
        return d


    def test_queryTimeout(self):
        """
        Test that query timeouts after some seconds.
        """
        d = self.proto.query(('127.0.0.1', 21345), [dns.Query(b'foo')])
        self.assertEqual(len(self.proto.liveMessages), 1)
        self.clock.advance(10)
        self.assertFailure(d, dns.DNSQueryTimeoutError)
        self.assertEqual(len(self.proto.liveMessages), 0)
        return d


    def test_writeError(self):
        """
        Exceptions raised by the transport's write method should be turned into
        C{Failure}s passed to errbacks of the C{Deferred} returned by
        L{DNSParser.query}.
        """
        def writeError(message, addr):
            raise RuntimeError("bar")
        self.proto.transport.write = writeError

        d = self.proto.query(('127.0.0.1', 21345), [dns.Query(b'foo')])
        return self.assertFailure(d, RuntimeError)


    def test_listenError(self):
        """
        Exception L{CannotListenError} raised by C{listenUDP} should be turned
        into a C{Failure} passed to errback of the C{Deferred} returned by
        L{DNSParser.query}.
        """
        def startListeningError():
            raise CannotListenError(None, None, None)
        self.proto.startListening = startListeningError
        # Clean up transport so that the protocol calls startListening again
        self.proto.transport = None

        d = self.proto.query(('127.0.0.1', 21345), [dns.Query(b'foo')])
        return self.assertFailure(d, CannotListenError)



class TestTCPController(TestController):
    """
    Pretend to be a DNS query processor for a DNSProtocol.

    @ivar connections: A list of L{DNSProtocol} instances which have
        notified this controller that they are connected and have not
        yet notified it that their connection has been lost.
    """
    def __init__(self):
        TestController.__init__(self)
        self.connections = []


    def connectionMade(self, proto):
        self.connections.append(proto)


    def connectionLost(self, proto):
        self.connections.remove(proto)



class DNSProtocolTestCase(unittest.TestCase):
    """
    Test various aspects of L{protocol.DNSProtocol}.
    """

    def setUp(self):
        """
        Create a L{protocol.DNSProtocol} with a deterministic clock.
        """
        self.clock = task.Clock()
        self.controller = TestTCPController()
        self.proto = protocol.DNSProtocol(self.controller)
        self.proto.makeConnection(proto_helpers.StringTransport())
        self.proto.callLater = self.clock.callLater


    def test_connectionTracking(self):
        """
        L{protocol.DNSProtocol} calls its controller's C{connectionMade}
        method with itself when it is connected to a transport and its
        controller's C{connectionLost} method when it is disconnected.
        """
        self.assertEqual(self.controller.connections, [self.proto])
        self.proto.connectionLost(
            Failure(ConnectionDone("Fake Connection Done")))
        self.assertEqual(self.controller.connections, [])


    def test_queryTimeout(self):
        """
        Test that query timeouts after some seconds.
        """
        d = self.proto.query([dns.Query(b'foo')])
        self.assertEqual(len(self.proto.liveMessages), 1)
        self.clock.advance(60)
        self.assertFailure(d, dns.DNSQueryTimeoutError)
        self.assertEqual(len(self.proto.liveMessages), 0)
        return d


    def test_simpleQuery(self):
        """
        Test content received after a query.
        """
        d = self.proto.query([dns.Query(b'foo')])
        self.assertEqual(len(self.proto.liveMessages.keys()), 1)
        m = dns.Message()
        m.id = next(iter(self.proto.liveMessages.keys()))
        m.answers = [dns.RRHeader(payload=dns.Record_A(address='1.2.3.4'))]
        def cb(result):
            self.assertEqual(result.answers[0].payload.dottedQuad(), '1.2.3.4')
        d.addCallback(cb)
        s = m.toStr()
        s = struct.pack('!H', len(s)) + s
        self.proto.dataReceived(s)
        return d


    def test_writeError(self):
        """
        Exceptions raised by the transport's write method should be turned into
        C{Failure}s passed to errbacks of the C{Deferred} returned by
        L{DNSProtocol.query}.
        """
        def writeError(message):
            raise RuntimeError("bar")
        self.proto.transport.write = writeError

        d = self.proto.query([dns.Query(b'foo')])
        return self.assertFailure(d, RuntimeError)


