# -*- test-case-name: parseproto.test.test_dns -*-
# Copyright (c) Twisted Matrix Laboratories.
# See LICENSE for details.

"""
DNS protocol parsing implementation under Parsley.

"""

from __future__ import absolute_import

import struct

# Twisted imports
from twisted.names import dns
from twisted.python import log, failure
from twisted.internet import protocol, defer
from twisted.internet.error import CannotListenError

# Parsley imports
from ometa.grammar import loadGrammar
from parsley import wrapGrammar
from ometa.runtime import ParseError


# Parseproto
import parseproto.dns


class DNSParser(object):

    def __init__(self, *args, **kwargs):
        self.bindings = self.setupBindings()
        self.grammar = wrapGrammar(loadGrammar(parseproto.dns, "grammar",
                                               self.bindings))


    def updateData(self, data=b''):
        self.data = data
        self.parser = self.grammar(data)


    def setupBindings(self):
        bindings = {}
        items = dns.__dict__.iterkeys()
        for record in [x for x in items if x.startswith('Record_')]:
            recordType = getattr(dns, record)
            bindings[record[len('Record_'):]] = recordType
        bindings['Parser'] = self
        bindings['UnknownRecord'] = dns.UnknownRecord
        bindings['Query'] = dns.Query
        bindings['RRHeader'] = dns.RRHeader
        # some trivial settings as we cannot modify twisted.names.dns
        bindings['A'] = self.record_AFromRawData
        bindings['A6'] = self.record_A6FromRawData
        bindings['AAAA'] = self.record_AAAAFromRawData
        bindings['WKS'] = self.record_WKSFromRawData
        bindings['Message'] = self.messageFromRawData
        bindings['Name'] = self.nameFromRawData
        bindings['getPayloadName'] = lambda t: dns.QUERY_TYPES.get(t, "UnknownRecord")
        return bindings


    def nameFromRawData(self, labels, offset=None):
        name = b'.'.join(labels)
        if offset is None:
            return dns.Name(name=name)
        visited = set()
        visited.add(offset)
        while 1:
            l = ord(self.data[offset])
            offset += 1
            if l == 0:
                return dns.Name(name)
            if (l >> 6) == 3:
                offset = (l & 63) << 8 | ord(self.data[offset])
                if offset in visited:
                    raise ValueError("Compression loop in compressed name")
                visited.add(offset)
                continue
            label = self.data[offset: offset+l]
            offset += l
            if name == b'':
                name = label
            else:
                name = name + b'.' + label


    @staticmethod
    def messageFromRawData(id, answer, opCode, auth, trunc, recDes, recAv,
                           rCode, nqueries, rrhnans, rrhnns, rrhnadd):
        m = dns.Message()
        m.maxSize = 0
        m.id, m.answer, m.opCode, m.auth, m.trunc, m.recDes, m.recAv, m.rCode = (
            id, answer, opCode, auth, trunc, recDes, recAv, rCode)
        # by default nqueries, rrhnans... would be '' when matches nothing
        # we should fix it in parsley instead of here
        m.queries = nqueries or []
        m.answers = rrhnans or []
        m.authority = rrhnns or []
        m.additional = rrhnadd or []
        return m


    @staticmethod
    def record_AFromRawData(address, ttl=None):
        record_A = dns.Record_A(ttl=ttl)
        record_A.address = address
        return record_A

    @staticmethod
    def record_A6FromRawData(ttl, prefixLen, suffix, prefix):
        record_A6 = dns.Record_A6(ttl=ttl, prefixLen=prefixLen)
        record_A6.bytes = int((128 - prefixLen) / 8.0)
        if record_A6.bytes:
            record_A6.suffix = suffix
        if record_A6.prefixLen:
            record_A6.prefix = prefix
        return record_A6


    @staticmethod
    def record_AAAAFromRawData(address, ttl):
        record_AAAA = dns.Record_AAAA(ttl=ttl)
        record_AAAA.address = address
        return record_AAAA


    @staticmethod
    def record_WKSFromRawData(address, protocol, map, ttl):
        record_WKS = dns.Record_WKS(protocol=protocol, map=map, ttl=ttl)
        record_WKS.address = address
        return record_WKS


    def __getattr__(self, item):
        """
        @param item: item is the rule to be invoked.
        """
        return getattr(self.parser, item)


    # a helper
    def showArgs(self, *args, **kwargs):
        print(args, kwargs)



class DNSDatagramProtocol(dns.DNSMixin, protocol.DatagramProtocol):
    """
    DNS protocol over UDP.
    """
    resends = None


    def __init__(self, *args, **kwargs):
        self.parser = DNSParser()
        super(DNSDatagramProtocol, self).__init__(*args, **kwargs)


    def stopProtocol(self):
        """
        Stop protocol: reset state variables.
        """
        self.liveMessages = {}
        self.resends = {}
        self.transport = None

    def startProtocol(self):
        """
        Upon start, reset internal state.
        """
        self.liveMessages = {}
        self.resends = {}

    def writeMessage(self, message, address):
        """
        Send a message holding DNS queries.

        @type message: L{Message}
        """
        self.transport.write(message.toStr(), address)

    def startListening(self):
        self._reactor.listenUDP(0, self, maxPacketSize=512)

    def datagramReceived(self, data, addr):
        """
        Read a datagram, extract the message in it and trigger the associated
        Deferred.
        """
        self.parser.updateData(data)
        try:
            m = self.parser.message()
        except ParseError:
            log.msg("Encountered ParseError from %s" % (addr,))
            return
        except:
            log.err(failure.Failure(), "Unexpected parsing error")
            return

        if m.id in self.liveMessages:
            d, canceller = self.liveMessages[m.id]
            del self.liveMessages[m.id]
            canceller.cancel()
            # XXX we shouldn't need this hack of catching exception on callback()
            try:
                d.callback(m)
            except:
                log.err()
        else:
            if m.id not in self.resends:
                self.controller.messageReceived(m, self, addr)


    def removeResend(self, id):
        """
        Mark message ID as no longer having duplication suppression.
        """
        try:
            del self.resends[id]
        except KeyError:
            pass

    def query(self, address, queries, timeout=10, id=None):
        """
        Send out a message with the given queries.

        @type address: C{tuple} of C{str} and C{int}
        @param address: The address to which to send the query

        @type queries: C{list} of C{Query} instances
        @param queries: The queries to transmit

        @rtype: C{Deferred}
        """
        if not self.transport:
            # XXX transport might not get created automatically, use callLater?
            try:
                self.startListening()
            except CannotListenError:
                return defer.fail()

        if id is None:
            id = self.pickID()
        else:
            self.resends[id] = 1

        def writeMessage(m):
            self.writeMessage(m, address)

        return self._query(queries, timeout, id, writeMessage)


class DNSProtocol(dns.DNSMixin, protocol.Protocol):
    """
    DNS protocol over TCP.
    """
    length = None
    buffer = b''


    def __init__(self, *args, **kwargs):
        self.parser = DNSParser()
        super(DNSProtocol, self).__init__(*args, **kwargs)


    def writeMessage(self, message):
        """
        Send a message holding DNS queries.

        @type message: L{Message}
        """
        s = message.toStr()
        self.transport.write(struct.pack('!H', len(s)) + s)

    def connectionMade(self):
        """
        Connection is made: reset internal state, and notify the controller.
        """
        self.liveMessages = {}
        self.controller.connectionMade(self)


    def connectionLost(self, reason):
        """
        Notify the controller that this protocol is no longer
        connected.
        """
        self.controller.connectionLost(self)


    def dataReceived(self, data):
        self.buffer += data

        while self.buffer:
            if self.length is None and len(self.buffer) >= 2:
                self.length = struct.unpack('!H', self.buffer[:2])[0]
                self.buffer = self.buffer[2:]

            if len(self.buffer) >= self.length:
                myChunk = self.buffer[:self.length]
                self.parser.updateData(myChunk)
                m = self.parser.message()

                try:
                    d, canceller = self.liveMessages[m.id]
                except KeyError:
                    self.controller.messageReceived(m, self)
                else:
                    del self.liveMessages[m.id]
                    canceller.cancel()
                    # XXX we shouldn't need this hack
                    try:
                        d.callback(m)
                    except:
                        log.err()

                self.buffer = self.buffer[self.length:]
                self.length = None
            else:
                break


    def query(self, queries, timeout=60):
        """
        Send out a message with the given queries.

        @type queries: C{list} of C{Query} instances
        @param queries: The queries to transmit

        @rtype: C{Deferred}
        """
        id = self.pickID()
        return self._query(queries, timeout, id, self.writeMessage)






