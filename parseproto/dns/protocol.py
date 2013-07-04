# -*- test-case-name: parseproto.test.test_dns -*-
# Copyright (c) Twisted Matrix Laboratories.
# See LICENSE for details.

"""
DNS protocol parsing implementation under Parsley.

"""

from __future__ import absolute_import


# Twisted imports
from twisted.names import dns

# Parsley imports
from ometa.grammar import loadGrammar
from parsley import wrapGrammar


# Parseproto
import parseproto.dns


class DNSParser:

    def __init__(self, data=b''):
        self.bindings = self.setupBindings()
        self.grammar = wrapGrammar(loadGrammar(parseproto.dns, "grammar",
                                               self.bindings))
        self.updateData(data)


    def updateData(self, data=b''):
        self.data = data
        self.parser = self.grammar(data)
        return self.parser


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
        return getattr(self.parser, item)


    # a helper
    def showArgs(self, *args, **kwargs):
        print(args, kwargs)




