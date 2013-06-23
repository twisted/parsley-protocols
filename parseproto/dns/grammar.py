

"""
byte, short and other C types are serialized in network/big endian
"""
grammarSource = r"""
byte = anything:b -> ord(b)
short = byte:high byte:low -> high << 8 | low
int = short:high short:low -> high << 16 | low


message = header:h
header = short:id byte:byte3 byte:byte4 !(DNSParser.updateHeader(id, byte3, byte4))
        short:nqueries short:nans short:nns short:nadd -> nqueries, nans, nns, nadd

header = short:id byte:byte3 byte:byte4 !(parser.type['header']





query = name:n short:type short:cls !(DNSParser.updateQuery(n, type, cls))

name = !(DNSParser.preName()) label* (byte:b ?(b == 0) -> DNSParser.tempName
        | pointer !(DNSParser.postName()) -> DNSParser.tempName)

# label = byte:l ?(0 < l < 64) <byte{l}>:la !(DNSParser.updateName(la))
# pointer = byte:ptrH ?(ptrH >> 6 == 3) byte:ptrL !(DNSParser.updateNameOffset(ptrH, ptrL))

# rrheader = name:n short:type short:cls int:ttl short:rdlength
#             (->DNSParser.msg.lookupRecordType(type)):t ?(t)
#             (->DNSParser.tempPayload = t(ttl=ttl)) payload
# payload 'A' = <anything{4}>:address !(DNSParser.tempPayload.address = address)
# payload 'A6' = anything:prefixLen (->int((128 - prefixLen) / 8.0)):bytesLen
#                 (?(bytesLen) <anything{bytesLen}>:suffix
#                     !(DNSParser.tempLayload.suffix = b'\x00' * (16 - bytesLen) + suffix))?
#                 (?(prefixLen) name:n !(DNSParser.tempPayload.prefix.name = n))
# payload 'AAAA' = <anything{16}>:address !(DNSParser.tempPayload.address = address)
# payload 'AFSDB' = short:subtype !(DNSParser.tempPayload.subtype = r)
#                     name:n !(DNSParser.tempPayload.hostname.name = n)
# payload 'CNAME' =
# payload 'DNAME'
# payload 'HINFO'
# payload 'MB'
# payload 'MD'
# payload 'MF'
# payload 'MG'
# payload 'MINFO'
# payload 'MR'
# payload 'MX'
# payload 'NAPTR'
# payload 'NS'
# payload 'NULL'
# payload 'PTR'
# payload 'RP'
# payload 'SOA'
# payload 'SPF'
# payload 'SRV'
# payload 'TXT'
# payload 'WKS'
# payload 'UnKnownRecord'
#
# start = header:h (->h[0]):nqueries query{nqueries} (->h[1]):nans rrheader{nans}
#         (->h[2]):nns rrheader{nns} (->h[3])nadd rrheader{nadd}

"""
