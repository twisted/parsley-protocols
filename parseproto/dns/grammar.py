

"""
byte, short and other C types are serialized in network/big endian
"""
grammarSource = r"""
byte = anything:b -> ord(b)
short = byte:high byte:low -> high << 8 | low
int = short:high short:low -> high << 16 | low


message = header:msgHeader (-> msgHeader[2][0]):nq query{nq}:nqueries
            -> DNSParser.getType('message', msgHeader, nqueries)
# message = header:msgHeader
#             -> DNSParser.getType('message', msgHeader, [])
header = short:id byte{2}:b2 short{4}:s4 -> id, b2, s4 # header of a message

query = name:n short:t short:c -> DNSParser.getType('query', n, t, c)
# name = <bytes{9}>
name = label*:labels (byte:b ?(b == 0) -> DNSParser.getType('name', labels)
        | pointer:offset -> DNSParser.getType('name', labels, offset))
label = byte:l ?(0 < l < 64) <byte{l}>:label -> label
pointer = byte:ptrH ?(ptrH >> 6 == 3) byte:ptrL -> (ptrH & 63) << 8 | ptrL

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
