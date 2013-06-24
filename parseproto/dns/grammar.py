

"""
byte, short and other C types are serialized in network/big endian
"""
grammarSource = r"""
byte = anything:b -> ord(b)
short = byte:high byte:low -> high << 8 | low
int = short:high short:low -> high << 16 | low
long = int:high int:low -> high << 32 | low


message = header:msgHeader (-> msgHeader[2][0]):nq query{nq}:nqueries
            (-> msgHeader[2][1]):nans rrheader{nans}:rrhnans
            (-> msgHeader[2][2]):nns rrheader{nns}:rrhnns
            (-> msgHeader[2][3]):nadd rrheader{nadd}:rrhnadd
            -> DNSParser.getType('message', msgHeader, nqueries, rrhnans, rrhnns, rrhnadd)

header = short:id byte{2}:b2 short{4}:s4 -> id, b2, s4 # header of a message

query = name:n short:t short:c -> DNSParser.getType('query', n, t, c)

name = label*:labels (byte:b ?(b == 0) -> DNSParser.getType('name', labels)
        | pointer:offset -> DNSParser.getType('name', labels, offset))
label = byte:l ?(0 < l < 64) <byte{l}>:label -> label
pointer = byte:ptrH ?(ptrH >> 6 == 3) byte:ptrL -> (ptrH & 63) << 8 | ptrL

rrheader = name:n short:t short:cls int:ttl short:rdlength
            (-> DNSParser.getPayloadName(t)):plname payload(plname, ttl, rdlength):pl
            -> DNSParser.getType('rrheader', n, t, cls, ttl, rdlength, pl)


payload 'A' :ttl :rdl = <anything{4}>:address
                        -> DNSParser.getPayload('A', ttl=ttl, address=address)
payload 'A6' :ttl :rdl = anything:pfl (-> int((128 - pfl) / 8.0)):bl
                        (-> None):sf (-> None):n
                        (?(bl) <anything{bl}>:sf)? (?(pfl) name:n)?
                        -> DNSParser.getPayload('A6', ttl=ttl, prefixLen=pfl, bytes=bl,
                                                suffix=sf, prefix=n)
payload 'AAAA' :ttl :rdl = <anything{16}>:address
                            -> DNSParser.getPayload('AAAA', ttl=ttl, address=address)
payload 'AFSDB' :ttl :rdl = short:subtype name:n
                            -> DNSParser.getPayload('AFSDB', ttl=ttl, subtype=subtype, hostname=n)

payload 'CNAME' :ttl :rdl = name:n -> DNSParser.getPayload('CNAME', ttl=ttl, name=n)
payload 'DNAME' :ttl :rdl = name:n -> DNSParser.getPayload('DNAME', ttl=ttl, name=n)
payload 'HINFO' :ttl :rdl = byte:cpu byte:os
                            -> DNSParser.getPayload('HINFO', ttl=ttl, cpu=cpu, os=os)
payload 'MB' :ttl :rdl = name:n -> DNSParser.getPayload('MB', ttl=ttl, name=n)
payload 'MD' :ttl :rdl = name:n -> DNSParser.getPayload('MD', ttl=ttl, name=n)
payload 'MF' :ttl :rdl = name:n -> DNSParser.getPayload('MF', ttl=ttl, name=n)
payload 'MG' :ttl :rdl = name:n -> DNSParser.getPayload('MG', ttl=ttl, name=n)
payload 'MINFO' :ttl :rdl = name:rmailbx name:emailbx
                            -> DNSParser.getPayload('MINFO', ttl=ttl,
                                                    rmailbx=rmailbx, emailbx=emailbx)
payload 'MR' :ttl :rdl = name:n -> DNSParser.getPayload('MR', ttl=ttl, name=n)
payload 'MX' :ttl :rdl = short:pref name:n
                        -> DNSParser.getPayload('MX', ttl=ttl, preference=pref, name=n)
payload 'NAPTR' :ttl :rdl = short:order short:pref
                            byte:l <anything{l}>:flags
                            byte:l <anything{l}>:service
                            byte:l <anything{l}>:regexp
                            name:n
                            -> DNSParser.getPayload('NAPTR', ttl=ttl, order=order,
                                preference=pref, flags=flags, service=service,
                                regexp=regexp, replacement=n)
payload 'NS' :ttl :rdl = name:n -> DNSParser.getPayload('NS', ttl=ttl, name=n)
payload 'NULL' :ttl :rdl = <anything{rdl}>:p -> DNSParser.getPayload('NULL', ttl=ttl, payload=p)
payload 'PTR' :ttl :rdl = name:n -> DNSParser.getPayload('PTR', ttl=ttl, name=n)
payload 'RP' :ttl :rdl = name:mbox name:txt
                        -> DNSParser.getPayload('RP', ttl=ttl, mbox=mbox, txt=txt)

# The corresponding fmt is !LlllL, why signed long here?
payload 'SOA' :ttl :rdl = name:mname name:rname long:serial long:refresh long:retry
                            long:expire long:minimum
                            -> DNSParser.getType('SOA', ttl=ttl, mname=mname, rname=rname,
                                serial=serial, refresh=refresh, retry=retry, expire=expire,
                                minimum=minimum)
payload 'SPF' :ttl :rdl = name:n -> DNSParser.getPayload('SPF', ttl=ttl, name=n)
payload 'SRV' :ttl :rdl = short:priority short:weight short:port name:n
                            -> DNSParser.getPayload('SRV', ttl=ttl, priority=priority,
                                weight=weight, port=port, target=n)
payload 'TXT' :ttl :rdl = (-> 0):soFar (?(soFar < rdl) byte:l <anything{l}>)*:data
                            -> DNSParser.getPayload('TXT', ttl=ttl, data=data)
payload 'WKS' :ttl :rdl = <anything{4}>:address byte:protocol (-> rdl - 5):l <anything{l}>:map
                            -> DNSParser.getPayload('WKS', ttl=ttl, address=address,
                                protocol=protocol, map=map)
payload 'UnknownRecord' :ttl :rdl = <anything{rdl}>:data
                                    -> DNSParser.getType('UnknownRecord', ttl=ttl, data=data)
"""


