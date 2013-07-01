"""
byte, short and other C types are serialized in network/big endian
"""
grammarSource = r"""
byte = anything:b -> ord(b)
short = byte:high byte:low -> high << 8 | low
int = short:high short:low -> high << 16 | low
long = int:high int:low -> high << 32 | low

message = short:id
            byte:b
            (-> b>>7 & 1, b>>3 & 1, b>>2 & 1, b>>1 & 1, b & 1):(anwser, opCode, auth, trunc, recDes)
            byte:b (-> b>>7 & 1, b & 0xf):(recAv, rCode)
            short:nq short:nans short:nns short:nadd
            query{nq}:nqueries
            (rrheader(auth)){nans}:rrhnans
            (rrheader(auth)){nns}:rrhnns
            (rrheader(auth)){nadd}:rrhnadd
            -> DNSParser.getType('message', answer, opCode, auth, trunc, recDes,
                recAv, rCode, nqueries, rrhnans, rrhnns, rrhadd)

query = name:n short:t short:c -> DNSParser.getType('query', n, t, c)

name = label*:labels (byte:b ?(b == 0) -> DNSParser.getType('name', labels)
        | pointer:offset -> DNSParser.getType('name', labels, offset))
label = byte:l ?(0 < l < 64) <byte{l}>:label -> label
pointer = byte:ptrH ?(ptrH >> 6 == 3) byte:ptrL -> (ptrH & 63) << 8 | ptrL

rrheader :auth = name:n short:t short:cls int:ttl short:rdlength
            (-> DNSParser.getPayloadName(t)):plname payload(plname, ttl, rdlength):pl
            -> DNSParser.getType('rrheader', auth, n, t, cls, ttl, pl)


payload 'A' :ttl :rdl = <anything{4}>:address
                        -> DNSParser.getType('A', ttl=ttl, address=address)
payload 'A6' :ttl :rdl = byte:pfl (-> int((128 - pfl) / 8.0)):bl
                        (-> '::'):sf (-> b''):n
                        (?(bl) <anything{bl}>:sf)? (?(pfl) name:n)?
                        -> DNSParser.getType('A6', ttl=ttl, prefixLen=pfl, suffix=sf, prefix=n.name)
payload 'AAAA' :ttl :rdl = <anything{16}>:address
                            -> DNSParser.getType('AAAA', ttl=ttl, address=address)
payload 'AFSDB' :ttl :rdl = short:subtype name:n
                            -> DNSParser.getType('AFSDB', ttl=ttl, subtype=subtype, hostname=n.name)

payload 'CNAME' :ttl :rdl = name:n -> DNSParser.getType('CNAME', ttl=ttl, name=n.name)
payload 'DNAME' :ttl :rdl = name:n -> DNSParser.getType('DNAME', ttl=ttl, name=n.name)
payload 'MB' :ttl :rdl = name:n -> DNSParser.getType('MB', ttl=ttl, name=n.name)
payload 'MD' :ttl :rdl = name:n -> DNSParser.getType('MD', ttl=ttl, name=n.name)
payload 'MF' :ttl :rdl = name:n -> DNSParser.getType('MF', ttl=ttl, name=n.name)
payload 'MR' :ttl :rdl = name:n -> DNSParser.getType('MR', ttl=ttl, name=n.name)
payload 'NS' :ttl :rdl = name:n -> DNSParser.getType('NS', ttl=ttl, name=n.name)
payload 'PTR' :ttl :rdl = name:n -> DNSParser.getType('PTR', ttl=ttl, name=n.name)
payload 'MG' :ttl :rdl = name:n -> DNSParser.getType('MG', ttl=ttl, name=n.name)
payload 'HINFO' :ttl :rdl = byte:cpu byte:os
                            -> DNSParser.getType('HINFO', ttl=ttl, cpu=cpu, os=os)
payload 'MINFO' :ttl :rdl = name:rmailbx name:emailbx
                            -> DNSParser.getType('MINFO', ttl=ttl,
                                                    rmailbx=rmailbx.name, emailbx=emailbx.name)
payload 'MX' :ttl :rdl = short:pref name:n
                        -> DNSParser.getType('MX', ttl=ttl, preference=pref, name=n.name)
payload 'NAPTR' :ttl :rdl = short:order short:pref
                            byte:l <anything{l}>:flags
                            byte:l <anything{l}>:service
                            byte:l <anything{l}>:regexp
                            name:n
                            -> DNSParser.getType('NAPTR', ttl=ttl, order=order,
                                preference=pref, flags=flags, service=service,
                                regexp=regexp, replacement=n.name)
payload 'NULL' :ttl :rdl = <anything{rdl}>:p -> DNSParser.getType('NULL', ttl=ttl, payload=p)
payload 'RP' :ttl :rdl = name:mbox name:txt
                        -> DNSParser.getType('RP', ttl=ttl, mbox=mbox.name, txt=txt.name)
# The corresponding fmt is !LlllL, why signed long here?
payload 'SOA' :ttl :rdl = name:mname name:rname long:serial long:refresh long:retry
                            long:expire long:minimum
                            -> DNSParser.getType('SOA', ttl=ttl, mname=mname.name, rname=rname.name,
                                serial=serial, refresh=refresh, retry=retry, expire=expire,
                                minimum=minimum)
payload 'SRV' :ttl :rdl = short:priority short:weight short:port name:n
                            -> DNSParser.getType('SRV', ttl=ttl, priority=priority,
                                weight=weight, port=port, target=n.name)
payload 'TXT' :ttl :rdl = (-> 0):soFar (?(soFar < rdl) byte:l <anything{l}>)*:data
                            -> DNSParser.getType('TXT', ttl=ttl, data=data)
payload 'SPF' :ttl :rdl = (-> 0):soFar (?(soFar < rdl) byte:l <anything{l}>)*:data
                            -> DNSParser.getType('SPF', ttl=ttl, data=data)
payload 'WKS' :ttl :rdl = <anything{4}>:address byte:protocol (-> rdl - 5):l <anything{l}>:map
                            -> DNSParser.getType('WKS', ttl=ttl, address=address,
                                protocol=protocol, map=map)
payload 'UnknownRecord' :ttl :rdl = <anything{rdl}>:data
                                    -> DNSParser.getType('UnknownRecord', ttl=ttl, data=data)
"""


