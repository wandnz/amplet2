import struct
import socket

# TODO move to another file
class VersionMismatch(Exception):
    def __init__(self, got, expected):
        self.got = got
        self.expected = expected
    def __str__(self):
        return "%d != %d" % (self.got, self.expected)


# version needs to keep up with the version number in src/tests/icmp/icmp.h
AMP_DNS_TEST_VERSION = 2014020400


# Old data coming from deployed amplet2-client debian package 0.1.13-1
# TODO remove this code once we have got rid of everyone that speaks this
# version
def data_2013022000(data):
    header_len = struct.calcsize("=I256sHHHBB")
    item_len = struct.calcsize("=128s256s16siIIHHHHHBB")

    # offset past the version number which has already been read
    offset = struct.calcsize("=I")

    # read the rest of the header that records test options
    query,qtype,qclass,payload,opts,count = struct.unpack_from("=256sHHHBB", data, offset)

    offset = header_len
    results = []

    # extract every item in the data portion of the message
    while count > 0:
        # "p" pascal string could be useful here, length byte before string
        name,instance,addr,rtt,qlen,size,ans,aut,add,flags,res,family,ttl = struct.unpack_from("=128s256s16siIIHHHHHBB", data, offset)

        # the C structure understands how to access the flags in the
        # appropriate byte order, but that doesn't help us here - swap it.
        flags = socket.ntohs(flags)

        if family == socket.AF_INET:
            addr = socket.inet_ntop(family, addr[:4])
        elif family == socket.AF_INET6:
            addr = socket.inet_ntop(family, addr)
        else:
            #print "Unknown address family %d" % family
            raise ValueError

        results.append(
                {
                    "destination": name.rstrip("\0"),
                    "instance": instance.rstrip("\0"),
                    "address": addr,
                    "rtt": rtt if rtt >= 0 else None,
                    "query_len": qlen,
		    "response_size": size if rtt >= 0 else None,
		    "total_answer": ans if rtt >= 0 else None,
		    "total_authority": aut if rtt >= 0 else None,
		    "total_additional": add if rtt >= 0 else None,
                    "flags": {
                        "rd": bool(flags & 0x0100),
                        "tc": bool(flags & 0x0200),
                        "aa": bool(flags & 0x0400),
                        "opcode": int(flags & 0x7800),
                        "qr": bool(flags & 0x8000),
                        "rcode": int(flags & 0x000f),
                        "cd": bool(flags & 0x0010),
                        "ad": bool(flags & 0x0020),
                        "ra": bool(flags & 0x0080),
		    } if rtt >= 0 else {},
		    "ttl": ttl if rtt >= 0 else None,
                }
            )
        offset += item_len
        count -= 1

    return {
        "query": query.rstrip("\0"),
        "query_type": get_query_type(qtype),
        "query_class": get_query_class(qclass),
        "udp_payload_size": payload,
        "recurse": bool(opts & 0x01),
        "dnssec": bool(opts & 0x02),
        "nsid": bool(opts & 0x04),
        "results": results,
    }


# New data that is byte swapped, variable length strings etc
def data_2014020400(data):
    header_len = struct.calcsize("!IHHHBBB")
    item_len = struct.calcsize("!16siIIHHHHBBBB")

    # offset past the version number which has already been read
    offset = struct.calcsize("!I")

    # read the rest of the header that records test options
    qtype,qclass,payload,opts,count,querylen = struct.unpack_from("!HHHBBB", data, offset)

    # get the variable length query string that follows the header
    assert(querylen > 0 and querylen < 255)
    offset = header_len
    (query,) = struct.unpack_from("!%ds" % querylen, data, offset)
    offset += querylen
    assert(querylen == len(query))

    results = []

    # extract every item in the data portion of the message
    while count > 0:
	# "p" pascal string could be useful here, length byte before string
        addr,rtt,qlen,size,ans,aut,add,flags,family,ttl,namelen,instancelen = struct.unpack_from("!16siIIHHHHBBBB", data, offset)

        # get the variable length ampname string that follows the data
        assert(namelen > 0 and namelen < 255)
        offset += item_len
        (name,) = struct.unpack_from("!%ds" % namelen, data, offset)
        offset += namelen
        assert(namelen == len(name))

        if instancelen > 0:
            # get the variable length instance string that follows the data
            assert(instancelen > 0 and instancelen < 255)
            (instance,) = struct.unpack_from("!%ds" % instancelen, data, offset)
            offset += instancelen
            assert(instancelen == len(instance))
        else:
            # otherwise no specific instance name, just use the server name
            instance = name

        if family == socket.AF_INET:
            addr = socket.inet_ntop(family, addr[:4])
        elif family == socket.AF_INET6:
            addr = socket.inet_ntop(family, addr)
        else:
            #print "Unknown address family %d" % family
            raise ValueError

        results.append(
		{
		    "destination": name.rstrip("\0"),
		    "instance": instance.rstrip("\0"),
		    "address": addr,
                    "rtt": rtt if rtt >= 0 else None,
		    "query_len": qlen,
		    "response_size": size if rtt >= 0 else None,
		    "total_answer": ans if rtt >= 0 else None,
		    "total_authority": aut if rtt >= 0 else None,
		    "total_additional": add if rtt >= 0 else None,
		    "flags": {
			"rd": bool(flags & 0x0100),
			"tc": bool(flags & 0x0200),
			"aa": bool(flags & 0x0400),
			"opcode": int(flags & 0x7800),
			"qr": bool(flags & 0x8000),
			"rcode": int(flags & 0x000f),
			"cd": bool(flags & 0x0010),
			"ad": bool(flags & 0x0020),
			"ra": bool(flags & 0x0080),
		    } if rtt >= 0 else {},
		    "ttl": ttl if rtt >= 0 else None,
		    }
		)
        count -= 1

    return {
	"query": query.rstrip("\0"),
	"query_type": get_query_type(qtype),
	"query_class": get_query_class(qclass),
	"udp_payload_size": payload,
	"recurse": bool(opts & 0x01),
	"dnssec": bool(opts & 0x02),
	"nsid": bool(opts & 0x04),
	"results": results,
    }

def get_data(data):
    """
    Extract the DNS test results from the data blob.

    The test result data consists of a single dns_report header_t followed
    by a number of dns_report_item_t structures with the individual test
    results. Both of these are described in src/tests/dns/dns.h
    """

    # check the version number first before looking at anything else
    version, = struct.unpack_from("!I", data, 0)

    # deal with the old version, which isn't byte swapped
    if version == socket.htonl(2013022000):
        return data_2013022000(data)

    # deal with the current version, which is what we should be using
    if version == 2014020400:
        return data_2014020400(data)

    raise VersionMismatch(version, AMP_DNS_TEST_VERSION)

def get_query_class(qclass):
    if qclass == 0x01:
        return "IN"
    return "0x%.02x" % qclass

def get_query_type(qtype):
    if qtype == 0x01:
        return "A"
    if qtype == 0x02:
        return "NS"
    if qtype == 0x06:
        return "SOA"
    if qtype == 0x0c:
        return "PTR"
    if qtype == 0x0e:
        return "MX"
    if qtype == 0x1c:
        return "AAAA"
    if qtype == 0xff:
        return "ANY"
    return "0x%.02x" % qtype

