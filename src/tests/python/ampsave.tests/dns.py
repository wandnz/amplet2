import socket
import ampsave.tests.dns_pb2 # XXX whatever this ends up being

def get_data(data):
    """
    Extract the DNS test results from the protocol buffer data
    """

    results = []
    msg = ampsave.tests.dns_pb2.Report()
    msg.ParseFromString(data)

    for i in msg.reports:
        # better check that the address is determined properly, even though
        # it doubles the length of the function
        try:
            address = socket.inet_ntop(i.family, i.address)
        except (ValueError, socket.error) as e:
            if i.family == socket.AF_INET:
                address = "0.0.0.0"
            elif i.family == socket.AF_INET6:
                address = "::"
            else:
                raise ValueError

        # again, should probably check this has sensible values
        if len(i.instance) > 0:
            instance = i.instance
        elif len(i.name) > 0:
            instance = i.name
        else:
            instance = "unknown"

        # build the result structure based on what fields were present
        results.append(
            {
                "destination": i.name if len(i.name) > 0 else "unknown",
                "instance": instance,
                "address": address,
                "rtt": i.rtt if i.HasField("rtt") else None,
                "query_len": i.query_length,
                "response_size": i.response_size if i.HasField("response_size") else None,
                "total_answer": i.total_answer if i.HasField("total_answer") else None,
                "total_authority": i.total_authority if i.HasField("total_authority") else None,
                "total_additional": i.total_additional if i.HasField("total_additional") else None,
                "flags": {
                    "rd": i.rd,
                    "tc": i.tc,
                    "aa": i.aa,
                    "opcode": i.opcode,
                    "qr": i.qr,
                    "rcode": i.rcode,
                    "cd": i.cd,
                    "ad": i.ad,
                    "ra": i.ra,
                } if i.HasField("rtt") else {},
                "ttl": i.ttl if i.HasField("ttl") else None,
                }
            )

    return {
	"query": msg.header.query,
	"query_type": get_query_type(msg.header.query_type),
	"query_class": get_query_class(msg.header.query_class),
	"udp_payload_size": msg.header.udp_payload_size,
	"recurse": msg.header.recurse,
	"dnssec": msg.header.dnssec,
	"nsid": msg.header.nsid,
	"results": results,
    }

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

