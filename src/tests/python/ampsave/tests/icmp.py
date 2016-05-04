import ampsave.tests.icmp_pb2
from ampsave.common import getPrintableAddress, getPrintableDscp

def get_data(data):
    """
    Extract the ICMP test results from the protocol buffer data
    """

    results = []
    msg = ampsave.tests.icmp_pb2.Report()
    msg.ParseFromString(data)

    for i in msg.reports:
        # build the result structure based on what fields were present
        results.append(
            {
                "target": i.name if len(i.name) > 0 else "unknown",
                "address": getPrintableAddress(i.family, i.address),
                "rtt": i.rtt if i.HasField("rtt") else None,
                "error_type": i.err_type if i.HasField("err_type") else None,
                "error_code": i.err_code if i.HasField("err_code") else None,
                "ttl": i.ttl if i.HasField("ttl") else None,
                "packet_size": msg.header.packet_size,
                "random": msg.header.random,
                "loss": 0 if i.HasField("rtt") else 1,
                "dscp": getPrintableDscp(msg.header.dscp),
            }
        )

    return results
