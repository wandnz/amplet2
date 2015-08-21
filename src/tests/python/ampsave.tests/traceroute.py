import ampsave.tests.traceroute_pb2
from ampsave.common import getPrintableAddress

def get_data(data):
    """
    Extract the TRACEROUTE test results from the protocol buffer data.
    """

    results = []
    msg = ampsave.tests.traceroute_pb2.Report()
    msg.ParseFromString(data)

    # someone has turned off all the reporting, ignore it, we shouldn't do this
    if msg.header.ip == False and msg.header.asn == False:
        return None

    for i in msg.reports:
        result = {
            "target": i.name if len(i.name) > 0 else "unknown",
            "address": getPrintableAddress(i.family, i.address),
            "length": len(i.path),
            "error_type": i.err_type if i.HasField("err_type") else None,
            "error_code": i.err_code if i.HasField("err_code") else None,
            "packet_size": msg.header.packet_size,
            "random": msg.header.random,
            "ip": msg.header.ip,
            "as": msg.header.asn,
            "hops": [],
        }

        for hop in i.path:
            # XXX not currently checking global flags, do I need to?
            # the fields shouldn't be present unless the flags are set
            hopitem = {}
            if msg.header.ip and hop.HasField("rtt"):
                hopitem["rtt"] = hop.rtt
            if msg.header.ip and hop.HasField("address"):
                hopitem["address"] = getPrintableAddress(i.family, hop.address)
            if msg.header.asn and hop.HasField("asn"):
                hopitem["as"] = hop.asn
            result["hops"].append(hopitem)

        # Add this whole path with hops to the results
        results.append(result)

    return results
