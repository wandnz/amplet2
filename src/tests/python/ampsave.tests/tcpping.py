import socket
import ampsave.tests.tcpping_pb2

def get_data(data):
    """
    Extract the test results from the protocol buffer data.
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

        results.append(
            {
                "target": i.name if len(i.name) > 0 else "unknown",
                "port": msg.header.port,
                "address": address,
                "rtt": i.rtt if i.HasField("rtt") else None,
                "replyflags": {
                    "fin": i.flags.fin,
                    "syn": i.flags.syn,
                    "rst": i.flags.rst,
                    "psh": i.flags.psh,
                    "ack": i.flags.ack,
                    "urg": i.flags.urg,
                } if i.HasField("rtt") else None,
                "icmptype": i.icmptype if i.HasField("icmptype") else None,
                "icmpcode": i.icmpcode if i.HasField("icmpcode") else None,
                "packet_size": msg.header.packet_size,
                "random": msg.header.random,
                "loss": 0 if i.HasField("rtt") or i.HasField("icmptype") or i.HasField("icmpcode") else 1
            }
        )

    return results

# vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
