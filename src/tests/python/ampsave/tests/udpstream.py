import ampsave.tests.udpstream_pb2
from ampsave.common import getPrintableAddress


def build_loss_periods(data):
    periods = []
    for i in data:
        if i.status == ampsave.tests.udpstream_pb2.Period.LOST:
            periods.append(("loss", i.length))
        elif i.status == ampsave.tests.udpstream_pb2.Period.RECEIVED:
            periods.append(("ok", i.length))
    return periods

def build_summary(data):
    if not data:
        return None
    return {
        "maximum": data.maximum,
        "minimum": data.minimum,
        "mean": data.mean,
        "samples": data.samples,
    }

def build_voip(data):
    if not data:
        return None
    return {
        "icpif": data.icpif,
        "cisco_mos": data.cisco_mos,
        "itu_rating": data.itu_rating,
        "itu_mos": data.itu_mos,
    }

def direction_to_string(direction):
    if direction == ampsave.tests.udpstream_pb2.Item.CLIENT_TO_SERVER:
        return "out"
    if direction == ampsave.tests.udpstream_pb2.Item.SERVER_TO_CLIENT:
        return "in"
    return "unknown"

def get_data(data):
    """
    Extract the udpstream test results from the protocol buffer data
    """

    results = []
    msg = ampsave.tests.udpstream_pb2.Report()
    msg.ParseFromString(data)

    for i in msg.reports:
        # build the result structure based on what fields were present
        results.append(
            {
                "direction": direction_to_string(i.direction),
                "rtt": build_summary(i.rtt) if i.HasField("rtt") else None,
                "jitter": build_summary(i.jitter) if i.HasField("jitter") else None,
                "percentiles": i.percentiles,
                "packets_received": i.packets_received,
                "loss_periods": build_loss_periods(i.loss_periods),
                "loss_percent": i.loss_percent,
                "voip": build_voip(i.voip) if i.HasField("voip") else None,
            }
        )

    return {
        "target": msg.header.name if len(msg.header.name) > 0 else "unknown",
        "address": getPrintableAddress(msg.header.family, msg.header.address),
        #"schedule": msg.header.schedule,
        "packet_size": msg.header.packet_size,
        "packet_spacing": msg.header.packet_spacing,
        "packet_count": msg.header.packet_count,
        "dscp": msg.header.dscp,
        "rtt_samples": msg.header.rtt_samples,
        "results": results,
    }

# vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
