import ampsave.tests.udpstream_pb2
from ampsave.common import getPrintableAddress


def build_loss_periods(data):
    periods = []
    for i in data:
        if i.status == ampsave.tests.udpstream_pb2.Period.LOST:
            periods.append(("loss", i.length))
        else if direction == ampsave.tests.udpstream_pb2.Period.RECEIVED:
            periods.append(("ok", i.length))
    return periods


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
                "max": i.maximum,
                "min": i.minimum,
                "median": i.median,
                "received": i.packets_received,
                # TODO does percentiles just present as a list?
                "percentiles": i.percentiles,
                "loss_periods": build_loss_periods(i.loss_periods),
            }
        )

    return {
        "target": msg.header.name if len(msg.header.name) > 0 else "unknown",
        "address": getPrintableAddress(msg.header.family, msg.header.address),
        "packet_size": msg.header.packet_size,
        "packet_spacing": msg.header.packet_spacing,
        "packet_count": msg.header.packet_count,
        "percentile_count": msg.header.percentile_count,
        #"random": msg.header.random,
        "results": results,
    }
