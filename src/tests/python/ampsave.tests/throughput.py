import ampsave.tests.throughput_pb2
from ampsave.common import getAddressFromMessage


def schedule_to_test_params(schedule):
    params = []

    parts = schedule.split(",")
    tcpreused = False
    for p in parts:
        if p == "n":
            tcpreused = False
            continue

        duration = p[1:]
        params.append({"duration":duration, "tcpreused":tcpreused})
        tcpreused = True

    return params


def direction_to_string(direction):
    if direction == ampsave.tests.throughput_pb2.Item.Direction.Value("CLIENT_TO_SERVER"):
        return "out"
    if direction == ampsave.tests.throughput_pb2.Item.Direction.Value("SERVER_TO_CLIENT"):
        return "in"
    return "unknown"


def get_data(data):
    """
    Extract the throughput test results from the protocol buffer data.
    """

    results = []
    msg = ampsave.tests.throughput_pb2.Report()
    msg.ParseFromString(data)

    testparams = schedule_to_test_params(msg.header.schedule)

    for i in msg.reports:
        params = testparams.pop(0)
        results.append(
            {
                "duration": params["duration"],
                "runtime": i.duration / 1000 / 1000,  # Report in msec
                "bytes": i.bytes,
                "direction": direction_to_string(i.direction),
                "tcpreused": params["tcpreused"],
            }
        )

    # TODO confirm what happens if the test fails to connect
    return {
        "target": msg.header.name,
        "address": getAddressFromMessage(msg.header),
        "schedule": msg.header.schedule,
        "write_size": msg.header.write_size,
        "results": results,
    }

# vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
