import struct
import socket

from ampsave.exceptions import AmpTestVersionMismatch

# TODO move to another file
def get_printable_address(family, addr):
    if family == socket.AF_INET:
        return socket.inet_ntop(family, addr[:4])
    elif family == socket.AF_INET6:
        return socket.inet_ntop(family, addr)
    raise ValueError

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
        tcpreused= True

    return params

# Needs to keep up with the version in src/tests/throughput/throughput.h
AMP_THROUGHPUT_TEST_VERSION = 2014031300

def get_data(data):
    """
    Extract the throughput test results from the data blob.

    The test result data consists of a single report_header_t
    followed by a number of report_result_t structures each possibly with
    report_web10g_t structures describing all the web10g data if available.
    these are described in src/tests/throughput/throughput.h
    """
    header_len = struct.calcsize("!IIQQ16s16sIBBH")
    result_len = struct.calcsize("!QQIIBBBBI")
    web10g_len = struct.calcsize("!480s")

    # check the version number first before looking at anything else
    if len(data) < header_len:
        print "%s: not enough data to unpack header", __file__
        return None
    version, = struct.unpack_from("!I", data, 0)
    if version != AMP_THROUGHPUT_TEST_VERSION:
        raise AmpTestVersionMismatch(version, AMP_THROUGHPUT_TEST_VERSION)
    offset = struct.calcsize("!I")

    # read the rest of the header that records test options
    count,start,end,client,server,sched_len,family,namelen = struct.unpack_from("!IQQ16s16sIBB", data, offset)
    offset = header_len

    # read the variable length schedule from the end of the header
    assert(sched_len > 0)
    if len(data[offset:]) < sched_len:
        print "%s: not enough data to unpack schedule", __file__
        return None
    (schedule,) = struct.unpack_from("!%ds" % sched_len, data, offset)
    offset += sched_len
    assert(sched_len == len(schedule))

    assert(namelen > 0 and namelen < 255)
    if len(data[offset:]) < namelen:
        print "%s: not enough data to unpack name", __file__
        return None
    (name,) = struct.unpack_from("!%ds" % namelen, data, offset)
    offset += namelen
    assert(namelen == len(name))


    # TODO confirm what happens if the test fails to connect
    results = {
        "target": name.rstrip("\0"),
        "count": count,
        "start": start,
        "end": end,
        "local_address": get_printable_address(family, client),
        "address": get_printable_address(family, server),
        "schedule": schedule.rstrip("\0"),
        "results": []
    }

    params = schedule_to_test_params(results["schedule"])
    if len(params) != count:
        print params, count, results
    assert(len(params) == count)
    # extract every server in the data portion of the message
    while count > 0:
        if len(data[offset:]) < result_len:
            print "%s: not enough data to unpack result", __file__
            return results
        duration,byte,packets,write,direction,webc,webs = struct.unpack_from("!QQIIBBB", data, offset)
        offset += result_len

        # Convert direction enum values into more descriptive strings
        if direction == 1:
            dirstr = "in"
        elif direction == 2:
            dirstr = "out"
        else:
            # XXX Should we actually be getting these other values?
            dirstr = "unknown"


        # duration is the time specified by the user in the schedule
        # runtime is the time it actually took the test to run
        result = {
            "duration": params[0]["duration"],
            "runtime": duration / 1000 / 1000,  # Report in msec
            "bytes": byte,
            "packets": packets,
            "write_size": write,
            "direction": dirstr,
            "tcpreused": params[0]["tcpreused"],
            "has_web10g_client": bool(webc),
            "has_web10g_server": bool(webs),
        }

        # XXX skip web10g reporting for now, it's a lot of data
        if webc:
            offset += web10g_len
        if webs:
            offset += web10g_len

        # Add this result set to the result list
        results["results"].append(result)
        count -= 1
        params = params[1:]

    return results

# vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
