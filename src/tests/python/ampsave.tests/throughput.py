import struct
import socket

# TODO move to another file
class VersionMismatch(Exception):
    def __init__(self, got, expected):
        self.got = got
        self.expected = expected
    def __str__(self):
        return "%d != %d" % (self.got, self.expected)


# TODO move to another file
def get_printable_address(family, addr):
    if family == socket.AF_INET:
        return socket.inet_ntop(family, addr[:4])
    elif family == socket.AF_INET6:
        return socket.inet_ntop(family, addr)
    raise ValueError


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
    version, = struct.unpack_from("!I", data, 0)
    if version != AMP_THROUGHPUT_TEST_VERSION:
        raise VersionMismatch(version, AMP_THROUGHPUT_TEST_VERSION)
    offset = struct.calcsize("!I")

    # read the rest of the header that records test options
    count,start,end,client,server,sched_len,family,namelen = struct.unpack_from("!IQQ16s16sIBB", data, offset)
    offset = header_len

    # read the variable length schedule from the end of the header
    assert(sched_len > 0)
    (schedule,) = struct.unpack_from("!%ds" % sched_len, data, offset)
    offset += sched_len
    assert(sched_len == len(schedule))

    assert(namelen > 0 and namelen < 255)
    (name,) = struct.unpack_from("!%ds" % namelen, data, offset)
    offset += namelen
    assert(namelen == len(name))


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

    # extract every server in the data portion of the message
    while count > 0:
        duration,byte,packets,write,direction,webc,webs = struct.unpack_from("!QQIIBBB", data, offset)
        offset += result_len

        result = {
            "duration": duration,
            "bytes": byte,
            "packets": packets,
            "write_size": write,
            "direction": direction,
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

    return results
