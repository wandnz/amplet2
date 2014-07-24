import struct
import socket

# TODO move to another file
class VersionMismatch(Exception):
    def __init__(self, got, expected):
        self.got = got
        self.expected = expected
    def __str__(self):
        return "%d != %d" % (self.got, self.expected)


# version needs to match the version number in src/tests/tcpping/tcpping.h
AMP_TCPPING_TEST_VERSION = 2014072100

def get_data(data):
    """
    Extract the test results from the data blob.

    The test result data consists of a single tcpping_report_header_t followed
    by a number of tcpping_report_item_t structures with the individual test
    results. Both of these are described in src/tests/tcpping/tcpping.h
    """
    # Check the version number first before looking at anything else.
    # Using the "!" format will automatically convert from network to host
    # byte order, which is pretty cool.
    version, = struct.unpack_from("!I", data, 0)

    # deal with the current version, which is what we should be using
    if version != AMP_TCPPING_TEST_VERSION:
        raise VersionMismatch(version, AMP_TCPPING_TEST_VERSION)
    
    header_len = struct.calcsize("!IhBB")
    item_len = struct.calcsize("!16sihBBBBBB")

    # offset past the version number which has already been read
    offset = struct.calcsize("!I")

    # read the rest of the header that records test options
    port,random,count = struct.unpack_from("!hBB", data, offset)

    offset = header_len
    results = []

    # extract every item in the data portion of the message
    while count > 0:
        # "p" pascal string could be useful here, length byte before string
        # except that they don't appear to work in any useful fashion
        # http://bugs.python.org/issue2981
        addr,rtt,packet_size,family,reply,replyflags,icmptype,icmpcode, \
                namelen = struct.unpack_from("!16sihBBBBBB", data, offset)

        assert(namelen > 0 and namelen < 255)
        offset += item_len
        (name,) = struct.unpack_from("!%ds" % namelen, data, offset)
        offset += namelen

        assert(namelen == len(name))

        if family == socket.AF_INET:
            addr = socket.inet_ntop(family, addr[:4])
        elif family == socket.AF_INET6:
            addr = socket.inet_ntop(family, addr)
        else:
            #print "Unknown address family %d" % family
            raise ValueError

        # Convert everything we can here so that the database insertion code
        # doesn't need to figure out what fields should be interpreted based
        # on there being a response or not. We know what we are doing at this
        # point, so set it up properly for the next step.
        results.append(
                {
                    "target": name.rstrip("\0"),
                    "port": port,
                    "address": addr,
                    "rtt": rtt if rtt >= 0 else None,
                    "reply": reply,
                    "replyflags": replyflags if reply == 1 else None,
                    "icmptype": icmptype if reply == 2 else None,
                    "icmpcode": icmptype if reply == 2 else None,
                    "packet_size": packet_size,
                    "random": random,
                    "loss": 1 if reply == 0 else 0,
                }
            )
        count -= 1

    return results

# vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
