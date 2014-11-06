import struct
import socket

# TODO move to another file
class VersionMismatch(Exception):
    def __init__(self, got, expected):
        self.got = got
        self.expected = expected
    def __str__(self):
        return "%d != %d" % (self.got, self.expected)


# version needs to keep up with the version number in src/tests/icmp/icmp.h
AMP_ICMP_TEST_VERSION = 2014020300


# Old data coming from deployed amplet2-client debian package 0.1.13-1
# TODO remove this code once we have got rid of everyone that speaks this
# version
def data_2013022000(data):
    header_len = struct.calcsize("=IhBB")
    item_len = struct.calcsize("=128s16siBBBB")

    # offset past the version number which has already been read
    offset = struct.calcsize("=I")

    # read the rest of the header that records test options
    packet_size,random,count = struct.unpack_from("=hBB", data, offset)

    offset = header_len
    results = []

    # extract every item in the data portion of the message
    while count > 0:
        name,addr,rtt,family,errtype,errcode,ttl = struct.unpack_from(
                "=128s16siBBBB", data, offset)

        if family == socket.AF_INET:
            addr = socket.inet_ntop(family, addr[:4])
        elif family == socket.AF_INET6:
            addr = socket.inet_ntop(family, addr)
        else:
            raise ValueError

        results.append(
                {
                    "target": name.rstrip("\0"),
                    "address": addr,
                    "rtt": rtt if rtt >= 0 else None,
                    "error_type": errtype if(rtt >= 0 or errtype > 0) else None,
                    "error_code": errcode if(rtt >= 0 or errcode > 0) else None,
                    "ttl": ttl if rtt >= 0 else None,
                    "packet_size": packet_size,
                    "random": random,
                    "loss": 0 if rtt >= 0 else 1,
                }
            )
        offset += item_len
        count -= 1
    return results


# New data that is byte swapped, variable length strings etc
def data_2014020300(data):
    header_len = struct.calcsize("!IhBB")
    item_len = struct.calcsize("!16siBBBBB")

    if len(data) < header_len:
        print "%s: not enough data to unpack header", __file__
        return None

    # offset past the version number which has already been read
    offset = struct.calcsize("!I")

    # read the rest of the header that records test options
    packet_size,random,count = struct.unpack_from("!hBB", data, offset)

    offset = header_len
    results = []

    # extract every item in the data portion of the message
    while count > 0:
        if len(data[offset:]) < item_len:
            print "%s: not enough data to unpack item", __file__
            return results
        # "p" pascal string could be useful here, length byte before string
        # except that they don't appear to work in any useful fashion
        # http://bugs.python.org/issue2981
        addr,rtt,family,errtype,errcode,ttl,namelen = struct.unpack_from(
                "!16siBBBBB", data, offset)
        assert(namelen > 0 and namelen < 255)
        offset += item_len
        if len(data[offset:]) < namelen:
            print "%s: not enough data to unpack name", __file__
            return results
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
                    "address": addr,
                    "rtt": rtt if rtt >= 0 else None,
                    "error_type": errtype if(rtt >= 0 or errtype > 0) else None,
                    "error_code": errcode if(rtt >= 0 or errcode > 0) else None,
                    "ttl": ttl if rtt >= 0 else None,
                    "packet_size": packet_size,
                    "random": random,
                    "loss": 0 if rtt >= 0 else 1,
                }
            )
        count -= 1

    return results



def get_data(data):
    """
    Extract the ICMP test results from the data blob.

    The test result data consists of a single icmp_report header_t followed
    by a number of icmp_report_item_t structures with the individual test
    results. Both of these are described in src/tests/icmp/icmp.h
    """
    # Check the version number first before looking at anything else.
    # Using the "!" format will automatically convert from network to host
    # byte order, which is pretty cool.
    if len(data) < struct.calcsize("!I"):
        print "%s: not enough data to unpack version number", __file__
        return None
    version, = struct.unpack_from("!I", data, 0)

    # deal with the old version, which isn't byte swapped
    if version == socket.htonl(2013022000):
        return data_2013022000(data)

    # deal with the current version, which is what we should be using
    if version == 2014020300:
        return data_2014020300(data)

    raise VersionMismatch(version, AMP_ICMP_TEST_VERSION)

