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


# version needs to keep up with the number in src/tests/traceroute/traceroute.h
AMP_TRACEROUTE_TEST_VERSION = 2014020300


# Old data coming from deployed amplet2-client debian package 0.1.13-1
# TODO remove this code once we have got rid of everyone that speaks this
# version
def data_2013032800(data):
    header_len = struct.calcsize("=IhBB")
    path_len = struct.calcsize("=128s16sIBBBB")
    hop_len = struct.calcsize("=16siI")

    # offset past the version number which has already been read
    offset = struct.calcsize("=I")

    # read the rest of the header that records test options
    packet_size,random,count = struct.unpack_from("=hBB", data, offset)

    offset = header_len
    results = []

    # extract every path in the data portion of the message
    while count > 0:
        name,addr,pad,family,length,errtype,errcode = struct.unpack_from(
                "=128s16sIBBBB", data, offset)
        offset += path_len

        path = {
            "target": name.rstrip("\0"),
            "address": get_printable_address(family, addr),
            "length": length,
            "error_type": errtype if errtype > 0 else None,
            "error_code": errcode if errcode > 0 else None,
            "packet_size": packet_size,
            "random": random,
            "hops": [],
        }

        # extract each hop in the path
        hopcount = length
        while hopcount > 0:
            hop_addr,rtt,pad = struct.unpack_from("=16siI", data, offset)
            offset += hop_len

            # Use a proper python None value to mark this rather than a -1
            if rtt < 0:
                rtt = None

            # Append this hop to the path list
            path["hops"].append({
                "rtt": rtt,
                "address": get_printable_address(family, hop_addr),
                })
            hopcount -= 1

        # Add this whole path with hops to the results
        results.append(path)
        count -= 1
    return results


# New data that is byte swapped, variable length strings etc
def data_2014020300(data):
    header_len = struct.calcsize("!IhBB")
    path_len = struct.calcsize("!16sBBBBB")
    hop_len = struct.calcsize("!16si")

    # offset past the version number which has already been read
    offset = struct.calcsize("!I")

    # read the rest of the header that records test options
    packet_size,random,count = struct.unpack_from("!hBB", data, offset)

    offset = header_len
    results = []

    # extract every path in the data portion of the message
    while count > 0:
        addr,family,length,errtype,errcode,namelen = struct.unpack_from(
		"!16sBBBBB", data, offset)
        assert(namelen > 0 and namelen < 255)
        offset += path_len
        (name,) = struct.unpack_from("!%ds" % namelen, data, offset)
        offset += namelen

        assert(namelen == len(name))

        path = {
            "target": name.rstrip("\0"),
            "address": get_printable_address(family, addr),
            "length": length,
            "error_type": errtype if errtype > 0 else None,
            "error_code": errcode if errcode > 0 else None,
            "packet_size": packet_size,
            "random": random,
            "hops": [],
        }

        # extract each hop in the path
        hopcount = length
        while hopcount > 0:
            hop_addr,rtt = struct.unpack_from("!16si", data, offset)
            offset += hop_len

            # Use a proper python None value to mark this rather than a -1
            if rtt < 0:
                rtt = None

            # Append this hop to the path list
            path["hops"].append({
                "rtt": rtt,
                "address": get_printable_address(family, hop_addr),
                })
            hopcount -= 1

        # Add this whole path with hops to the results
        results.append(path)
        count -= 1

    return results


def get_data(data):
    """
    Extract the TRACEROUTE test results from the data blob.

    The test result data consists of a single traceroute_report_header_t
    followed by a number of traceroute_report_path_t structures each with
    traceroute_report_hop_t structures describing all the hops. All of
    these are described in src/tests/traceroute/traceroute.h
    """

    # check the version number first before looking at anything else
    version, = struct.unpack_from("!I", data, 0)

    # deal with the old version, which isn't byte swapped
    if version == socket.htonl(2013032800):
        return data_2013032800(data)

    # deal with the current version, which is what we should be using
    if version == 2014020300:
        return data_2014020300(data)

    raise VersionMismatch(version, AMP_TRACEROUTE_TEST_VERSION)
