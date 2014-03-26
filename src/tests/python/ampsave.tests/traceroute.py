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


# version needs to keep up with the version number in src/tests/icmp/icmp.h
AMP_TRACEROUTE_TEST_VERSION = 2014020300

def get_data(data):
    """
    Extract the TRACEROUTE test results from the data blob.

    The test result data consists of a single traceroute_report_header_t
    followed by a number of traceroute_report_path_t structures each with
    traceroute_report_hop_t structures describing all the hops. All of
    these are described in src/tests/traceroute/traceroute.h
    """
    header_len = struct.calcsize("!IhBB")
    path_len = struct.calcsize("!16sBBBBB")
    hop_len = struct.calcsize("!16si")

    # check the version number first before looking at anything else
    version, = struct.unpack_from("!I", data, 0)
    if version != AMP_TRACEROUTE_TEST_VERSION:
        raise VersionMismatch(version, AMP_TRACEROUTE_TEST_VERSION)
    offset = struct.calcsize("!I")

    # read the rest of the header that records test options
    packet_size,random,count = struct.unpack_from("!hBB", data, offset)

    offset = header_len
    results = []

    # extract every path in the data portion of the message
    while count > 0:
	# "p" pascal string could be useful here, length byte before string
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
            #"complete": complete,
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
