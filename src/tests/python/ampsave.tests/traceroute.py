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
AMP_TRACEROUTE_TEST_VERSION = 2014080700


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
def parse_data(data):
    # These values are only set by later versions, this is what the older
    # tests should default to
    lookup_ip = True
    lookup_as = False

    # offset past the version number
    version, = struct.unpack_from("!I", data, 0)
    offset = struct.calcsize("!I")

    # read the rest of the header that records test options
    if version == 2014020300:
        header_len = struct.calcsize("!IhBB")
        path_len = struct.calcsize("!16sBBBBB")
        hop_len = struct.calcsize("!16si")
        if len(data) < header_len:
            print "%s: not enough data to unpack 2014020300 header", __file__
            return None
        packet_size,random,count = struct.unpack_from("!hBB", data, offset)
    else:
        header_len = struct.calcsize("!IhBBBB")
        path_len = struct.calcsize("!16sBBBBB")
        hop_len = struct.calcsize("!16sqi")
        if len(data) < header_len:
            print "%s: not enough data to unpack header", __file__
            return None
        packet_size,random,count,lookup_ip,lookup_as = struct.unpack_from(
                "!hBBBB", data, offset)

    # someone has turned off all the reporting, ignore it, we shouldn't do this
    if lookup_ip == False and lookup_as == False:
        return None

    offset = header_len
    results = []

    # extract every path in the data portion of the message
    while count > 0:
        # make sure there is at least enough data for the path header, if not
        # then stop unpacking and report the paths we already have
        if len(data[offset:]) < path_len:
            print "%s: not enough data to unpack path header", __file__
            return results
        addr,family,length,errtype,errcode,namelen = struct.unpack_from(
		"!16sBBBBB", data, offset)
        assert(namelen > 0 and namelen < 255)
        offset += path_len

        # again, if there isn't enough data, return all complete paths so far
        if len(data[offset:] < namelen:
            print "%s: not enough data to unpack target name", __file__
            return results
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
            "ip": lookup_ip,
            "as": lookup_as,
            "hops": [],
        }

        # extract each hop in the path
        hopcount = length
        while hopcount > 0:
            # if we only get a partial path then give up and return all the
            # completed paths that we have
            if len(data[offset:]) < hop_len:
                print "%s: not enough data to unpack path item", __file__
                return results
            if version == 2014020300:
                hop_addr,rtt = struct.unpack_from("!16si", data, offset)
            else:
                hop_addr,asn,rtt = struct.unpack_from("!16sqi", data, offset)
            offset += hop_len

            hopitem = {}

            if lookup_ip:
                if rtt < 0:
                    rtt = None
                hopitem["rtt"] = rtt
                hopitem["address"] = get_printable_address(family, hop_addr)

            if lookup_as:
                hopitem["as"] = asn

            # Append this hop to the path list
            path["hops"].append(hopitem)
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
    if len(data) < struct.calcsize("!I"):
        print "%s: not enough data to unpack version number", __file__
        return None
    version, = struct.unpack_from("!I", data, 0)

    # deal with the old version, which isn't byte swapped
    if version == socket.htonl(2013032800):
        return data_2013032800(data)

    # deal with the current version, which is what we should be using
    if version == 2014020300 or version == 2014080700:
        return parse_data(data)

    raise VersionMismatch(version, AMP_TRACEROUTE_TEST_VERSION)
