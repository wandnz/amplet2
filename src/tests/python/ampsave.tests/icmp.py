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
AMP_ICMP_TEST_VERSION = 2013022000

def get_data(data):
    """
    Extract the ICMP test results from the data blob. 

    The test result data consists of a single icmp_report header_t followed 
    by a number of icmp_report_item_t structures with the individual test 
    results. Both of these are described in src/tests/icmp/icmp.h
    """
    header_len = struct.calcsize("=IhBB")
    item_len = struct.calcsize("=128s16siBBBB")

    # check the version number first before looking at anything else
    version, = struct.unpack_from("=I", data, 0)
    if version != AMP_ICMP_TEST_VERSION:
	raise VersionMismatch(version, AMP_ICMP_TEST_VERSION)
    offset = struct.calcsize("=I")
    
    # read the rest of the header that records test options
    packet_size,random,count = struct.unpack_from("=hBB", data, offset)

    offset = header_len
    results = []

    # extract every item in the data portion of the message
    while count > 0:
	# "p" pascal string could be useful here, length byte before string
	name,addr,rtt,family,errtype,errcode,ttl = struct.unpack_from(
		"=128s16siBBBB", data, offset)
    
	if family == socket.AF_INET:
	    addr = socket.inet_ntop(family, addr[:4])
	elif family == socket.AF_INET6:
	    addr = socket.inet_ntop(family, addr)
	else:
	    #print "Unknown address family %d" % family
	    raise ValueError

        # TODO should things like loss be included here, or leave them up
        # to the next stage to calculate them? Easier just to do it here?
        results.append(
                {
                    "target": name.rstrip("\0"),
                    "address": addr,
                    "rtt": rtt,
                    "error_type": errtype,
                    "error_code": errcode,
                    "ttl": ttl,
                    "packet_size": packet_size,
                    "random": random,
                    "loss": True if rtt < 0 else False,
                }
            )
	offset += item_len
	count -= 1

    return results
