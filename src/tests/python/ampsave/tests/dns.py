#
# This file is part of amplet2.
#
# Copyright (c) 2013-2016 The University of Waikato, Hamilton, New Zealand.
#
# Author: Brendon Jones
#
# All rights reserved.
#
# This code has been developed by the University of Waikato WAND
# research group. For further information please see http://www.wand.net.nz/
#
# amplet2 is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 as
# published by the Free Software Foundation.
#
# In addition, as a special exception, the copyright holders give
# permission to link the code of portions of this program with the
# OpenSSL library under certain conditions as described in each
# individual source file, and distribute linked combinations including
# the two.
#
# You must obey the GNU General Public License in all respects for all
# of the code used other than OpenSSL. If you modify file(s) with this
# exception, you may extend this exception to your version of the
# file(s), but you are not obligated to do so. If you do not wish to do
# so, delete this exception statement from your version. If you delete
# this exception statement from all source files in the program, then
# also delete it here.
#
# amplet2 is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with amplet2. If not, see <http://www.gnu.org/licenses/>.
#

import ampsave.tests.dns_pb2
from ampsave.common import getPrintableAddress, getPrintableDscp

def get_data(data):
    """
    Extract the DNS test results from the protocol buffer data
    """

    results = []
    msg = ampsave.tests.dns_pb2.Report()
    msg.ParseFromString(data)

    for i in msg.reports:
        # build the result structure based on what fields were present
        results.append(
            {
                "destination": i.name if len(i.name) > 0 else "unknown",
                # XXX nntsc is trying to split streams based on the instance
                # that responded, which I'm not 100% certain is the best idea.
                # For now we'll keep putting the server hostname in this field
                "instance": i.name if len(i.name) > 0 else "unknown",
                "address": getPrintableAddress(i.family, i.address),
                "rtt": i.rtt if i.HasField("rtt") else None,
                "query_len": i.query_length,
                "response_size": i.response_size if i.HasField("response_size") else None,
                "total_answer": i.total_answer if i.HasField("total_answer") else None,
                "total_authority": i.total_authority if i.HasField("total_authority") else None,
                "total_additional": i.total_additional if i.HasField("total_additional") else None,
                "flags": {
                    "rd": i.flags.rd,
                    "tc": i.flags.tc,
                    "aa": i.flags.aa,
                    "opcode": i.flags.opcode,
                    "qr": i.flags.qr,
                    "rcode": i.flags.rcode,
                    "cd": i.flags.cd,
                    "ad": i.flags.ad,
                    "ra": i.flags.ra,
                } if i.HasField("rtt") and i.HasField("flags") else {},
                "ttl": i.ttl if i.HasField("ttl") else None,
                # XXX create a new field to store the instance name returned
                # by the NSID query so that we don't break nntsc
                "nsid_bytes": i.instance if len(i.instance) > 0 else None,
                "rrsig": i.rrsig,
                }
            )

    return {
        "query": msg.header.query,
        "query_type": get_query_type(msg.header.query_type),
        "query_class": get_query_class(msg.header.query_class),
        "udp_payload_size": msg.header.udp_payload_size,
        "recurse": msg.header.recurse,
        "dnssec": msg.header.dnssec,
        "nsid": msg.header.nsid,
        "dscp": getPrintableDscp(msg.header.dscp),
        "results": results,
    }

def get_query_class(qclass):
    """
    Convert a DNS query class into a human readable string
    """
    if qclass == 0x01:
        return "IN"
    return "0x%.02x" % qclass

def get_query_type(qtype):
    """
    Convert a DNS query type into a human readable string
    """
    if qtype == 0x01:
        return "A"
    if qtype == 0x02:
        return "NS"
    if qtype == 0x06:
        return "SOA"
    if qtype == 0x0c:
        return "PTR"
    if qtype == 0x0e:
        return "MX"
    if qtype == 0x1c:
        return "AAAA"
    if qtype == 0xff:
        return "ANY"
    return "0x%.02x" % qtype

