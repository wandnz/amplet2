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

import ampsave.tests.traceroute_pb2
from ampsave.common import getPrintableAddress, getPrintableDscp

def get_data(data):
    """
    Extract the TRACEROUTE test results from the protocol buffer data.
    """

    results = []
    msg = ampsave.tests.traceroute_pb2.Report()
    msg.ParseFromString(data)

    # someone has turned off all the reporting, ignore it, we shouldn't do this
    if msg.header.ip is False and msg.header.asn is False:
        return None

    for i in msg.reports:
        result = {
            "target": i.name if len(i.name) > 0 else "unknown",
            "address": getPrintableAddress(i.family, i.address),
            "length": len(i.path),
            "error_type": i.err_type if i.HasField("err_type") else None,
            "error_code": i.err_code if i.HasField("err_code") else None,
            "packet_size": msg.header.packet_size,
            "random": msg.header.random,
            "ip": msg.header.ip,
            "as": msg.header.asn,
            "dscp": getPrintableDscp(msg.header.dscp),
            "hops": [],
        }

        for hop in i.path:
            # XXX not currently checking global flags, do I need to?
            # the fields shouldn't be present unless the flags are set
            hopitem = {}
            if msg.header.ip and hop.HasField("rtt"):
                hopitem["rtt"] = hop.rtt
            elif msg.header.ip:
                hopitem["rtt"] = None

            if msg.header.ip and hop.HasField("address"):
                hopitem["address"] = getPrintableAddress(i.family, hop.address)
            elif msg.header.ip:
                hopitem["address"] = None

            if msg.header.asn and hop.HasField("asn"):
                hopitem["as"] = hop.asn
            elif msg.header.asn:
                hopitem["as"] = None

            result["hops"].append(hopitem)

        # Add this whole path with hops to the results
        results.append(result)

    return results
