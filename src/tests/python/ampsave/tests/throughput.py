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

import ampsave.tests.throughput_pb2
from ampsave.common import getPrintableAddress, getPrintableDscp

def schedule_to_test_params(schedule):
    """
    Extract the test parameters we care about from the test schedule
    """
    params = []

    parts = schedule.split(",")
    for part in parts:
        # for now, ignore 'n' in the schedule in case old versions are reporting
        if part == "n":
            continue
        duration = part[1:]
        # tcpreused is now always false, but needs to still be present for
        # backwards compatibility with old streams. There are no known
        # instances where anyone has reused the TCP connection so this
        # shouldn't affect anything.
        params.append({"duration":duration, "tcpreused":False})

    return params

def direction_to_string(direction):
    """
    Convert direction enum into a human readable string
    """
    if direction == ampsave.tests.throughput_pb2.Item.CLIENT_TO_SERVER:
        return "out"
    if direction == ampsave.tests.throughput_pb2.Item.SERVER_TO_CLIENT:
        return "in"
    return "unknown"

def protocol_to_string(protocol):
    """
    Convert protocol enum into a human readable string
    """
    if protocol == ampsave.tests.throughput_pb2.HTTP_POST:
        return "http"
    return "default"

def get_data(data):
    """
    Extract the throughput test results from the protocol buffer data.
    """

    results = []
    msg = ampsave.tests.throughput_pb2.Report()
    msg.ParseFromString(data)

    testparams = schedule_to_test_params(msg.header.schedule)

    for i in msg.reports:
        params = testparams.pop(0)
        results.append({
            "duration": params["duration"],
            "runtime": i.duration//1000//1000 if i.HasField("duration") else None,
            "bytes": i.bytes if i.HasField("bytes") else None,
            "direction": direction_to_string(i.direction),
            "tcpreused": params["tcpreused"],
            "retransmits": i.tcpinfo.total_retrans if i.HasField("tcpinfo") and i.tcpinfo.HasField("total_retrans") else None,
            "rtt": i.tcpinfo.rtt if i.HasField("tcpinfo") and i.tcpinfo.HasField("rtt") else None,
            "rttvar": i.tcpinfo.rttvar if i.HasField("tcpinfo") and i.tcpinfo.HasField("rttvar") else None,
            "rttmin": i.tcpinfo.min_rtt if i.HasField("tcpinfo") and i.tcpinfo.HasField("min_rtt") else None,
        })

    # TODO confirm what happens if the test fails to connect
    return {
        "target": msg.header.name,
        "address": getPrintableAddress(msg.header.family, msg.header.address),
        "schedule": msg.header.schedule,
        "write_size": msg.header.write_size,
        "dscp": getPrintableDscp(msg.header.dscp),
        "protocol": protocol_to_string(msg.header.protocol),
        "results": results,
    }

# vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
