#
# This file is part of amplet2.
#
# Copyright (c) 2019-2020 The University of Waikato, Hamilton, New Zealand.
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

import socket
import ampsave.tests.sip_pb2
from ampsave.common import getPrintableAddress, getPrintableDscp

def build_summary(data):
    """
    Build the jitter summary dictionary if the appropriate data was reported
    """
    if not data:
        return None
    return {
        "maximum": data.maximum,
        "minimum": data.minimum,
        "mean": data.mean,
        "sd": data.sd,
    }

def build_stream(data):
    """
    Build the stream statistics dictionary if the appropriate data was reported
    """
    if not data:
        return None
    return {
        "packets": data.packets,
        "bytes": data.bytes,
        "lost": data.lost,
        "discarded": data.discarded,
        "reordered": data.reordered,
        "duplicated": data.duplicated,
        "jitter": build_summary(data.jitter),
        "loss": build_summary(data.loss),
        "mos": build_mos(data.mos),
    }

def build_mos(data):
    """
    Build the VoIP result dictionary if the appropriate data was reported
    """
    if not data:
        return None
    return {
        "itu_rating": data.itu_rating,
        "itu_mos": data.itu_mos,
    }

def get_data(data):
    """
    Extract the sip test results from the protocol buffer data
    """

    results = []
    msg = ampsave.tests.sip_pb2.Report()
    msg.ParseFromString(data)

    for i in msg.reports:
        # build the result structure based on what fields were present
        results.append(
            {
                "time_till_first_response": i.time_till_first_response if i.HasField("time_till_first_response") else None,
                "time_till_connected": i.time_till_connected if i.HasField("time_till_connected") else None,
                "duration": i.duration if i.HasField("duration") else None,
                "rtt": build_summary(i.rtt) if i.HasField("rtt") else None,
                "rx": build_stream(i.rx) if i.HasField("rx") else None,
                "tx": build_stream(i.tx) if i.HasField("tx") else None,
            }
        )

    return {
        "uri": msg.header.uri if len(msg.header.uri) > 0 else "unknown",
        "useragent": msg.header.useragent,
        "filename": msg.header.filename,
        "max_duration": msg.header.max_duration,
        "proxy": list(msg.header.proxy),
        "repeat": msg.header.repeat,
        "dscp": getPrintableDscp(msg.header.dscp),
        "hostname": msg.header.hostname,
        "address": getPrintableAddress(msg.header.family, msg.header.address),
        "results": results,
    }

# vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
