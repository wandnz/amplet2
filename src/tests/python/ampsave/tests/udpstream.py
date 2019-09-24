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

import ampsave.tests.udpstream_pb2
from ampsave.common import getPrintableAddress, getPrintableDscp

def build_loss_periods(data):
    """
    Build the loss periods list showing packet drop patterns
    """
    periods = []
    for i in data:
        if i.status == ampsave.tests.udpstream_pb2.Period.LOST:
            periods.append(("loss", i.length))
        elif i.status == ampsave.tests.udpstream_pb2.Period.RECEIVED:
            periods.append(("ok", i.length))
    return periods

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
        "samples": data.samples,
    }

def build_voip(data):
    """
    Build the VoIP result dictionary if the appropriate data was reported
    """
    if not data:
        return None
    return {
        "icpif": data.icpif,
        "cisco_mos": data.cisco_mos,
        "itu_rating": data.itu_rating,
        "itu_mos": data.itu_mos,
    }

def direction_to_string(direction):
    """
    Convert direction enum into a human readable string
    """
    if direction == ampsave.tests.udpstream_pb2.Item.CLIENT_TO_SERVER:
        return "out"
    if direction == ampsave.tests.udpstream_pb2.Item.SERVER_TO_CLIENT:
        return "in"
    return "unknown"

def get_data(data):
    """
    Extract the udpstream test results from the protocol buffer data
    """

    results = []
    msg = ampsave.tests.udpstream_pb2.Report()
    msg.ParseFromString(data)

    for i in msg.reports:
        # build the result structure based on what fields were present
        results.append(
            {
                "direction": direction_to_string(i.direction),
                "rtt": build_summary(i.rtt) if i.HasField("rtt") else None,
                "jitter": build_summary(i.jitter) if i.HasField("jitter") else None,
                "percentiles": i.percentiles,
                "packets_received": i.packets_received if i.HasField("packets_received") else None,
                "loss_periods": build_loss_periods(i.loss_periods),
                "loss_percent": i.loss_percent if i.HasField("loss_percent") else None,
                "voip": build_voip(i.voip) if i.HasField("voip") else None,
            }
        )

    return {
        "target": msg.header.name if len(msg.header.name) > 0 else "unknown",
        "address": getPrintableAddress(msg.header.family, msg.header.address),
        #"schedule": msg.header.schedule,
        "packet_size": msg.header.packet_size,
        "packet_spacing": msg.header.packet_spacing,
        "packet_count": msg.header.packet_count,
        "dscp": getPrintableDscp(msg.header.dscp),
        "rtt_samples": msg.header.rtt_samples,
        "results": results,
    }

# vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
