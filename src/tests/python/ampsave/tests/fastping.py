#
# This file is part of amplet2.
#
# Copyright (c) 2018 The University of Waikato, Hamilton, New Zealand.
#
# Author: Jayden Hewer
#         Brendon Jones
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

import ampsave.tests.fastping_pb2
from ampsave.common import getPrintableAddress, getPrintableDscp

def _build_summary(data):
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
        "samples": data.samples,
        "percentiles": data.percentiles,
    }

def get_data(data):
    """
    Extract the fastping test results from the protocol buffer data
    """

    results = []
    msg = ampsave.tests.fastping_pb2.Report()
    msg.ParseFromString(data)

    for i in msg.reports:
        results.append(
            {
                "runtime": i.runtime if i.HasField("runtime") else None,
                "rtt": _build_summary(i.rtt) if i.HasField("rtt") else None,
                "jitter": _build_summary(i.jitter) if i.HasField("jitter") else None,
            }
        )

    return {
        "target": msg.header.name if len(msg.header.name) > 0 else "unknown",
        "address": getPrintableAddress(msg.header.family, msg.header.address),
        "rate": msg.header.rate,
        "size": msg.header.size,
        "count": msg.header.count,
        "dscp": getPrintableDscp(msg.header.dscp),
        "preprobe": msg.header.preprobe,
        "results": results,
    }
