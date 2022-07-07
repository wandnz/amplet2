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

import ampsave.tests.youtube_pb2
from ampsave.common import getPrintableDscp

def get_data(data):
    """
    Extract the YOUTUBE test results from the protocol buffer data.
    """

    msg = ampsave.tests.youtube_pb2.Report()
    msg.ParseFromString(data)

    timeline = []
    for event in msg.item.timeline:
        timeline.append({
            "timestamp": event.timestamp,
            "event": event.type,
            "data": event.quality if event.quality else None,
        })

    return {
        "video": msg.header.video,
        "requested_quality": msg.header.quality,
        "dscp": getPrintableDscp(msg.header.dscp),
        "browser": msg.header.browser,
        "useragent": msg.header.useragent,
        "max_runtime": msg.header.maxruntime,
        "title": msg.item.title,
        "actual_quality": msg.item.quality,
        "initial_buffering": msg.item.initial_buffering,
        "playing_time": msg.item.playing_time,
        "stall_time": msg.item.stall_time,
        "stall_count": msg.item.stall_count,
        "total_time": msg.item.total_time,
        "pre_time": msg.item.pre_time,
        "reported_duration": msg.item.reported_duration,
        "timeline": timeline,
    }
