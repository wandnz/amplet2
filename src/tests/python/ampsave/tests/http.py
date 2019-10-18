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

import ampsave.tests.http_pb2
from ampsave.common import getPrintableDscp

def get_data(data):
    """
    Extract the HTTP test results from the protocol buffer data.
    """

    msg = ampsave.tests.http_pb2.Report()
    msg.ParseFromString(data)

    results = {
        "url": msg.header.url,
        "duration": msg.header.duration if msg.header.duration > 0 else None,
        "bytes": msg.header.total_bytes if msg.header.total_bytes > 0 else None,
        "server_count": len(msg.servers),
        "object_count": msg.header.total_objects,
        "keep_alive": msg.header.persist,
        "max_connections": msg.header.max_connections,
        "max_connections_per_server": msg.header.max_connections_per_server,
        "max_persistent_connections_per_server": msg.header.max_persistent_connections_per_server,
        "pipelining": msg.header.pipelining,
        "pipelining_maxrequests": msg.header.pipelining_maxrequests,
        "caching": msg.header.caching,
        "dscp": getPrintableDscp(msg.header.dscp),
        "useragent": msg.header.useragent,
        "proxy": msg.header.proxy,
        "failed_object_count": 0,
        "servers": []
    }

    # extract every server that we contacted
    for s in msg.servers:
        server = {
            "hostname": s.hostname,
            "address": s.address,
            "start": s.start,
            "end": s.end,
            "bytes": s.total_bytes,
            #"object_count": # XXX is this used?
            "objects": [],
        }

        # extract each object from this server
        for obj in s.objects:
            if obj.code == 0:
                results["failed_object_count"] += 1

            # Append this object to the list for this server
            server["objects"].append({
                "path": obj.path,
                "start": obj.start,
                "end": obj.end,
                "lookup_time": obj.lookup,
                "connect_time": obj.connect,
                "start_transfer_time": obj.start_transfer,
                "total_time": obj.total_time,
                "code": obj.code,
                "bytes": obj.size,
                "connect_count": obj.connect_count,
                "pipeline": obj.pipeline,
                "headers": {
                    "flags": {
                        "pub": obj.cache_headers.pub,
                        "priv": obj.cache_headers.priv,
                        "no_cache": obj.cache_headers.no_cache,
                        "no_store": obj.cache_headers.no_store,
                        "no_transform": obj.cache_headers.no_transform,
                        "must_revalidate": obj.cache_headers.must_revalidate,
                        "proxy_revalidate": obj.cache_headers.proxy_revalidate,
                    },
                    "max_age": obj.cache_headers.max_age if obj.cache_headers.HasField("max_age") else None,
                    "s_maxage": obj.cache_headers.s_maxage if obj.cache_headers.HasField("s_maxage") else None,
                    "x_cache": obj.cache_headers.x_cache if obj.cache_headers.HasField("x_cache") else None,
                    "x_cache_lookup": obj.cache_headers.x_cache_lookup if obj.cache_headers.HasField("x_cache_lookup") else None,
                },
            })

        # Add this whole server with objects to the results
        results["servers"].append(server)

    return results
