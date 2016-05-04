import ampsave.tests.http_pb2
from ampsave.common import getPrintableAddress, getPrintableDscp

def get_data(data):
    """
    Extract the HTTP test results from the protocol buffer data.
    """

    results = []
    msg = ampsave.tests.http_pb2.Report()
    msg.ParseFromString(data)

    results = {
        "url": msg.header.url,
        "duration": msg.header.duration,
        "bytes": msg.header.total_bytes,
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
            # XXX can we report properly to prevent this?
            # If there is only one server, with one object and that object
            # has a code of zero, then we failed to fetch anything at all.
            # Change the duration to None so the graphs properly interrupt
            # the line.
            if ( len(msg.servers) == 1 and
                    msg.header.total_objects == 1 and obj.code == 0 ):
                results["duration"] = None
                # TODO should we still add the object?
                #results["object_count"] = 0
                #server["object_count"] = 0
                #break

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
