import ampsave.tests.http_pb2
from ampsave.common import getPrintableAddress

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
        "bytes": msg.header.size,
        "server_count": msg.header.total_servers,
        "object_count": msg.header.total_objects,
        "keep_alive": msg.header.persist,
        "max_connections": msg.header.max_connections,
        "max_connections_per_server": msg.header.max_connections_per_server,
        "max_persistent_connections_per_server": msg.header.max_persistent_connections_per_server,
        "pipelining": msg.header.pipelining,
        "pipelining_maxrequests": msg.header.pipelining_maxrequests,
        "caching": msg.header.caching,
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
            if ( msg.header.total_servers == 1 and
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
                        "pub": obj.pub,
                        "priv": obj.priv,
                        "no_cache": obj.no_cache,
                        "no_store": obj.no_store,
                        "no_transform": obj.no_transform,
                        "must_revalidate": obj.must_revalidate,
                        "proxy_revalidate": obj.proxy_revalidate,
                    },
                    "max_age": obj.max_age if obj.HasField("max_age") else None,
                    "s_maxage": obj.s_maxage if obj.HasField("s_maxage") else None,
                    "x_cache": obj.x_cache if obj.HasField("x_cache") else None,
                    "x_cache_lookup": obj.x_cache_lookup if obj.HasField("x_cache_lookup") else None,
                },
            })

        # Add this whole server with objects to the results
        results["servers"].append(server)

    return results
