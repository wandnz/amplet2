import socket

def getPrintableAddress(family, address):
    try:
        addrstr = socket.inet_ntop(family, address)
    except (ValueError, socket.error) as e:
        if family == socket.AF_INET:
            addrstr = "0.0.0.0"
        elif family == socket.AF_INET6:
            addrstr = "::"
        else:
            # TODO Should this return a string, an empty string or None?
            # Or go back to throwing an exception (which we then have to catch)
            addrstr = "unknown"
    return addrstr
