import socket

def getAddressFromMessage(msg):
    try:
        address = socket.inet_ntop(msg.family, msg.address)
    except (ValueError, socket.error) as e:
        if msg.family == socket.AF_INET:
            address = "0.0.0.0"
        elif msg.family == socket.AF_INET6:
            address = "::"
        else:
            # TODO Should this return a string, an empty string or None?
            # Or go back to throwing an exception (which we then have to catch)
            address = "unknown"
    return address
