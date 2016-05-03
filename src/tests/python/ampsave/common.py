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

def getPrintableDscp(value):
    if value == 0:
        return "Default"
    if value == 0b001000:
        return "CS1";
    if value == 0b010000:
        return "CS2";
    if value == 0b011000:
        return "CS3";
    if value == 0b100000:
        return "CS4";
    if value == 0b101000:
        return "CS5";
    if value == 0b110000:
        return "CS6";
    if value == 0b111000:
        return "CS7";
    if value == 0b001010:
        return "AF11";
    if value == 0b001100:
        return "AF12";
    if value == 0b001110:
        return "AF13";
    if value == 0b010010:
        return "AF21";
    if value == 0b010100:
        return "AF22";
    if value == 0b010110:
        return "AF23";
    if value == 0b011010:
        return "AF31";
    if value == 0b011100:
        return "AF32";
    if value == 0b011110:
        return "AF33";
    if value == 0b100010:
        return "AF41";
    if value == 0b100100:
        return "AF42";
    if value == 0b100110:
        return "AF43";
    if value == 0b101100:
        return "VA";
    if value == 0b101110:
        return "EF";
    return "0x%.02x" % value
