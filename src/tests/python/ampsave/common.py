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
