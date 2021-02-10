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
"""
AMP test saving module
"""

import sys
from .tests import *
from .exceptions import UnknownTestError

def _import_data_functions():
    """
    Load all the available data parsing functions for the AMP tests.
    """
    modules = {}

    for name in tests.__all__:
        modules[name] = sys.modules['ampsave.tests.' + name]
    return modules

_modules = _import_data_functions()

def get_data(test, raw):
    if test in _modules:
        return _modules[test].get_data(raw)
    raise UnknownTestError(test)

def list_modules():
    return list(_modules.keys())
