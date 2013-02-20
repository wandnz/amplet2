import os, sys
import ampsave.tests

def import_data_functions():
    """
    Load all the available data parsing functions for the AMP tests.
    """
    from ampsave.tests import *
    modules = {}

    for name in ampsave.tests.__all__:
	modules[name] = sys.modules['ampsave.tests.' + name]
    return modules
