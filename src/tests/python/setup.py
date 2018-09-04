try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

setup(name="ampsave",
    version="0.8.4",
    description="AMP server data storage package",
    author="Brendon Jones",
    author_email='contact@wand.net.nz',
    url='http://www.wand.net.nz',
    packages=['ampsave', 'ampsave.tests'],
    package_dir = {
	'ampsave':'ampsave',
	'ampsave.tests':'ampsave/tests',
	},
    )
