import os

from setuptools import setup, find_packages

here = os.path.abspath(os.path.dirname(__file__))
#README = open(os.path.join(here, 'README.txt')).read()
#CHANGES = open(os.path.join(here, 'CHANGES.txt')).read()

requires = [
    'pyasn1',
    'pyasn1_modules',
    'pycrypto',
    'pyramid_chameleon',
    'pyramid',
    'pyramid_debugtoolbar',
    'pyramid_assetviews',
    'waitress',
    ]

setup(name='amppki',
      version='0.1',
      description='amp-pki',
      #long_description=README + '\n\n' +  CHANGES,
      long_description="AMP PKI web interface",
      classifiers=[
        "Programming Language :: Python",
        "Framework :: Pyramid",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: Internet :: WWW/HTTP :: WSGI :: Application",
        ],
      author='',
      author_email='',
      url='',
      keywords='web wsgi bfg pylons pyramid',
      packages=find_packages(),
      include_package_data=True,
      zip_safe=False,
      #test_suite='ampweb',
      install_requires=requires,
      entry_points="""\
      [paste.app_factory]
      main = amppki:main
      """,
      )
