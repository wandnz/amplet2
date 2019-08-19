# amplet2

The [AMP active measurement system](http://amp.wand.net.nz) is a set of
software that is designed to perform continuous, distributed, black-box active
network measurement.

amplet2 is the client portion of the AMP system, and is responsible
for performing the measurements - it should be run on each of the measurement
hosts. Each client independently schedules and runs tests, acts as a
cooperative endpoint for tests run by other hosts, and reports test results to
a central collector for analysis and display.

Prebuilt .deb packages are available at https://dl.bintray.com/wand/amp/ and
RPM packages for Centos 7 at https://dl.bintray.com/wand/amp-rpm/. The
[amplet2 wiki](https://github.com/wanduow/amplet2/wiki) contains instructions
on [installing the amplet2 client](https://github.com/wanduow/amplet2/wiki/Installing-the-Amplet2-Client) using these packages.

The other components of the AMP system are:
- [ampweb](https://github.com/wanduow/amp-web) - Front-end web interface.
- [ampy](https://github.com/wanduow/ampy) - Interface between the display front- and the data storage back-end.
- [nntsc](https://github.com/wanduow/nntsc) - Data storage back-end.


## Tests

Some of the built in tests require that the destination host also be running the
amplet2 software, while others will work using existing Internet infrastructure
and protocols. Tests currently available include:

 * ICMP latency
 * TCP latency
 * UDP DNS latency
 * UDP latency and jitter
 * UDP traceroute
 * TCP throughput
 * HTTP performance


## Documentation

Documentation, usage instructions and manual pages can be found in the
[amplet2 wiki](https://github.com/wanduow/amplet2/wiki).

For more information please email contact@wand.net.nz.

----

This code has been developed by the
[University of Waikato](http://www.waikato.ac.nz)
[WAND network research group](http://www.wand.net.nz).
It is licensed under the GNU General Public License (GPL) version 2. Please
see the included file COPYING for details of this license.

Copyright (c) 2013-2016 The University of Waikato, Hamilton, New Zealand.
All rights reserved.
