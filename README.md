# amplet2

amplet2 is the client portion of the
[AMP active measurement system](http://amp.wand.net.nz), and is responsible
for performing the measurements - it should be run on each of the measurement
probes. Each client independently schedules and runs tests, acts as a
cooperative endpoint for tests run by other probes, and reports test results to
a central collector for analysis and display.


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
