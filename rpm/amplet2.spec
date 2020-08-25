Name: amplet2
Version: 0.10.5
Release: 1%{?dist}
Summary: AMP Network Performance Measurement Suite

Group: Applications/Internet
License: GPLv2
URL: https://github.com/wanduow/amplet2
Source0: https://github.com/wanduow/amplet2/archive/%{version}.tar.gz
Patch0: amplet2-client-init.patch
Patch1: amplet2-client-service.patch
BuildRoot:	%(mktemp -ud %{_tmppath}/%{name}-%{version}-%{release}-XXXXXX)

BuildRequires: automake libtool openssl-devel libconfuse-devel libevent-devel >= 2.0.21 libcurl-devel unbound-devel libpcap-devel protobuf-c-devel librabbitmq-devel >= 0.7.1 flex libyaml-devel systemd libcap-devel pjproject-devel


%description
AMP measures network performance from distributed nodes, according
to a configured schedule. The resulting data is transferred back to
one or more rabbitmq brokers via the AMQP protocol.


%package client
Summary: AMP Network Performance Measurement Suite - Client Tools
Requires: librabbitmq >= 0.7.1 libevent >= 2.0.21 rsyslog protobuf-c systemd initscripts
%description client
This package contains the client tools for the AMP Measurement Suite.
These measure the network performance to specified targets according
to a configured schedule. The resulting data is transferred back to
one or more rabbitmq brokers via the AMQP protocol.

%package client-sip
Summary: AMP Network Performance Measurement Suite - SIP Test
Requires: amplet2-client = %{version}
%description client-sip
This package contains the SIP test for the AMP Measurement Suite.


%prep
%setup -q
%patch0 -p1
%patch1 -p1


%build
if [ -x bootstrap.sh ]; then ./bootstrap.sh; fi
%configure --enable-sip

make %{?_smp_mflags}
%install
rm -rf %{buildroot}
make install DESTDIR=%{buildroot}
install -D amplet2-client.init %{buildroot}%{_initrddir}/amplet2-client
install -m 644 -D src/measured/rsyslog/10-amplet2.conf %{buildroot}%{_sysconfdir}/rsyslog.d/10-amplet2.conf
install -m 644 -D amplet2-client.service %{buildroot}%{_unitdir}/amplet2-client.service
install -m 644 -D src/measured/rabbitmq/client-rabbitmq.config %{buildroot}%{_docdir}/amplet2-client/examples/rabbitmq/client-rabbitmq.config
rm -rf %{buildroot}/usr/lib/python2.6/
rm -rf %{buildroot}%{_libdir}/*a
rm -rf %{buildroot}%{_libdir}/%{name}/tests/*a
rm -rf %{buildroot}/usr/share/%{name}/rsyslog/
rm -rf %{buildroot}/usr/share/%{name}/rabbitmq/


%check
make check


%clean
rm -rf %{buildroot}


%files client
%defattr(-,root,root,-)
%doc %{_mandir}/man8/amplet2.8.gz
%doc %{_mandir}/man8/amplet2-remote.8.gz
%doc %{_mandir}/man8/amp-dns.8.gz
%doc %{_mandir}/man8/amp-external.8.gz
%doc %{_mandir}/man8/amp-fastping.8.gz
%doc %{_mandir}/man8/amp-http.8.gz
%doc %{_mandir}/man8/amp-icmp.8.gz
%doc %{_mandir}/man8/amp-tcpping.8.gz
%doc %{_mandir}/man8/amp-throughput.8.gz
%doc %{_mandir}/man8/amp-trace.8.gz
%doc %{_mandir}/man8/amp-udpstream.8.gz
%exclude %{_mandir}/man8/amp-youtube.8.gz
%caps(cap_net_raw=pe cap_net_admin=pe cap_net_bind_service=pe) %{_sbindir}/amplet2
%{_bindir}/amplet2-remote
%{_bindir}/amp-dns
%{_bindir}/amp-external
%caps(cap_net_raw=pe) %{_bindir}/amp-fastping
%{_bindir}/amp-http
%caps(cap_net_raw=pe) %{_bindir}/amp-icmp
%caps(cap_net_raw=pe cap_net_admin=pe) %{_bindir}/amp-tcpping
%caps(cap_net_bind_service=pe) %{_bindir}/amp-throughput
%caps(cap_net_raw=pe) %{_bindir}/amp-trace
%caps(cap_net_bind_service=pe) %{_bindir}/amp-udpstream
%{_libdir}/libamp.*so*
%{_libdir}/amplet2/tests/dns.so
%{_libdir}/amplet2/tests/external.so
%{_libdir}/amplet2/tests/fastping.so
%{_libdir}/amplet2/tests/http.so
%{_libdir}/amplet2/tests/icmp.so
%{_libdir}/amplet2/tests/tcpping.so
%{_libdir}/amplet2/tests/throughput.so
%{_libdir}/amplet2/tests/trace.so
%{_libdir}/amplet2/tests/udpstream.so
%config(noreplace) %{_sysconfdir}/%{name}/*
%config(noreplace) %{_sysconfdir}/rsyslog.d/10-amplet2.conf
%{_initrddir}/*
%dir %{_localstatedir}/run/%{name}/
%doc %{_docdir}/amplet2-client/examples/rabbitmq/*
%{python2_sitelib}/ampsave-*.egg-info
%{python2_sitelib}/ampsave/*
%license COPYING
%{_unitdir}/amplet2-client.service

%files client-sip
%defattr(-,root,root,-)
%doc
%{_mandir}/man8/amp-sip.8.gz
%{_bindir}/amp-sip
%{_libdir}/amplet2/tests/sip.so
%{_libdir}/amplet2/extra/sip-test-8000.wav

%post client
/sbin/ldconfig

# create the system user that will run the amp tests
adduser -r --home %{_sysconfdir}/%{name} amplet

# Make sure keys directory exists and has the appropriate permissions
mkdir -p %{_sysconfdir}/%{name}/keys
chmod 2750 %{_sysconfdir}/%{name}/keys

# the amplet user should own everything in the config directory
chown -R amplet: %{_sysconfdir}/%{name}/

mkdir -p /var/log/amplet2

CLIENTDIR=%{_sysconfdir}/%{name}/clients
if [ `ls -lah ${CLIENTDIR} | grep -c "\.conf$"` -eq 0 ]; then
    cp ${CLIENTDIR}/client.example ${CLIENTDIR}/default.conf
fi

# Copy a default rabbitmq configuration file into place if there
# isn't already one there. We'll assume if there is one then the
# user knows what they are doing.
# TODO this doesn't help if the user later installs rabbitmq-server
# TODO looks like rabbitmq-server RPMs ship with a sample file already in place?
if rpm -q rabbitmq-server >/dev/null; then
    ACTUAL="/etc/rabbitmq/rabbitmq.config"
    EXAMPLE="/usr/share/doc/amplet2-client/examples/client-rabbitmq.config"

    # Also need to check that the example config even exists - some
    # docker images are stripping docs (see /etc/yum.conf)
    if [ -d /etc/rabbitmq/ -a ! -f ${ACTUAL} -a -f ${EXAMPLE} ]; then
        cp ${EXAMPLE} ${ACTUAL}
        chown rabbitmq:rabbitmq ${ACTUAL}
        # restart rabbitmq-server so the new config takes effect
        systemctl restart rabbitmq.service
    fi
fi

# only restart rsyslog during install, not upgrade
if [ $1 -eq 1 ]; then
    systemctl restart rsyslog.service
fi
%systemd_post amplet2-client.service


%preun client
%systemd_preun amplet2-client.service


%postun client -p /sbin/ldconfig


%changelog
* Wed Aug 26 2020 Brendon Jones <brendonj@waikato.ac.nz> 0.10.5-1
- amplet2: Zero control struct before use, preventing a crash on exit.
- amplet2: Check socket options exist before trying to compile them.
- amplet2: Replace index() and rindex() with strchr() and strrchr().

* Fri Jul  3 2020 Brendon Jones <brendonj@waikato.ac.nz> 0.10.4-1
- sip: Allow test to take both a URI and a normal target.
- sip: Update man page with new options.
- sip: Remove (unused) "family" from result dict, to match other tests.
- traceroute: Don't increment TTL if already at the maximum path length.

* Thu May 28 2020 Brendon Jones <brendonj@waikato.ac.nz> 0.10.3-1
- amplet2: Allow setting default parameters for servers started by tests.
- amplet2: Allow including other files in the client configuration file.
- sip: Fix copy and paste error in mutex name.
- sip: Start remote server before initialising pjsip locally.
- sip: Cleanup and return more often rather than exiting with error.

* Fri May 22 2020 Brendon Jones <brendonj@waikato.ac.nz> 0.10.2-1
- amplet2: Switch to using libevent rather than libwandevent (#41).
- amplet2: Set server name indication on rabbitmq shovels.
- fastping: Free percentile data in summary structures when finished.
- package: Set VCS fields in Debian control file.
- sip: Set minimum targets for test to zero (it could be a URI instead).
- sip: Correctly flag options as not having arguments.
- sip: Set DSCP bits, and send the option to the server too.
- sip: Add optional account registration.
- sip: Remove all codecs except PCMA/8000 and set clock rate to 8000Hz.
- sip: Fix incorrect loss percent/period used by SIP test to calculate MOS.
- sip: Fix use of original transport config instead of the duplicated one.
- sip: Ensure new 8000Hz wav file is part of the amplet2-client-sip package.
- standalone tests: Avoid shadowing test specific long options struct.

* Mon Mar 30 2020 Brendon Jones <brendonj@waikato.ac.nz> 0.10.1-1
- package: set noreplace on the rsyslogd config file in RPM packages.
- youtube: don't print test timing results if they aren't set.

* Tue Mar 24 2020 Brendon Jones <brendonj@waikato.ac.nz> 0.10.0-1
- amplet2: move standalone test binaries from /usr/sbin to /usr/bin/.
- sip: fix building the test with older libpjsip packages.
- sip: fix building the test on armhf and arm64 architectures.
- sip: build a separate {deb,rpm} package containing the sip test.
- udpstream: link the test with -lm again.

* Tue Mar 10 2020 Brendon Jones <brendonj@waikato.ac.nz> 0.9.14-1
- sip: add new SIP/RTP test, currently disabled by default.

* Mon Feb 24 2020 Brendon Jones <brendonj@waikato.ac.nz> 0.9.13-1
- dns: use SO_TIMESTAMPING to get timestamps for sent packets (#35).
- fastping: use SO_TIMESTAMPING to get timestamps for sent packets (#35).
- icmp: use SO_TIMESTAMPING to get timestamps for sent packets (#35).
- tcpping: use SO_TIMESTAMPING to get timestamps for sent packets (#35).
- traceroute: use SO_TIMESTAMPING to get timestamps for sent packets (#35).
- udpstream: fix incorrect test name in error message.
- amplet2: make shovel prefetch-count configurable, set to 1 by default (#38).

* Thu Nov 14 2019 Brendon Jones <brendonj@waikato.ac.nz> 0.9.12-1
- amplet2: add workaround for setsockopt failure under non-amd64 qemu/docker.

* Wed Oct 23 2019 Brendon Jones <brendonj@waikato.ac.nz> 0.9.11-1
- dns: avoid waiting for LOSS_TIMEOUT if no packets are outstanding.
- dns: only count DNS query length if the query was actually sent.
- fastping: be stricter in checking before reporting parts of results.
- fastping: ignore duplicate responses.
- fastping: limit valid fastping sequence numbers to those sent.
- fastping: check length of data when validating fastping response.
- fastping: add more debugging output.
- fastping: apply a BPF filter to restrict incoming response packets.
- fastping: sleep less at low sending rates.
- http: ensure server/object/global start/end times always get set.
- http: total object count should also include failed objects.
- icmp: avoid waiting for LOSS_TIMEOUT if no packets are outstanding.
- tcpping: avoid waiting for LOSS_TIMEOUT if no packets are outstanding.
- throughput: avoid using default protobuf values for runtime and bytes.
- traceroute: fix reporting too many non-responsive hops.
- traceroute: don't connect to whois server with no addresses to query.
- udpstream: be stricter in checking before reporting parts of results.
- all tests: update to accept unresolved hostnames as destinations.

* Mon Aug 19 2019 Brendon Jones <brendonj@waikato.ac.nz> 0.9.10-1
- package: put binaries in the same location they are in Debian packages.
- package: run unit tests after building package.
- dns: fix incorrect test name in error message.
- amplet2: explicitly set protocol buffer version 2 in .proto files.
- amplet2: replace deprecated ASN1_STRING_data() with ASN1_STRING_get0_data().
- amplet2: replace deprecated RSA_generate_key() with RSA_generate_key_ex().

* Thu Jul 11 2019 Brendon Jones <brendonj@waikato.ac.nz> 0.9.9-1
- amplet2: set CAP_NET_ADMIN to run tcpping test.
- amplet2: set CAP_NET_BIND_SERVICE to run throughput and udpstream tests.
- tcpping: set CAP_NET_ADMIN to allow pcap capture.
- throughput: set CAP_NET_BIND_SERVICE to allow binding to low ports.
- udpstream: set CAP_NET_BIND_SERVICE to allow binding to low ports.

* Fri Jul  5 2019 Brendon Jones <brendonj@waikato.ac.nz> 0.9.8-1
- package: specify dependencies correctly for the client subpackage.
- package: fix the reference in postinst to the config directory to be correct.
- package: create directories during postinst rather than in init scripts.
- amplet2: start as root to run rabbitmqctl before switching to amplet user.

* Wed Jul  3 2019 Brendon Jones <brendonj@waikato.ac.nz> 0.9.7-1
- amplet2: run all test processes as a non-privileged user.
- amplet2: update man pages with capabilities and links to other programs.
- udpstream: fix incorrect test name in error message.

* Thu Jun 13 2019 Brendon Jones <brendonj@waikato.ac.nz> 0.9.6-1
- package: fix RPATH in RPM packaging so test libraries can be found (#32).
- package: flag man pages so they get installed by automake and RPMs (#32).
- package: various minor file attribute fixes (#32).
- external: drop all groups before setting user/group to "nobody" (#33).
- fastping: link libm correctly with the test library.

* Tue Jun 11 2019 Brendon Jones <brendonj@waikato.ac.nz> 0.9.5-1
- package: bring RPM packaging up to date (#32).
- external: enable test by default (#33).

* Thu May  9 2019 Brendon Jones <brendonj@waikato.ac.nz> 0.9.4-1
- amplet2: add new test to run external programs (temporarily disabled) (#33).
- fastping: fix incorrect test name on man page.
- youtube: use strictly incrementing javascript timer.

* Thu Apr 11 2019 Brendon Jones <brendonj@waikato.ac.nz> 0.9.3-1
- fastping: enable test by default (#26).
- fastping: add missing header to the distribution tarball.
- fastping: change result fields to better match backend expectations.
- fastping: change offset into fastping packet depending on address family.
- fastping: sleep at low packet rates when possible.

* Thu Mar 28 2019 Brendon Jones <brendonj@waikato.ac.nz> 0.9.2-1
- youtube: set chromium UserDataDir to /tmp/.amplet2/chromium/ (#29).
- youtube: move wrapper from /usr/sbin/ to avoid creating dirs there (#29).
- youtube: terminate cleanly if player receives an error (#30).

* Wed Feb 13 2019 Brendon Jones <brendonj@waikato.ac.nz> 0.9.1-1
- amplet2: close the pidfile after writing the PID.
- dns: change nsid result field name so it doesn't shadow header variable.
- package: change amplet2-server package architecture from "any" to "all".
- youtube: always set and report the YouTube test user agent.
- youtube: add flag to specify maximum run time of a YouTube video.
- youtube: print console.log() messages in the YouTube test to the debug log.
- youtube: fix horizontal resolution for "large" quality.
- youtube: rework Makefile to build more sensibly.
- youtube: mute video by default so it will autoplay.

* Fri Nov  2 2018 Brendon Jones <brendonj@waikato.ac.nz> 0.9.0-1
- build: libamp.so is now versioned (#15).
- amplet2: remove bounds checking for test IDs so all values are valid. This
  allows others to write tests without needing to recompile amplet2 (#15).
- amplet2: Fix argument parsing by scheduler to deal with quotes (#19).
- dns: update unit tests for new rrsig and nsid fields (#23, #24).
- amplet2: add new high frequency ICMP stream test "fastping" (#26).
- amplet2: set environ to NULL after free, so cleanup functions don't use it.
- amplet2: Print line number of config block when reporting schedule errors.

* Mon Sep  3 2018 Brendon Jones <brendonj@waikato.ac.nz> 0.8.4-1
- package: don't try to install sample rabbitmq.config if file doesn't exist.
- amplet2: fix crash caused by incorrect/duplicated SSL cleanup.
- amplet2: fix small memory leak when unregistering test modules.
- amplet2: fix exit codes to be more consistent (#2).
- dns: report on presence of RRSIG resource records if DNSSEC enabled (#23).
- dns: fix result handing to correctly extract NSID responses (#24).

* Mon Jul 30 2018 Brendon Jones <brendonj@waikato.ac.nz> 0.8.3-1
- http: allow setting a proxy to use.
- http: allow setting the User-Agent string to use.
- http: correctly null terminate headers without clobbering the next one.
- server: fix postinst setup to work with rabbitmq-server >= 3.7.0.

* Mon Jul 23 2018 Brendon Jones <brendonj@waikato.ac.nz> 0.8.2-1
- amplet2: Set shovel reconnect delay to random value between 60s and 180s.
- amplet2: Add new YouTube video streaming quality test.
- standalone tests: Don't wait for name resolution if there are no names.
- build: Try to be more accurate regarding which headers are included.

* Tue Nov  7 2017 Brendon Jones <brendonj@waikato.ac.nz> 0.8.1-1
- amplet2: allow tests to be limited to a single address family.
- throughput: replace web10g with newly available TCP_INFO stats.
- throughput: report total data transmitted using power of two units.
- udpstream: increase wait time for reflected packets once sending complete.
- package: supply sample rabbitmq.config files, but don't install any.

* Tue Jul 18 2017 Brendon Jones <brendonj@waikato.ac.nz> 0.8.0-1
- build: update SSL library check to still succeed with newer versions.
- build: check for external SASL method in AMQP library.
- throughput: fix EADDRINUSE by not binding to addresses that aren't used.
- http: extract count of failed object fetches in ampsave.
- server: force tcpreused to always be true in throughput test results.
- amplet2: move SSL configuration to its own section in the config file.
- amplet2: set default value of vialocal based on rabbitmq being present.
- amplet2: set default collector SSL config option based on the port used.
- amplet2: use server-side cipher list ordering.
- amplet2: ensure that the correct versions of librabbitmq functions are
  used that match the version listed as a dependency.
- amplet2: don't allow negative latency values, clamp them at zero.
- amplet2: improve some error messages to be more useful/accurate.
- amplet2: set --no-as-needed to build test libraries using newer GCC.
- amplet2: don't crash when bad options are given on the command line.
- package: update init script to configure rabbitmq and required directories.
- package: try to avoid restarting services unnecessarily on package install.
- package: rename rsyslogd config file so it sorts earlier than default.
- package: removed amplet2-client-lite packages, determine rabbitmq usage at
  runtime.
- throughput: added ability to masquerade as HTTP POST stream.
- throughput: removed test control headers from data stream.
- http: try to parse URL fragments or decimal encoded characters.
- http: split URLs where '?' is used after hostname without '/'.
- traceroute: use library functions to receive packets rather than calling
  the low level functions directly.
- testlib: fix wrapping values when comparing timevals on 32-bit machines.
- amplet2: remove default collector address and make it mandatory to be set.
- Update documentation.

* Thu Sep 22 2016 Brendon Jones <brendonj@waikato.ac.nz> 0.7.0-1
- Add access control list for access to starting test servers, running tests.
- Remove standard Diffie-Hellman ciphers from list of allowable choices.
- Use libwandevent to run packet probing in icmp and dns tests.
- Use backported librabbitmq4 rather than our own version with EXTERNAL auth.
- Fix scheduling bug where the wrong time units could be used in some cases.
- Don't start the tcpping test loss timer till after the last packet is sent.
- Always include the scheme when reporting an HTTP test URL.
- Improve logging around fetching ASN data for traceroute test.
- Remove unused stopset code from traceroute test.
- Improve accuracy of probe timers in traceroute test.
- Randomise first TTL in traceroute test to help spread probes out.
- Add command line options to configure the traceroute probing window.
- Bind remotely started test servers to the correct interface and address.
- Fix certificate request retry timer to properly cap at the maximum value.
- Don't enforce client-wide minimum packet spacing in the udpstream test.
- Deal better with setting inter packet gap if time goes backwards.
- Tighten schedule clock fudge factor from 500ms to 100ms.
- Use '!' instead of ':' to specify address families in the schedule file.
- Add manpages for amplet2-remote and amp-udpstream.
- Update example configuration file documentation.
- Update usage statements for binaries.
- Update build dependencies.
- Update licensing.
- Update man pages.

* Tue May 31 2016 Brendon Jones <brendonj@waikato.ac.nz> 0.6.2-1
- Added new test to perform udp jitter/latency/loss/mos tests.
- Exit main event loop on SIGTERM so we can log shutdown messages.
- Smarter default configuration for ampname.
- Fixed permissions for downloaded certificates.
- Write pidfile earlier to help prevent puppet starting multiple instances.
- Fix crash when checking the address families on interfaces with no address.
- Exponentially backoff when checking for newly signed certificates.
- Add ability to remotely trigger test execution.
- Reuse SSL control connection when being asked by a remote client to start
  a test server rather than creating a new redundant one.
- Use the same code path for control traffic whether using SSL or not.
- Fix bug where non-default control port wasn't being passed to tests.
- Watchdog timers are now run inside the child process.
- Unblock signals on child processes so they can be killed by init scripts.
- Print short error messages on init script failure.
- Dynamically link standalone tests to the specific test libraries.
- Add ability to set DSCP bits for all tests.
- Prevent possible race in TCP ping test.
- Free BPF filters after they have been installed in TCP ping test.
- Fix bug in tcpping test where SYN payload could prevent matching packets.
- Fix bug in tcpping test where packet size was incorrectly calculated.
- Fix bug in dns test where payload size EDNS option wasn't being set.
- Try to deal with URLs at the top level starting with "../" in the HTTP test.
- Follow redirects when fetching remote schedule files.
- Force refetch of remote schedule on a SIGUSR2.
- Updated documentation.

* Fri Aug 21 2015 Brendon Jones <brendonj@waikato.ac.nz> 0.5.0-1
- Use Google protocol buffers when reporting test results.

* Tue Jul 21 2015 Brendon Jones <brendonj@waikato.ac.nz> 0.4.8-1
- Rewrite ASN lookups to deal better with whois server issues.
- More debug around ASN lookups during traceroute test.
- Break report messages into blocks of 255 results.
- Don't update HTTP endtime after cleaning up - let returned objects set it.
- Don't try to log an ampname before it has been set.
- Don't count failed object fetches towards global HTTP test statistics.
- First basic attempt to include the ampname when logging to syslog.
- Add runtime option to HTTP test to force SSL version.
- Add config option to amplet2 client to set minimum inter-packet delay.

* Fri Mar 27 2015 Brendon Jones <brendonj@waikato.ac.nz> 0.4.3-1
- Don't report HTTP test data if name resolution fails (same as other tests).
- Add HTTP test option to suppress parsing of initial object.
- Fix comparison of test schedule objects to properly check end time.

* Wed Mar 18 2015 Brendon Jones <brendonj@waikato.ac.nz> 0.4.2-1
- Don't do address to name translation when accepting on control socket.

* Fri Mar 13 2015 Brendon Jones <brendonj@waikato.ac.nz> 0.4.1-1
- Always initialise SSL, even if not needed for reporting to rabbitmq.

* Tue Mar 10 2015 Brendon Jones <brendonj@waikato.ac.nz> 0.4.0-1
- Add ability to generate keys and fetch signed certificates if not present.
- Fix HTTP test to deal with HTTPS URLs.
- Speed up random packet generation in throughput test by using /dev/urandom.
- Always configure rabbitmq if with a local broker (unless configured not to).
- Fix the nametable to properly use names as targets.

* Wed Feb 11 2015 Brendon Jones <brendonj@waikato.ac.nz> 0.3.9-1
- Fix rescheduling tests when run slightly early around test period boundaries.
- Fix a possible infinite loop in the tcpping test.
- Replace an assert with a warning when a watchdog can't be removed.
- Add ability to dump schedule config when receiving a SIGUSR2.

* Fri Dec  5 2014 Brendon Jones <brendonj@waikato.ac.nz> 0.3.8-2
- Fix tcpping test when bound to a single interface.
- Quieten some too common, unhelpful warning messages.
- Fix tests being rescheduled immediately due to clock drift.
- No longer attempts to resolve address families the test interface lacks.

* Mon Nov  3 2014 Brendon Jones <brendonj@waikato.ac.nz> 0.3.7-1
- Bring the schedule parser in line with the generated schedules.
- Fix buffer management when fetching large amounts of ASN data.
- Fix HTTP test to record and follow 3XX redirects.
- Fix HTTP test to better deal with headers using weird separators/caps.
- Fix traceroute test when low TTL responses incorrectly decrement TTL.
- Allow tests to be warned before the watchdog attempts to kill them.
- Properly close local unix sockets (ASN, DNS) when forking for a test.

* Tue Sep 30 2014 Brendon Jones <brendonj@waikato.ac.nz> 0.3.6-1
- Updated schedule file format to new testing YAML format.
- Updated ASN fetching for traceroute test to use TCP bulk whois interface.
- Fix HTTP test crashing with long URLs.

* Thu Aug 28 2014 Brendon Jones <brendonj@waikato.ac.nz> 0.3.5-1
- Use package name as ident when logging to syslog.
- Update test thread names to reflect the test being performed.
- Use socket timestamps rather than gettimeofday() where possible.
- Upgrade from libwandevent2 to libwandevent3.
- Use local stopsets in traceroute test to reduce nearby probing.
- Add option to traceroute test to fetch AS numbers for addresses in path.
- Added TCPPing test.

* Thu Jun 26 2014 Brendon Jones <brendonj@waikato.ac.nz> 0.3.3-8
- Update initscipts to better deal with multiple amplet clients
- Mark some files as config files to preserve some local modifications

* Wed Jun 18 2014 Brendon Jones <brendonj@waikato.ac.nz> 0.3.3-1
- Fix name resolution threads writing to dead test processes.
- Use local resolvers from /etc/resolv.conf if none specified.

* Mon Jun 9 2014 Brendon Jones <brendonj@waikato.ac.nz> 0.3.1-1
- New upstream release
- Able to run multiple clients on a single machine
- Local resolver that can cache DNS responses

* Mon Mar 31 2014 Brendon Jones <brendonj@waikato.ac.nz> 0.2.1-1
- New upstream release
- Renamed binaries, configs, etc to be more consistent
- Added HTTP test
- Added throughput test
- Added control socket for starting test servers
- All tests can now be bound to specific source interfaces/addresses
- Added simple test schedule fetching via HTTP/HTTPS

* Fri Sep 13 2013 Brendon Jones <brendonj@waikato.ac.nz> 0.1.7-2
- Create keys directory during postinst

* Mon Sep  9 2013 Brendon Jones <brendonj@waikato.ac.nz> 0.1.7-1
- New upstream release
- Fixes to traceroute test (packet sizes, late response packets)
- Schedule file can limit address family for name resolution

* Tue Aug 27 2013 Brendon Jones <brendonj@waikato.ac.nz> 0.1.6-1
- Split into two packages: main and lite

* Fri Aug 23 2013 Brendon Jones <brendonj@waikato.ac.nz> 0.1.5-1
- Initial RPM packaging

