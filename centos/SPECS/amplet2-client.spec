Name: amplet2
Version: 0.8.4
Release: 1%{?dist}
Summary: AMP Network Performance Measurement Suite - Client Tools

Group: Applications/Internet
License: AMP
URL: http://research.wand.net.nz/software/amp.php
Source0: https://github.com/wanduow/amplet2/archive/v0.8.4.tar.gz
Patch0: amplet2-client-init.patch
Patch1: amplet2-client-default.patch
BuildRoot:	%(mktemp -ud %{_tmppath}/%{name}-%{version}-%{release}-XXXXXX)

BuildRequires: openssl-devel libconfuse-devel libwandevent-devel >= 3.0.1 libcurl-devel unbound-devel libpcap-devel protobuf-c-devel librabbitmq4-devel >= 0.7.1
Requires: librabbitmq4 >= 0.7.1 libwandevent >= 3.0.1 libcurl unbound-libs libpcap rsyslog protobuf-c

%description
This package contains the client tools for the AMP Measurement Suite.
These measure the network performance to specified targets according
to a configured schedule. The resulting data is transferred back to
one or more rabbitmq brokers via the AMQP protocol.


%prep
%setup -q
%patch0 -p1
%patch1 -p1


%build
%configure
sed -i 's|^hardcode_libdir_flag_spec=.*|hardcode_libdir_flag_spec=""|g' libtool
sed -i 's|^runpath_var=LD_RUN_PATH|runpath_var=DIE_RPATH_DIE|g' libtool

make %{?_smp_mflags} 
%install
rm -rf %{buildroot}
make install DESTDIR=%{buildroot}
install -D amplet2-client.init %{buildroot}%{_initrddir}/%{name}-client
install -D amplet2-client.default %{buildroot}%{_sysconfdir}/default/%{name}-client
install -D src/measured/rsyslog/10-amplet2.conf %{buildroot}%{_sysconfdir}/rsyslog.d/10-amplet2.conf
# XXX this is hax, should amplet2 be in sbin or bin?
mkdir %{buildroot}%{_sbindir}/
mv %{buildroot}%{_bindir}/amplet2 %{buildroot}%{_sbindir}/
rm -rf %{buildroot}/usr/lib/python2.6/
rm -rf %{buildroot}%{_libdir}/*a
rm -rf %{buildroot}%{_libdir}/%{name}/tests/*a
rm -rf %{buildroot}/usr/share/amplet2/rsyslog/

%clean
rm -rf %{buildroot}


%files
%defattr(-,root,root,-)
%doc
%{_bindir}/*
%attr(4755, root, root) %{_sbindir}/amplet2
%{_libdir}/*so
%{_libdir}/amplet2/tests/*so
%{_sysconfdir}/%{name}/*
%{_sysconfdir}/rsyslog.d/10-amplet2.conf
%config %{_initrddir}/*
%config %{_sysconfdir}/default/*
%dir %{_localstatedir}/run/%{name}/
%doc %{_datarootdir}/%{name}/rabbitmq/*


%post
if [ -x "`which invoke-rc.d 2>/dev/null`" ]; then
	invoke-rc.d rsyslog restart || exit $?
else
	/etc/init.d/rsyslog restart || exit $?
fi

# update init scripts
if [ -x /sbin/chkconfig ]; then
	/sbin/chkconfig --add amplet2-client
else
	for i in 2 3 4 5; do
		ln -sf /etc/init.d/amplet2-client /etc/rc.d/rc${i}.d/S60amplet2-client
	done
	for i in 1 6; do
		ln -sf /etc/init.d/amplet2-client /etc/rc.d/rc${i}.d/K20amplet2-client
	done
fi


%preun
if [ $1 -eq 0 ]; then
	/etc/init.d/amplet2-client stop > /dev/null 2>&1
	if [ -x /sbin/chkconfig ]; then
		/sbin/chkconfig --del amplet2-client
	else
		rm -f /etc/rc.d/rc?.d/???amplet2-client
	fi
fi


%changelog
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

* Mon Sep 22 2016 Brendon Jones <brendonj@waikato.ac.nz> 0.7.0-1
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

