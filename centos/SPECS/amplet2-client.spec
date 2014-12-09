Name: amplet2
Version: 0.3.8
Release: 2%{?dist}
Summary: AMP Network Performance Measurement Suite - Client Tools

Group: Applications/Internet
License: AMP
URL: http://research.wand.net.nz/software/amp.php
Source0: http://research.wand.net.nz/software/amp/amplet2-0.3.8.tar.gz
Patch0: amplet2-client-init.patch
Patch1: amplet2-client-default.patch
Patch2: amplet2-client-makefile.patch
BuildRoot:	%(mktemp -ud %{_tmppath}/%{name}-%{version}-%{release}-XXXXXX)

BuildRequires: openssl-devel libconfuse-devel libwandevent-devel >= 3.0.1 libcurl-devel unbound-devel libpcap-devel
Requires: rabbitmq-server >= 3.1.5 librabbitmq-amp >= 0.4.0 libwandevent >= 3.0.1 libcurl unbound-libs libpcap rsyslog

%description
This package contains the client tools for the AMP Measurement Suite.
These measure the network performance to specified targets according
to a configured schedule. The resulting data is transferred back to
one or more rabbitmq brokers via the AMQP protocol.


%package lite
Summary: AMP client tools without a local rabbitmq broker
Group: Applications/Internet
Requires: librabbitmq-amp >= 0.4.0 libwandevent >= 3.0.1 libcurl unbound-libs libpcap rsyslog

%description lite
AMP client tools without a local rabbitmq broker



%prep
%setup -q
%patch0 -p1
%patch1 -p1
%patch2 -p1


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
install -D src/measured/rsyslog/amplet2.conf %{buildroot}%{_sysconfdir}/rsyslog.d/amplet2.conf
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
%{_sysconfdir}/rsyslog.d/amplet2.conf
%config %{_initrddir}/*
%config %{_sysconfdir}/default/*
%dir %{_localstatedir}/run/%{name}/

%files lite
%defattr(-,root,root,-)
%doc
%{_bindir}/*
%attr(4755, root, root) %{_sbindir}/amplet2
%{_libdir}/*so
%{_libdir}/amplet2/tests/*so
%{_sysconfdir}/%{name}/*
%{_sysconfdir}/rsyslog.d/amplet2.conf
%config %{_initrddir}/*
%config %{_sysconfdir}/default/*
%dir %{_localstatedir}/run/%{name}/


%pre
GROUPNAME=measure
USERNAME=measure
getent group $GROUPNAME >/dev/null || groupadd -r $GROUPNAME
getent passwd $USERNAME >/dev/null || \
    useradd -r -g $GROUPNAME -s /sbin/nologin \
    -c "AMP measurement daemon user" $USERNAME
exit 0

%pre lite
GROUPNAME=measure
USERNAME=measure
getent group $GROUPNAME >/dev/null || groupadd -r $GROUPNAME
getent passwd $USERNAME >/dev/null || \
    useradd -r -g $GROUPNAME -s /sbin/nologin \
    -c "AMP measurement daemon user" $USERNAME
exit 0


%post
if [ -x "`which invoke-rc.d 2>/dev/null`" ]; then
	invoke-rc.d rsyslog restart || exit $?
else
	/etc/init.d/rsyslog restart || exit $?
fi

# Create directory for SSL keys
if [ ! -d "/etc/amplet2/keys/" ]; then
	mkdir /etc/amplet2/keys/
	chown measure: /etc/amplet2/keys
	chmod 700 /etc/amplet2/keys
	# TODO fetch the keys somehow and save them here
fi

# Enable the shovel plugin for rabbitmq
if [ -x "`which rabbitmq-plugins 2>/dev/null`" ]; then
	rabbitmq-plugins enable rabbitmq_shovel || exit $?
else
	echo "Can't enable shovel plugin, aborting"
	exit 1
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

%post lite
if [ -x "`which invoke-rc.d 2>/dev/null`" ]; then
	invoke-rc.d rsyslog restart || exit $?
else
	/etc/init.d/rsyslog restart || exit $?
fi

# Create directory for SSL keys
if [ ! -d "/etc/amplet2/keys/" ]; then
	mkdir /etc/amplet2/keys/
	chown measure: /etc/amplet2/keys
	chmod 700 /etc/amplet2/keys
	# TODO fetch the keys somehow and save them here
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

%preun lite
if [ $1 -eq 0 ]; then
	/etc/init.d/amplet2-client stop > /dev/null 2>&1
	if [ -x /sbin/chkconfig ]; then
		/sbin/chkconfig --del amplet2-client
	else
		rm -f /etc/rc.d/rc?.d/???amplet2-client
	fi
fi


%changelog
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

