Name: amplet2
Version: 0.1.7
Release: 2%{?dist}
Summary: AMP Network Performance Measurement Suite - Client Tools

Group: Applications/Internet
License: AMP
URL: http://research.wand.net.nz/software/amp.php
Source0: http://research.wand.net.nz/software/amp/amplet2-0.1.7.tar.gz	
Patch0: amplet2-client-init.patch
BuildRoot:	%(mktemp -ud %{_tmppath}/%{name}-%{version}-%{release}-XXXXXX)

BuildRequires: openssl-devel libconfuse-devel libwandevent-devel
Requires: rabbitmq-server >= 3.1.5 librabbitmq-amp >= 0.4.0 libwandevent

%description
This package contains the client tools for the AMP Measurement Suite.
These measure the network performance to specified targets according
to a configured schedule. The resulting data is transferred back to
one or more rabbitmq brokers via the AMQP protocol.


%package lite
Summary: AMP client tools without a local rabbitmq broker
Group: Applications/Internet
Requires: librabbitmq-amp >= 0.4.0 libwandevent

%description lite
AMP client tools without a local rabbitmq broker



%prep
%setup -q
%patch0 -p1


%build
%configure --disable-http CFLAGS="-I/home/vagrant/librabbitmq-amp-0.4.0/librabbitmq/ \
			     -I/home/vagrant/libwandevent/trunk/" \
		     LDFLAGS="-L/home/vagrant/libwandevent/trunk/.libs/ \
			      -L/home/vagrant/librabbitmq-amp-0.4.0/librabbitmq/.libs"

make %{?_smp_mflags} 
%install
rm -rf %{buildroot}
make install DESTDIR=%{buildroot}
install -D amplet2-client.init %{buildroot}%{_initrddir}/%{name}-client
# XXX this is hax, should measured be in sbin or bin?
mkdir %{buildroot}%{_sbindir}/
mv %{buildroot}%{_bindir}/measured %{buildroot}%{_sbindir}/
rm -rf %{buildroot}/usr/lib/python2.6/
rm -rf %{buildroot}%{_libdir}/*a
rm -rf %{buildroot}%{_libdir}/%{name}/tests/*a

%clean
rm -rf %{buildroot}


%files
%defattr(-,root,root,-)
%doc
%{_bindir}/*
%{_sbindir}/measured
%attr(4755, root, root) %{_sbindir}/measured
%{_libdir}/*so
%{_libdir}/amplet2/tests/*so
%{_sysconfdir}/%{name}/*
%{_datadir}/%{name}/rsyslog/measured.conf
%{_initrddir}/*

%files lite
%defattr(-,root,root,-)
%doc
%{_bindir}/*
%{_sbindir}/measured
%attr(4755, root, root) %{_sbindir}/measured
%{_libdir}/*so
%{_libdir}/amplet2/tests/*so
%{_sysconfdir}/%{name}/*
%{_datadir}/%{name}/rsyslog/measured.conf
%{_initrddir}/*


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
# Install the appropriate config as the main measured.conf
if [ ! -f "/etc/amplet2/measured.conf" ]; then
	ln -s /etc/amplet2/measured-local.conf /etc/amplet2/measured.conf
else
	echo "/etc/amplet2/measured.conf already exists, skipping"
fi

# update rsyslog
if [ ! -f "/etc/rsyslog.d/measured.conf" ]; then
	cp /usr/share/amplet2/rsyslog/measured.conf /etc/rsyslog.d/90-measured.conf
	if [ -x "`which invoke-rc.d 2>/dev/null`" ]; then
		invoke-rc.d rsyslog restart || exit $?
	else
                /etc/init.d/rsyslog restart || exit $?
	fi
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

# TODO for now we assume that rabbitmq-server is only present
# because of us, so we can use the main instance and default config
# file location
# update rabbit-server config
if [ ! -f "/etc/rabbitmq/rabbitmq.config" ]; then
	ln -s /etc/amplet2/shovel.config /etc/rabbitmq/rabbitmq.config
	if [ -x "`which invoke-rc.d 2>/dev/null`" ]; then
		invoke-rc.d rabbitmq-server restart || exit $?
	else
		/etc/init.d/rabbitmq-server restart || exit $?
	fi
else
	echo "/etc/rabbitmq/rabbitmq.config already exists."
	echo "Please merge with /etc/amplet2/shovel.config and restart rabbitmq"
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
# Install the appropriate config as the main measured.conf
if [ ! -f "/etc/amplet2/measured.conf" ]; then
	ln -s /etc/amplet2/measured-lite.conf /etc/amplet2/measured.conf
else
	echo "/etc/amplet2/measured.conf already exists, skipping"
fi

# update rsyslog
if [ ! -f "/etc/rsyslog.d/measured.conf" ]; then
	cp /usr/share/amplet2/rsyslog/measured.conf /etc/rsyslog.d/90-measured.conf
	if [ -x "`which invoke-rc.d 2>/dev/null`" ]; then
		invoke-rc.d rsyslog restart || exit $?
	else
                /etc/init.d/rsyslog restart || exit $?
	fi
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

