Name: librabbitmq-amp
Version: 0.4.0
Release: 1%{?dist}
Summary: C library for AMQP with AMP patches	

Group: Development/Libraries
License: MIT
URL: https://github.com/alanxz/rabbitmq-c		
Source0: https://foo/librabbitmq-master-amp.tar.gz
Patch0: sasl-external.patch
BuildRoot:	%(mktemp -ud %{_tmppath}/%{name}-%{version}-%{release}-XXXXXX)

BuildRequires: cmake xmlto popt-devel

%description
C library for AMQP with AMP patches

%package devel
Summary: Development files for RabbitMQ-c
Group: Development/Libraries
Requires: %{name} = %{version}-%{release}

%description devel
Development files for RabbitMQ-C.


%prep
%setup -q
%patch0 -p1


%build
autoreconf -i
%configure --disable-tools --disable-docs --disable-static --disable-examples
make %{?_smp_mflags}


%install
rm -rf %{buildroot}
make install  DESTDIR="%{buildroot}"
rm %{buildroot}%{_libdir}/librabbitmq.la


%clean
rm -rf %{buildroot}

%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig

%files
%defattr(-,root,root,-)
%{_libdir}/*.so.*
%{_libdir}/pkgconfig/*

%files devel
%defattr(-,root,root,-)
%{_includedir}/*.h
%{_libdir}/*.so


%changelog
* Mon Aug 26 2013 Brendon Jones <brendonj@waikato.ac.nz> 0.4.0-1
- Initial RPM packaging
