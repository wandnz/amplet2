Name: libwandevent
Version: 2.0.1
Release: 1%{?dist}
Summary: C API for writing event driven programs	

Group: Development/Libraries
License: GPL2
URL: http://research.wand.net.nz/software/libwandevent.php	
Source0: http://research.wand.net.nz/software/libwandevent/libwandevent-2.0.1.tar.gz
BuildRoot: %(mktemp -ud %{_tmppath}/%{name}-%{version}-%{release}-XXXXXX)


%description
Libwandevent is a software library written in C that provides an API for
developing event-driven programs. Libwandevent is intended for the development
of programs that may have a number of 'events' that can occur at any given
point in the program's execution which need to be handled as soon as possible
without blocking or waiting on other inactive events.
.
The idea behind the design of libwandevent is that the developer will register
events and provide libwandevent with a function that is to be called should
that event occur. All of the code for managing the events and determining
whether an event has occurred is contained within libwandevent, leaving the
developer free to concentrate on the events themselves rather than having to
check for the occurrence of the event.

%package devel
Group: Development/Libraries
Summary: Development files for libwandevent

%description devel
Development files for libwandevent

%prep
%setup -q


%build
%configure
make %{?_smp_mflags}


%install
rm -rf %{buildroot}
make install DESTDIR=%{buildroot}


%clean
rm -rf %{buildroot}


%files
%defattr(-,root,root,-)
%doc
%{_libdir}/*.so.*

%files devel
%defattr(-,root,root,-)
%doc
%{_includedir}/*.h
%{_libdir}/*.a
%{_libdir}/*.la
%{_libdir}/*.so

%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig

%changelog
* Fri Aug 23 2013 Brendon Jones <brendonj@waikato.ac.nz> 2.0.1-1
- Initial RPM packaging
