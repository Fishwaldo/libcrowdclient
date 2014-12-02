%if %{defined mdkversion}
%define __libtoolize    /bin/true
%endif


Name: libcrowdclient
Group: Productivity/Networking/Other
Summary: Crowd Client for C++ Applications
URL: http://stash.my-ho.st/stash/projects/DYNCS/repos/libcrowdclient/browse
License: LGPL2+
Version: 1.1
Release: 1
BuildRequires: gcc-c++ make gsoap gsoap-devel pkg-config automake autoconf libtool boost-devel
Source0: libcrowdclient-%{version}.tar.gz

BuildRoot: %{_tmppath}/%{name}-root

%description
a pure C++ library that interfaces with Atlassian Crowd for Authentication 
and Authorization. You can use this library to interface your applications 
with the Crowd Identity Management server at 
http://www.atlassian.com/software/crowd/overview

%package -n %{name}-devel
Summary: Crowd Client for C++ Applications
Group: Development/Libraries/C and C++
Requires: %{name} = %{version}-%{release}
#BuildRequires: %{name}

%description -n %{name}-devel
a pure C++ library that interfaces with Atlassian Crowd for Authentication 
and Authorization. You can use this library to interface your applications 
with the Crowd Identity Management server at 
http://www.atlassian.com/software/crowd/overview


%prep

%setup -q

%build
./bootstrap.sh
%configure --disable-static
make %{?_smp_mflags}

%install
make install DESTDIR=${RPM_BUILD_ROOT} 


%files
%defattr(-,root,root,-)
%{_prefix}/bin/crowdclient
%{_libdir}/libcrowdclient.so.*
%doc README.md

%files -n %{name}-devel
%defattr(-,root,root,-)
%{_includedir}/*
%{_libdir}/libcrowdclient.so
%{_libdir}/libcrowdclient.la


%post
/sbin/ldconfig

%postun
/sbin/ldconfig

%changelog
