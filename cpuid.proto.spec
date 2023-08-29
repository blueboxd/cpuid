Summary: dumps CPUID information about the CPU(s)
Name: cpuid
Version: %{version}
Release: %{release}
License: GPL
Group: System Environment/Base
Source: cpuid-%{version}.src.tar.gz
Packager: Todd Allen <cpuid@etallen.com>
URL: http://www.etallen.com/cpuid.html
BuildRoot: %{getenv:HOME}/rpmbuild/BUILDROOT/%{name}-%{version}-%{release}.%{_arch}
%description
cpuid dumps detailed information about the CPU(s) gathered from the CPUID 
instruction, and also determines the exact model of CPU(s).

%prep
%setup

%build
%{__make} %{?_smp_mflags} CFLAGS="$RPM_OPT_FLAGS"

%install
%{__make} install BUILDROOT=${RPM_BUILD_ROOT} INSTALL_STRIP=

%clean
%{__rm} -rf $RPM_BUILD_DIR/$RPM_PACKAGE_NAME-$RPM_PACKAGE_VERSION

%files
%defattr(-,root,root)
%{_bindir}/cpuid
%{_mandir}/man1/cpuid.1.gz
%{_bindir}/cpuinfo2cpuid
%{_mandir}/man1/cpuinfo2cpuid.1.gz
%doc ChangeLog FUTURE FAMILY.NOTES
%license LICENSE
