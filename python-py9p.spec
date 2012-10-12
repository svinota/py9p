Name: python-py9p
Version: 1.0.1
Release: 1%{?dist}
Summary: Pure Python implementation of 9P protocol (Plan9)
License: MIT
Group: Development/Languages
URL: https://github.com/svinota/py9p

BuildArch: noarch
BuildRequires: python2-devel
Source: http://peet.spb.ru/archives/py9p-%version.tar.gz

%description
Protocol 9P is developed for Plan9 operating system from Bell Labs.
It is used for remote file access, and since files are key objects
in Plan9, 9P can be used also for composite file access, RPC etc.

This library provides low-level 9p2000.u API. For high-level look
into python-pyvfs.

%prep
%setup -q -n py9p-%{version}

%build
# nothing to build

%install
%{__python} setup.py install --root $RPM_BUILD_ROOT

%files
%doc README* LICENSE
%{python_sitelib}/py9p*

%changelog
* Fri Oct 12 2012 Peter V. Saveliev <peet@redhat.com> 1.0.1-1
- Initial RH build
