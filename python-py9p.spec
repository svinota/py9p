Name: python-py9p
Version: 1.0.5
Release: 2%{?dist}
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

%package -n fuse9p
Summary: Plan9 filesystem client for FUSE
License: MIT
Group: Applications/File
URL: https://github.com/svinota/py9p
Requires: %name = %version-%release

%description -n fuse9p
Protocol 9P is developed for Plan9 operating system from Bell Labs.
It is used for remote file access, and since files are key objects
in Plan9, 9P can be used also for composite file access, RPC etc.

This package contains FUSE client for the 9p protocol. It is in the
beta development state.


%prep
%setup -q -n py9p-%{version}

%build
# nothing to build

%install
%{__python} setup.py install --root $RPM_BUILD_ROOT

%files
%doc README* LICENSE
%{python_sitelib}/py9p*

%files -n fuse9p
%_bindir/fuse9p
%_mandir/man1/fuse9p.*


%changelog
* Thu Nov 29 2012 Peter V. Saveliev <peet@redhat.com> 1.0.5-2
- fuse9p stateful I/O
- 9p marshalling is thread-safe now

* Wed Nov 07 2012 Peter V. Saveliev <peet@redhat.com> 1.0.5-1
- fuse9p subpackage added (beta)
- pki authentication fixed

* Fri Oct 19 2012 Peter V. Saveliev <peet@redhat.com> 1.0.2-1
- support AES-encrypted keys
- authfs fixed

* Fri Oct 12 2012 Peter V. Saveliev <peet@redhat.com> 1.0.1-1
- Initial RH build
