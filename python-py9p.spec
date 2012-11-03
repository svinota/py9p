Name: python-module-py9p
Version: 1.0.5
Release: alt3
Summary: Pure Python implementation of 9P protocol (Plan9)
License: MIT
Group: Development/Python
URL: https://github.com/svinota/py9p

BuildArch: noarch
BuildPreReq: python-devel rpm-build-python
Source: py9p-%version.tar.gz

%description
Protocol 9P is developed for Plan9 operating system from Bell Labs.
It is used for remote file access, and since files are key objects
in Plan9, 9P can be used also for composite file access, RPC etc.

This library provides low-level 9p2000.u API. For high-level look
into python-module-pyvfs.

%package -n fuse9p
Summary: Plan9 filesystem client for FUSE
License: MIT
Group: Development/Python
URL: https://github.com/svinota/py9p

%description -n fuse9p
Protocol 9P is developed for Plan9 operating system from Bell Labs.
It is used for remote file access, and since files are key objects
in Plan9, 9P can be used also for composite file access, RPC etc.

This package contains FUSE client for the 9p protocol.

%prep
%setup -q -n py9p-%{version}

%install
%{__python} setup.py install --root=%buildroot --install-lib=%{python_sitelibdir}

%files
%doc README* LICENSE
%{python_sitelibdir}/py9p*

%files -n fuse9p
%_bindir/fuse9p
%_man1dir/fuse9p.*

%changelog
* Sat Nov 03 2012 Peter V. Saveliev <peet@altlinux.org> 1.0.5-alt3
- pki authentication fixed

* Sat Nov 03 2012 Peter V. Saveliev <peet@altlinux.org> 1.0.5-alt2
- FUSE client defaults to background mode

* Thu Nov 01 2012 Peter V. Saveliev <peet@altlinux.org> 1.0.5-alt1
- FUSE client added

* Fri Oct 26 2012 Peter V. Saveliev <peet@altlinux.org> 1.0.4-alt1
- support for arbitrary keys for PKI
- support sticky bit (Unix, 9P2000.u)

* Tue Oct 16 2012 Peter V. Saveliev <peet@altlinux.org> 1.0.2-alt1
- support AES-encrypted keys
- fixed authfs
 
* Fri Oct 12 2012 Peter V. Saveliev <peet@altlinux.org> 1.0.1-alt1
- Rebuild from new repo layout

* Thu Oct 20 2011 Vitaly Kuznetsov <vitty@altlinux.ru> 1.0-alt2.1
- Rebuild with Python-2.7

* Wed Aug 24 2011 Peter V. Saveliev <peet@altlinux.org> 1.0-alt2
- file access mode for AF_UNIX socket

* Thu Aug 18 2011 Peter V. Saveliev <peet@altlinux.org> 1.0-alt1
- standalone git repo, version bump

* Thu Jul  7 2011 Peter V. Saveliev <peet@altlinux.org> 0.7.1-alt4
- iproute2 can add and delete addresses on interfaces
- more attributes parsed by rtnl
- wireless interfaces detection (ioctl) in rtnl
- get/set attributes in attr_msg class
- new utility function (make_map) that creates two-way mappings of set of attributes

* Wed Jun 17 2011 Peter V. Saveliev <peet@altlinux.org> 0.7.1-alt3
- cxkey utility added
- named parameters for py9p.Dir
- zeroconf.py fixed and tested

* Sun May 29 2011 Peter V. Saveliev <peet@altlinux.org> 0.7.1-alt2
- Sisyphus build fixed.

* Sun May 29 2011 Peter V. Saveliev <peet@altlinux.org> 0.7.1-alt1
- RPM prepared.

* Wed Nov 25 2009 Eugeny A. Rostovtsev (REAL) <real at altlinux.org> 0.4.6-alt7.svn1392.1
- Rebuilt with python 2.6
