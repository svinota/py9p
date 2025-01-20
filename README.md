project EOL notice
==================

This project is no longer maintained. Plan9 9p2000 protocol implementation
is completely rewritten and provided in `pyroute2`, see the links:

 * project: https://github.com/svinota/pyroute2
 * module: https://github.com/svinota/pyroute2/tree/master/pyroute2/plan9
 * documentation and examples: https://docs.pyroute2.org/plan9.html


py9p
====

The code is based on Andrey Mirtchovski's py9p, but differs in some things:

 * the protocol implementation is faster up to 3 times
 * thread-safe
 * python3 support
 * has no sk1 support — temporarily; it will be added back soon
 * has working pki support for RSA ssh keys
 * FUSE client

Fuse client (fuse9p) has features not provided by other mount implementations
like 9pfuse from «Plan9 from User Space» or Linux kernel's v9fs. Firstly,
fuse9p supports authentication (right now only pki). Having comparable speed
with v9fs on big read/write requests, it is up to several hundreds times faster
in reading directories. And will be more faster in the future :)

 * Documentation: none yet, working on it
 * Installation: make install
 * Requirements: Python >= 2.6

You can also use the library without installation, but in this case you
should set up PYTHONPATH manually and run `make force-version` to update
all \*.in files.

