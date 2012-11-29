#!/usr/bin/env python

from distutils.core import setup

man1dir="/usr/share/man/man1"

setup(name='py9p',
    version='1.0.6',
    description='9P Protocol Implementation',
    author='Andrey Mirtchovski',
    author_email='aamirtch@ucalgary.ca',
    maintainer='Peter V. Saveliev',
    maintainer_email='peet@redhat.com',
    url='https://github.com/svinota/py9p',
    license="MIT",
    packages=[
        'py9p'
        ],
    scripts=[
        'fuse9p/fuse9p',
        ],
    data_files=[
        (man1dir, ['fuse9p/fuse9p.1',]),
        ],
    classifiers=[
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Operating System :: POSIX',
        'Intended Audience :: Developers',
        'Development Status :: 4 - Beta',
        ],
    long_description='''
9P protocol implementation
==========================

The library allows you to use 9P protocol in your
applications.

Please note, that the library is not fully compatible
with the initial version by Andrey Mirtchovski.

Links
=====

 * home: https://github.com/svinota/py9p
 * bugs: https://github.com/svinota/py9p/issues
 * pypi: http://pypi.python.org/pypi/py9p/

Changes
=======

1.0.6 -- Paleoarchean
---------------------

 * Tcreate client call fixed
 * fuse9p client, supporting stateful I/O,
   "reconnect after network errors" and so on.

1.0.4 -- Eoarchaean
-------------------

 * support arbitrary key files for PKI

1.0.3
-----

 * initial pypi release
'''
)
