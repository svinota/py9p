#!/usr/bin/env python

# Copyright (c) 2011-2012 Peter V. Saveliev
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

from distutils.core import setup

man1dir="/usr/share/man/man1"

setup(name='py9p',
    version='1.0.7',
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
        '9pfs/9pfs',
        ],
    data_files=[
        (man1dir, ['fuse9p/fuse9p.1',]),
        (man1dir, ['9pfs/9pfs.1',]),
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
applications. Please note, that the library is not
fully compatible with the original version by
Andrey Mirtchovski.

Also, this package provides two components:

 * fuse9p -- FUSE 9p client
 * 9pfs -- simple file server (alpha state)

Links
=====

 * home: https://github.com/svinota/py9p
 * bugs: https://github.com/svinota/py9p/issues
 * pypi: http://pypi.python.org/pypi/py9p/

Changes
=======

1.0.7 -- Mesoarchean
--------------------

 * PKI auth fixed
 * fuse9p: "persistent connection" feature, -P
 * fuse9p: symlink support
 * fuse9p: multiple fixes of the background mode
 * 9pfs: new component, that grow up from localfs
 * py9p: provide mode conversion routines

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
