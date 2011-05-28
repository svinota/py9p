#!/usr/bin/env python

from distutils.core import setup

setup(name='py9p',
    version='0.0.1',
    description='9P Protocol Implementation',
    author='Andrey Mirtchovski',
    author_email='aamirtch@ucalgary.ca',
    url='http://grid.ucalgary.ca',
    packages=[
        'py9p'
        ],
    scripts=[
        'examples/cl.py',
        'examples/localsrv.py',
        'examples/simplesrv.py',
    ],
      
)
