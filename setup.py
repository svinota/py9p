#!/usr/bin/env python

from distutils.core import setup

# bump version
setup(name='py9p',
    version='0.7.1',
    description='9P Protocol Implementation',
    author='Andrey Mirtchovski',
    author_email='aamirtch@ucalgary.ca',
    url='http://grid.ucalgary.ca',
    license="MIT",
    packages=[
        'py9p'
        ]
)
