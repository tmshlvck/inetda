#!/usr/bin/env python

from setuptools import setup

setup(name='inetda',
    version='1.0',
    description='Internet Data Analysis tools',
    install_requires = [
        'fasteners', 
        ],
    packages = ['RIPEValidatoConnector', 'ipfind'],
    scripts = [
        'ipgrep.py',
        ],
   )

