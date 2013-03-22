#!/usr/bin/python

from setuptools import setup

setup(
    name='YubiAuth',
    version='0.1',
    packages=['yubiauth'],
    install_requires=['sqlalchemy', 'webobj', 'passlib', 'pyhsm'],
    test_suite="nose.collector",
    tests_require=['Nose'],
)
