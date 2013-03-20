#!/usr/bin/python

from setuptools import setup

setup(
    name = 'YubiAuth',
    version = '0.1',
    packages = ['yubiauth'],
    test_suite = "nose.collector",
    tests_require = ['Nose'],
)
