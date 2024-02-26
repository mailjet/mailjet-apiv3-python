#!/usr/bin/env python
# coding=utf-8

import os
from setuptools import find_packages, setup

HERE = os.path.abspath(os.path.dirname(__file__))
PACKAGE_NAME = 'mailjet_rest'

with open("README.md", "r") as fh:
    long_description = fh.read()

# Dynamically calculate the version based on mailjet_rest.VERSION.
version = "latest"

setup(
    name=PACKAGE_NAME,
    author='starenka',
    author_email='starenka0@gmail.com',
    maintainer='Mailjet',
    maintainer_email='api@mailjet.com',
    version="latest",
    download_url='https://github.com/mailjet/mailjet-apiv3-python/releases/' + version,
    url='https://github.com/mailjet/mailjet-apiv3-python',
    description=('Mailjet V3 API wrapper'),
    long_description=long_description,
    long_description_content_type="text/markdown",
    classifiers=['Development Status :: 4 - Beta',
                 'Environment :: Console',
                 'Intended Audience :: Developers',
                 'License :: The MIT License (MIT)',
                 'Natural Language :: English',
                 'Operating System :: OS Independent',
                 'Programming Language :: Python :: 2.7',
                 'Programming Language :: Python :: 3.5',
                 'Programming Language :: Python :: 3.6',
                 'Topic :: Utilities'],
    license='MIT',
    keywords='Mailjet API v3 / v3.1 Python Wrapper',

    include_package_data=True,
    install_requires=['requests>=2.4.3'],
    tests_require=['unittest'],
    entry_points={},
    packages=find_packages(),
)
