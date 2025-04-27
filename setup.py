#!/usr/bin/env python
# pycrtsh
# Copyright (c) 2017-2023 Etienne Tek Maynier
# This software is released under the MIT license
# See https://opensource.org/license/mit/
from setuptools import setup

with open("README.md", "r") as fh:
    long_description = fh.read()

setup(
    name="pycrtsh",
    version="0.3.13",
    description="Python library to request crt.sh certificate information",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Te-k/pycrtsh",
    author="Tek",
    author_email="tek@randhome.io",
    keywords="security",
    install_requires=[
        "requests",
        "lxml==5.3.0",
        "beautifulsoup4>=4.12.3",
        "python-dateutil",
        "psycopg2-binary>=2.9.10",
    ],
    license="MIT",
    packages=["pycrtsh"],
    entry_points={"console_scripts": ["certsh=pycrtsh.cli:main"]},
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
)
