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
    version="0.3.11",
    description="Python library to request crt.sh certificate information",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Te-k/pycrtsh",
    author="Tek",
    author_email="tek@randhome.io",
    keywords="security",
    install_requires=[
        "requests",
        "lxml==4.9.2",
        "beautifulsoup4>=4.11.1",
        "python-dateutil",
        "psycopg2>=2.9.6",
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
