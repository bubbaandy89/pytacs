#!/usr/bin/env python

import os

from setuptools import find_packages, setup


# Utility function to read the README file.
# Used for the long_description.  It's nice, because now 1) we have a top level
# README file and 2) it's easier to type in the README file than to put a raw
# string in below ...
def read(fname) -> str:
    return open(os.path.join(os.path.dirname(__file__), fname)).read()


setup(
    name="pytacs_plus",
    version="0.0.1",
    description=("A Python socketserver based tacacs+ server"),
    keywords="Python TACACS+",
    url="https://github.com/bubbaandy89/pytacs",
    long_description=read("README.md"),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Topic :: Utilities",
        "License :: OSI Approved :: GPL v1.2",
    ],
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    package_data={
        "pytacs": ["py.typed"],
    },
    install_requires=[],
)
