#!/usr/bin/env python
import logging
import os
from importlib import util
from os import path

import setuptools
from setuptools import setup

# read the contents of your README file
this_directory = path.abspath(path.dirname(__file__))
with open(path.join(this_directory, "README.md"), encoding="utf-8") as f:
    long_description = f.read()

logger = logging.getLogger(__name__)
spec = util.spec_from_file_location(
    "airiam.version", os.path.join("airiam", "version.py")
)
# noinspection PyUnresolvedReferences
mod = util.module_from_spec(spec)
spec.loader.exec_module(mod)  # type: ignore
version = mod.version  # type: ignore

setup(
    extras_require={
        "dev": [
            "Cerberus==1.3.2",
            "coverage==5.0.4",
            "coverage-badge==1.0.1",
            "moto==1.3.14",
            "pipenv-setup==3.0.1",
            "pytest==5.4.1"
        ]
    },
    install_requires=[
        "boto3>=1.12.43",
        "colorama==0.4.3",
        "python-terraform==0.10.1",
        "requests>=2.22.0",
        "termcolor==1.1.0"
    ],
    license="Apache License 2.0",
    name="airiam",
    version=version,
    description="Least privilege AWS IAM Terraformer",
    author="bridgecrew",
    author_email="meet@bridgecrew.io",
    url="https://github.com/bridgecrewio/AirIAM",
    packages=setuptools.find_packages(exclude=["tests*"]),
    scripts=["bin/airiam","bin/airiam.cmd"],
    long_description=long_description,
    long_description_content_type="text/markdown",
    classifiers=[
        'Environment :: Console',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'Programming Language :: Python :: 3.7',
        'Topic :: Security',
        'Topic :: Software Development :: Build Tools'
    ]
)
