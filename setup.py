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
            "alabaster==0.7.12",
            "attrs==19.3.0",
            "babel==2.7.0",
            "certifi==2019.11.28",
            "chardet==3.0.4",
            "coverage==4.5.4",
            "coverage-badge==1.0.1",
            "detect-secrets==0.13.0",
            "docopt==0.6.2",
            "docutils==0.15.2",
            "idna==2.8",
            "imagesize==1.1.0",
            "importlib-metadata==1.1.0; python_version < '3.8'",
            "jinja2==2.10.3",
            "lark-parser==0.7.8",
            "markupsafe==1.1.1",
            "more-itertools==8.0.0",
            "packaging==19.2",
            "pluggy==0.13.1",
            "py==1.8.0",
            "pygments==2.5.2",
            "pyparsing==2.4.5",
            "pytest==5.3.1",
            "python-hcl2==0.2.0",
            "pytz==2019.3",
            "pyyaml==5.1.2",
            "requests==2.22.0",
            "six==1.13.0",
            "snowballstemmer==2.0.0",
            "sphinx==2.2.1",
            "sphinxcontrib-applehelp==1.0.1",
            "sphinxcontrib-devhelp==1.0.1",
            "sphinxcontrib-htmlhelp==1.0.2",
            "sphinxcontrib-jsmath==1.0.1",
            "sphinxcontrib-qthelp==1.0.2",
            "sphinxcontrib-serializinghtml==1.1.3",
            "urllib3==1.25.7",
            "wcwidth==0.1.7",
            "zipp==0.6.0",
        ]
    },
    install_requires=[
        "attrs==19.3.0",
        "aws-sam-translator==1.22.0",
        "aws-xray-sdk==2.4.3",
        "boto==2.49.0",
        "boto3==1.12.26",
        "botocore==1.15.26",
        "certifi==2019.11.28",
        "cffi==1.14.0",
        "cfn-lint==0.29.0",
        "chardet==3.0.4",
        "cryptography==2.8",
        "decorator==4.4.2",
        "docker==4.2.0",
        "docutils==0.15.2",
        "ecdsa==0.15",
        "future==0.18.2",
        "idna==2.8",
        "importlib-metadata==1.5.0",
        "Jinja2==2.11.1",
        "jmespath==0.9.5",
        "jsondiff==1.1.2",
        "jsonpatch==1.25",
        "jsonpickle==1.3",
        "jsonpointer==2.0",
        "jsonschema==3.2.0",
        "MarkupSafe==1.1.1",
        "mock==4.0.2",
        "moto==1.3.14",
        "networkx==2.4",
        "numpy==1.18.2",
        "pandas==1.0.3",
        "pyasn1==0.4.8",
        "pycparser==2.20",
        "pyrsistent==0.15.7",
        "python-dateutil==2.8.1",
        "python-jose==3.1.0",
        "python-terraform==0.10.1",
        "pytz==2019.3",
        "PyYAML==5.3.1",
        "requests==2.23.0",
        "responses==0.10.12",
        "rsa==4.0",
        "s3transfer==0.3.3",
        "six==1.14.0",
        "sshpubkeys==3.1.0",
        "termcolor==1.1.0",
        "urllib3==1.25.8",
        "websocket-client==0.57.0",
        "Werkzeug==1.0.0",
        "wrapt==1.12.1",
        "xmltodict==0.12.0",
        "zipp==3.1.0",
        "colorama==0.4.3"
    ],
    license="Apache License 2.0",
    name="airiam",
    version=version,
    description="Least privilege AWS IAM Terraformer",
    author="bridgecrew",
    author_email="meet@bridgecrew.io",
    url="https://github.com/bridgecrewio/AirIAM",
    packages=setuptools.find_packages(exclude=["tests*"]),
    scripts=["bin/airiam"],
    long_description=long_description,
    long_description_content_type="text/markdown",
    classifiers=[
        'Environment :: Console',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Topic :: Security',
        'Topic :: Software Development :: Build Tools'
    ]
)
