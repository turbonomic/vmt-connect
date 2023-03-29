#!/usr/bin/python3

import os

from setuptools import find_packages, setup

about = {}
here = os.path.abspath(os.path.dirname(__file__))
requires = ["ijson>=3.1.4,<4", "requests>=2.28.1,<3"]

extra_requires = {"jq": ["jq>=1.1.3,<2"]}


with open(os.path.join(here, "vmtconnect", "__about__.py"), "r") as fp:
    exec(fp.read(), about)

with open(os.path.join(here, "README.md"), "r") as fp:
    readme = fp.read()


setup(
    name=about["__title__"],
    version=about["__version__"],
    description=about["__description__"],
    long_description=readme,
    long_description_content_type="text/markdown",
    author=about["__author__"],
    author_email=about["__author_email__"],
    url="https://github.com/turbonomic/vmt-connect",
    packages=find_packages(),
    classifiers=[
        "Intended Audience :: Developers",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Topic :: Software Development",
    ],
    package_data={"": ["LICENSE", "NOTICE"]},
    include_package_data=True,
    python_requires=">=3.8",
    install_requires=requires,
    extra_require=extra_requires,
    license=about["__license__"],
)
