#!/usr/bin/env bash

bumpversion --allow-dirty build
python setup.py bdist_wheel
