.. # Links
.. _CPython: http://www.python.org/
.. _PyPi: http://pypi.org/
.. _Requests: http://docs.python-requests.org/en/master/
.. _IronPython: http://http://ironpython.net/
.. _repository: https://github.com/rastern/vmt-connect
.. _releases: https://github.com/rastern/vmt-connect/releases
.. _Apache 2.0: https://github.com/rastern/vmt-connect/blob/master/LICENSE
.. _Turbonomic: http://www.turbonomic.com

===============
Getting Started
===============

About
=====

*vmt-connect* is a connection wrapper for working with the `Turbonomic`_ API. It
provides interfaces for connecting to and interacting with Turbonomic.


Installation
============

Prior version of *vmt-connect* were distributed as a stand-alone single file
Python module, which could be placed in the same folder as the calling script.
As of v2.2.3, *vmt-connect* is now distributed as a Python wheel package to be
installed via pip. The package is not available on `PyPi`_ at this time.

.. code:: bash

   pip3 install vmtconnect-3.0.6-py3-none-any.whl

Requirements
============

In order to use vmt-connect you will need to be running a supported version of
Python, and install the Requests_ module.

* Python:

  - CPython_ >= 3.5

* Requests_ >= 2.10.0


Importing
=========

In the most basic case, you need to import the package.

.. code:: python

   import vmtconnect

However, you may find it more useful to alias the import

.. code:: python

   import vmtconnect as vc


GitHub Source
=============

The source code for vmt-connect is provided via a read-only GitHub repository_.

Individual release archives may be found `here`__.

__ releases_

Contributors
============

Author:
  * R.A. Stern

Bug Fixes:
  * Austin Portal

Additional QA:
  * Chris Sawtelle
  * Ray Mileo
  * Ryan Geyer


License
=======

*vmt-connect* is distributed under the `Apache 2.0`_ software license, which may
also be obtained from the Apache Software Foundation, http://www.apache.org/licenses/LICENSE-2.0
