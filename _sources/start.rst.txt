.. # Links
.. _CPython: http://www.python.org/
.. _PyPi: http://pypi.org/
.. _Requests: http://docs.python-requests.org/en/master/
.. _IronPython: http://http://ironpython.net/
.. _GitHub: https://github.com/turbonomic/vmt-connect
.. _releases: https://github.com/turbonomic/vmt-connect/releases
.. _Apache 2.0: https://github.com/turbonomic/vmt-connect/blob/master/LICENSE
.. _Turbonomic: https://www.turbonomic.com

===============
Getting Started
===============

About
=====

*vmt-connect* is a connection wrapper for working with the `Turbonomic`_ API. It
provides not only connection handling, but also many convenience methods for
handling common tasks within Turbonomic.


Installation
============

.. code:: bash

   pip install vmtconnect

Requirements
============

In order to use vmt-connect you will need to be running a supported version of
Python, and install the Requests_ module.

* Python:

  - CPython_ >= 3.6

* Requests_ >= 2.21.0

* Turbonomic_

  - Classic >= 5.9
  - XL >= 7.21

Importing
=========

In the most basic case, you need to import the package.

.. code:: python

   import vmtconnect

However, you may find it more useful to alias the import

.. code:: python

   import vmtconnect as vc


Source Code
===========

*vmt-connect* is now an official Turbonomic_ Open Source project. The source code
continues to be hosted on GitHub_.

Individual release archives may be found `here`__.

__ releases_

Contributors
============

Creator and Principal Author:
  * R.A. Stern

Contributors:
  * Austin Portal
  * Chris Sawtelle
  * Ray Mileo
  * Ryan Geyer


License
=======

*vmt-connect* is distributed under the `Apache 2.0`_ software license, which may
also be obtained from the Apache Software Foundation, http://www.apache.org/licenses/LICENSE-2.0
