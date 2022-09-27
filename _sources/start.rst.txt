.. # Links
.. _CPython: https://www.python.org/
.. _PyPi: http://pypi.org/
.. _Requests: https://requests.readthedocs.io/en/latest/
.. _IronPython: http://http://ironpython.net/
.. _GitHub: https://github.com/turbonomic/vmt-connect
.. _releases: https://github.com/turbonomic/vmt-connect/releases
.. _Apache 2.0: https://www.apache.org/licenses/LICENSE-2.0.txt
.. _Turbonomic: https://www.ibm.com/cloud/turbonomic

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

* Requests_ >= 2.25.1

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

*vmt-connect* is an official Turbonomic_ Open Source project. The source code
continues to be hosted on GitHub_.

Individual release archives may be found `here`__.

__ releases_

Contributors
============

Current Maintainers:
  * John Fabry
  * Ray Mileo

Past Contributors:
  * R.A. Stern (Creator)
  * Austin Portal
  * Chris Sawtelle
  * Ryan Geyer


Turbonomic REST API Guides
==========================

The following published user guides are available to aid in developing against
the Turbonomic REST API. Additional resources are available on the `Turbonomic Documentation <https://www.ibm.com/docs/en/tarm/8.6.3?topic=api-reference>`_ website.

  * `XL 8.6.3 <https://www.ibm.com/docs/en/tarm/8.6.3?topic=api-reference>`_
  * `XL 8.1.0 <https://docs.turbonomic.com/pdfdocs/Turbonomic_API_PRINT_8.1.0.pdf>`_
  * `XL 8.0.1 <https://docs.turbonomic.com/docApp/doc/index.html?config=8.0.json#!/MAPPED&DEFAULT_DEDICATED_XL&showToc=1>`_
  * `XL 7.22.2 <https://docs.turbonomic.com/pdfdocs/Turbonomic_User_Guide_7.21.2.pdf>`_
  * `Unofficial User Guide <http://rsnyc.sdf.org/vmt/>`_ for 6.0.
  * `6.0 <https://archive.turbonomic.com/wp-content/uploads/docs/Turbonomic_REST_API_PRINT_60.pdf>`_
  * `5.9 <https://archive.turbonomic.com/wp-content/uploads/docs/VMT_REST2_API_PRINT.pdf>`_

License
=======

*vmt-connect* is distributed under the `Apache 2.0`_ software license, which may
also be obtained from the Apache Software Foundation, https://www.apache.org/licenses/LICENSE-2.0.txt
