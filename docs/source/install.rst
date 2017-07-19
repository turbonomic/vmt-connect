Installation
============

vmt-connect is a stand-alone Python module, and not provided as a PyPi package.
The module can be placed in the same folder as your calling script and imported
locally, or it can be placed in a folder included in the ``PYTHONPATH``.


Requirements
-------------

In order to use vmt-connect you will need to be running a supported version of
Python, and install the Requests_ module.

* Python -- one of the following:

  - CPython_ >= 2.7 or >= 3.3

* Requests_ >= 2.10.0

.. _CPython: http://www.python.org/
.. _PyPy: http://pypy.org/
.. _Requests: http://docs.python-requests.org/en/master/
.. _IronPython: http://http://ironpython.net/


Importing
---------

In the most basic case, you need to import the module, either from a local source
file or from a location in your ``PYTHONPATH``.

.. code:: python

   import vmtconnect

However, you may find it more useful to alias the import

.. code:: python

   import vmtconnect as vc

Alternatively, you can manually update the internal import search path within
your script to import vmt-connect from another location. For instance, if you
created a folder in your project directory for local modules called `modules`,
you could add the relative path for importing:

.. code:: python

   import os
   import sys
   sys.path.insert(0, os.path.abspath('./modules'))

   import vmtconnect


GitHub Source
-------------

The source code for vmt-connect is provided via a read-only GitHub repository_.

.. _repository: https://github.com/rastern/vmt-connect

Individual release archives may be found `here <https://github.com/rastern/vmt-connect/releases>`_.
