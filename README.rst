.. _installation: https://rastern.github.io/vmt-connect/start.html#installation

==============================================
vmt-connect: Turbonomic API Connection Wrapper
==============================================

vmt-connect is a single file Python module that provides a more user-friendly wrapper around the second generation Turbonomic API. The wrapper provides useful helper functions for handling general tasks within the API, such as searching, filtering, and error checking. This module is not intended to be a full API client implementation.


Installation
============

To install vmt-connect, copy the *vmtconnect.py* file to your project folder, or
alternatively, manually install it in your python modules path. For detailed
instructions please see the `installation`_ section of the documentation.

vmt-connect does not support PyPi installation via pip or setuputils.


Usage
=====

Basic Connection
----------------

.. code-block:: python

   import vmtconnect as vcon

   conn = vcon.VMTConnection('localhost', 'administrator', '<password>')
   vms = conn.get_virtualmachines()
   print(vms)


Documentation
=============

Detailed documentation is available `here <https://rastern.github.io/vmt-connect>`_.


How to Contribute
=================

vmt-connect is provided as a read-only repository, and is not accepting pull requests.