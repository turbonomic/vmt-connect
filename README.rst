.. _installation: https://turbonomic.github.io/vmt-connect/start.html#installation

==============================================
vmt-connect: Turbonomic API Connection Wrapper
==============================================

*vmt-connect* is a more user-friendly wrapper around the second generation Turbonomic
API. The wrapper provides useful helper functions for handling general tasks within
the API, such as searching, filtering, and error checking. This module is not
intended to be a full API client implementation.


Installation
============

The latest wheel file can be installed via pip using the install command. For
detailed instructions please see the `installation`_ section of the documentation.


Usage
=====

Basic Connection
----------------

.. code-block:: python

   import vmtconnect as vcon

   conn = vcon.VMTConnection('localhost', 'administrator', '<password>')
   vms = conn.get_virtualmachines()
   print(vms)

The `user guide <https://turbonomic.github.io/vmt-connect/userguide.html>`_ is a
good place to start.


Documentation
=============

Detailed documentation is available `here <https://turbonomic.github.io/vmt-connect>`_.
