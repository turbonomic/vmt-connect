:mod:`vmtconnect` --- Developer Interfaces
==========================================

.. module:: vmtconnect

vmt-connect provides a single session based connection interface class, and
several exceptions for communicating with Turbonomic instances.


Connections
-----------

.. autoclass:: VMTConnection
   :show-inheritance:
   :inherited-members:


Exceptions
----------

.. autoexception:: vmtconnect.VMTConnectionError
.. autoexception:: vmtconnect.HTTPError
.. autoexception:: vmtconnect.HTTP500Error
.. autoexception:: vmtconnect.HTTP502Error
.. autoexception:: vmtconnect.HTTPWarn

