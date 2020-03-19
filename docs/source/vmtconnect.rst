===================================
vmtconnect --- Developer Interfaces
===================================

.. module:: vmtconnect

*vmt-connect* provides two connection interface classes, and several exceptions
for communicating with Turbonomic instances.


Connections
===========

.. autoclass:: Version
   :members:

.. autoclass:: VersionSpec
   :members:

.. autoclass:: Connection
   :members:

.. autoclass:: Session
   :show-inheritance:
   :inherited-members:
   :members:


Exceptions
==========

.. autoexception:: vmtconnect.VMTConnectionError
.. autoexception:: vmtconnect.VMTVersionError
.. autoexception:: vmtconnect.VMTUnknownVersion
.. autoexception:: vmtconnect.VMTVersionWarning
.. autoexception:: vmtconnect.VMTMinimumVersionWarning
.. autoexception:: vmtconnect.VMTFormatError
.. autoexception:: VMTNextCursorMissingError
.. autoexception:: vmtconnect.HTTPError
.. autoexception:: vmtconnect.HTTP400Error
.. autoexception:: vmtconnect.HTTP401Error
.. autoexception:: vmtconnect.HTTP404Error
.. autoexception:: vmtconnect.HTTP500Error
.. autoexception:: vmtconnect.HTTP502Error
.. autoexception:: vmtconnect.HTTP503Error
.. autoexception:: vmtconnect.HTTPWarn
