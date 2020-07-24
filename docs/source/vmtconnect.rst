====================
Developer Interfaces
====================

.. module:: vmtconnect

This part of the documentation covers all the interfaces of vmt-connect.

Connections
===========

Connection
^^^^^^^^^^
.. autoclass:: Connection
   :members:

Session
^^^^^^^
.. autoclass:: Session
   :show-inheritance:
   :members:

|

Response Handlers
=================

Pager
^^^^^
.. autoclass:: Pager
   :members:

|

Versioning
==========

Version
^^^^^^^
.. autoclass:: Version
   :members:

VersionSpec
^^^^^^^^^^^
.. autoclass:: VersionSpec
   :members:

|

Utilities
=========

enumerate_stats()
^^^^^^^^^^^^^^^^^
.. autofunction:: enumerate_stats

|

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

|

Deprecated Interfaces
=====================

.. autoclass:: VMTConnection
.. autoclass:: VMTVersion
