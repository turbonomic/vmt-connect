====================
Developer Interfaces
====================

This part of the documentation covers all the interfaces of vmt-connect.

.. contents::
   :local:

Main Module
===========

:py:attr:`Import:` **vmtconnect**

Connections
-----------

Connection
^^^^^^^^^^
.. autoclass:: vmtconnect.Connection
   :members:

Session
^^^^^^^
.. autoclass:: vmtconnect.Session
   :show-inheritance:
   :members:

|

Response Handlers
-----------------

Pager
^^^^^
.. autoclass:: vmtconnect.Pager
   :members:

|

Versioning
----------

Version
^^^^^^^
.. autoclass:: vmtconnect.Version
   :members:

VersionSpec
^^^^^^^^^^^
.. autoclass:: vmtconnect.VersionSpec
   :members:

|

Utilities
---------

.. autofunction:: vmtconnect.enumerate_stats

|

Exceptions
----------

.. autoexception:: vmtconnect.VMTConnectionError
.. autoexception:: vmtconnect.VMTVersionError
.. autoexception:: vmtconnect.VMTUnknownVersion
.. autoexception:: vmtconnect.VMTVersionWarning
.. autoexception:: vmtconnect.VMTMinimumVersionWarning
.. autoexception:: vmtconnect.VMTFormatError
.. autoexception:: vmtconnect.VMTNextCursorMissingError
.. autoexception:: vmtconnect.HTTPError
.. autoexception:: vmtconnect.HTTP400Error
.. autoexception:: vmtconnect.HTTP401Error
.. autoexception:: vmtconnect.HTTP404Error
.. autoexception:: vmtconnect.HTTP500Error
.. autoexception:: vmtconnect.HTTP502Error
.. autoexception:: vmtconnect.HTTP503Error
.. autoexception:: vmtconnect.HTTPWarning

|

Deprecated Interfaces
---------------------

.. autoclass:: vmtconnect.VMTConnection
.. autoclass:: vmtconnect.VMTVersion

|

Security Module
===============

:py:attr:`Import:` **vmtconnect.security**

Classes
-------

Credential
^^^^^^^^^^
.. autoclass:: vmtconnect.security.Credential
   :members:

|

Utility Module
==============

:py:attr:`Import:` **vmtconnect.util**

.. autofunction:: vmtconnect.util.enumerate_stats

.. autofunction:: vmtconnect.util.mem_cast

.. autofunction:: vmtconnect.util.to_defaultdict

|
