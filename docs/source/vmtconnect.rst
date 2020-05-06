====================
Developer Interfaces
====================

.. module:: vmtconnect

This part of the documentation covers all the interfaces of vmt-connect.

Connections
===========

.. autoclass:: Connection
   :members:

.. autoclass:: Session
   :show-inheritance:
   :inherited-members:
   :members:


Response Handlers
=================

.. autoclass:: Pager
   :members:


Versioning
==========

.. autoclass:: Version
   :members:

.. autoclass:: VersionSpec
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
