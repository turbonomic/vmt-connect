.. # Links
.. _API: https://cdn.turbonomic.com/wp-content/uploads/docs/VMT_REST2_API_PRINT.pdf
.. _Turbonomic: http://www.turbonomic.com

==========
User Guide
==========

*vmt-connect* provides base communication operations with the `Turbonomic`_ `API`_.

Talking to Turbo
================

vmt-connect provides two interfaces for connecting to the Turbonomic API_. The
first is a standard REST based :class:`~vmtconnect.Connection`, while the second
is a session based connection class, :class:`~vmtconnect.Session`. There is also
a legacy class :class:`~vmtconnect.VMTConnection` that serves as an alias to
:class:`~vmtconnect.Session` for backwards compatibility. This will be removed
in a future version, and code should be updated to the proper connection class.


Getting Connected
-----------------

Using the :class:`~vmtconnect.Connection` class to connect to Turbonomic is very simple.

.. code:: python

   import vmtconnect

   vmt = vmtconnect.Connection(host='localhost', username='bob', password='*****')

With this we have a connection setup and ready to use. Let's get a list of all
the Virtual Machines in the environment, and show how many we find.

.. code:: python

   vms = vmt.get_virtualmachines()
   print(len(vms))

Using that same result set, we can investigate other properties of the VMs that
are already returned. For instance, lets filter out only the VMs from a single
vCenter instance.

.. code:: python

   vc_uuid = '_wDNeYErKEeapb_68sPF4mg' # internal Turbo UUID
   vc_vms = [x for x in vms if x['discoveredBy']['uuid'] == vc_uuid]



Legacy Connections
------------------

Any existing code using the :class:`~vmtconnect.VMTConnection` class should continue
to operate as before. The underlying communication will be handled by the :class:`~vmtconnect.Session`
class, and code should be updated to the new class names as soon as possible.

.. code:: python

   import vmtconnect as vc

   vmt = vc.VMTConnection(host='localhost', username='bob', password='*****')


Working with Results
--------------------

Regardless of the connection class used, all JSON results are automatically
deserialized into Python objects and can be accessed directly. Because Turbonomic
may return a single item or a list of items on most endpoints, the connection
classes will serialize the result into a list regardless of the count so that
all return types are as uniform as possible.

Using the deserialized objects, we can easily displaying which host a VM lives
on, continuing from the earlier example.

.. code:: python

   vms = vmt.get_virtualmachines()

   for vm in vms:
       try:
           for x in vm['providers']:
               if x['className'] == 'PhysicalMachine':
                   print(vm['displayName'], 'resides on', x['displayName'])
       except KeyError:
           print(vm['displayName'], 'is powered off')

For more details on the exact data structure of each Turbonomic entity, see the
`API`_ documentation.