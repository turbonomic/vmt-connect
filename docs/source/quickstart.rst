.. # Links
.. _API: https://cdn.turbonomic.com/wp-content/uploads/docs/VMT_REST2_API_PRINT.pdf

Quickstart Guide
================

vmt-connect provides two interfaces for connecting to the Turbonomic API_.
In general we can focus on the most useful of these, :class:`~vmtconnect.VMTConnection`.


Getting Connected
-----------------

Using the :class:`~vmtconnect.VMTConnection` class to connect to Turbonomic is very simple.

.. code:: python

   import vmtconnect

   vmt = vmtconnect.VMTConnection(host='localhost', username='bob', password='*****')

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


Working with Results
--------------------

When using :class:`~vmtconnect.VMTConnection` all JSON results are automatically
deserialized into Python objects and can be accessed directly. Turbonomic most
commonly returns a list of entities, even for single items, so we are often
working with a list of dictionaries.

Using the deserialized objects, we can easily displaying which host a VM lives on.

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