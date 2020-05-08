.. # Links
.. _API: https://greencircle.vmturbo.com/community/products/pages/documentation
.. _Turbonomic: http://www.turbonomic.com

==============
Advanced Usage
==============

Paged Results
-------------

For versions of Turbonomic that support paged responses, *vmt-connect* provides
and optional :py:class:`~vmtconnect.Pager` class for working with the paginated
results. By default, *vmt-connect* will return the first page of results only
unless the **pager** flag is set to ``True``.

For example, when querying all entities in a given market, you will receive the
first set of entries (300-500 depending on version) in the usual list of dictionaries
format:

.. code:: python

    conn = vmtconnect.Connection(username='user', password='pass')
    response = conn.get_entities()


Although *vmt-connect* detects the response is paged, in order to keep backwards
compatibility with previous code it returns the expected response that previous
versions would, which in this case is the first page of the result set. You
can validate by checking the headers returned:

.. code:: python

    conn = vmtconnect.Connection(username='user', password='pass')
    response = conn.get_entities()

    if 'x-next-cursor' in conn.last_response.headers:
        print('Paged response')


One option is to let the pager fetch all the results in the cursor and combine
them into a single monolithic response using the **fetch_all** parameter:

.. code:: python

    response = conn.get_entities(fetch_all='True')


This works if the response is small. Larger responses will use excessive amounts
of memory caching the results, and we will generally see better performance by
looping over the pages. We do this by using the :py:attr:`~vmtconnect.Pager.next`
property of the :py:class:`~vmtconnect.Pager`, and checking if it is :py:attr:`~vmtconnect.Pager.complete`:

.. code:: python

    response = conn.get_entities(pager='True')

    while True:
        # filter out just the entities we need - VMs with the word 'blue' in
        # the name
        entitycache = [x for x in response.next if 'blue' in x['displayName'].lower()]

        # do something with our data
        interesting_things(entitycache)

        if response.complete:
            # optionally try to free some memory as we go - this requires ensuring
            # we deep copy the list if we're referencing data in it, or python
            # will continue to keep the memory reference alive
            del entitycache
            break


Version Control
---------------

When specific implementations, integrations, or scripts require specific versions
of Turbonomic, need to override one of the minimum versions, or need to exclude
incompatible versions, you will need to pass in a custom :py:class:`~vmtconnect.VersionSpec`
to your connection. The version specification object permits fine grained control
of which versions you wish to restrict execution to, and supports both white lists
and black lists.


To lock a script to a specific version you would use a spec as follows:

.. code:: python

    spec = vmtconnect.VersionSpec(['6.4.10'])
    conn = vmtconnect.Connection(username='user', password='pass', req_versions=spec)


If, on the other hand, you only need to exclude specific problematic dot releases
from a branch, you would be better served with the following:

.. code:: python

    spec = vmtconnect.VersionSpec(['6.4+'], exclude=['6.4.1', '6.4.2', '6.4.5', '6.4.12'])


In some cases you may be working on a development build, which Turbonomic terms
a snapshot. These builds have a string flag 'SNAPSHOT' appended to the version
which is generally not parsable by the version logic, and will produce an error.
To explicitly allow a dev build, or work around an erroneously flagged version,
set the **snapshot** parameter to ``True``.

.. code:: python

    spec = vmtconnect.VersionSpec(['7.21+'], snapshot=True)
