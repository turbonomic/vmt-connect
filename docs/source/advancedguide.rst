.. # Links
.. _API: https://support-turbonomic.force.com/TurbonomicCustomerCommunity/s/documentation
.. _cryptography: https://pypi.org/project/cryptography/
.. _Fernet: https://github.com/fernet/spec/blob/master/Spec.md
.. _jq: https://stedolan.github.io/jq/
.. _jq python: https://pypi.org/project/jq/
.. _jq script: https://stedolan.github.io/jq/manual/
.. _Turbonomic: https://www.turbonomic.com
.. _Requests: https://docs.python-requests.org/en/master/
.. _proxies: https://docs.python-requests.org/en/master/user/advanced/#proxies
.. _RFC 2732: https://datatracker.ietf.org/doc/html/rfc2732

==============
Advanced Usage
==============

Connections
-----------

All parameters to the :py:class:`~vmtconnect.Connection` and :py:class:`~vmtconnect.Session`
classes are technically optional, however Turbonomic does require authentication.
Thus while ``vmtconnect.Connection()`` and ``vmtconnect.Session()`` are valid
calls, they will fail authentication checks regardless. All connections must
provide either a `username` and `password`, or an `auth` string. The `auth` string
is simply a base64 encoded 'Basic Authentication' format string containing the
username and password joined by a colon (:).

.. code:: bash

    # generating a base64 auth string hash in Linux
    echo -n "bob:insecure123" | base64


The `host` parameter defaults to the string literal ``localhost`` for convenience
when working with code that will live on the Turbonomic control instance itself.
If using an IPv6 address, you will need to provide the requisite square brackets
surrounding the address as defined in `RFC 2732`_.

.. code:: python

    # all of these are equivalent
    auth = '...'
    vmt = vmtconnect.Connection(auth=auth)                # 'localhost'
    vmt = vmtconnect.Connection('127.0.0.1', auth=auth)   # IPv4
    vmt = vmtconnect.Connection(host='[::1]', auth=auth)  # IPv6

Additional HTTP headers may be provided using the `headers` parameters. Headers
must be supplied in a format compatible with `Requests`_. Any headers supplied
in this manner will be attached to all requests sent. If you require specific
headers for a specific call, you may attach headers to the  individual query
directly.

.. code:: python

    customheaders = {
      'Pragma': 'no-cache',
      'X-Forwarded-For', '129.78.138.66'
    }

    vmt = vmtconnect.Connection(auth='...', headers=customheaders)

Like headers, Requests `proxies`_ are also supported in the proper format, and
are passed to the `proxies` parameter.

.. code:: python

    proxies = {
      'http': 'http://10.10.1.10:3128',
      'https': 'http://10.10.1.10:1080',
    }

    vmt = vmtconnect.Connection(auth='...', proxies=proxies)


Paged Results
-------------

For versions of Turbonomic that support paged responses, *vmt-connect* provides
an optional :py:class:`~vmtconnect.Pager` class for working with the paginated
results. By default, *vmt-connect* will return the first page of results only
unless the **pager** flag is set to ``True``.

Basic Pagination
^^^^^^^^^^^^^^^^

When querying all entities in a given market, for example, you will by default
receive the first set of entries (300-500 depending on version) in the usual list
of dictionaries format:

.. code:: python

    conn = vmtconnect.Connection(username='user', password='pass')
    response = conn.get_entities()


.. warning::
    Automatic pagination in Turbonomic Classic is not implemented on all endpoints
    that support pagination. Some, such as market actions, default to the historical
    behavior of returning all results. When using Classic endpoints with pagination
    it is recommended to manually set a **limit** value of reasonable size, such
    as 100.

Although *vmt-connect* detects the response is paged, in order to keep backwards
compatibility with previous code it returns the expected response that previous
versions would, which in this case is the first page of the result set. You
can validate by checking the headers returned:

.. code:: python

    conn = vmtconnect.Session(username='user', password='pass')
    response = conn.get_entities()

    if 'x-next-cursor' in conn.last_response.headers:
        print('Paged response')


One option is to let the pager fetch all the results in the cursor and combine
them into a single monolithic response using the **fetch_all** parameter:

.. code:: python

    response = conn.get_entities(fetch_all=True)


This works if the response is small. Larger responses will use excessive amounts
of memory caching the results, and we will generally see better performance by
looping over the pages. We do this by using the :py:attr:`~vmtconnect.Pager.next`
property of the :py:class:`~vmtconnect.Pager`, and checking if it is :py:attr:`~vmtconnect.Pager.complete`:

.. code:: python

    response = conn.get_entities(pager=True)

    while not response.complete:
        # filter out just the entities we need - VMs with the word 'blue' in
        # the name
        entitycache = [x for x in response.next if 'blue' in x['displayName'].lower()]

        # do something with our data
        interesting_things(entitycache)


Response Filters
----------------

Starting in v3.4.0, *vmt-connect* supports filtering JSON responses in order to
reduce memory consumption when working with extremely large responses, and to
permit fine grained control over the data received. Two methods of filtering
are supported; a custom filtering domain specific language (DSL), and `jq`_ script
syntax. The native DSL provides a simplified set of features, which provide
significantly faster performance and memory reduction over jq. Using `jq script`_
provides significantly more flexibility in terms of filtering and even re-writing
the JSON response, at the cost of both speed and memory. Regardless which filter
style is used, the filter is applied to each top-most object in the response.
Thus if the response is a list, each object in the list will be filtered one at
a time. If the response is a single key-value pari, the filter will be applied
once to the whole response.

Response filters may be applied to almost any method supported by *vmt-connect*,
direct requests, as well as paged results. To apply a filter to a request simply
add the **filter** keyword argument to the method call with the corresponding
filter you wish to apply:

.. code-block:: python
    :caption: Example filtered request

    conn = vmtconnect.Session(username='user', password='pass')
    filter = ['uuid,displayName,details']
    actions = conn.get_actions(filter=filter)


.. code-block:: python
    :caption: Example filtered request with pagination and cursor size limit

    vconnmt = vmtconnect.Session(username='user', password='pass')
    filter = ['uuid,displayName,details']
    actions = conn.get_actions(filter=filter, pager=True, limit=100)

For the purposes of demonstrating filter examples in the sub-sections below,
please refer to this example JSON response.

.. raw:: html

   <details>
   <summary><b>Show/Hide Example</b></summary>

.. literalinclude:: ./_static/action.json
  :language: json
  :caption: action.json

.. raw:: html

   </details>

|

Native DSL
^^^^^^^^^^

Native DSL filters are constructed using a list of filter strings. Each string
contains either a list of keys, or a dot-reference path to a single key to extract
from the source JSON response. You only need to specify the minimum level of depth
required to retrieve the contents desired, thus if you want all contents under
a specific key, you only need provide the path to said key. Multiple filters
for the same top-level key will be merged, thus you can cherry pick a subset of
an object using multiple filter entries. The below examples demonstrate these
behaviors.

.. code-block:: python
    :caption: Multiple Keys Expanded

    filter = [
      'uuid',
      'details',
      'actionType',
      'target'
    ]

.. code-block:: python
    :caption: Multiple Keys Compact
    :name: ex1

    filter = [
      'uuid,details,actionType,target'
    ]

This above equivalent examples will extract only the **uuid**, **details**,
**actionType**, and the entire **target** object from every object in the response
list. All other fields will be discarded.

.. code-block:: python
    :caption: Sub-selecting Parts of an object
    :name: ex2

    filter = [
      'uuid,details,actionType',
      'target.uuid',
      'target.displayName'
      'target.discoveredBy.displayName',
      'currentValue',
      'newValue'
    ]

Here we have extracted the **uuid**, **details**, and **actionType** again. In
addition a sub-selection of the **target** object have been pulled, as well as
the **currentValue** and **newValue** top level keys. All the **target** parts
will be returned in their original structure, as referenced by the dot notation.

.. code-block:: python
    :caption: Sub-selecting Parts of an object

    filter = [
      'uuid,details,actionType,stats'
    ]

Nested lists are automatically parsed to include all items by default. Although
you cannot filter individual indices based on their children, you can sub-select
or slice portions of the list using Python's slicing syntax, as shown in the
following examples.

.. code-block:: python
    :caption: Sub-selecting a specific item in a list

    filter = [
      'uuid,details,actionType',
      'stats[0]'
    ]

|

.. code-block:: python
    :caption: Sub-selecting a range from a list, with stepping

    filter = [
      'uuid,details,actionType',
      'stats[2:10:2]'
    ]

|

.. code-block:: python
    :caption: All of these are equivalent

    filter = [
      'stats',
      'stats[]',
      'stats[*]',
      'stats[0:]'
    ]

|

.. code-block:: python
    :caption: Dot-referencing with lists

    filter = [
      'uuid,details,actionType',
      'stats.name',
      'stats.value'
    ]

A more formal definition of the DSL is provided in the following rail-road diagrams.

**Filter**

.. raw:: html
    :file: _static/rrfilter.svg

|

**Field**

.. raw:: html
    :file: _static/rrfield.svg

|

**Slice**

.. raw:: html
    :file: _static/rrslice.svg

|

jq Script
^^^^^^^^^

In addition to the native DSL, *vmt-connect* supports `jq script`_ via the `jq python`_
package. Jq provides a more powerful parsing language for not simply filtering,
but also altering JSON content. This includes value checking, recursion, deletion,
insertion, and numerous other functions. Unfortunately this capability comes at
a significant performance and memory hit compared to the native DSL on very large
responses. The entirety of jq cannot be covered here, though a couple examples
are provided below to demonstrate the usage difference. The primary defining
difference is that jq scripts must be provided as a single string, and not as a
python list.

.. note::
    Jq must be installed on the host system, and the jq python module must also
    be installed for *vmt-connect* using pip Extras. Jq is not installed or enabled
    by default with *vmt-connect*.

    Example:
      pip install vmt-connect[jq]

.. code-block:: python
    :caption: Jq style multiple keys selection

    filter = '. | {uuid, details, actionType, target}'

See :ref:`ex1`.

|

.. code-block:: python
    :caption: Jq style multiple keys selection

    filter = """
      . | {
        uuid,
        details,
        actionType,
        target: (
           .target | {
             uuid,
             className,
             displayName,
             discoveredBy: (.discoveredBy | {displayName})
           }
        )
    }
    """

See :ref:`ex2`.

|

.. code-block:: python
    :caption: Filtering based on values

    filter = '. | select(.actionType == "DELETE") | {uuid, details, actionType, target}'

|


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


Credentials
-----------

Prior to v3.3.0, *vmt-connect* provided no native mechanism for securing credentials.
To fill the gap Turbonomic provided a package called "TurboAPICredStore", which
provided for the creation and management of encrypted API credentials. That library
has now been integrated directly into *vmt-connect* as the security module.
Credentials are managed using the :py:class:`~vmtconnect.security.Credential`
class, and a command-line utility is provided for creating credentials in a similar
manner to what TurboAPICredStore had provided.

*vmt-connect* utilizes the `cryptography`_ package for symmetric encryption using
the `Fernet`_ specification. This means in addition to the encrypted message,
called a token, there is a unique encryption key, the secret, which must be secured
separately. *vmt-connect* necessarily leaves the security of the secret key up
to the user, and appropriate measures must be taken to ensure access to the secret
is available only to intended parties.

Module Interface
^^^^^^^^^^^^^^^^

Encrypted credentials can be created, and retrieved using the security module's
:py:class:`~vmtconnect.security.Credential` class. Creating new credentials can
be done with the interactive using the :py:meth:`~vmtconnect.security.Credential.create`
method:

.. code-block:: python

    cred = vmtconnect.security.Credential()
    cred.create()

If no parameters are supplied, the user will be prompted for a username and password,
which will be encrypted with a new unique key. Because this method has interactive
inputs, in general it is advisable to create new credentials using the command-line
interface, detailed further down; or by providing a context appropriate wrapper
for the :py:meth:`~vmtconnect.security.Credential.set` method.

Working with existing credentials is fairly simple. Upon initialization you may
specify either or both the key file and credential file to the constructor.
Credentials can then be decrypted directly:

.. code-block:: python

    cred = vmtconnect.security.Credential(key='/keystore/.turbokey', cred='user.cred')
    auth = cred.decrypt()


Command-line Interface
^^^^^^^^^^^^^^^^^^^^^^

The command-line interface utility, turboauth, is intended for creating encrypted
credentials for the Turbonomic API in anticipation for automated integrations.
The command can be used to create new, or replace existing credential and key
files.

.. code-block:: bash

    # create new set in the current folder
    # if the key file already exists, it will be re-used for encryption instead
    # of being overwritten
    turboauth -k .key -c user.cred

    # to overwrite files, you must use the -f or --force flag
    turboauth -k .key -c user.cred -f

    # to change the basepath of the files, use the -b or --basepath option
    turboauth -b .secret -k .key -c user.cred
