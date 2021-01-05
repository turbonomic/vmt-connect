# Copyright 2017-2020 R.A. Stern
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# libraries

import base64
from collections import defaultdict
from copy import deepcopy
import datetime
import json
import math
import os
import re
import sys
import warnings

import requests
from urllib.parse import urlunparse, urlencode

from vmtconnect import security
from vmtconnect import util
from vmtconnect import versions

from .__about__ import (__author__, __copyright__, __description__,
                        __license__, __title__, __version__)



__all__ = [
    '__author__',
    '__build__',
    '__copyright__',
    '__description__',
    '__license__',
    '__title__',
    '__version__',
    'Connection',
    'HTTPError',
    'HTTP401Error',
    'HTTP404Error',
    'HTTP500Error',
    'HTTP502Error',
    'HTTPWarn',
    'Session',
    'Version',
    'VersionSpec',
    'VMTConnection',
    'VMTConnectionError',
    'VMTFormatError',
    'VMTMinimumVersionWarning',
    'VMTUnknownVersion',
    'VMTVersion',
    'VMTVersionError',
    'VMTVersionWarning',
    'enumerate_stats'
]

_entity_filter_class = {
    'application': 'Application',
    'applicationserver': 'ApplicationServer',
    'database': 'Database',
    'db': 'Database',                       # for convenience
    'ds': 'Storage',                        # for convenience
    'diskarray': 'DiskArray',
    'cluster': 'Cluster',
    'group': 'Group',
    'namespace': 'Namespace',               # 7.22
    'physicalmachine': 'PhysicalMachine',
    'pm': 'PhysicalMachine',                # for convenience
    'storage': 'Storage',
    'storagecluster': 'StorageCluster',
    'storagecontroller': 'StorageController',
    'switch': 'Switch',
    'vdc': 'VirtualDataCenter',             # for convenience
    'virtualapplication': 'VirtualApplication',
    'virtualdatacenter': 'VirtualDataCenter',
    'virtualmachine': 'VirtualMachine',
    'vm': 'VirtualMachine'                  # for convenience
}

_class_filter_prefix = {
    'Application': 'apps',
    'ApplicationServer': 'appSrvs',
    'Database': 'database',
    'DiskArray': 'diskarray',
    'Cluster': 'clusters',
    'Group': 'groups',
    'Namespace': 'namespaces',
    'PhysicalMachine': 'pms',
    'Storage': 'storage',
    'StorageCluster': 'storageClusters',
    'StorageController': 'storagecontroller',
    'Switch': 'switch',
    'VirtualApplication': 'vapps',
    'VirtualDataCenter': 'vdcs',
    'VirtualMachine': 'vms',
}

_exp_type = {
    '=': 'EQ',
    '!=': 'NEQ',
    '<>': 'NEQ',
    '>': 'GT',
    '>=': 'GTE',
    '<': 'LT',
    '<=': 'LTE'
}

ENV = {}
GLOBAL_ENV = 'vmtconnect.env'
SCRIPT_ENV = None

try:
    SCRIPT_ENV = os.path.splitext(sys.argv[0])[0] + '.env'
except Exception:
    pass



## ----------------------------------------------------
##  Error Classes
## ----------------------------------------------------
class VMTConnectionError(Exception):
    """Base connection exception class."""
    pass


class VMTVersionError(Exception):
    """Incompatible version error."""
    def __init__(self, message=None):
        if message is None:
            message = 'Your version of Turbonomic does not meet the minimum ' \
                      'required version for this program to run.'
        super().__init__(message)


class VMTUnknownVersion(Exception):
    """Unknown version."""
    pass


class VMTVersionWarning(Warning):
    """Generic version warning."""
    pass

class VMTMinimumVersionWarning(VMTVersionWarning):
    """Minimum version warnings."""
    pass

class VMTFormatError(Exception):
    """Generic format error."""
    pass


class VMTPagerError(Exception):
    """Generic pager error"""
    pass


class VMTNextCursorMissingError(VMTConnectionError):
    """Raised if the paging cursor header is not provided when expected"""
    pass


class HTTPError(Exception):
    """Raised when an blocking or unknown HTTP error is returned."""
    pass


class HTTP400Error(HTTPError):
    """Raised when an HTTP 400 error is returned."""
    pass


class HTTP401Error(HTTP400Error):
    """Raised when access fails, due to bad login or insufficient permissions."""
    pass


class HTTP404Error(HTTP400Error):
    """Raised when a requested resource cannot be located."""
    pass


class HTTP500Error(HTTPError):
    """Raised when an HTTP 500 error is returned."""
    pass


class HTTP502Error(HTTP500Error):
    """Raised when an HTTP 502 Bad Gateway error is returned. In most cases this
    indicates a timeout issue with synchronous calls to Turbonomic and can be
    safely ignored."""
    pass


class HTTP503Error(HTTP500Error):
    """Raised when an HTTP 503 Service Unavailable error is returned. Subsequent
    calls should be expected to fail, and this should be treated as terminal to
    the session."""
    pass


class HTTPWarning(Warning):
    """Raised when an HTTP error can always be safely ignored."""
    pass



# ----------------------------------------------------
#  API Wrapper Classes
# ----------------------------------------------------
class Version:
    """Turbonomic instance version object

    The :py:class:`~Version` object contains instance version information, and
    equivalent Turbonomic version information in the case of a white label
    product.

    Args:
        version (obj): Version object returned by Turbonomic instance.

    Attributes:
        version (str): Reported Instance version
        product (str): Reported Product name
        snapshot (bool): ``True`` if the build is a snapshot / dev build, ``False``
            otherwise.
        base_version (str): Equivalent Turbonomic version
        base_build (str): Equivalent Turbonomic build
        base_branch (str): Equivalent Turbonomic branch

    Raises:
        VMTUnknownVersion: When version data cannot be parsed.
    """

    def __init__(self, version):
        self.version = None
        keys = self.parse(version)

        for key in keys:
            setattr(self, key, keys[key])

    def __str__(self):
        return self.version

    def __repr__(self):
        return self._version

    @staticmethod
    def map_version(name, version):
        try:
            return versions.mappings[name.lower()][version]
        except KeyError:
            raise VMTUnknownVersion

    @staticmethod
    def parse(obj):
        snapshot = '-SNAPSHOT'
        re_product = r'^([\S]+)\s'
        re_version = r'^.* Manager ([\d.]+)([-\w]+)? \(Build (\")?\d+(\")?\)'
        fields = ('version', 'branch', 'build', 'marketVersion')
        sep = '\n'
        ver = defaultdict(lambda: None)
        ver['product'] = re.search(re_product, obj['versionInfo']).group(1)
        ver['version'] = re.search(re_version, obj['versionInfo']).group(1)
        extra = re.search(re_version, obj['versionInfo']).group(2) or None
        ver['snapshot'] = bool(extra)

        for x in fields:
            label = x

            if x in ('version', 'build', 'branch'):
                label = 'base_' + label

            ver[label] = obj.get(x)

            try:
                ver[label] = ver[label].rstrip(snapshot)

                # late detection for build errors where the snapshot tag is
                # getting added or simply not removed in some places
                # observed in CWOM and Turbo builds.
                if snapshot in obj.get(x):
                    ver['snapshot'] = True

                ver[label] = ver[label].rstrip(extra)
            except Exception:
                pass

        # backwards compatibility pre 6.1 white label version mapping
        # forward versions of classic store this directly (usually)
        if ver['base_branch'] is None or ver['base_version'] is None:
            if ver['product'] == 'Turbonomic':
                ver['base_version'] = ver['version']
                ver['base_branch'] = ver['version']
                ver['base_build'] = re.search(re_version,
                                              obj['versionInfo']).group(3)
            elif ver['product'] in versions.names:
                ver['base_version'] = Version.map_version(
                                          versions.names[ver['product']],
                                          ver['version'])

        ver['_version'] = serialize_version(ver['base_version'])
        ver['components'] = obj['versionInfo'].rstrip(sep).split(sep)
        # for manual XL detection, or other feature checking
        comps = ver['base_version'].split('.')
        ver['base_major'] = int(comps[0])
        ver['base_minor'] = int(comps[1])
        ver['base_patch'] = int(comps[2])
        ver['base_extra'] = int(comps[3]) if len(comps) > 3 else 0

        # XL platform specific detection
        if 'action-orchestrator: ' in obj['versionInfo'] and ver['base_major'] >= 7:
            ver['platform'] = 'xl'
        else:
            ver['platform'] = 'classic'

        return ver


class VersionSpec:
    #TODO Additionally, you may use python version prefixes: >=, >, <, <=, ==
    """Turbonomic version specification object

    The :py:class:`~VersionSpec` object contains version compatibility and
    requirements information. Versions must be in dotted format, and may
    optionally have a '+' postfix to indicate versions greater than or equal
    to are acceptable. If using '+', you only need to specify the minimum
    version required, as all later versions will be accepted independent of
    minor release branch. E.g. 6.0+ includes 6.1, 6.2, and all later branches.

    Examples:
        VersionSpec(['6.0+'], exclude=['6.0.1', '6.1.2', '6.2.5', '6.3.0'])

        VersionSpec(['7.21+'], snapshot=True)

    Args:
        versions (list, optional): A list of acceptable versions.
        exclude (list, optional): A list of versions to explicitly exclude.
        required (bool, optional): If set to True, an error is thrown if no
            matching version is found when :meth:`~VMTVersion.check` is run.
            (Default: ``True``)
        snapshot (bool, optional): If set to True, will permit connection to
            snapshot builds tagged with '-SNAPSHOT'. (Default: ``False``)
        cmp_base (bool, optional): If ``True``, white label versions will be
            translated to their corresponding base Turbonomic version prior to
            comparison. If ``False``, only the explicit product version will be
            compared. (Default: ``True``)

    Raises:
        VMTFormatError: If the version format cannot be parsed.
        VMTVersionError: If version requirement is not met.

    Notes:
        The Turbonomic API is not a well versioned REST API, and each release is
        treated as if it were a separate API, while retaining the name of
        "API 2.0" to distinguish it from the "API 1.0" implementation available
        prior to the Turbonomic HTML UI released with v6.0 of the core product.

        As of v3.2.0 `required` now defaults to ``True``.
    """
    def __init__(self, versions=None, exclude=None, required=True,
                 snapshot=False, cmp_base=True):
        self.versions = versions
        self.exclude = exclude or []
        self.required = required
        self.allow_snapshot = snapshot
        self.cmp_base = cmp_base

        try:
            self.versions.sort()
        except AttributeError:
            raise VMTFormatError('Invalid input format')

    @staticmethod
    def str_to_ver(string):
        try:
            string = string.strip('+')

            return serialize_version(string)
        except Exception:
            msg = 'Unrecognized version format. ' \
                  f"This may be due to a broken snapshot build: {string}"
            raise VMTFormatError()

    @staticmethod
    def cmp_ver(a, b):
        a = VersionSpec.str_to_ver(a)
        b = VersionSpec.str_to_ver(b)

        if int(a) > int(b):
            return 1
        elif int(a) < int(b):
            return -1

        return 0

    @staticmethod
    def _check(current, versions, required=True, warn=True):
        for v in versions:
            res = VersionSpec.cmp_ver(current, v)

            if (res >= 0 and v[-1] == '+') or res == 0:
                return True

        if required:
            raise VMTVersionError('Required version not met')

        if warn:
            msg = 'Your version of Turbonomic does not meet the ' \
                  'minimum recommended version. You may experience ' \
                  'unexpected errors, and are strongly encouraged to ' \
                  'upgrade.'
            warnings.warn(msg, VMTMinimumVersionWarning)

        return False

    def check(self, version):
        """Checks a :py:class:`~Version` for validity against the :py:class:`~VersionSpec`.

        Args:
            version (obj): The :py:class:`~Version` to check.

        Returns:
            True if valid, False if the version is excluded or not found.

        Raises:
            VMTVersionError: If version requirement is not met.
        """
        # exclusion list gatekeeping
        if self.cmp_base:
            try:
                if version.base_version is None:
                    msg = 'Version does not contain a base version, ' \
                          'using primary version as base.'
                    warnings.warn(msg, VMTVersionWarning)
                    ver = version.version
                else:
                    ver = version.base_version

            except AttributeError:
                raise VMTVersionError(f'Urecognized version: {version.product} {version.version}')
        else:
            ver = version.version

        # kick out or warn on snapshot builds
        if version.snapshot:
            if self.allow_snapshot:
                msg = 'You are connecting to a snapshot / development' \
                      ' build. API functionality may have changed, or be broken.'
                warnings.warn(msg, VMTVersionWarning)
            else:
                raise VMTVersionError(f'Snapshot build detected.')

        # kick out on excluded version match
        if self._check(ver, self.exclude, required=False, warn=False):
            return False

        # return on explicit match
        if self._check(ver, self.versions, required=self.required):
            return True

        return False


class VMTVersion(VersionSpec):
    """Alias for :py:class:`~VersionSpec` to provide backwards compatibility.

    Warning:
        Deprecated. Use :py:class:`~VersionSpec` instead.
    """
    def __init__(self, versions=None, exclude=None, require=False):
        super().__init__(versions=versions, exclude=exclude, required=require)


class Pager:
    """API request pager class

    A :py:class:`~Pager` is a special request handler which permits the processing
    of paged :py:meth:`~Connection.request` results, keeping state between each
    successive call. Although you can instantiate a :py:class:`~Pager` directly,
    it is strongly recommended to request one by adding ``pager=True`` to your
    existing :py:class:`Connection` method call.

    Args:
        conn (:py:class:`Connection`): Connection object to associate the pager
            to.
        response (:py:class:`requests.Response`): Requests :py:class:`requests.Response`
            object to build the pager from. This must be the object, and not the
            JSON parsed output.
        filter (dict): Filter to apply to results.
        **kwargs: Additional :py:class:`requests.Request` keyword arguments.

    Attributes:
        all (list): Collect and list all responses combined.
        complete (bool): Flag indicating the cursor has been exhausted.
        next (list): Next response object. Calling this
            updates the :py:class:`~Pager` internal state.
        page (int): Current page index, as counted by number of responses.
        records (int): Count of records in the current page.
        records_fetched (int): Cumulative count of records received.
        records_total (int): Count of records reported by the API.
        response (:py:class:`requests.Request`): Most recent response object.

    Raises:
        VMTNextCursorMissingError: When cursor headers are broken or missing.

    Notes:
        The use of the :py:attr:`~Pager.all` property negates all memory savings by
        caching all responses before returning any results. This should be used
        sparringly to prevent unnecessary and excessive memory usage for extremely
        large datasets.

        Some versions of Turbonomic have endpoints that return malformed, or
        non-working pagination headers. These are chiefly XL versions prior to
        7.21.2.

        It is possible a cursor may expire before you've processed all results
        for extremely large sets. A :py:class:`VMTNextCursorMissingError` will
        be returned when the cursor is no longer availble. Therefore, you should
        always catch this error type when working with a :py:class:`~Pager`.
    """
    def __init__(self, conn, response, filter=None, filter_float=False, **kwargs):
        self.__conn = conn
        self.__response = response
        self.__filter = filter
        self.__filter_float = filter_float
        self.__complete = False
        self.__kwargs = kwargs
        self.__next = "0"
        self.__method = self.__response.request.method
        self.__body = self.__response.request.body

        self.page = 0
        self.records = 0
        self.records_fetched = 0
        self.records_total = 0

    def _complete(self):
        self.__next = "-1"
        self.__complete = True

    def prepare_next(self):
        base = urlunparse((self.__conn.protocol,
                           self.__conn.host,
                           self.__conn.base_path,
                           '','',''))
        partial = self.__response.url.replace(base, '')

        if 'cursor' in partial:
            self.__resource, self.__query = partial.split('?', 1)
            self.__query = re.sub(r'(?<=\?|&)cursor=([\d]+)', f"cursor={self.__next}", self.__query)
        else:
            try:
                self.__resource, self.__query = partial.split('?', 1)
                self.__query += '&'
            except ValueError:
                self.__resource = partial
                self.__query = '?'

            self.__query += f"cursor={self.__next}"

    @property
    def all(self):
        data = []

        while True:
            _page = self.next

            if _page is None:
                self.__complete = True
                break

            data += _page

        return data

    @property
    def complete(self):
        return self.__complete

    @property
    def next(self):
        # newly initiated objects will have a __next value of 0, and we should
        # try to return the first result set, we'll throw an error when we try
        # to get the next result
        if self.complete:
            return None
        elif self.__next != "0":
            # get next
            self.__response = self.__conn._request(self.__method,
                                                   self.__resource,
                                                   self.__query,
                                                   self.__body,
                                                   **self.__kwargs)

            self.__conn.request_check_error(self.__response)
        # endif

        try:
            self.__next = self.__response.headers['x-next-cursor']
        except (ValueError, KeyError):
            self._complete()

        res = self.filtered_response if self.__filter else self.__response.json()
        self.__conn.cookies = self.__response.cookies
        self.page += 1
        self.records = len(res)
        self.records_fetched += self.records

        if self.page == 1:
            self.records_total = int(self.__response.headers.get('x-total-record-count', -1))

        if self.__next:
            self.prepare_next()
        elif self.records_total > 0 and self.records_fetched < self.records_total:
            raise VMTNextCursorMissingError(f'Expected a follow-up cursor, none provided. Received {self.records_fetched} of {self.records_total} expected values.')
        else:
            self._complete()

        if self.__filter:
            self.__response = None

        return [res] if isinstance(res, dict) else res

    @property
    def filtered_response(self):
        return util.filter_copy(self.__response.content.decode(),
                                self.__filter,
                                use_float=self.__filter_float)

    @property
    def response_object(self):
        return self.__response

    @property
    def response(self):
        res = self.__response.json()
        return [res] if isinstance(res, dict) else res


class Connection:
    """Turbonomic instance connection class

    The primary API interface. In addition to the noted method parameters, each
    method also supports a per call **fetch_all** flag, as well as a **pager** flag.
    Each of these override the connection global property, and will be safely
    ignored if the endpoint does not support, or does not require paging the
    results. Additionally, you may pass :py:class:`requests.Request` keyword
    arguments to each call if required (e.g. `timeout <https://requests.readthedocs.io/en/master/user/quickstart/#timeouts>`_).
    Care should be taken, as some parameters will break *vmt-connect* calls if they
    conflict with existing headers, or alter expected results.

    Args:
        host (str, optional): The hostname or IP address to connect to. (default:
            `localhost`)
        username (str, optional): Username to authenticate with.
        password (str, optional): Password to authenticate with.
        auth (str, optional): Pre-encoded 'Basic Authentication' string which
            may be used in place of a ``username`` and ``password`` pair.
        base_url (str, optional): Base endpoint path to use. (default:
            `/vmturbo/rest/`)
        req_versions (:py:class:`VersionSpec`, optional): Versions requirements object.
        disable_hateoas (bool, optional): Removes HATEOAS navigation links.
            (default: ``True``)
        ssl (bool, optional): Use SSL or not. (default: ``True``)
        verify (string, optional): SSL certificate bundle path. (default: ``False``)
        cert (string, optional): Local client side certificate file.
        headers (dict, optional): Dicitonary of additional persistent headers.
        use_session (bool, optional): If set to ``True``, a :py:class:`requests.Session`
            will be created, otherwise individual :py:class:`requests.Request`
            calls will be made. (default: ``True``)
        proxies (dict, optional): Dictionary of proxy definitions.

    Attributes:
        disable_hateoas (bool): HATEOAS links state.
        fetch_all (bool): Fetch all cursor results state.
        headers (dict): Dictionary of custom headers for all calls.
        last_response (:py:class:`requests.Response`): The last response object
            received.
        proxies (dict): Dictionary of proxies to use. You can also configure
            proxies using the `HTTP_PROXY` and `HTTPS_PROXY` environment variables.
        results_limit (int): Results set limiting & curor stepping value.
        update_headers (dict): Dictionary of custom headers for put and post calls.
        version (:py:class:`Version`): Turbonomic instance version object.

    Raises:
        VMTConnectionError: If connection to the server failed.
        VMTUnknownVersion: When unable to determine the API base path.
        HTTP401Error: When access is denied.

    Notes:
        The default minimum version for classic builds is 6.1.x, and for XL it
        is 7.21.x Using a previous version will trigger a version warning. To
        avoid this warning, you will need to explicitly pass in a :py:class:`~VersionSpec`
        object for the version desired.

        Beginning with v6.0 of Turbonomic, HTTP redirects to a self-signed HTTPS
        connection. Because of this, vmt-connect defaults to using SSL. Versions
        prior to 6.0 using HTTP will need to manually set ssl to ``False``. If
        **verify** is given a path to a directory, the directory must have been
        processed using the c_rehash utility supplied with OpenSSL. For client
        side certificates using **cert**: the private key to your local certificate
        must be unencrypted. Currently, Requests, which vmt-connect relies on,
        does not support using encrypted keys. Requests uses certificates from
        the package certifi which should be kept up to date.

        The /api/v2 path was added in 6.4, and the /api/v3 path was added in XL
        branch 7.21. The XL API is not intended to be an extension of the Classic
        API, though there is extensive parity. *vmt-connect* will attempt to
        detect which API you are connecting to and adjust accordingly where
        possible.

        XL uses OID identifiers internally instead of UUID identifiers. The
        change generally does not affect the API, the UUID label is still used,
        although the structure of the IDs is different.
    """
    # system level markets to block certain actions
    # this is done by name, and subject to breaking if names are abused
    __system_markets = ['Market', 'Market_Default']
    __system_market_ids = []

    def __init__(self, host=None, username=None, password=None, auth=None,
                 base_url=None, req_versions=None, disable_hateoas=True,
                 ssl=True, verify=False, cert=None, headers=None,
                 use_session=True, proxies=None):

        # temporary for initial discovery connections
        self.__use_session(False)

        self.__verify = verify
        self.__version = None
        self.__cert = cert
        self.__logedin = False
        self.host = host or 'localhost'
        self.protocol = 'http' if ssl == False else 'https'
        self.disable_hateoas = disable_hateoas
        self.fetch_all = False
        self.results_limit = 0
        self.headers = headers or {}
        self.cookies = None
        self.proxies = proxies
        self.update_headers = {}
        self.last_response = None

        if self.protocol == 'http':
            msg = 'You should be using HTTPS'
            warnings.warn(msg, HTTPWarning)

        # because the unversioned base path /vmturbo/rest is flagged for deprication
        # we have a circular dependency:
        #   we need to know the version to know which base path to use
        #   we need the base path to query the version
        # vmtconnect will attempt to resolve this by trying all known base paths
        # until the correct one is found, or fail if it cannot sort it out
        self.__use_session(use_session)
        self.base_path = self.__resolve_base_path(base_url)

        # set auth encoding
        if auth:
            try:
                self.__basic_auth = auth.encode()
            except AttributeError:
                self.__basic_auth = auth
        elif (username and password):
            self.__basic_auth = base64.b64encode(f"{username}:{password}".encode())
        else:
            raise VMTConnectionError('Missing credentials')

        try:
            self.__login()
            self.__logedin = True
        except HTTPError:
            if self.last_response.status_code == 301 and self.protocol == 'http' \
            and self.last_response.headers.get('Location', '').startswith('https'):
                msg = 'HTTP 301 Redirect to HTTPS detected when using HTTP, switching to HTTPS'
                warnings.warn(msg, HTTPWarning)
                self.protocol = 'https'
                self.__login()
            else:
                raise
        except HTTP401Error:
            raise
        except Exception as e:
            # because classic accepts encoded credentials, we'll try manually attach here
            self.headers.update(
                {'Authorization': f'Basic {self.__basic_auth.decode()}'}
            )
            self.__logedin = True

        if self.is_xl():
            self.__req_ver = req_versions or VersionSpec(['7.21+'])
        else:
            self.__req_ver = req_versions or VersionSpec(['6.1+'])

        self.__req_ver.check(self.version)
        self.__get_system_markets()
        self.__market_uuid = self.get_markets(uuid='Market')[0]['uuid']
        self.__basic_auth = None

        # for inventory caching - used to prevent thrashing the API with
        # repeated calls for full inventory lookups within some expensive calls
        # <!> deprecated due to pagination and XL
        self.__inventory_cache_timeout = 600
        self.__inventory_cache = {'Market': {'data': None,
                                             'expires': datetime.datetime.now()
                                            }
                                 }

    @staticmethod
    def _bool_to_text(value):
        return 'true' if value else 'false'

    @staticmethod
    def _search_criteria(op, value, filter_type, case_sensitive=False):
        criteria = {
            'expType': _exp_type.get(op, op),
            'expVal': value,
            'caseSensitive': case_sensitive,
            'filterType': filter_type
        }

        return criteria

    @staticmethod
    def _stats_filter(stats):
        statistics = []

        for stat in stats:
            statistics.append({'name': stat})

        return statistics

    @property
    def version(self):
        if self.__version is None:
            # temporarily disable hateoas, shouldn't matter though
            hateoas = self.disable_hateoas
            self.disable_hateoas = False

            try:
                self.__version = Version(self.request('admin/versions')[0])
            finally:
                self.disable_hateoas = hateoas

        return self.__version

    def __login(self):
        u, p = (base64.b64decode(self.__basic_auth)).decode().split(':', maxsplit=1)
        body = {'username': (None, u), 'password': (None, p)}
        self.request('login', 'POST', disable_hateoas=False, content_type=None, files=body, allow_redirects=False)

    def __use_session(self, value):
        if value:
            self.session = True
            self.__session = requests.Session()

            # possible fix for urllib3 connection timing issue - https://github.com/requests/requests/issues/4664
            adapter = requests.adapters.HTTPAdapter(max_retries=3)
            self.__session.mount('http://', adapter)
            self.__session.mount('https://', adapter)

            self.__conn = self.__session.request
        else:
            self.session = False
            self.__conn = requests.request

    def __resolve_base_path(self, path=None):
        # /vmturbo/rest is the "unversioned" path (1st gen v2)
        # /api/v2 is the v2 path intended for classic; some XL instances use it (2nd gen v2)
        # /api/v3 is the v3 path intended for XL; not all XL instances support it
        # there's also possibly /t8c/v1 and /api/v4 ... go figure
        if path is not None:
            return path

        if path is None:
            for base in ['/api/v3/', '/vmturbo/rest/']:
                try:
                    self.base_path = base
                    v = self.version
                    return base
                except HTTP400Error:
                    self.base_path = None
                    continue
                except Exception:
                    raise

        raise VMTUnknownVersion('Unable to determine base path')

    def __is_cache_valid(self, id):
        try:
            if datetime.datetime.now() < self.__inventory_cache[id]['expires'] and \
            self.__inventory_cache[id]['data']:
                return True
        except KeyError:
            pass

        return False

    def __get_system_markets(self):
        res = self.get_markets()
        self.__system_market_ids = [x['uuid'] for x in res if 'displayName' in x and x['displayName'] in self.__system_markets]

    def _clear_response(self, flag):
        if flag:
            self.last_response = None

    def _search_cache(self, id, name, type=None, case_sensitive=False):
        # populates internal cache
        self.get_cached_inventory(id)
        results = []

        for e in self.__inventory_cache[id]['data']:
            if (case_sensitive and e['displayName'] != name) or \
               (e['displayName'].lower() != name.lower()) or \
               (type and e['className'] != type):
                continue

            results += [e]

        return results

    def _request(self, method, resource, query='', data=None, **kwargs):
        method = method.upper()
        url = urlunparse((self.protocol, self.host,
                          self.base_path + resource.lstrip('/'), '', query, ''))

        # add custom content-type if specified, if None remove it completely,
        # else add default type
        if 'content_type' in kwargs:
            if kwargs['content_type']:
                self.headers.update({'Content-Type': kwargs.get('content_type', 'application/json')})
            elif 'Content-Type' in self.headers:
                del self.headers['Content-Type']

            del kwargs['content_type']
        else:
            self.headers.update({'Content-Type': 'application/json'})

        kwargs['verify'] = self.__verify
        kwargs['headers'] = {**self.headers, **kwargs.get('headers', {})}

        if self.cookies:
            kwargs['cookies'] = self.cookies

        if method in ('POST', 'PUT'):
            kwargs['headers'] = {**kwargs['headers'], **self.update_headers}
            kwargs['data'] = data

        if self.proxies and 'proxies' not in kwargs:
            kwargs['proxies'] = self.proxies

        try:
            return self.__conn(method, url, **kwargs)
        except requests.exceptions.ConnectionError as e:
            raise VMTConnectionError(e)
        except Exception:
            raise

    def request_check_error(self, response):
        """Checks a request response for common errors and raises their corresponding exception.

        Raises:
            HTTPError: All unhandled non 200 level HTTP codes.
            HTTP400Error: All unhandled 400 level client errors.
            HTTP401Error: When access to the resource is not authorized.
            HTTP404Error: When requested resource is not found.
            HTTP500Error: All unhandled 500 level server errors.
            HTTP502Error: When a gateway times out.
            HTTP503Error: When a service is unavailable.
        """
        if response.status_code/100 == 2:
            return False

        msg = ''

        try:
            msg = f': [{response.json()}]'
        except Exception:
            try:
                msg = f': [{response.content}]'
            except Exception:
                pass

        if response.status_code == 503:
            if 'Retry-After' in response.headers:
                retry = 'Retry after: ' + response.headers['Retry-After']
            else:
                retry = 'No retry provided.'
            raise HTTP503Error(f'HTTP 503 - Service Unavailable: {retry}')
        if response.status_code == 502:
            raise HTTP502Error(f'HTTP 502 - Bad Gateway {msg}')
        if response.status_code/100 == 5:
            raise HTTP500Error(f'HTTP {response.status_code} - Server Error {msg}')
        if response.status_code == 401:
            raise HTTP401Error(f'HTTP 401 - Unauthorized {msg}')
        if response.status_code == 404:
            raise HTTP404Error(f'HTTP 404 - Resource Not Found {msg}')
        if response.status_code/100 == 4:
            raise HTTP400Error(f'HTTP {response.status_code} - Client Error {msg}')
        if response.status_code/100 != 2:
            raise HTTPError(f'HTTP Code {response.status_code} returned {msg}')

    def request(self, path, method='GET', query='', dto=None, **kwargs):
        """Constructs and sends an appropriate HTTP request.

        Most responses will be returned as a list of one or more objects, as
        parsed from the JSON response. As of v3.2.0 you may request a :py:class:`~Pager`
        instance instead. The **pager** and **fetch_all** parameters may be used to
        alter the response behaviour.

        Args:
            path (str): API resource to utilize, relative to ``base_path``.
            method (str, optional): HTTP method to use for the request. (default: `GET`)
            query (dict, optional): A dictionary of key-value paires to attach.
                A single pre-processed string may also be used, for backwards
                compatibility.
            dto (str, optional): Data transfer object to send to the server.
            pager (bool, optional): If set to ``True``, a :py:class:`~Pager`
                instance will be returned, instead of a single response of
                the cursor. (default: ``False``)
            fetch_all (bool, optional): If set to ``True``, will fetch all results
                into a single response when a cursor is returned, otherwise only
                the current result set is returned. This option overrides the
                `pager` parameter. (default: ``False``)
            limit (int, optional): Sets the response limit for a single call.
                This overrides results_limit, if it is also set.
            nocache (bool, optional): If set to ``True``, responses will not be
                cached in the :py:attr:`~Connection.last_response` attribute.
                (default: ``False``)
            **kwargs: Additional :py:class:`requests.Request` keyword arguments.

        Notes:
            The **fetch_all** parameter default was changed in v3.2 from ``True``
            to ``False`` with the addition of the :py:class:`Pager` response
            class.
            String based **query** parameters are deprecated, use dictionaries.
        """
        # attempt to detect a misdirected POST
        if dto is not None and method == 'GET':
            method = 'POST'

        # assign and then remove non-requests kwargs
        fetch_all = kwargs.get('fetch_all', self.fetch_all)
        filter = kwargs.get('filter', None)
        limit = kwargs.get('limit', None)
        nocache = kwargs.get('nocache', False)
        pager = kwargs.get('pager', False)
        uuid = kwargs.get('uuid', None)
        filter_float = kwargs.get('filter_float', False)
        disable_hateoas = kwargs.get('disable_hateoas', self.disable_hateoas)
        path += f'/{uuid}' if uuid is not None else ''

        for x in ['fetch_all', 'filter', 'limit', 'nocache', 'pager', 'uuid', 'filter_float', 'disable_hateoas']:
            try:
                del kwargs[x]
            except KeyError:
                pass

        if isinstance(query, str):
            msg = 'Query parameters should be passed in as a dictionary.'
            warnings.warn(msg, DeprecationWarning)

        if isinstance(query, dict):
            query = '&'.join([f'{k}={v}' for k,v in query.items()])

        if self.results_limit > 0 or limit:
            limit = limit if limit else self.results_limit
            query = '&'.join([query or '', f"limit={limit}"])

        if disable_hateoas:
            query = '&'.join([query or '', f"disable_hateoas=true"])

        self.last_response = self._request(method, path, query.strip('&'), dto, **kwargs)
        self.request_check_error(self.last_response)

        if pager or 'x-next-cursor' in self.last_response.headers:
            res = Pager(self, self.last_response, filter, filter_float, **kwargs)
            self._clear_response(nocache)

            if fetch_all:
                return res.all
            elif pager:
                return res
            else:
                return res.next

        if filter:
            res = util.filter_copy(self.last_response.content.decode(),
                                   filter,
                                   use_float=filter_float)
        else:
            res = self.last_response.json()

        self._clear_response(nocache)

        return [res] if isinstance(res, dict) else res

    def is_xl(self):
        """Checks if the connection is to an XL or Classic type instance.

        Returns:
            ``True`` if connected to an XL instance, ``False`` otherwise.
        """
        if self.version.platform == 'xl':
            return True

        return False

    def get_actions(self, market='Market', uuid=None, **kwargs):
        """Returns a list of actions.

        The get_actions method returns a list of actions from a given market,
        or can be used to lookup a specific action by its uuid. The options are
        mutually exclusive, and a uuid will override a market lookup. If neither
        parameter is provided, all actions from the real-time market will be
        listed.

        Args:
            market (str, optional): The market to list actions from
            uuid (str, optional): Specific UUID to lookup.

        Returns:
            A list of actions
        """
        if uuid:
            return self.request('actions', uuid=uuid, **kwargs)

        return self.request(f'markets/{market}/actions', **kwargs)

    def get_cached_inventory(self, id, uuid=None, **kwargs):
        """Returns the entities inventory from cache, populating the cache if
        necessary. The ID provided should be either a market ID, or one of the
        alternative inventory IDs:

        - __clusters - Clusters
        - __groups  - Groups
        - __group_entities - Group entities
        - __group_members - Group members


        Args:
            id (str): Inventory id to get cached inventory for.
            uuid (str, optional): If supplied, the matching entity will be returned
                instead of the entire cache.

        Returns:
            A list of market entities in :obj:`dict` form.
        """
        if not self.__is_cache_valid(id):
            if id in self.__inventory_cache:
                del self.__inventory_cache[id]

            self.__inventory_cache[id] = {}

            if id == '__clusters':
                self.__inventory_cache[id]['data'] = self.search(types=['Cluster'], fetch_all=True, **kwargs)
            elif id == '__groups':
                self.__inventory_cache[id]['data'] = self.request('groups', fetch_all=True, **kwargs)
            elif id == '__group_entities':
                self.__inventory_cache[id]['data'] = self.request(f'groups/{uuid}/entities', **kwargs)
            elif id == '__group_members':
                self.__inventory_cache[id]['data'] = self.request(f'groups/{uuid}/members', **kwargs)
            else:
                self.__inventory_cache[id]['data'] = self.request(f'markets/{id}/entities', fetch_all=True, **kwargs)

            delta = datetime.timedelta(seconds=self.__inventory_cache_timeout)
            self.__inventory_cache[id]['expires'] = datetime.datetime.now() + delta

        if uuid:
            res = [x for x in self.__inventory_cache[id]['data'] if x['uuid'] == uuid]

            if id == '__group_entities' and not res:
                res = self.request(f'groups/{uuid}/entities', **kwargs)
                self.__inventory_cache[id]['data'].extend(res)
            elif id == '__group_members' and not res:
                res = self.request(f'groups/{uuid}/members', **kwargs)
                self.__inventory_cache[id]['data'].extend(res)

            return deepcopy(res)

        return deepcopy(self.__inventory_cache[id]['data'])

    def get_current_user(self, **kwargs):
        """Returns the current user.

        Returns:
            A list of one user object in :obj:`dict` form.
        """
        return self.request('users/me', **kwargs)

    def get_users(self, uuid=None, **kwargs):
        """Returns a list of users.

        Args:
            uuid (str, optional): Specific UUID to lookup.

        Returns:
            A list of user objects in :obj:`dict` form.
        """
        return self.request('users', uuid=uuid, **kwargs)

    def get_markets(self, uuid=None, **kwargs):
        """Returns a list of markets.

        Args:
            uuid (str, optional): Specific UUID to lookup.

        Returns:
            A list of markets in :obj:`dict` form.
        """
        return self.request('markets', uuid=uuid, **kwargs)

    def get_market_entities(self, uuid='Market', **kwargs):
        """Returns a list of entities in the given market.

        Args:
            uuid (str, optional): Market UUID. (default: `Market`)

        Returns:
            A list of market entities in :obj:`dict` form.
        """
        return self.request(f'markets/{uuid}/entities', **kwargs)

    def get_market_entities_stats(self, uuid='Market', filter=None, **kwargs):
        """Returns a list of market entity statistics.

        Args:
            uuid (str, optional): Market UUID. (default: `Market`)
            filter (dict, optional): DTO style filter to limit stats returned.

        Returns:
            A list of entity stats objects in :obj:`dict` form.
        """
        if filter:
            return self.request(f'markets/{uuid}/entities/stats', method='POST', dto=filter, **kwargs)

        return self.request(f'markets/{uuid}/entities/stats', **kwargs)

    def get_market_state(self, uuid='Market', **kwargs):
        """Returns the state of a market.

        Args:
            uuid (str, optional): Market UUID. (default: `Market`)

        Returns:
            A string representation of the market state.
        """
        return self.get_markets(uuid, **kwargs)[0]['state']

    def get_market_stats(self, uuid='Market', filter=None, **kwargs):
        """Returns a list of market statistics.

        Args:
            uuid (str, optional): Market UUID. (default: `Market`)
            filter (dict, optional): DTO style filter to limit stats returned.

        Returns:
            A list of stat objects in :obj:`dict` form.
        """
        if filter:
            return self.request(f'markets/{uuid}/stats', method='POST', dto=filter, **kwargs)

        return self.request(f'markets/{uuid}/stats', **kwargs)

    def get_entities(self, type=None, uuid=None, detail=False, market='Market',
                     cache=False, **kwargs):
        """Returns a list of entities in the given market.

        Args:
            type (str, optional): Entity type to filter on.
            uuid (str, optional): Specific UUID to lookup.
            detail (bool, optional): Include entity aspect details. This
                parameter works only when specifying an entity UUID. (default: ``False``)
            market (str, optional): Market to query. (default: ``Market``)
            cache (bool, optional): If true, will retrieve entities from the
                market cache. (default: ``False``)

        Returns:
            A list of entities in :obj:`dict` form.


        Notes:
            **type** filtering is performed locally and is not compatible with
            responses that return a :py:class:`~Pager` object. Therefore, if you
            attempt to request a :py:class:`~Pager` response, **type** will be
            ignored.
        """
        query = {}

        if market == self.__market_uuid:
            market = 'Market'

        if uuid:
            path = f'entities/{uuid}'
            market = None

            if detail:
                query['include_aspects'] = True

        if cache:
            entities = self.get_cached_inventory(market)

            if uuid:
                entities = [deepcopy(x) for x in entities if x['uuid'] == uuid]
        else:
            if market is not None:
                entities = self.get_market_entities(market, **kwargs)
            else:
                entities = self.request(path, method='GET', query=query, **kwargs)

        if type and isinstance(entities, Pager):
            return [deepcopy(x) for x in entities if x['className'] == type]

        return entities

    def get_virtualmachines(self, uuid=None, market='Market', **kwargs):
        """Returns a list of virtual machines in the given market.

        Args:
            uuid (str, optional): Specific UUID to lookup.
            market (str, optional): Market to query. (default: `Market`)

        Returns:
            A list of virtual machines in :obj:`dict` form.
        """
        return self.get_entities('VirtualMachine', uuid=uuid, market=market, **kwargs)

    def get_physicalmachines(self, uuid=None, market='Market', **kwargs):
        """Returns a list of hosts in the given market.

        Args:
            uuid (str, optional): Specific UUID to lookup.
            market (str, optional): Market to query. (default: `Market`)

        Returns:
            A list of hosts in :obj:`dict` form.
        """
        return self.get_entities('PhysicalMachine', uuid=uuid, market=market, **kwargs)

    def get_datacenters(self, uuid=None, market='Market', **kwargs):
        """Returns a list of datacenters in the given market.

        Args:
            uuid (str, optional): Specific UUID to lookup.
            market (str, optional): Market to query. (default: `Market`)

        Returns:
            A list of datacenters in :obj:`dict` form.
        """
        return self.get_entities('DataCenter', uuid=uuid, market=market, **kwargs)

    def get_datastores(self, uuid=None, market='Market', **kwargs):
        """Returns a list of datastores in the given market.

        Args:
            uuid (str, optional): Specific UUID to lookup.
            market (str, optional): Market to query. (default: `Market`)

        Returns:
            A list of datastores in :obj:`dict` form.
        """
        return self.get_entities('Storage', uuid=uuid, market=market, **kwargs)

    def get_clusters(self, uuid=None, cache=False, **kwargs):
        """Returns a list of clusters

        Args:
            uuid (str): Cluster UUID.
            cache (bool, optional): If true, will retrieve entities from the
                market cache. (default: ``False``)

        Returns:
            A list of clusters in :obj:`dict` form.
        """
        if cache:
            clusters = self.get_cached_inventory('__clusters')
        else:
            clusters = self.search(types=['Cluster'], **kwargs)

        if uuid:
            return [deepcopy(x) for x in clusters if x['uuid'] == uuid]

        return clusters

    def get_entity_cluster(self, uuid, cache=False, **kwargs):
        """Get the cluster an entity belongs to."""
        clstr = self.get_clusters(cache=cache, **kwargs)

        for c in clstr:
            try:
                if uuid in c['memberUuidList']:
                    return c
            except KeyError:
                pms = self.get_group_entities(c['uuid'], **kwargs)
                for p in pms:
                    if uuid == p['uuid']:
                        return c

                    for vm in p.get('consumers', []):
                        if uuid == vm['uuid']:
                            return c

    def get_entity_groups(self, uuid, **kwargs):
        """Returns a list of groups the entity belongs to.

        Args:
            uuid (str): Entity UUID.

        Returns:
            A list containing groups the entity belongs to.
        """
        return self.request(f'entities/{uuid}/groups', **kwargs)

    def get_entity_stats(self, scope, start_date=None, end_date=None,
                         stats=None, related_type=None, dto=None, **kwargs):
        """Returns stats for the specific scope of entities.

        Provides entity level stats with filtering. If using the DTO keyword,
        all other parameters save kwargs will be ignored.

        Args:
            scope (list): List of entities to scope to.
            start_date (int, optional): Unix timestamp in miliseconds. Uses
                current time if blank.
            end_date (int, optional): Unix timestamp in miliseconds. Uses current
                time if blank.
            stats (list, optional): List of stats classes to retrieve.
            related_type (str, optional): Related entity type to pull stats for.
            dto (dict, optional): Complete JSON DTO of the stats required.

        Returns:
            A list of stats for all periods between start and end dates.
        """
        if dto is None:
            dto = {'scopes': scope}
            period = {}

            if start_date:
                period['startDate'] = start_date

            if end_date:
                period['endDate'] = end_date

            if stats:
                period['statistics'] = self._stats_filter(stats)

            if period:
                dto['period'] = period

            if related_type:
                dto['relatedType'] = related_type

        dto = json.dumps(dto)

        return self.request('stats', method='POST', dto=dto, **kwargs)

    # TODO: vmsByAltName is supposed to do this - broken
    def get_entity_by_remoteid(self, remote_id, target_name=None,
                               target_uuid=None, **kwargs):
        """Returns a list of entities from the real-time market for a given remoteId

        Args:
            remote_id (str): Remote id to lookup.
            target_name (str, optional): Name of Turbonomic target known to host
                the entity.
            target_uuid (str, optional): UUID of Turbonomic target known to host
                the entity.

        Returns:
            A list of entities in :obj:`dict` form.
        """
        entities = [deepcopy(x) for x in self.get_entities(**kwargs) if x.get('remoteId') == remote_id]

        if target_name and entities:
            entities = [deepcopy(x) for x in entities if x['discoveredBy']['displayName'] == target_name]

        if target_uuid and entities:
            entities = [deepcopy(x) for x in entities if x['discoveredBy']['uuid'] == target_uuid]

        return entities

    def get_groups(self, uuid=None, cache=False, **kwargs):
        """Returns a list of groups in the given market

        Args:
            uuid (str, optional): Specific UUID to lookup.
            cache (bool, optional): If true, will retrieve entities from the
                market cache. (default: ``False``)

        Returns:
            A list of groups in :obj:`dict` form.
        """
        if cache:
            groups = self.get_cached_inventory('__groups')

            if uuid:
                return [deepcopy(x) for x in groups if x['uuid'] == uuid]

            return groups

        return self.request('groups', uuid=uuid, **kwargs)

    def get_group_actions(self, uuid=None, **kwargs):
        """Returns a list of group actions.

        Args:
            uuid (str): Group UUID.

        Returns:
            A list containing all actions for the given the group.
        """
        return self.request(f'groups/{uuid}/actions', **kwargs)

    def get_group_by_name(self, name, **kwargs):
        """Returns the first group that match `name`.

        Args:
            name (str): Group name to lookup.

        Returns:
            A list containing the group in :obj:`dict` form.
        """
        groups = self.get_groups(**kwargs)

        for grp in groups:
            if grp['displayName'] == name:
                return [grp]

        return None

    def get_group_entities(self, uuid, cache=False, **kwargs):
        """Returns a detailed list of member entities that belong to the group.

        Args:
            uuid (str): Group UUID.
            cache (bool, optional): If true, will retrieve entities from the
                market cache. (default: ``False``)

        Returns:
            A list containing all members of the group and their related consumers.
        """
        if cache:
            return self.get_cached_inventory('__group_entities', uuid=uuid, **kwargs)

        return self.request(f'groups/{uuid}/entities', **kwargs)

    def get_group_members(self, uuid, cache=False, **kwargs):
        """Returns a list of members that belong to the group.

        Args:
            uuid (str): Group UUID.
            cache (bool, optional): If true, will retrieve entities from the
                market cache. (default: ``False``)

        Returns:
            A list containing all members of the group.
        """
        if cache:
            return self.get_cached_inventory('__group_members', uuid=uuid, **kwargs)

        return self.request(f'groups/{uuid}/members', **kwargs)

    def get_group_stats(self, uuid, stats_filter=None, start_date=None,
                        end_date=None, **kwargs):
        """Returns the aggregated statistics for a group.

        Args:
            uuid (str): Specific group UUID to lookup.
            stats_filter (list, optional): List of filters to apply.
            start_date (str, optional): Unix timestamp in miliseconds or relative
                time string.
            end_date (int, optional): Unix timestamp in miliseconds or relative
                time string.

        Returns:
            A list containing the group stats in :obj:`dict` form.
        """
        if stats_filter is None:
            return self.request(f'groups/{uuid}/stats', **kwargs)

        dto = {}

        if stats_filter:
            dto['statistics'] = self._stats_filter(stats_filter)

        if start_date:
            dto['startDate'] = start_date

        if end_date:
            dto['endDate'] = end_date

        dto = json.dumps(dto)

        return self.request(f'groups/{uuid}/stats', method='POST', dto=dto, **kwargs)

    def get_scenarios(self, uuid=None, **kwargs):
        """Returns a list of scenarios.

        Args:
            uuid (str, optional): Specific UUID to lookup.

        Returns:
            A list of scenarios in :obj:`dict` form.
        """
        return self.request('scenarios', uuid=uuid, **kwargs)

    def get_supplychains(self, uuids, types=None, states=None, detail=None,
                         environment=None, aspects=None, health=False, **kwargs):
        """Returns a set of supplychains for the given uuid.

        Args:
            uuids (list): List of UUIDs to query.
            types (list, optional): List of entity types.
            states: (list, optional): List of entity states to filter by.
            detail: (str, optional): Entity detail level.
            environment: (str, optional): Environment to filter by.
            aspects: (list, optional): List of entity aspects to filter by.
            health: (bool, optional): If ``True`` entity health information will
                included. (default: ``False``)
        """
        args = {
            'uuids': ','.join(uuids) if isinstance(uuids, list) else uuids,
            'types': ','.join(types) if types else None,
            'entity_states': ','.join(states) if states else None,
            'detail_type': detail,
            'environment_type': environment,
            'aspect_names': ','.join(aspects) if aspects else None,
            'health': health
        }

        return self.request('supplychains',
                            query={k:v for k,v in args.items() if v is not None},
                            **kwargs)

    def get_targets(self, uuid=None, **kwargs):
        """Returns a list of targets.

        Args:
            uuid (str, optional): Specific UUID to lookup.

        Returns:
            A list containing targets in :obj:`dict` form.
        """
        return self.request('targets', uuid=uuid, **kwargs)

    def get_target_for_entity(self, uuid=None, name=None,
                              type='VirtualMachine', **kwargs):
        """Returns a list of templates.

        Args:
            uuid (str, optional): Entity UUID to lookup.
            name (str, optional): Name to lookup.
            type (str, optional): Entity type for name based lookups (Default: `VirtualMachine`).

        Returns:
            A list of targets for an entity in :obj:`dict` form.

        Notes:
            Use of UUIDs is strongly encouraged to avoid collisions.
            Only one parameter is required. If both are supplied, **uuid** overrides.
            If a name lookup returns multiple entities, only the first is returned.
        """
        if uuid:
            entity = self.get_entities(uuid=uuid, **kwargs)[0]
        else:
            entity = self.search_by_name(name, type)[0]

        return self.request('targets', uuid=entity['discoveredBy']['uuid'], **kwargs)

    def get_templates(self, uuid=None, **kwargs):
        """Returns a list of templates.

        Args:
            uuid (str, optional): Specific UUID to lookup.

        Returns:
            A list containing templates in :obj:`dict` form.
        """
        return self.request('templates', uuid=uuid, **kwargs)

    def get_template_by_name(self, name, **kwargs):
        """Returns a template by name.

        Args:
            name (str): Name of the template.

        Returns:
            A list containing the template in :obj:`dict` form.
        """
        templates = self.get_templates(**kwargs)

        for tpl in templates:
            # not all contain displayName
            if 'displayName' in tpl and tpl['displayName'] == name:
                return [tpl]

    def add_group(self, dto):
        """Raw group creation method.

        Args:
            dto (str): JSON representation of the GroupApiDTO.

        Returns:
            Group object in :obj:`dict` form.

        See Also:
            https://turbonomic.github.io/vmt-connect/start.html#turbonomic-rest-api-guides
        """
        return self.request('groups', method='POST', dto=dto)

    def add_static_group(self, name, type, members=None):
        """Creates a static group.

        Args:
            name (str): Group display name.
            type (str): Group type.
            members (list): List of member UUIDs.

        Returns:
            Group object in :obj:`dict` form.
        """
        if members is None:
            members = []

        dto = {
            'displayName': name,
            'isStatic': True,
            'groupType': type,
            'memberUuidList': members
        }

        return self.add_group(json.dumps(dto))

    def add_static_group_members(self, uuid, members=None):
        """Add members to an existing static group.

        Args:
            uuid (str): UUID of the group to be updated.
            members (list): List of member entity UUIDs.

        Returns:
            The updated group definition.
        """
        if members is None:
            members = []

        group = self.get_group_members(uuid)
        ext = [x['uuid'] for x in group]

        return self.update_static_group_members(uuid, ext + members)

    def add_template(self, dto):
        """Creates a template based on the supplied DTO object.

        Args:
            dto (obj): Template definition

        Returns:
            Template object in :obj:`dict` form.
        """
        return self.request('/templates', method='POST', dto=dto)

    def del_group(self, uuid):
        """Removes a group.

        Args:
            uuid (str): UUID of the group to be removed.

        Returns:
            ``True`` on success, False otherwise.
        """
        return self.request('groups', method='DELETE', uuid=uuid)

    def del_market(self, uuid, scenario=False):
        """Removes a market, and optionally the associated scenario.

        Args:
            uuid (str): UUID of the market to be removed.
            scenario (bool, optional): If ``True`` will remove the scenario too.

        Returns:
            ``True`` on success, False otherwise.
        """
        if uuid in self.__system_market_ids:
            return False

        if scenario:
            try:
                self.del_scenario(self.get_markets(uuid)[0]['scenario']['uuid'])
            except Exception:
                pass

        return self.request('markets', method='DELETE', uuid=uuid)

    def del_scenario(self, uuid):
        """Removes a scenario.

        Args:
            uuid (str): UUID of the scenario to be removed.

        Returns:
            ``True`` on success, False otherwise.
        """
        return self.request('scenarios', method='DELETE', uuid=uuid)

    def search(self, **kwargs):
        """Raw search method.

        Provides a basic interface for issuing direct queries to the Turbonomic
        search endpoint. There are three sets of possible parameters, which must
        not be mixed.

        Args:
            Set
            q (str, optional): Query string.
            types (list): Types of entities to return. Must include either
                `types` or `group_type`.
            scopes (list, optional): Entities to scope to.
            state (str, optional): State filter.
            environment_type (str, optional): Environment filter.
            group_type (str): Group type filter. Must include either `types` or
                `group_type`.
            detail_type (str, optional): Entity detail filter.
            entity_types (list, optional): Member entity types filter.
            probe_types (list, optional): Target probe type filter.
            regex (bool, optional): Flag for regex query string searching.
            Set
            uuid (str): UUID of an object to lookup.
            Set
            dto (str): JSON representation of the StatScopesApiInputDTO.

        Returns:
            A list of search results.

        See Also:
            https://turbonomic.github.io/vmt-connect/start.html#turbonomic-rest-api-guides

            Search criteria list: `http://<host>/vmturbo/rest/search/criteria`
        """
        if 'uuid' in kwargs and kwargs.get('uuid') is not None:
            uuid = kwargs['uuid']
            del kwargs['uuid']
            return self.request('search', method='GET', uuid=uuid, **kwargs)

        if 'dto' in kwargs and kwargs.get('dto') is not None:
            dto = kwargs['dto']
            del kwargs['dto']
            return self.request('search', method='POST', dto=dto, **kwargs)

        query = {}
        remove = []
        args = ['q', 'types', 'scopes', 'state', 'environment_type', 'group_type',
        'detail_type', 'entity_types', 'regex', 'probe_types']

        for k in args:
            v = kwargs.get(k)
            if v is not None:
                if k in ['types', 'scopes', 'entity_types', 'probe_types']:
                    query[k] = ','.join(v)
                else:
                    query[k] = v

                remove += [k]

        for x in remove:
            del kwargs[x]

        return self.request('search', query=query, **kwargs)

    def search_by_name(self, name, type=None, case_sensitive=False,
                       from_cache=False, **kwargs):
        """Searches for an entity by name.

        Args:
            name (str): Display name of the entity to search for.
            type (str, optional): One or more entity classifications to aid in
                searching. If None, all types are searched via consecutive
                requests.
            case_sensitive (bool, optional): Search case sensitivity. (default: ``False``)
            from_cache (bool, optional): Uses the cached inventory if set. (default: ``False``)

        Notes:
            The option from_cache is deprecated, and will be removed in a future
            version. This is due primarily to large memory concerns on XL instances.
            Pagination should be used instead.

        Returns:
            A list of matching results.
        """
        results = []

        if type is None:
            search_classes = {x for x in _entity_filter_class.values()}
        elif isinstance(type, list):
            search_classes = [_entity_filter_class[x.lower()] for x in type]
        else:
            search_classes = [_entity_filter_class[type.lower()]]

        for fclass in search_classes:
            if from_cache:
                results += self._search_cache('Market', name, fclass, case_sensitive)
                continue

            try:
                sfilter = _class_filter_prefix[fclass] + 'ByName'
                criteria = self._search_criteria('EQ', name, sfilter, case_sensitive)
                dto = {'className': fclass, 'criteriaList': [criteria]}

                results += self.search(dto=json.dumps(dto))
            except Exception:
                pass

        return results

    def update_action(self, uuid, accept):
        """Update a manual action by accepting or rejecting it.

        Args:
             uuid (str): UUID of action to update.
             accept (bool): ``True`` to accept, or ``False`` to reject the action.

        Returns:
            None
        """
        return self.request('actions', method='POST', uuid=uuid,
                            query=f'accept={self._bool_to_text(accept)}'
        )


    def update_static_group_members(self, uuid, members, name=None, type=None):
        """Update static group members by fully replacing it.

        Args:
            uuid (str): UUID of the group to be updated.
            members (list): List of member entity UUIDs.
            name (str, optional): Display name of the group.
            type (str, optional): Ignored - kept for backwards compatibility

        Returns:
            The updated group definition.
        """
        group = self.get_groups(uuid)[0]
        name = name if name else group['displayName']

        dto = json.dumps({'displayName': name,
                          'groupType': group['groupType'],
                          'memberUuidList': members}
        )

        return self.request('groups', method='PUT', uuid=uuid, dto=dto)


class Session(Connection):
    """Alias for :py:class:`~Connection` to provide convenience.

    See :py:class:`~Connection` for parameter details.

    Notes:
        The value for the :py:class:`~Connection.session` property will always be set to ``True`` when using :py:class:`~Session`

    """
    def __init__(self, *args, **kwargs):
        kwargs['use_session'] = True
        super().__init__(*args, **kwargs)


class VMTConnection(Session):
    """Alias for :py:class:`~Connection` to provide backwards compatibility.

    See :py:class:`~Connection` for parameter details.

    Notes:
        The value for :py:class:`~Connection.session` will default to ``True``
        when using :py:class:`~VMTConnection`

    Warning:
        Deprecated. Use :py:class:`~Connection` or :py:class:`~Session`
        instead.
    """
    def __init__(self, *args, **kwargs):
        msg = 'This interface is deprecated. Use Connection or Session'
        warnings.warn(msg, DeprecationWarning)
        super().__init__(*args, **kwargs)



# ----------------------------------------------------
#  Utility functions
# ----------------------------------------------------
def enumerate_stats(data, entity=None, period=None, stat=None):
    """Provided as an alias for backwards compatibility only."""
    return util.enumerate_stats(data, entity, period, stat)


def __register_env(data):
    for k, v in data.items():
        try:
            ENV[k] = v
        except Exception as e:
            pass


def serialize_version(string, delim='.', minlen=4):
    comps = string.split(delim)
    serial = ''

    for x in range(minlen):
        try:
            serial += comps[x] if x < 1 else f"{int(comps[x]):>02d}"
        except IndexError:
            serial += '00'

    return serial



# ----------------------------------------------------
#  Load local environments if found
# ----------------------------------------------------
for file in [GLOBAL_ENV, SCRIPT_ENV]:
    try:
        with open(file, 'r') as fp:
            __register_env(json.load(fp))
    except Exception as e:
        pass
