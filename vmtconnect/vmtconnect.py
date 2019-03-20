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

import re
import warnings
import base64
import json
import requests
import datetime

from collections import defaultdict
from urllib.parse import urlunparse, urlencode

try:
    from enum import Enum
except ImportError:
    try:
        from aenum import Enum
    except ImportError:
        print('Critical failure: no enum module found')


_entity_filter_class = {
    'application': 'Application',
    'applicationserver': 'ApplicationServer',
    'database': 'Database',
    'db': 'Database',                       # for convenience
    'ds': 'Storage',                        # for convenience
    'diskarray': 'DiskArray',
    'cluster': 'Cluster',
    'group': 'Group',
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

_product_names = {
    'Cisco': 'cwom'
}

_version_mappings = {
    'cwom':  {
        '1.0': '5.8.3.1',
        '1.1': '5.9.1',
        '1.1.3': '5.9.3',
        '1.2.0': '6.0.3',
        '1.2.1': '6.0.6',
        '1.2.2': '6.0.9',
        '1.2.3': '6.0.11.1',
        '2.0.0': '6.1.1',
        '2.0.1': '6.1.6',
        '2.0.2': '6.1.8',
        '2.0.3': '6.1.12',
        '2.1.0': '6.2.2',
        '2.1.1': '6.2.7.1',
        '2.1.2': '6.2.10'
    }
}



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
        super(VMTVersionError, self).__init__(message)


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


class HTTPError(Exception):
    """Raised when an blocking or unknown HTTP error is returned."""
    pass


class HTTP401Error(HTTPError):
    """Raised when access fails, due to bad login or insufficient permissions."""
    pass


class HTTP404Error(HTTPError):
    """Raised when a requested resource cannot be located."""
    pass


class HTTP500Error(HTTPError):
    """Raised when an HTTP 500 error returned."""
    pass


class HTTP502Error(HTTP500Error):
    """Raised when an HTTP 502 Bad Gateway error is returned. In most cases this
    indicates a timeout issue with synchronous calls to Turbonomic and can be
    safely ignored."""
    pass


class HTTPWarn(Exception):
    """Raised when an HTTP error can always be safely ignored."""
    pass



# ----------------------------------------------------
#  API Wrapper Classes
# ----------------------------------------------------
class Version(object):
    """Turbonomic instance version object

    The :class:`~Version` object contains instance version information.

    Args:
        version: Version object returned by Turbonomic instance.
    """
    def __init__(self, version):
        keys = self.parse(version)

        for key in keys:
            setattr(self, key, keys[key])

    @staticmethod
    def map_version(name, version):
        try:
            return _version_mappings[name.lower()][version]
        except KeyError:
            raise VMTUnknownVersion

    @staticmethod
    def parse(obj):
        fields = ('version', 'branch', 'build', 'marketVersion')
        sep = '\n'
        ver = defaultdict(lambda : None)

        ver['product'] = re.search(r'^([\S]+)\s', obj['versionInfo']).group(1)
        ver['version'] = re.search(r'Manager ([\d.]+) \(Build \d+\)',
                                   obj['versionInfo']).group(1)

        for x in fields:
            if x in ('version', 'build', 'branch'):
                label = 'base_' + x
            else:
                label = x

            ver[label] = obj[x] if x in obj else None

        # backwards compatibility pre 6.1 white label version mapping
        # forward versions store this directly
        if 'branch' not in ver and 'version' not in ver:
            if ver['product'] in _product_names:
                ver['base_version'] = Version.map_version(
                                          _product_names[ver['product']],
                                          ver['version'])

        ver['components'] = obj['versionInfo'].rstrip(sep).split(sep)

        return ver


class VersionSpec(object):
    """Turbonomic version specification object

    The :class:`~VersionSpec` object contains version compatibility and
    requirements information. Versions must be in dotted format, and may
    optionally have a '+' postfix to indicate versions greater than or equal
    to are acceptable. If using '+', you only need to specify the minimum
    version required, as all later versions will be accepted independent of
    minor release branch. E.g. 6.0+ includes 6.1, 6.2, and all later branches.

    Examples:
        VersionSpec(['6.0+'], exclude=['6.0.1', '6.1.2', '6.2.5', '6.3.0'])

    Args:
        versions (list, optional): A list of acceptable versions.
        exclude (list, optional): A list of versions to explicitly exclude.
        required (bool, optional): If set to True, an error is thrown if no
            matching version is found when :method:`~VMTVersion.check` is run.
        cmp_base (bool, optional): If True, white label versions will be translated
            to their corresponding base Turbonomic version prior to comparison. If
            False, only the explicit product version will be compared. (Default: True)

    Notes:
        The Turbonomic API is not a versioned REST API, and each release is treated
        as if it were a separate API, while retaining the name of "API 2.0" to
        distinguish it from the "API 1.0" implementation available prior to the
        Turbonomic HTML UI released with v6.0 of the core product.
    """
    def __init__(self, versions=None, exclude=None, required=False, cmp_base=True):
        self.versions = versions or ['6.1.0+']  # API 2
        self.exclude = exclude or []
        self.required = required
        self.cmp_base = cmp_base

        try:
            self.versions.sort()
        except AttributeError:
            raise VMTFormatError('Invalid input format')

    @staticmethod
    def str_to_ver(string):
        string = string.strip('+')

        if not re.search(r'[\d.]+\d+', string) \
           or not string.replace('.', '').isdigit():
            raise VMTFormatError('Unrecognized version format')

        return string.split('.')

    @staticmethod
    def cmp_ver(a, b):
        a1 = VersionSpec.str_to_ver(a)
        b1 = VersionSpec.str_to_ver(b)

        for x in range(0, len(a1)):
            if int(a1[x]) > int(b1[x]):
                return 1
            elif int(a1[x]) < int(b1[x]):
                return -1

        return 0

    @staticmethod
    def _check(current, versions, required=True, warn=True):
        for v in versions:
            res = VersionSpec.cmp_ver(current, v)

            if (res > 0 and v[-1] == '+') or res == 0:
                return True

        if required:
            raise VMTVersionError()
        elif warn:
            warnings.warn('Your version of Turbonomic does not meet the ' \
                          'minimum recommended version. You may experience ' \
                          'unexpected errors, and are strongly encouraged to ' \
                          'upgrade.', VMTMinimumVersionWarning)

    def check(self, version):
        """Checks a :class:~`Version` for validity against the :class:`~VersionSpec`.

        Args:
            version (obj): The :class:~`Version` to check.

        Returns:
            True if valid, False if the version is excluded or not found.

        Exceptions:
            Raises :class:`VMTVersionError` if version requirement is not met.
        """
        # exclusion list gatekeeping
        if self.cmp_base:
            try:
                if version.base_version is None:
                    warnings.warn('Version does not contain a base version, using primary version as base.', VMTVersionWarning)
                    ver = version.version
                else:
                    ver = version.base_version

            except AttributeError:
                raise VMTVersionError('Urecognized version: {} {}'.format(
                                      version.product, version.version))
        else:
            ver = version.version

        # kick out on excluded version match
        if self._check(ver, self.exclude, required=False, warn=False):
            return False

        # return on explicit match
        if self._check(ver, self.versions, required=self.required):
            return True

        return False


class VMTVersion(VersionSpec):
    """Alias for :class:`~VersionSpec` to provide backwards compatibility.

    Notes:
        To be removed in a future branch.
    """
    def __init__(self, versions=None, exclude=None, require=False):
        super().__init__(versions=versions, exclude=exclude, required=require)


class Connection(object):
    """Turbonomic instance connection class

    Args:
        host (str, optional): The hostname or IP address to connect to. (default:
            `localhost`)
        username (str, optional): Username to authenticate with.
        password (str, optional): Password to authenticate with.
        auth (str, optional): Pre-encoded 'Basic Authentication' string which
            may be used in place of a ``username`` and ``password`` pair.
        base_url (str, optional): Base endpoint path to use. (default:
            `/vmturbo/rest/`)
        req_versions (:class:`VersionSpec`, optional): Versions requirements object.
        disable_hateoas (bool, optional): Removes HATEOAS navigation links.
            (default: `True`)
        ssl (bool, optional): Use SSL or not. (default: `True`)
        verify (string, optional): SSL certificate bundle path. (default: `False`)
        cert (string, optional): Local client side certificate file.
        headers (dict, optional): Dicitonary of additional persistent headers.
        use_session (bool, optional): If set to True, a :py:class:`Requests.Session`
            will be created, otherwise individual :py:class:`Requests.Request`
            calls will be made. (default: `True`)

    Attributes:
        disable_hateoas (bool): HATEOAS links state.
        headers (dict): Dictionary of custom headers for all calls.
        update_headers (dict): Dictionary of custom headers for put and post calls.
        version (str): Turbonomic instance version.

    Notes:
        The default minimum version has been bumped up to Turbonomic 6.1.x. Using a previous version will trigger a version warning. To avoid this warning, you will need to explicitly pass in a :class:`~VMTVersionSpec` object for the version desired.
        Beginning with v6.0 of Turbonomic, HTTP redirects to a self-signed HTTPS connection. Because of this, vmt-connect defaults to using SSL. Versions prior to 6.0 using HTTP will need to manually set ssl to False.
        If verify is given a path to a directory, the directory must have been processed using the c_rehash utility supplied with OpenSSL.
        For client side certificates using `cert`: the private key to your local certificate must be unencrypted. Currently, Requests does not support using encrypted keys.
        Requests uses certificates from the package certifi.
    """
    # system level markets to block certain actions
    # this is done by name, and subject to breaking if names are abused
    __system_markets = ['Market', 'Market_Default']
    __system_market_ids = []

    def __init__(self, host=None, username=None, password=None, auth=None,
                 base_url=None, req_versions=None, disable_hateoas=True,
                 ssl=True, verify=False, cert=None, headers=None, use_session=False):

        if use_session:
            self.__session = requests.Session()

            # possible fix for urllib3 connection timing issue - https://github.com/requests/requests/issues/4664
            adapter = requests.adapters.HTTPAdapter(max_retries=3)
            self.__session.mount('http://', adapter)
            self.__session.mount('https://', adapter)

            self.__conn = self.__session.request
        else:
            self.__session = False
            self.__conn = requests.request

        self.host = host or 'localhost'
        self.base_path = base_url or '/vmturbo/rest/'
        self.protocol = 'https' if ssl else 'http'
        self.disable_hateoas = disable_hateoas

        self.__verify = verify
        self.__version = None
        self.__req_ver = isinstance(req_versions, VersionSpec) or VersionSpec()

        self.__cert = cert
        self.headers = headers or {}
        self.update_headers = {'Content-Type': 'application/json'}

        # set auth encoding
        if auth:
            try:
                self.__basic_auth = auth.encode()
            except AttributeError:
                self.__basic_auth = auth
        elif (username and password):
            self.__basic_auth = base64.b64encode('{}:{}'.format(
                username, password).encode())
        else:
            raise VMTConnectionError('Missing credentials')


        # XL will use tokens, not yet available in 6.x
        # because we accept encoded credentials, we'll manually attach here
        self.headers.update(
            {'Authorization': u'Basic {}'.format(self.__basic_auth.decode())}
        )

        # verify version
        self.__req_ver.check(self.version)

        self.__get_system_markets()
        self.__market_uuid = self.get_markets(uuid='Market')[0]['uuid']

        # for inventory caching - used to prevent thrashing the API with
        # repeated calls for full inventory lookups within some expensive calls
        self.__inventory_cache = None
        self.__inventory_cache_timeout = 600
        self.__inventory_cache_expires = datetime.datetime.now()

    def _request(self, method, resource, query='', dto=None, **kwargs):
        method = method.upper()
        url = urlunparse((self.protocol, self.host,
                          self.base_path + resource.lstrip('/'), '', query, ''))

        kwargs['verify'] = self.__verify

        if method in ('POST', 'PUT'):
            if 'headers' in kwargs:
                kwargs['headers'] = {**kwargs['headers'], **self.headers, **self.update_headers}
            else:
                kwargs['headers'] = {**self.headers, **self.update_headers}

            return self.__conn(method, url, data=dto, **kwargs)
        else:
            return self.__conn(method, url, **kwargs)

    def request(self, path, method='GET', query='', dto=None, uuid=None, **kwargs):
        """Constructs and sends an appropriate HTTP request.

        Args:
            path (str): API resource to utilize, relative to `base_path`.
            method (str, optional): HTTP method to use for the request. (default: GET)
            query (str, optional): Query string parameters to attach.
            dto (str, optional): Data transfer object to send to the server.
            uuid (str, optional): Turbonomic object UUID to operate on.
            **kwargs: Additional :py:class:`Requests.Request` keyword arguments.
        """
        if uuid is not None:
            path = '{}/{}'.format(path, uuid)

        # attempt to detect a misdirected POST
        if dto is not None and method == 'GET':
            method = 'POST'

        if method == 'GET' and self.disable_hateoas:
            query += ('&' if query != '' else '') + 'disable_hateoas=true'

        msg = ''
        response = self._request(method=method, resource=path, query=query,
                                 dto=dto, **kwargs)

        try:
            res = response.json()

            if response.status_code/100 != 2:
                msg = ': [{}]'.format(res['exception'])
        except Exception:
            pass

        if response.status_code == 502:
            raise HTTP502Error('(API) HTTP 502 - Bad Gateway{}'.format(msg))
        elif response.status_code == 401:
            raise HTTP401Error('(API) HTTP 401 - Unauthorized{}'.format(msg))
        elif response.status_code == 404:
            raise HTTP404Error('(API) HTTP 404 - Resource Not Found{}'.format(msg))
        elif response.status_code/100 == 5:
            raise HTTP500Error('(API) HTTP {} - Server Error{}'.format(response.status_code, msg))
        elif response.status_code/100 != 2:
            raise HTTPError('(API) HTTP Code {} returned{}'.format(response.status_code, msg))
        elif response.text == 'true':
            return True
        elif response.text == 'false':
            return False
        else:
            return [res] if isinstance(res, dict) else res

    @staticmethod
    def _bool_to_text(value):
        value = 'true' if value else 'false'

        return value

    @staticmethod
    def _search_criteria(op, value, filter_type, case_sensitive=False):
        if op in _exp_type:
            op = _exp_type[op]

        criteria = {
            'expType': op,
            'expVal': value,
            'caseSensitive': case_sensitive,
            'filterType': filter_type
        }

        return criteria

    @staticmethod
    def _stats_filter(stats):
        statistics = []
        for stat in stats:
            statistics += [{'name': stat}]

        return statistics

    @property
    def version(self):
        if self.__version is None:
            self.__version = Version(self.request('admin/versions')[0])

        return self.__version

    def __is_cache_valid(self):
        if datetime.datetime.now() <= self.__inventory_cache_expires and \
           self.__inventory_cache is not None:
            return True

        return False

    def __get_system_markets(self):
        res = self.get_markets()
        self.__system_market_ids = [x['uuid'] for x in res if x['displayName'] in self.__system_markets]

    def _search_cache(self, name, type=None, case_sensitive=False):
        results = []
        self.get_cached_inventory()

        for e in self.__inventory_cache:
            if (case_sensitive and e['displayName'] != name) or \
               (e['displayName'].lower() != name.lower()):
                continue
            if type and e['className'] != type:
                continue

            results += [e]

        return results

    def get_actions(self, market='Market', uuid=None):
        """Returns a list of actions.

        The get_actions method returns a list of actions from a given market,
        or can be used to lookup a specific action by its uuid. The options are
        mutually exclusive, and a uuid will override a market lookup. If neither
        parameter is provided, all actions from the real-time market will be listed.

        Args:
            market (str, optional): The market to list actions from
            uuid (str, optional): Specific UUID to lookup.

        Returns:
            A list of actions
        """
        if uuid is not None:
            return self.request('actions', uuid=uuid)

        return self.request('markets/{}/actions'.format(market))

    def get_cached_inventory(self):
        """Returns the market entities inventory from cache, populating the
        cache if necessary.
        """
        if not self.__is_cache_valid():
            delta = datetime.timedelta(seconds=self.__inventory_cache_timeout)
            self.__inventory_cache = self.request('markets/Market/entities')
            self.__inventory_cache_expires = datetime.datetime.now() + delta

        return self.__inventory_cache

    def get_current_user(self):
        """Returns the current user.

        Returns:
            A list of one user object in :obj:`dict` form.
        """
        return self.request('users/me')

    def get_users(self, uuid=None):
        """Returns a list of users.

        Args:
            uuid (str, optional): Specific UUID to lookup.

        Returns:
            A list of user objects in :obj:`dict` form.
        """
        return self.request('users', uuid=uuid)

    def get_markets(self, uuid=None):
        """Returns a list of markets.

        Args:
            uuid (str, optional): Specific UUID to lookup.

        Returns:
            A list of markets in :obj:`dict` form.
        """
        return self.request('markets', uuid=uuid)

    def get_market_state(self, uuid='Market'):
        """Returns the state of a market.

        Args:
            uuid (str, optional): Market UUID. (default: `Market`)

        Returns:
            A string representation of the market state.
        """
        return self.get_markets(uuid)[0]['state']

    def get_market_stats(self, uuid='Market', filter=None):
        """Returns a list of market statistics.

        Args:
            uuid (str, optional): Market UUID. (default: `Market`)
            filter (dict, optional): DTO style filter to limit stats returned.

        Returns:
            A list of stat objects in :obj:`dict` form.
        """
        if filter is not None:
            self.request('markets/{}/stats'.format(uuid), method='POST', dto=filter)

        return self.request('markets/{}/stats'.format(uuid))

    def get_entities(self, type=None, uuid=None, market='Market'):
        """Returns a list of entities in the given market.

        Args:
            type (str, optional): Entity type to filter on.
            uuid (str, optional): Specific UUID to lookup.
            market (str, optional): Market to query. (default: `Market`)

        Returns:
            A list of entities in :obj:`dict` form.

        """
        if uuid is not None:
            path = 'entities/{}'.format(uuid)
        elif market == 'Market' or market == self.__market_uuid:
            path = False
        else:
            path = 'markets/{}/entities'.format(market)

        if not path:
            entities = self.get_cached_inventory()
        else:
            entities = self.request(path)

        if type is not None:
            return [x for x in entities if x['className'] == type]
        else:
            return entities

    def get_virtualmachines(self, uuid=None, market='Market'):
        """Returns a list of virtual machines in the given market.

        Args:
            uuid (str, optional): Specific UUID to lookup.
            market (str, optional): Market to query. (default: `Market`)

        Returns:
            A list of virtual machines in :obj:`dict` form.
        """
        return self.get_entities('VirtualMachine', uuid=uuid, market=market)

    def get_physicalmachines(self, uuid=None, market='Market'):
        """Returns a list of hosts in the given market.

        Args:
            uuid (str, optional): Specific UUID to lookup.
            market (str, optional): Market to query. (default: `Market`)

        Returns:
            A list of hosts in :obj:`dict` form.
        """
        return self.get_entities('PhysicalMachine', uuid=uuid, market=market)

    def get_datacenters(self, uuid=None, market='Market'):
        """Returns a list of datacenters in the given market.

        Args:
            uuid (str, optional): Specific UUID to lookup.
            market (str, optional): Market to query. (default: `Market`)

        Returns:
            A list of datacenters in :obj:`dict` form.
        """
        return self.get_entities('DataCenter', uuid=uuid, market=market)

    def get_datastores(self, uuid=None, market='Market'):
        """Returns a list of datastores in the given market.

        Args:
            uuid (str, optional): Specific UUID to lookup.
            market (str, optional): Market to query. (default: `Market`)

        Returns:
            A list of datastores in :obj:`dict` form.
        """
        return self.get_entities('Storage', uuid=uuid, market=market)

    def get_entity_groups(self, uuid):
        """Returns a list of groups the entity belongs to.

        Args:
            uuid (str): Entity UUID.

        Returns:
            A list containing groups the entity belongs to.
        """
        return self.request('entities/{}/groups'.format(uuid))

    def get_entity_stats(self, scope, start_date=None, end_date=None,
                         stats=None):
        """Returns stats for the specific scope of entities.

        Provides entity level stats with filtering.

        Args:
            scope (list): List of entities to scope to.
            start_date (int): Unix timestamp in miliseconds. Uses current time
                if blank.
            end_date (int): Unix timestamp in miliseconds. Uses current time if
                blank.
            stats (list): List of stats classes to retrieve.

        Returns:
            A list of stats for all periods between start and end dates.
        """
        dto = {'scopes': scope}

        period = {}
        if start_date is not None:
            period['startDate'] = start_date
        if end_date is not None:
            period['endDate'] = end_date
        if stats is not None and len(stats) > 0:
            period['statistics'] = self._stats_filter(stats)

        if len(period) > 0:
            dto['period'] = period

        dto = json.dumps(dto)

        return self.request('stats', method='POST', dto=dto)

    # TODO: vmsByAltName is supposed to do this - broken
    def get_entity_by_remoteid(self, remote_id, target_name=None, target_uuid=None):
        """Returns a list of entities from the real-time market for a given remoteId

        Args:
            remote_id (str): Remote id to lookup.
            target_name (str, optional): Name of Turbonomic target known to host the entity.
            target_uuid (str, optional): UUID of Turbonomic target known to host the entity.

        Returns:
            A list of entities in :obj:`dict` form.
        """
        entities = self.get_entities()
        entities = [x for x in entities if 'remoteId' in x and x['remoteId'] == remote_id]

        if target_name is not None:
            entities = [x for x in entities if x['discoveredBy']['displayName'] == target_name]

        if target_uuid is not None:
            entities = [x for x in entities if x['discoveredBy']['uuid'] == target_uuid]

        return entities

    def get_groups(self, uuid=None):
        """Returns a list of groups in the given market

        Args:
            uuid (str, optional): Specific UUID to lookup.

        Returns:
            A list of groups in :obj:`dict` form.
        """
        return self.request('groups', uuid=uuid)

    def get_group_by_name(self, name):
        """Returns the first group that match `name`.

        Args:
            name (str): Group name to lookup.

        Returns:
            A list containing the group in :obj:`dict` form.
        """
        groups = self.get_groups()

        for grp in groups:
            if grp['displayName'] == name:
                return [grp]

    def get_group_members(self, uuid):
        """Returns a list of member entities that belong to the group.

        Args:
            uuid (str): Group UUID.

        Returns:
            A list containing all members of the group, of the appropriate group
            type.
        """
        return self.request('groups/{}/members'.format(uuid))

    def get_group_stats(self, uuid, stats_filter=None):
        """Returns the aggregated statistics for a group.

        Args:
            uuid (str): Specific group UUID to lookup.
            stats_filter (list): List of filters to apply.

        Returns:
            A list containing the group stats in :obj:`dict` form.
        """
        if stats_filter is None:
            return self.request('groups/{}/stats'.format(uuid))

        dto = json.dumps({'statistics': self._stats_filter(stats_filter)})

        return self.request('groups/{}/stats'.format(uuid), method='POST', dto=dto)

    def get_scenarios(self, uuid=None):
        """Returns a list of scenarios.

        Args:
            uuid (str, optional): Specific UUID to lookup.

        Returns:
            A list of scenarios in :obj:`dict` form.
        """
        return self.request('scenarios', uuid=uuid)

    def get_targets(self, uuid=None):
        """Returns a list of targets.

        Args:
            uuid (str, optional): Specific UUID to lookup.

        Returns:
            A list containing targets in :obj:`dict` form.
        """
        return self.request('targets', uuid=uuid)

    def get_target_for_entity(self, uuid=None, name=None, type='VirtualMachine'):
        """Returns a list of templates.

        Args:
            uuid (str, optional): Entity UUID to lookup.
            name (str, optional): Name to lookup.
            type (str, optional): Entity type for name based lookups (Default: VirtualMachine).

        Returns:
            A list of targets for an entity in :obj:`dict` form.

        Notes:
            Use of UUIDs is strongly encouraged to avoid collisions.
            Only one parameter is required. If both are supplied, uuid overrides.
            If a name lookup returns multiple entities, only the first is returned.
        """
        if uuid is not None:
            entity = self.get_entities(uuid=uuid)
        else:
            entity = self.search_by_name(name, type)

        return self.request('targets', uuid=entity[0]['discoveredBy']['uuid'])

    def get_templates(self, uuid=None):
        """Returns a list of templates.

        Args:
            uuid (str, optional): Specific UUID to lookup.

        Returns:
            A list containing templates in :obj:`dict` form.
        """
        return self.request('templates', uuid=uuid)

    def get_template_by_name(self, name):
        """Returns a template by name.

        Args:
            name (str): Name of the template.

        Returns:
            A list containing the template in :obj:`dict` form.
        """
        templates = self.get_templates()

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
            REST API Guide `5.9 <https://cdn.turbonomic.com/wp-content/uploads/docs/VMT_REST2_API_PRINT.pdf>`_, `6.0 <https://cdn.turbonomic.com/wp-content/uploads/docs/Turbonomic_REST_API_PRINT_60.pdf>`_
        """
        return self.request('groups', method='POST', dto=dto)

    def add_static_group(self, name, type, members=None):
        """Creates a static group.

        Args:
            name (str): Group display name.
            type (str): Group type.
            members (list): List of member UUIDs.

        Returns:
            Group object :obj:`dict` form.
        """
        if members is None:
            members = []

        dto = {'displayName': name,
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

        group = self.get_groups(uuid)[0]
        members.extend(group['memberUuidList'])

        dto = json.dumps({'displayName': group['displayName'],
                          'groupType': group['groupType'],
                          'memberUuidList': members}
        )

        return self.request('groups', method='PUT', uuid=uuid, dto=dto)

    def del_group(self, uuid):
        """Removes a group.

        Args:
            uuid (str): UUID of the group to be removed.

        Returns:
            True on success, False otherwise.
        """
        return self.request('groups', method='DELETE', uuid=uuid)

    def del_market(self, uuid, scenario=False):
        """Removes a market, and optionally the associated scenario.

        Args:
            uuid (str): UUID of the market to be removed.
            scenario (bool, optional): If True will remove the scenario too.

        Returns:
            True on success, False otherwise.
        """
        if uuid in self.__system_market_ids:
            return False

        if scenario:
            try:
                market = self.get_markets(uuid)
                self.del_scenario(market['scenario']['uuid'])
            except Exception as e:
                pass

        return self.request('markets', method='DELETE', uuid=uuid)

    def del_scenario(self, uuid):
        """Removes a scenario.

        Args:
            uuid (str): UUID of the scenario to be removed.

        Returns:
            True on success, False otherwise.
        """
        return self.request('scenarios', method='DELETE', uuid=uuid)

    def search(self, dto=None, q=None, types=None, scopes=None, state=None, group_type=None):
        """Raw search method.

        Provides a basic interface for issuing direct queries to the Turbonomic
        search endpoint.

        Args:
            dto (str, optional): JSON representation of the StatScopesApiInputDTO.

            q (str, optional): Query string.
            types (list, optional): Types of entities to return.
            scopes (list, optional): Entities to scope to.
            state (str, optional): State filter.
            group_type (str, optional): Group type filter.

        Returns:
            A list of search results.

        See Also:
            REST API Guide `5.9 <https://cdn.turbonomic.com/wp-content/uploads/docs/VMT_REST2_API_PRINT.pdf>`_, `6.0 <https://cdn.turbonomic.com/wp-content/uploads/docs/Turbonomic_REST_API_PRINT_60.pdf>`_

            Search criteria list: `http://<host>/vmturbo/rest/search/criteria`
        """
        if dto is not None:
            return self.request('search', method='POST', dto=dto)

        query = {}
        vars = {'q': q, 'types': types, 'scopes': scopes, 'state': state, 'group_type': group_type}

        for v in vars.keys():
            if vars[v] is not None:
                if v[-1] == 's':
                    query[v] = ','.join(vars[v])
                else:
                    query[v] = vars[v]

        return self.request('search', query=urlencode(query))

    def search_by_name(self, name, type=None, case_sensitive=False, from_cache=False):
        """Searches for an entity by name.

        Args:
            name (str): Display name of the entity to search for.
            type (str, optional): One or more entity classifications to aid in
                searching. If None, all types are searched via consecutive
                requests.
            case_sensitive (bool, optional): Search case sensitivity. (default: `False`)
            from_cache (bool, optional): Uses the cached inventory if set. (default: `False`)

        Returns:
            A list of matching results.
        """
        results = []

        if type is None:
            search_classes = set([x for x in _entity_filter_class.values()])
        elif isinstance(type, list):
            search_classes = [_entity_filter_class[x.lower()] for x in type]
        else:
            search_classes = [_entity_filter_class[type.lower()]]

        for fclass in search_classes:
            if from_cache:
                results += self._search_cache(name, fclass, case_sensitive)
                continue

            try:
                sfilter = _class_filter_prefix[fclass] + 'ByName'
                criteria = self._search_criteria('EQ', name, sfilter, case_sensitive)
                dto = {'className': fclass, 'criteriaList': [criteria]}

                results += self.search(json.dumps(dto))
            except:
                pass

        return results

    def update_action(self, uuid, accept):
        """Update a manual action by accepting or rejecting it.

        Args:
             uuid (str): UUID of action to update.
             accept (bool): True to accept, or False to reject the action.

        Return:
            None
        """
        return self.request('actions', method='POST', uuid=uuid,
                            query='accept={}'.format(self._bool_to_text(accept))
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
        name = name if name is not None else group['displayName']

        dto = json.dumps({'displayName': name,
                          'groupType': group['groupType'],
                          'memberUuidList': members}
        )

        return self.request('groups', method='PUT', uuid=uuid, dto=dto)


class Session(Connection):
    """Alias for :class:`~Connection` to provide convenience.

    See :class:`~Connection` for parameter details.

    Notes:
        The value for `session` will always be set to `True` when using :class:`~Session`

    """
    def __init__(self, *args, **kwargs):
        kwargs['use_session'] = True
        super().__init__(*args, **kwargs)


class VMTConnection(Session):
    """Alias for :class:`~Connection` to provide backwards compatibility.

    See :class:`~Connection` for parameter details.

    Notes:
        The value for `session` will default to `True` when using :class:`~VMTConnection`
        To be removed in a future branch.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
