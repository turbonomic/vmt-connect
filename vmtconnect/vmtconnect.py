from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import re
import warnings
import base64
import json
import requests

try:
  from urllib.parse import urlunparse, urlencode
except:
  from urlparse import urlunparse


__version__ = '1.2.1'
__all__ = [
    'VMTConnectionError',
    'HTTPError',
    'HTTP404Error',
    'HTTP500Error',
    'HTTP502Error',
    'HTTPWarn',
    'VMTRawConnection',
    'VMTConnection',
    'VMTVersionError',
    'VMTFormatError'
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



## ----------------------------------------------------
##  Error Classes
## ----------------------------------------------------
class VMTConnectionError(Exception):
    """Base connection exception class."""
    pass


class VMTVersionError(Exception):
    """Versions Error"""
    def __init__(self, message=None):
        if message is None:
            message = 'Your version of Turbonomic does not meet the minimum ' \
                      'required version for this program to run.'
        super(VMTVersionError, self).__init__(message)


class VMTFormatError(Exception):
    """Generic format error"""
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
class VMTVersion(object):
    """Turbonomic version specification object

    The :class:`~VMTVersion` object contains version compatibility and
    requirements information. Versions must be in three-dotted semantic format,
    and may optionally have a '+' postfix to indicate versions greater than or
    equal to are acceptable. If using '+', you only need to specify the minimum
    version required, as all later versions will be accepted independent of minor
    release branch. E.g. 5.7.0+ includes 5.8 and 5.9 branches.

    Examples:
        VMTVersion(['5.7.0+'], exclude=['5.7.5', '5.8.0', '5.8.1', '5.9.0'])

    Args:
        versions (list, optional): A list of acceptable versions.
        exclude (list, optional): A list of versions to explicitly exclude.
        require (bool, optional): If set to True, an error is thrown if no
            matching version is found when :method:`~VMTVersion.check` is run.
    """
    def __init__(self, versions=None, exclude=None, require=True):
        self.versions = versions or ['5.7.0+']  # API 2
        self.exclude = exclude or []
        self.require = require

        self.versions.sort()

    @staticmethod
    def str_to_ver(string):
        string = string.strip('+')

        if string.count('.') != 2 or string.count('-') > 0 \
           or not string.replace('.', '').isdigit():
            raise VMTFormatError('Incorrect version format')

        return string.split('.')

    @staticmethod
    def cmp_ver(a, b):
        a1 = VMTVersion.str_to_ver(a)
        b1 = VMTVersion.str_to_ver(b)

        for x in range(0, 3):
            if int(a1[x]) > int(b1[x]):
                return 1
            elif int(a1[x]) < int(b1[x]):
                return -1

        return 0

    @staticmethod
    def _check(current, versions, require=True, warn=True):
        for v in versions:
            res = VMTVersion.cmp_ver(current, v)

            if (res > 0 and v[-1] == '+') or res == 0:
                return True

        if require:
            raise VMTVersionError()
        elif warn:
            warnings.warn('Your version of Turbonomic does not meet the ' \
                          ' minimum recommended version. You may experience ' \
                          'unexpected errors, and are strongly encouraged to ' \
                          'upgrade.')

        return False

    def min(self):
        return self.versions[0].strip('+')

    def check(self, version):
        """Checks a version number for validity

        Args:
            version (str): The version to check.

        Returns:
            True if valid, False if the version is excluded or not found.

        Exceptions:
            Raises :class:`VMTVersionError` if version requirement is not met.
        """
        if self._check(version, self.exclude, require=False, warn=False):
            return False

        if self._check(version, self.versions, require=self.require):
            return True

        return False


class VMTRawConnection(object):
    """A basic stateless connection to a Turbonomic instance. This connection
    returns the whole :class:`requests.Response` object, without post-processing.

    Args:
        host (str, optional): The hostname or IP address to connect to. (default:
            `localhost`)
        username (str, optional): Username to authenticate with.
        password (str, optional): Password to authenticate with.
        auth (str, optional): Pre-encoded 'Basic Authentication' string which
            may be used in place of a ``username`` and ``password`` pair.
        base_url (str, optional): Base endpoint path to use. (default:
            `/vmturbo/rest/`)
        ssl (bool, optional): Use SSL or not. (default: `False`)

    Attributes:
        host: Hostname or IP address connected to.
        base_url: Base endpoint path used.
        response: :obj:`requests.Response` object.
        headers: Dictionary of headers to send with each request.
        protocol: Service protocol to use (HTTP, or HTTPS).
    """
    def __init__(self, host=None, username=None, password=None, auth=None,
                 base_url=None, ssl=False):
        self.__username = username
        self.__password = password
        self.__basic_auth = auth
        self.host = host or 'localhost'
        self.base_path = base_url or '/vmturbo/rest/'
        self.response = None
        self.protocol = 'http'

        # set auth encoding
        if not self.__basic_auth and (self.__username and self.__password):
            self.__basic_auth = base64.b64encode('{}:{}'.format(self.__username,
                                                                self.__password).encode())

        self.__username = self.__password = None
        self.headers = {'Authorization': u'Basic {}'.format(self.__basic_auth.decode())}

        if ssl:
            self.protocol = 'https'

    def request(self, resource, method='GET', query='', dto=None, **kwargs):
        """Constructs and sends an appropriate HTTP request.

        Args:
            resource (str): API resource to utilize, relative to `base_path`.
            method (str, optional): HTTP method to use for the request. (default: GET)
            query (str, optional): Query string to use.
            dto (str, optional): Data transfer object to send to the server.
            **kwargs: Arbitrary keyword arguments.
        """
        if 'headers' in kwargs:
            kwargs['headers'].update(self.headers)
        else:
            kwargs['headers'] = self.headers

        url = urlunparse((self.protocol, self.host,
                          self.base_path + resource.lstrip('/'), '', query, ''))

        for case in [method.upper()]:
            if case == 'POST':
                if 'Content-Type' not in kwargs['headers']:
                    kwargs['headers'].update({'Content-Type': 'application/json'})

                self.response = requests.post(url, data=dto, **kwargs)
                break
            if case == 'PUT':
                self.response = requests.put(url, **kwargs)
                break
            if case == 'DELETE':
                self.response = requests.delete(url, **kwargs)
                break

            # default is GET
            self.response = requests.get(url, **kwargs)

        return self.response


class VMTConnection(VMTRawConnection):
    """A wrapper for :class:`VMTRawConnection` with additional helper methods.

    Args:
        host (str, optional): The hostname or IP address to connect to. (default:
            `localhost`)
        username (str, optional): Username to authenticate with.
        password (str, optional): Password to authenticate with.
        auth (str, optional): Pre-encoded 'Basic Authentication' string which
            may be used in place of a ``username`` and ``password`` pair.
        base_url (str, optional): Base endpoint path to use. (default:
            `/vmturbo/rest/`)
        ssl (bool, optional): Use SSL or not. (default: `False`)
        version (:class:`VMTVersion`, optional): Versions requirements object.

    Attributes:
        version (str): Turbonomic instance version.
    """

    # system level markets to block certain actions
    # this is done by name, and subject to breaking if names are abused
    __system_markets = ['Market', 'Market_Default']
    __system_market_ids = []

    def __init__(self, host=None, username=None, password=None, auth=None,
                 base_url=None, ssl=False, versions=None):
        super(VMTConnection, self).__init__(host, username, password, auth,
              base_url=base_url, ssl=ssl)

        self.__version = None
        self.__req_ver = versions or VMTVersion()
        self.__req_ver.check(self.version)
        self.__get_system_markets()

    def request(self, path, method='GET', query='', dto=None, uuid=None, **kwargs):
        """Provides the same functionality as :meth:`VMTRawConnection.request`
        with error checking and output deserialization.
        """
        if uuid is not None:
            path = '{}/{}'.format(path, uuid)

        # attempt to detect a POST
        if dto is not None and method == 'GET':
            method = 'POST'

        response = super(VMTConnection, self).request(resource=path,
                                                      method=method,
                                                      query=query,
                                                      dto=dto,
                                                      **kwargs)

        if response.status_code == 502:
            raise HTTP502Error('(API) HTTP 502 - Bad Gateway')
        elif response.status_code == 401:
            raise HTTP401Error('(API) HTTP 401 - Unauthorized (bad login or no permissions to resource)')
        elif response.status_code == 404:
            raise HTTP404Error('(API) HTTP 404 - Resource Not Found')
        elif response.status_code/100 == 5:
            raise HTTP500Error('(API) HTTP %s - Server Error' % (response.status_code))
        elif response.status_code/100 != 2:
            raise HTTPError('(API) HTTP Code %s returned' % (response.status_code))
        elif response.text == 'true':
            return True
        elif response.text == 'false':
            return False
        else:
            res = response.json()
            return [res] if isinstance(res, dict) else res

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
            self.__version = self._get_ver()

        return self.__version

    def _get_ver(self):
        res = self.request('admin/versions')[0]
        try:
            return re.search('Manager (\d+\.\d+\.\d+) \(Build \d+\)',
                             res['versionInfo']).group(1)
        except:
            return None

    def __get_system_markets(self):
        res = self.get_markets()
        self.__system_market_ids = [x['uuid'] for x in res if x['displayName'] in self.__system_markets]

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
        return self.get_markets(uuid)['state']

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
        """
        if uuid is not None:
            path = 'entities/{}'.format(uuid)
        else:
            path = 'markets/{}/entities'.format(market)

        entities = self.request(path)

        if type is not None:
            return [x for x in entities if x['className'] == type]
        else:
            return entities

    def get_virtualmachines(self, uuid=None, market='Market'):
        """Returns a list of virtual machines in the given market

        Args:
            uuid (str, optional): Specific UUID to lookup.
            market (str, optional): Market to query. (default: `Market`)

        Returns:
            A list of virtual machines in :obj:`dict` form.
        """
        return self.get_entities('VirtualMachine', uuid=uuid, market=market)

    def get_physicalmachines(self, uuid=None, market='Market'):
        """Returns a list of hosts in the given market

        Args:
            uuid (str, optional): Specific UUID to lookup.
            market (str, optional): Market to query. (default: `Market`)

        Returns:
            A list of hosts in :obj:`dict` form.
        """
        return self.get_entities('PhysicalMachine', uuid=uuid, market=market)

    def get_datacenters(self, uuid=None, market='Market'):
        """Returns a list of datacenters in the given market

        Args:
            uuid (str, optional): Specific UUID to lookup.
            market (str, optional): Market to query. (default: `Market`)

        Returns:
            A list of datacenters in :obj:`dict` form.
        """
        return self.get_entities('DataCenter', uuid=uuid, market=market)

    def get_datastores(self, uuid=None, market='Market'):
        """Returns a list of datastores in the given market

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
            `5.9 REST API Guide (JSON) <https://cdn.turbonomic.com/wp-content/uploads/docs/VMT_REST2_API_PRINT.pdf>`_
        """
        return self.request('groups', method='POST', dto=dto)

    def add_static_group(self, name, type, members=[]):
        """Creates a static group.

        Args:
            name (str): Group display name.
            type (str): Group type.
            members (list): List of member UUIDs.

        Returns:
            Group object :obj:`dict` form.
        """
        dto = {'displayName': name,
               'isStatic': True,
               'groupType': type,
               'memberUuidList': members
               }

        return self.add_group(dto)

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
            `5.9 REST API Guide (JSON) <https://cdn.turbonomic.com/wp-content/uploads/docs/VMT_REST2_API_PRINT.pdf>`_
            Search criteria list: `http://<host>/vmturbo/rest/search/criteria`_
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

    def search_by_name(self, name, type=None, case_sensitive=False):
        """Searches for an entity by name.

        Args:
            name (str): Display name of the entity to search for.
            type (str, optional): An entity classification to aid in searching.
                If None, all types are searched via consecutive requests.
            case_sensitive (bool, optional): Search case sensitivity. (default: False)

        Returns:
            A list of matching results.
        """
        results = []

        if type is None:
            search_classes = set([x for x in _entity_filter_class.values()])
        else:
            search_classes = [_entity_filter_class[type.lower()]]

        for fclass in search_classes:
            try:
                sfilter = _class_filter_prefix[fclass] + 'ByName'
                criteria = self._search_criteria('EQ', name, sfilter, case_sensitive)
                dto = {'className': fclass, 'criteriaList': [criteria]}

                results += self.search(json.dumps(dto))
            except:
                pass

        return results
