from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import base64
import json
import requests

try:
  from urllib.parse import urlunparse, urlencode
except:
  from urlparse import urlunparse


__version__ = '1.1.1'
__all__ = [
    'VMTConnectionError',
    'HTTPError',
    'HTTP404Error',
    'HTTP500Error',
    'HTTP502Error',
    'HTTPWarn',
    'VMTRawConnection',
    'VMTConnection'
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


class HTTPError(Exception):
    """Raised when an blocking or unknown HTTP error is returned."""
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
            self.__basic_auth = base64.b64encode('{}:{}'.format(self.__username, self.__password).encode())

        self.__username = self.__password = None
        self.headers = {'Authorization': u'Basic {}'.format(self.__basic_auth.decode())}

        if ssl:
            self.protocol = 'https'

    def request(self, resource, method='GET', query='', dto=None, *args, **kwargs):
        """Constructs and sends an appropriate HTTP request.

        Args:
            resource (str): API resource to utilize, relative to `base_path`.
            method (str, optional): HTTP method to use for the request. (default: GET)
            query (str, optional): Query string to use.
            dto (str, optional): Data transfer object to send to the server.
            *args: Variable length argument list.
            **kwargs: Arbitrary keyword arguments.
        """
        if 'headers' in kwargs:
            kwargs['headers'].update(self.headers)
        else:
            kwargs['headers'] = self.headers

        url = urlunparse((self.protocol, self.host, self.base_path+resource.lstrip('/'), '', query, ''))

        for case in [method.upper()]:
            if case == 'POST':
                if 'Content-Type' not in kwargs['headers']:
                    kwargs['headers'].update({'Content-Type': 'application/json'})

                self.response = requests.post(url, data=dto, *args, **kwargs)
                break
            if case == 'PUT':
                self.response = requests.put(url, *args, **kwargs)
                break
            if case == 'DELETE':
                self.response = requests.delete(url, *args, **kwargs)
                break

            # default is GET
            self.response = requests.get(url, *args, **kwargs)

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
    """
    def __init__(self, host=None, username=None, password=None, auth=None,
                 base_url=None, ssl=False):
        super(VMTConnection, self).__init__(host, username, password, auth,
              base_url=base_url, ssl=ssl)

    def request(self, path, method='GET', query='', dto=None, uuid=None, *args, **kwargs):
        """Provides the same functionality as :meth:`VMTRawConnection.request`
        with error checking and output deserialization.
        """
        if uuid is not None:
            path = '{}/{}'.format(path, uuid)

        # attempt to detect a POST
        if dto is not None and method == 'GET':
            method = 'POST'

        response = super(VMTConnection, self).request(resource=path, method=method, query=query, dto=dto, *args, **kwargs)

        if response.status_code == 502:
            raise HTTP502Error('(API) HTTP 502 Bad Gateway returned')
        elif response.status_code == 404:
            raise HTTP404Error('(API) HTTP 404 Not Found returned')
        elif response.status_code/100 == 5:
            raise HTTP500Error('(API) HTTP Code %s returned' % (response.status_code))
        elif response.status_code/100 != 2:
            raise HTTPError('(API) HTTP Code %s returned' % (response.status_code))
        elif response.text == 'true':
            return True
        elif response.text == 'false':
            return False
        else:
            return response.json()

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

    def get_market_stats(self, uuid='Market'):
        """Returns a list of market statistics.

        Args:
            uuid (str, optional): Market UUID. (default: `Market`)

        Returns:
            A list of stat objects in :obj:`dict` form.
        """
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
        return self.get_entities('VirtualDataCenter', uuid=uuid, market=market)

    def get_datastores(self, uuid=None, market='Market'):
        """Returns a list of datastores in the given market

        Args:
            uuid (str, optional): Specific UUID to lookup.
            market (str, optional): Market to query. (default: `Market`)

        Returns:
            A list of datastores in :obj:`dict` form.
        """
        return self.get_entities('Storage', uuid=uuid, market=market)

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
        if stats is not None:
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
            A list containing one group in :obj:`dict` form.
        """
        groups = self.get_groups()

        for grp in groups:
            if grp['displayName'] == name:
                return grp

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
                return tpl

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

    def search(self, dto):
        """Raw search method.

        Provides a basic interface for issuing direct queries to the Turbonomic
        search endpoint.

        Args:
            dto (str): JSON representation of the StatScopesApiInputDTO.

        Returns:
            A list of search results.

        See Also:
            `5.9 REST API Guide (JSON) <https://cdn.turbonomic.com/wp-content/uploads/docs/VMT_REST2_API_PRINT.pdf>`_
            Search criteria list: `http://<host>/vmturbo/rest/search/criteria`_
        """
        return self.request('search', method='POST', dto=dto)

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
