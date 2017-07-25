from __future__ import absolute_import
from __future__ import division
from __future__ import print_function


import base64, json
import requests

try:
  from urllib.parse import urlunparse, urlencode
except:
  from urlparse import urlunparse


__version__ = '1.0.0.dev'
__all__ = [
    'VMTConnectionError',
    'VMTSessionError',
    'HTTPError',
    'HTTP500Error',
    'HTTP502Error',
    'HTTPWarn',
    'VMTConnection',
    'VMTSession'
]


## ----------------------------------------------------
##  Error Classes
## ----------------------------------------------------
# base exception class
class VMTConnectionError(Exception):
    """Base connection exception class."""
    pass


# session handling error
class VMTSessionError(Exception):
    """Base session exception class."""
    pass


# connection issue
class HTTPError(Exception):
    """Raised when an blocking or unknown HTTP error is returned."""
    pass


# server error
class HTTP500Error(HTTPError):
    """Raised when an HTTP 500 error returned."""
    pass


# bad gateway (ignorable due to sync issues)
class HTTP502Error(HTTP500Error):
    """Raised when an HTTP 502 Bad Gateway error is returned. In most cases this
    indicates a timeout issue with synchronous calls to Turbonomic and can be
    safely ignored."""
    pass


# for non-breaking errors
class HTTPWarn(Exception):
    """Raised when an HTTP error can always be safely ignored."""
    pass



# ----------------------------------------------------
#  API Wrapper Classes
# ----------------------------------------------------
# base vmturbo conneciton class
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
            raise HTTP502Error('(API) HTTP 502 returned')
        elif response.status_code/100 == 5:
            raise HTTP500Error('(API) HTTP Code %s returned' % (response.status_code))
        elif response.status_code/100 != 2:
            raise HTTPError('(API) HTTP Code %s returned' % (response.status_code))
        else:
            return response.json()

    def get_users(self, uuid=None):
        """Returns a list of users.

        Args:
            uuid (str, optional): Specific UUID to lookup.

        Returns:
            A list of user objects in :obj:`dict` form.
        """
        return self.request('users', uuid=uuid)

    def get_templates(self, uuid=None):
        """Returns a list templates.

        Args:
            uuid (str, optional): Specific UUID to lookup.

        Returns:
            A list of templates in :obj:`dict` form.
        """
        return self.request('templates', uuid=uuid)

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
        return self.get_entities('VirtualMachine', uuid, market=market)

    def get_physicalmachines(self, uuid=None, market='Market'):
        """Returns a list of hosts in the given market

        Args:
            uuid (str, optional): Specific UUID to lookup.
            market (str, optional): Market to query. (default: `Market`)

        Returns:
            A list of hosts in :obj:`dict` form.
        """
        return self.get_entities('PhysicalMachine', uuid, market='Market')

    def get_datacenters(self, uuid=None, market='Market'):
        """Returns a list of datacenters in the given market

        Args:
            uuid (str, optional): Specific UUID to lookup.
            market (str, optional): Market to query. (default: `Market`)

        Returns:
            A list of datacenters in :obj:`dict` form.
        """
        return self.get_entities('VirtualDataCenter', uuid, market=market)

    def get_datastores(self, uuid=None, market='Market'):
        """Returns a list of datastores in the given market

        Args:
            uuid (str, optional): Specific UUID to lookup.
            market (str, optional): Market to query. (default: `Market`)

        Returns:
            A list of datastores in :obj:`dict` form.
        """
        return self.get_entities('Storage', uuid, market=market)

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
            uuid (str, optional): Specific UUID to lookup.

        Returns:
            A list containing one group in :obj:`dict` form.
        """
        groups = self.get_groups()

        for grp in groups:
            if grp['displayName'] == name:
                return grp

    def get_group_stats(self, uuid):
        """Returns the aggregated statistics for a group.

        Args:
            uuid (str): Specific group UUID to lookup.

        Returns:
            A list containing the group stats in :obj:`dict` form.
        """
        return self.request('groups/{}/stats'.format(uuid))

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