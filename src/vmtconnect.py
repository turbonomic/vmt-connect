from __future__ import absolute_import
from __future__ import division
from __future__ import print_function


import base64, json
import requests

from urllib.parse import urlunparse, urlencode


__version__ = '1.0.0'
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
    pass


# session handling error
class VMTSessionError(Exception):
    pass


# connection issue
class HTTPError(Exception):
    pass


# server error
class HTTP500Error(HTTPError):
    pass


# bad gateway (ignorable due to sync issues)
class HTTP502Error(HTTP500Error):
    pass


# for non-breaking errors
class HTTPWarn(Exception):
    pass



# ----------------------------------------------------
#  API Wrapper Classes
# ----------------------------------------------------
# base vmturbo conneciton class
class VMTConnection(object):
    def __init__(self, host=None, username=None, password=None, auth=None,
                 base_url=None, ssl=False):
        self.__username = username
        self.__password = password
        self.__basic_auth = auth
        self.host = host
        self.base_path = base_url or '/vmturbo/rest/'
        self.response = None
        self.service = 'http'

        # set auth encoding
        if not self.__basic_auth and (self.__username and self.__password):
            self.__basic_auth = base64.b64encode('{}:{}'.format(self.__username, self.__password).encode())

        self.__username = self.__password = None
        self.headers = {'Authorization': u'Basic {}'.format(self.__basic_auth.decode())}

        if ssl:
            self.service = 'https'

    def request(self, resource, method='GET', query='', dto=None, *args, **kwargs):
        if 'headers' in kwargs:
            kwargs['headers'].update(self.headers)
        else:
            kwargs['headers'] = self.headers

        url = urlunparse((self.service, self.host, self.base_path+resource.lstrip('/'), '', query, ''))

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


class VMTSession(VMTConnection):
    def __init__(self, host=None, username=None, password=None, auth=None, base_url=None):
        super().__init__(host, username, password, auth, base_url=base_url)

    def request(self, path, method='GET', query='', dto=None, uuid=None, *args, **kwargs):
        if uuid is not None:
            path = '{}/{}'.format(path, uuid)

        # attempt to detect a POST
        if dto is not None and method == 'GET':
            method = 'POST'

        response = super().request(resource=path, method=method, query=query, dto=dto, *args, **kwargs)

        if response.status_code == 502:
            raise HTTP502Error('(API) HTTP 502 returned')
        elif response.status_code/100 == 5:
            raise HTTP500Error('(API) HTTP Code %s returned' % (response.status_code))
        elif response.status_code/100 != 2:
            raise HTTPError('(API) HTTP Code %s returned' % (response.status_code))
        else:
            return response.json()

    def get_users(self, uuid=None):
        return self.request('users', uuid=uuid)

    def get_templates(self, uuid=None):
        return self.request('templates', uuid=uuid)

    def get_markets(self, uuid=None):
        return self.request('markets', uuid=uuid)

    def get_market_state(self, uuid):
        return self.get_markets(uuid)['state']

    def get_market_stats(self, uuid):
        return self.request('markets/{}/stats'.format(uuid))

    def get_entities(self, type=None, uuid=None, market='Market'):
        if uuid is not None:
            path = 'entities/{}'.format(uuid)
        else:
            path = 'markets/{}/entities'.format(market)

        entities = self.request(path)

        if type is not None:
            return [x for x in entities if x['className'] == type]
        else:
            return entities

    def get_virtualmachines(self, uuid=None):
        return self.get_entities('VirtualMachine', uuid)

    def get_physicalmachines(self, uuid=None):
        return self.get_entities('PhysicalMachine', uuid)

    def get_datacenters(self, uuid=None):
        return self.get_entities('VirtualDataCenter', uuid)

    def get_datastores(self, uuid=None):
        return self.get_entities('Storage', uuid)

    def get_groups(self, uuid=None):
        return self.request('groups', uuid=uuid)

    def get_group_by_name(self, name):
        groups = self.get_groups()

        for grp in groups:
            if grp['displayName'] == name:
                return grp

    def get_group_stats(self, uuid):
        return self.request('groups/{}/stats'.format(uuid))

    def get_templates(self, uuid=None):
        return self.request('templates', uuid=uuid)

    def get_template_by_name(self, name):
        templates = self.get_templates()

        for tpl in templates:
            # not all contain displayName
            if 'displayName' in tpl and tpl['displayName'] == name:
                return tpl