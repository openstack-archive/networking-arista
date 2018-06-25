# Copyright (c) 2014 OpenStack Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import json
import socket

from oslo_log import log as logging
from oslo_utils import excutils
import requests
import six

from networking_arista._i18n import _, _LI, _LW
from networking_arista.common import exceptions as arista_exc
from networking_arista.ml2.rpc.base import AristaRPCWrapperBase

LOG = logging.getLogger(__name__)


class AristaRPCWrapperJSON(AristaRPCWrapperBase):
    def __init__(self):
        super(AristaRPCWrapperJSON, self).__init__()
        self.current_sync_name = None

    def _get_url(self, host="", user="", password=""):
        return ('https://%s:%s@%s/openstack/api/' %
                (user, password, host))

    def _api_host_url(self, host=""):
        return self._get_url(host, self._api_username(), self._api_password())

    def _send_request(self, host, path, method, data=None,
                      sanitized_data=None):
        request_headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'X-Sync-ID': self.current_sync_name
        }
        url = self._api_host_url(host=host) + path
        # Don't log the password
        log_url = self._get_url(host=host, user=self._api_username(),
                                password="*****") + path

        resp = None
        data = json.dumps(data)
        try:
            msg = (_('JSON request type: %(type)s url %(url)s data: '
                     '%(data)s sync_id: %(sync)s') %
                   {'type': method, 'url': log_url,
                    'data': sanitized_data or data,
                    'sync': self.current_sync_name})
            LOG.info(msg)
            func_lookup = {
                'GET': requests.get,
                'POST': requests.post,
                'PUT': requests.put,
                'PATCH': requests.patch,
                'DELETE': requests.delete
            }
            func = func_lookup.get(method)
            if not func:
                LOG.warning(_LW('Unrecognized HTTP method %s'), method)
                return None

            resp = func(url, timeout=self.conn_timeout, verify=False,
                        data=data, headers=request_headers)
            msg = (_LI('JSON response contains: %(code)s %(resp)s') %
                   {'code': resp.status_code,
                   'resp': resp.json()})
            LOG.info(msg)
            if resp.ok:
                return resp.json()
            else:
                raise arista_exc.AristaRpcError(msg=resp.json().get('error'))
        except requests.exceptions.ConnectionError:
            msg = (_('Error connecting to %(url)s') % {'url': url})
            LOG.warning(msg)
        except requests.exceptions.ConnectTimeout:
            msg = (_('Timed out connecting to API request to %(url)s') %
                   {'url': url})
            LOG.warning(msg)
        except requests.exceptions.Timeout:
            msg = (_('Timed out during API request to %(url)s') %
                   {'url': url})
            LOG.warning(msg)
        except requests.exceptions.InvalidURL:
            msg = (_('Ignore attempt to connect to invalid URL %(url)s') %
                   {'url': self._server_ip})
            LOG.warning(msg)
        except ValueError:
            LOG.warning(_LW("Ignoring invalid JSON response: %s"), resp.text)
        except Exception as error:
            msg = six.text_type(error)
            LOG.warning(msg)
            # reraise the exception
            with excutils.save_and_reraise_exception() as ctxt:
                ctxt.reraise = True
        return {} if method == 'GET' else None

    def _check_if_cvx_leader(self, host):
        url = 'agent/'
        data = self._send_request(host, url, 'GET')
        return False if not data else data.get('isLeader', False)

    def _get_eos_master(self):
        cvx = self._get_cvx_hosts()
        for self._server_ip in cvx:
            if self._check_if_cvx_leader(self._server_ip):
                return self._server_ip
        return None

    def send_api_request(self, path, method, data=None, sanitized_data=None):
        host = self._get_eos_master()
        if not host:
            msg = six.text_type("Could not find CVX leader")
            LOG.info(msg)
            self.set_cvx_unavailable()
            raise arista_exc.AristaRpcError(msg=msg)
        self.set_cvx_available()
        return self._send_request(host, path, method, data, sanitized_data)

    def _set_region_update_interval(self):
        path = 'region/%s' % self.region
        data = {
            'name': self.region,
            'syncInterval': self.sync_interval
        }
        self.send_api_request(path, 'PUT', [data])

    def register_with_eos(self, sync=False):
        self.create_region(self.region)
        self._set_region_update_interval()

    def get_cvx_uuid(self):
        path = 'agent/'
        try:
            data = self.send_api_request(path, 'GET')
            return data.get('uuid', None)
        except arista_exc.AristaRpcError:
            return None

    def create_region(self, region):
        path = 'region/'
        data = {'name': region}
        return self.send_api_request(path, 'POST', [data])

    def get_region(self, name):
        path = 'region/%s' % name
        try:
            regions = self.send_api_request(path, 'GET')
            for region in regions:
                if region['name'] == name:
                    return region
        except arista_exc.AristaRpcError:
            pass
        return None

    def sync_start(self):
        LOG.info('Attempt to start sync')
        self.current_sync_name = None
        try:
            region = self.get_region(self.region)

            # If the region doesn't exist, we may need to create
            # it in order for POSTs to the sync endpoint to succeed
            if not region:
                self.register_with_eos()
                return False

            if region.get('syncInterval') != self.sync_interval:
                self._set_region_update_interval()

            if region and region['syncStatus'] == 'syncInProgress':
                LOG.info('Sync in progress, not syncing')
                return False

            req_id = self._get_random_name()
            data = {
                'requester': socket.gethostname().split('.')[0],
                'requestId': req_id
            }
            path = 'region/' + self.region + '/sync'
            self.send_api_request(path, 'POST', data)
            self.current_sync_name = req_id
            return True
        except (KeyError, arista_exc.AristaRpcError):
            LOG.info('Not syncing due to RPC error')
            return False
        LOG.info('Not syncing due to server syncStatus')
        return False

    def sync_end(self):
        LOG.info('Attempting to end sync')
        try:
            path = 'region/' + self.region + '/sync'
            self.send_api_request(path, 'DELETE')
            self.current_sync_name = None
            return True
        except arista_exc.AristaRpcError:
            LOG.info('Not ending sync due to RPC error')
            return False
