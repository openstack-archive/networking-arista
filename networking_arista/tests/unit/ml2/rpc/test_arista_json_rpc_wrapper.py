# Copyright (c) 2013 OpenStack Foundation
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

import functools
import operator
import socket

import mock
from mock import patch
from neutron_lib.plugins import constants as plugin_constants
from neutron_lib.plugins import directory
from oslo_config import cfg
from oslo_utils import importutils

from neutron.tests.unit import testlib_api

from networking_arista.ml2.rpc import arista_json
from networking_arista.tests.unit import utils


BASE_RPC = "networking_arista.ml2.rpc.arista_json.AristaRPCWrapperJSON."
JSON_SEND_FUNC = BASE_RPC + "send_api_request"
RAND_FUNC = BASE_RPC + "_get_random_name"
DB_LIB_MODULE = 'networking_arista.ml2.rpc.arista_json.db_lib'


def setup_valid_config():
    utils.setup_arista_wrapper_config(cfg)


class _UnorderedDictList(list):
    def __init__(self, iterable='', sort_key=None):
        super(_UnorderedDictList, self).__init__(iterable)
        try:
            (self[0] or {})[sort_key]
            self.sort_key = sort_key
        except (IndexError, KeyError):
            self.sort_key = None

    def __eq__(self, other):
        if isinstance(other, list) and self.sort_key:
            key = operator.itemgetter(self.sort_key)
            return sorted(self, key=key) == sorted(other, key=key)
        else:
            return super(_UnorderedDictList, self).__eq__(other)


class TestAristaJSONRPCWrapper(testlib_api.SqlTestCase):
    def setUp(self):
        super(TestAristaJSONRPCWrapper, self).setUp()
        plugin_klass = importutils.import_class(
            "neutron.db.db_base_plugin_v2.NeutronDbPluginV2")
        directory.add_plugin(plugin_constants.CORE, plugin_klass())
        setup_valid_config()
        self.drv = arista_json.AristaRPCWrapperJSON()
        self.drv._server_ip = "10.11.12.13"
        self.region = 'RegionOne'

    def _verify_send_api_request_call(self, mock_send_api_req, calls,
                                      unordered_dict_list=False):
        if unordered_dict_list:
            wrapper = functools.partial(_UnorderedDictList, sort_key='id')
        else:
            wrapper = lambda x: x

        expected_calls = [
            mock.call(c[0], c[1], *(wrapper(d) for d in c[2:])) for c in calls
        ]

        mock_send_api_req.assert_has_calls(expected_calls, any_order=True)

    @patch(JSON_SEND_FUNC)
    def test_register_with_eos(self, mock_send_api_req):
        self.drv.register_with_eos()
        calls = [
            ('region/RegionOne', 'PUT',
             [{'name': 'RegionOne', 'syncInterval': 1}])
        ]
        self._verify_send_api_request_call(mock_send_api_req, calls)

    def _get_random_name(self):
        return 'thisWillBeRandomInProd'

    @patch(JSON_SEND_FUNC)
    @patch(RAND_FUNC, _get_random_name)
    def test_sync_start(self, mock_send_api_req):
        mock_send_api_req.side_effect = [
            [{'name': 'RegionOne', 'syncStatus': '',
              'syncInterval': self.drv.sync_interval}],
            [{}]
        ]
        assert self.drv.sync_start()
        calls = [
            ('region/RegionOne/sync', 'POST',
             {'requester': socket.gethostname().split('.')[0],
              'requestId': self._get_random_name()})
        ]
        self._verify_send_api_request_call(mock_send_api_req, calls)

    @patch('requests.Response')
    def test_sync_start_exception(self, mock_response):
        mock_response.ok.return_value = False
        self.assertFalse(self.drv.sync_start())

    @patch(JSON_SEND_FUNC)
    def test_sync_start_no_region(self, mock_send_api_req):
        mock_send_api_req.return_value = {}
        self.assertFalse(self.drv.sync_start())
        calls = [
            ('region/RegionOne', 'GET'),
            ('region/', 'POST', [{'name': 'RegionOne'}])
        ]
        self._verify_send_api_request_call(mock_send_api_req, calls)

    def _get_region(self, region):
        return {'name': region, 'syncStatus': 'syncTimedout',
                'syncInterval': self.sync_interval}

    @patch('requests.post')
    @patch(BASE_RPC + 'get_region', _get_region)
    @patch(BASE_RPC + '_get_eos_master', lambda _: 'cvx')
    @patch(RAND_FUNC, _get_random_name)
    def test_sync_start_after_failure(self, mock_post):
        self.drv.current_sync_name = 'bad-sync-id'
        self.assertTrue(self.drv.sync_start())
        expected_header = {'Content-Type': 'application/json',
                           'Accept': 'application/json',
                           'X-Sync-ID': None}
        mock_post.assert_called_once_with(mock.ANY,
                                          data=mock.ANY,
                                          timeout=mock.ANY,
                                          verify=mock.ANY,
                                          headers=expected_header)

    @patch(JSON_SEND_FUNC)
    @patch(RAND_FUNC, _get_random_name)
    def test_sync_start_incorrect_interval(self, mock_send_api_req):
        mock_send_api_req.side_effect = [
            [{'name': 'RegionOne', 'syncStatus': '',
              'syncInterval': 0.0}],
            [{}],
            [{'syncStatus': 'syncInProgress',
              'requestId': self._get_random_name()}]
        ]
        assert self.drv.sync_start()
        calls = [
            ('region/RegionOne', 'PUT',
             [{'name': 'RegionOne',
               'syncInterval': self.drv.sync_interval}]),
            ('region/RegionOne/sync', 'POST',
             {'requester': socket.gethostname().split('.')[0],
              'requestId': self._get_random_name()})
        ]
        self._verify_send_api_request_call(mock_send_api_req, calls)

    @patch(JSON_SEND_FUNC)
    @patch(RAND_FUNC, _get_random_name)
    def test_sync_end(self, mock_send_api_req):
        mock_send_api_req.return_value = [{'requester':
                                           self._get_random_name()}]
        self.drv.current_sync_name = self._get_random_name()
        self.assertTrue(self.drv.sync_end())
        calls = [
            ('region/RegionOne/sync', 'DELETE')
        ]
        self._verify_send_api_request_call(mock_send_api_req, calls)

    @patch(JSON_SEND_FUNC)
    def test_create_region(self, mock_send_api_req):
        self.drv.create_region('foo')
        calls = [('region/', 'POST', [{'name': 'foo'}])]
        self._verify_send_api_request_call(mock_send_api_req, calls)

    @patch('requests.Response')
    def test_get_region_exception(self, mock_response):
        mock_response.ok.return_value = False
        self.assertIsNone(self.drv.get_region('foo'))

    @patch('requests.Response')
    def test_get_cvx_uuid_exception(self, mock_response):
        mock_response.ok.return_value = False
        self.assertIsNone(self.drv.get_cvx_uuid())
