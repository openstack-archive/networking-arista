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
import requests
import socket

import mock
from mock import patch
from neutron_lib import constants as n_const
from neutron_lib.plugins import constants as plugin_constants
from neutron_lib.plugins import directory
from oslo_config import cfg
from oslo_utils import importutils

from neutron.tests.unit import testlib_api

from networking_arista.common import db_lib
from networking_arista.ml2.rpc import arista_json
import networking_arista.tests.unit.ml2.utils as utils


BASE_RPC = "networking_arista.ml2.rpc.arista_json.AristaRPCWrapperJSON."
JSON_SEND_FUNC = BASE_RPC + "_send_api_request"
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
        ndb = db_lib.NeutronNets()
        self.drv = arista_json.AristaRPCWrapperJSON(ndb)
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
             [{'name': 'RegionOne', 'syncInterval': 10}])
        ]
        self._verify_send_api_request_call(mock_send_api_req, calls)

    def _get_random_name(self):
        return 'thisWillBeRandomInProd'

    @patch(JSON_SEND_FUNC)
    @patch(RAND_FUNC, _get_random_name)
    def test_sync_start(self, mock_send_api_req):
        mock_send_api_req.side_effect = [
            [{'name': 'RegionOne', 'syncStatus': ''}],
            [{}],
            [{'syncStatus': 'syncInProgress',
              'requestId': self._get_random_name()}]
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

    @patch(JSON_SEND_FUNC)
    def test_delete_region(self, mock_send_api_req):
        self.drv.delete_region('foo')
        calls = [('region/', 'DELETE', [{'name': 'foo'}])]
        self._verify_send_api_request_call(mock_send_api_req, calls)

    @patch('requests.Response')
    def test_get_region__updated_exception(self, mock_response):
        mock_response.ok.return_value = False
        self.assertEqual(self.drv.get_region_updated_time(),
                         {'regionTimestamp': ''})

    @patch(JSON_SEND_FUNC)
    def test_get_tenants(self, mock_send_api_req):
        self.drv.get_tenants()
        calls = [('region/RegionOne/tenant', 'GET')]
        self._verify_send_api_request_call(mock_send_api_req, calls)

    @patch(JSON_SEND_FUNC)
    def test_delete_tenant_bulk(self, mock_send_api_req):
        self.drv.delete_tenant_bulk(['t1', 't2'])
        calls = [('region/RegionOne/tenant', 'DELETE',
                  [{'id': 't1'}, {'id': 't2'}])]
        self._verify_send_api_request_call(mock_send_api_req, calls)

    def _createNetworkData(self, tenant_id, network_id, shared=False,
                           seg_id=100, network_type='vlan'):
        return {
            'network_id': network_id,
            'tenantId': tenant_id,
            'shared': shared,
            'segments': [{'segmentation_id': seg_id,
                          'physical_network': 'default',
                          'id': 'segment_id_1',
                          'is_dynamic': False,
                          'network_type': network_type}],
        }

    @patch(JSON_SEND_FUNC)
    def test_create_network_bulk(self, mock_send_api_req):
        n = []
        n.append(self._createNetworkData('t1', 'net1', seg_id=100))
        n.append(self._createNetworkData('t1', 'net2', seg_id=200))
        n.append(self._createNetworkData('t1', 'net3', network_type='flat'))
        self.drv.create_network_bulk('t1', n)
        calls = [
            ('region/RegionOne/network', 'POST',
             [{'id': 'net1', 'tenantId': 't1', 'shared': False},
              {'id': 'net2', 'tenantId': 't1', 'shared': False},
              {'id': 'net3', 'tenantId': 't1', 'shared': False}]),
            ('region/RegionOne/segment', 'POST',
                [{'id': 'segment_id_1', 'networkId': 'net1', 'type': 'vlan',
                  'segmentationId': 100, 'segmentType': 'static'},
                 {'id': 'segment_id_1', 'networkId': 'net2', 'type': 'vlan',
                  'segmentationId': 200, 'segmentType': 'static'}])
        ]
        self._verify_send_api_request_call(mock_send_api_req, calls, True)

    @patch(JSON_SEND_FUNC)
    def test_delete_network_bulk(self, mock_send_api_req):
        self.drv.delete_network_bulk('t1', ['net1', 'net2'])
        calls = [
            ('region/RegionOne/network', 'DELETE',
             [{'id': 'net1', 'tenantId': 't1'},
              {'id': 'net2', 'tenantId': 't1'}])
        ]
        self._verify_send_api_request_call(mock_send_api_req, calls, True)

    @patch(JSON_SEND_FUNC)
    def test_create_network_segments(self, mock_send_api_req):
        segments = [{'segmentation_id': 101,
                     'physical_network': 'default',
                     'id': 'segment_id_1',
                     'is_dynamic': False,
                     'network_type': 'vlan'},
                    {'segmentation_id': 102,
                     'physical_network': 'default',
                     'id': 'segment_id_2',
                     'is_dynamic': True,
                     'network_type': 'vlan'}]
        self.drv.create_network_segments('t1', 'n1', 'net1', segments)
        calls = [
            ('region/RegionOne/segment', 'POST',
                [{'id': 'segment_id_1', 'networkId': 'n1', 'type': 'vlan',
                  'segmentationId': 101, 'segmentType': 'static'},
                 {'id': 'segment_id_2', 'networkId': 'n1', 'type': 'vlan',
                  'segmentationId': 102, 'segmentType': 'dynamic'}])
        ]
        self._verify_send_api_request_call(mock_send_api_req, calls, True)

    @patch(JSON_SEND_FUNC)
    def test_delete_network_segments(self, mock_send_api_req):
        segments = [{'segmentation_id': 101,
                     'physical_network': 'default',
                     'id': 'segment_id_1',
                     'is_dynamic': False,
                     'network_type': 'vlan'},
                    {'segmentation_id': 102,
                     'physical_network': 'default',
                     'id': 'segment_id_2',
                     'is_dynamic': True,
                     'network_type': 'vlan'}]
        self.drv.delete_network_segments('t1', segments)
        calls = [
            ('region/RegionOne/segment', 'DELETE',
                [{'id': 'segment_id_1'},
                 {'id': 'segment_id_2'}])
        ]
        self._verify_send_api_request_call(mock_send_api_req, calls)

    @patch(JSON_SEND_FUNC)
    @patch(DB_LIB_MODULE)
    def test_create_instance_bulk(self, mock_db_lib, mock_send_api_req):
        tenant_id = 'ten-3'
        num_devices = 8
        num_ports_per_device = 2

        device_count = 0
        devices = {}
        for device_id in range(0, num_devices):
            dev_id = 'dev-id-%d' % device_id
            devices[dev_id] = {'vmId': dev_id,
                               'baremetal_instance': False,
                               'ports': []
                               }
            for port_id in range(0, num_ports_per_device):
                port_id = 'port-id-%d-%d' % (device_id, port_id)
                port = {
                    'device_id': 'dev-id-%d' % device_id,
                    'hosts': ['host_%d' % (device_count)],
                    'portId': port_id
                }
                devices[dev_id]['ports'].append(port)
            device_count += 1

        device_owners = [n_const.DEVICE_OWNER_DHCP,
                         'compute',
                         'baremetal',
                         n_const.DEVICE_OWNER_DVR_INTERFACE]
        port_list = []

        net_count = 0
        for device_id in range(0, num_devices):
            for port_id in range(0, num_ports_per_device):
                port = {
                    'portId': 'port-id-%d-%d' % (device_id, port_id),
                    'device_id': 'dev-id-%d' % device_id,
                    'device_owner': device_owners[device_id % 4],
                    'network_id': 'network-id-%d' % net_count,
                    'name': 'port-%d-%d' % (device_id, port_id),
                    'tenant_id': tenant_id,
                    'segments': [{
                        'network_id': 'network-id-%d' % net_count,
                        'segment_type': 'static',
                        'segmentation_id': (5000 + net_count),
                        'is_dynamic': False,
                        'network_type': 'vxlan',
                        'id': 'segment-id-%d' % (5000 + net_count)},
                        {'network_id': 'network-id-%d' % net_count,
                         'segment_type': 'dynamic',
                         'segmentation_id': (500 + net_count),
                         'is_dynamic': True,
                         'network_type': 'vlan',
                         'id': 'segment-id-%d' % (500 + net_count)}],
                }
                port_list.append(port)
                net_count += 1

        create_ports = {}
        for port in port_list:
            create_ports.update(utils.port_dict_representation(port))

        port_network_segments = {}
        for port in port_list:
            port_network_segments[port['portId']] = port['segments']

        profiles = {}
        for port in port_list:
            profiles[port['portId']] = {'vnic_type': 'normal'}
            if port['device_owner'] == 'baremetal':
                profiles[port['portId']] = {
                    'vnic_type': 'baremetal',
                    'profile': '{"local_link_information":'
                    '[{"switch_id": "switch01", "port_id": "Ethernet1"}]}'}

        mock_db_lib.get_network_segments_by_port_id.side_effect = (
            port_network_segments.get)
        self.drv.create_instance_bulk(tenant_id, create_ports, devices,
                                      profiles)
        calls = [
            ('region/RegionOne/tenant?tenantId=ten-3', 'GET'),
            ('region/RegionOne/dhcp?tenantId=ten-3', 'POST',
                [{'id': 'dev-id-0', 'hostId': 'host_0'},
                 {'id': 'dev-id-4', 'hostId': 'host_4'}]),
            ('region/RegionOne/vm?tenantId=ten-3', 'POST',
                [{'id': 'dev-id-1', 'hostId': 'host_1'},
                 {'id': 'dev-id-5', 'hostId': 'host_5'}]),
            ('region/RegionOne/baremetal?tenantId=ten-3', 'POST',
                [{'id': 'dev-id-2', 'hostId': 'host_2'},
                 {'id': 'dev-id-6', 'hostId': 'host_6'}]),
            ('region/RegionOne/router?tenantId=ten-3', 'POST',
                [{'id': 'dev-id-3', 'hostId': 'host_3'},
                 {'id': 'dev-id-7', 'hostId': 'host_7'}]),
            ('region/RegionOne/port', 'POST',
                [{'networkId': 'network-id-0', 'id': 'port-id-0-0',
                  'tenantId': 'ten-3', 'instanceId': 'dev-id-0',
                  'name': 'port-0-0', 'hosts': ['host_0'],
                  'instanceType': 'dhcp', 'vlanType': 'allowed'},
                 {'networkId': 'network-id-1', 'id': 'port-id-0-1',
                  'tenantId': 'ten-3', 'instanceId': 'dev-id-0',
                  'name': 'port-0-1', 'hosts': ['host_0'],
                  'instanceType': 'dhcp', 'vlanType': 'allowed'},

                 {'networkId': 'network-id-2', 'id': 'port-id-1-0',
                  'tenantId': 'ten-3', 'instanceId': 'dev-id-1',
                  'name': 'port-1-0', 'hosts': ['host_1'],
                  'instanceType': 'vm', 'vlanType': 'allowed'},
                 {'networkId': 'network-id-3', 'id': 'port-id-1-1',
                  'tenantId': 'ten-3', 'instanceId': 'dev-id-1',
                  'name': 'port-1-1', 'hosts': ['host_1'],
                  'instanceType': 'vm', 'vlanType': 'allowed'},

                 {'networkId': 'network-id-4', 'id': 'port-id-2-0',
                  'tenantId': 'ten-3', 'instanceId': 'dev-id-2',
                  'name': 'port-2-0', 'hosts': ['host_2'],
                  'instanceType': 'baremetal', 'vlanType': 'native'},
                 {'networkId': 'network-id-5', 'id': 'port-id-2-1',
                  'tenantId': 'ten-3', 'instanceId': 'dev-id-2',
                  'name': 'port-2-1', 'hosts': ['host_2'],
                  'instanceType': 'baremetal', 'vlanType': 'native'},

                 {'networkId': 'network-id-6', 'id': 'port-id-3-0',
                  'tenantId': 'ten-3', 'instanceId': 'dev-id-3',
                  'name': 'port-3-0', 'hosts': ['host_3'],
                  'instanceType': 'router', 'vlanType': 'allowed'},
                 {'networkId': 'network-id-7', 'id': 'port-id-3-1',
                  'tenantId': 'ten-3', 'instanceId': 'dev-id-3',
                  'name': 'port-3-1', 'hosts': ['host_3'],
                  'instanceType': 'router', 'vlanType': 'allowed'},

                 {'networkId': 'network-id-8', 'id': 'port-id-4-0',
                  'tenantId': 'ten-3', 'instanceId': 'dev-id-4',
                  'name': 'port-4-0', 'hosts': ['host_4'],
                  'instanceType': 'dhcp', 'vlanType': 'allowed'},
                 {'networkId': 'network-id-9', 'id': 'port-id-4-1',
                  'tenantId': 'ten-3', 'instanceId': 'dev-id-4',
                  'name': 'port-4-1', 'hosts': ['host_4'],
                  'instanceType': 'dhcp', 'vlanType': 'allowed'},

                 {'networkId': 'network-id-10', 'id': 'port-id-5-0',
                  'tenantId': 'ten-3', 'instanceId': 'dev-id-5',
                  'name': 'port-5-0', 'hosts': ['host_5'],
                  'instanceType': 'vm', 'vlanType': 'allowed'},
                 {'networkId': 'network-id-11', 'id': 'port-id-5-1',
                  'tenantId': 'ten-3', 'instanceId': 'dev-id-5',
                  'name': 'port-5-1', 'hosts': ['host_5'],
                  'instanceType': 'vm', 'vlanType': 'allowed'},

                 {'networkId': 'network-id-12', 'id': 'port-id-6-0',
                  'tenantId': 'ten-3', 'instanceId': 'dev-id-6',
                  'name': 'port-6-0', 'hosts': ['host_6'],
                  'instanceType': 'baremetal', 'vlanType': 'native'},
                 {'networkId': 'network-id-13', 'id': 'port-id-6-1',
                  'tenantId': 'ten-3', 'instanceId': 'dev-id-6',
                  'name': 'port-6-1', 'hosts': ['host_6'],
                  'instanceType': 'baremetal', 'vlanType': 'native'},

                 {'networkId': 'network-id-14', 'id': 'port-id-7-0',
                  'tenantId': 'ten-3', 'instanceId': 'dev-id-7',
                  'name': 'port-7-0', 'hosts': ['host_7'],
                  'instanceType': 'router', 'vlanType': 'allowed'},
                 {'networkId': 'network-id-15', 'id': 'port-id-7-1',
                  'tenantId': 'ten-3', 'instanceId': 'dev-id-7',
                  'name': 'port-7-1', 'hosts': ['host_7'],
                  'instanceType': 'router', 'vlanType': 'allowed'}]),

            ('region/RegionOne/port/port-id-0-0/binding',
             'POST', [{'portId': 'port-id-0-0',
                       'hostBinding': [{
                           'segment': [{'networkId': 'network-id-0',
                                        'segment_type': 'static',
                                        'segmentationId': 5000,
                                        'type': 'vxlan',
                                        'id': 'segment-id-5000'},
                                       {'networkId': 'network-id-0',
                                        'segment_type': 'dynamic',
                                        'segmentationId': 500,
                                        'type': 'vlan',
                                        'id': 'segment-id-500'}],
                           'host': 'host_0'}]}]),
            ('region/RegionOne/port/port-id-0-1/binding',
             'POST', [{'portId': 'port-id-0-1',
                       'hostBinding': [{
                           'segment': [{'networkId': 'network-id-1',
                                        'segment_type': 'static',
                                        'segmentationId': 5001,
                                        'type': 'vxlan',
                                        'id': 'segment-id-5001'},
                                       {'networkId': 'network-id-1',
                                        'segment_type': 'dynamic',
                                        'segmentationId': 501,
                                        'type': 'vlan',
                                        'id': 'segment-id-501'}],
                           'host': 'host_0'}]}]),

            ('region/RegionOne/port/port-id-1-0/binding',
             'POST', [{'portId': 'port-id-1-0',
                       'hostBinding': [{
                           'segment': [{'networkId': 'network-id-2',
                                        'segment_type': 'static',
                                        'segmentationId': 5002,
                                        'type': 'vxlan',
                                        'id': 'segment-id-5002'},
                                       {'networkId': 'network-id-2',
                                        'segment_type': 'dynamic',
                                        'segmentationId': 502,
                                        'type': 'vlan',
                                        'id': 'segment-id-502'}],
                           'host': 'host_1'}]}]),
            ('region/RegionOne/port/port-id-1-1/binding',
             'POST', [{'portId': 'port-id-1-1',
                       'hostBinding': [{
                           'segment': [{'networkId': 'network-id-3',
                                        'segment_type': 'static',
                                        'segmentationId': 5003,
                                        'type': 'vxlan',
                                        'id': 'segment-id-5003'},
                                       {'networkId': 'network-id-3',
                                        'segment_type': 'dynamic',
                                        'segmentationId': 503,
                                        'type': 'vlan',
                                        'id': 'segment-id-503'}],
                           'host': 'host_1'}]}]),

            ('region/RegionOne/port/port-id-2-0/binding',
             'POST', [{'portId': 'port-id-2-0',
                       'switchBinding': [{
                           'interface': u'Ethernet1',
                           'host': 'host_2',
                           'segment': [{'networkId': 'network-id-4',
                                        'segment_type': 'static',
                                        'segmentationId': 5004,
                                        'type': 'vxlan',
                                        'id': 'segment-id-5004'},
                                       {'networkId': 'network-id-4',
                                        'segment_type': 'dynamic',
                                        'segmentationId': 504,
                                        'type': 'vlan',
                                        'id': 'segment-id-504'}],
                           'switch': u'switch01'}]}]),
            ('region/RegionOne/port/port-id-2-1/binding',
             'POST', [{'portId': 'port-id-2-1',
                       'switchBinding': [
                           {'interface': u'Ethernet1',
                            'host': 'host_2',
                            'segment': [{'networkId': 'network-id-5',
                                         'segment_type': 'static',
                                         'segmentationId': 5005,
                                         'type': 'vxlan',
                                         'id': 'segment-id-5005'},
                                        {'networkId': 'network-id-5',
                                         'segment_type': 'dynamic',
                                         'segmentationId': 505,
                                         'type': 'vlan',
                                         'id': 'segment-id-505'}],
                            'switch': u'switch01'}]}]),

            ('region/RegionOne/port/port-id-3-0/binding',
             'POST', [{'portId': 'port-id-3-0',
                       'hostBinding': [{
                           'segment': [{'networkId': 'network-id-6',
                                        'segment_type': 'static',
                                        'segmentationId': 5006,
                                        'type': 'vxlan',
                                        'id': 'segment-id-5006'},
                                       {'networkId': 'network-id-6',
                                        'segment_type': 'dynamic',
                                        'segmentationId': 506,
                                        'type': 'vlan',
                                        'id': 'segment-id-506'}],
                           'host': 'host_3'}]}]),
            ('region/RegionOne/port/port-id-3-1/binding',
             'POST', [{'portId': 'port-id-3-1',
                       'hostBinding': [{
                           'segment': [{'networkId': 'network-id-7',
                                        'segment_type': 'static',
                                        'segmentationId': 5007,
                                        'type': 'vxlan',
                                        'id': 'segment-id-5007'},
                                       {'networkId': 'network-id-7',
                                        'segment_type': 'dynamic',
                                        'segmentationId': 507,
                                        'type': 'vlan',
                                        'id': 'segment-id-507'}],
                           'host': 'host_3'}]}]),

            ('region/RegionOne/port/port-id-4-0/binding',
             'POST', [{'portId': 'port-id-4-0',
                       'hostBinding': [{
                           'segment': [{'networkId': 'network-id-8',
                                        'segment_type': 'static',
                                        'segmentationId': 5008,
                                        'type': 'vxlan',
                                        'id': 'segment-id-5008'},
                                       {'networkId': 'network-id-8',
                                        'segment_type': 'dynamic',
                                        'segmentationId': 508,
                                        'type': 'vlan',
                                        'id': 'segment-id-508'}],
                           'host': 'host_4'}]}]),
            ('region/RegionOne/port/port-id-4-1/binding',
             'POST', [{'portId': 'port-id-4-1',
                       'hostBinding': [{
                           'segment': [{'networkId': 'network-id-9',
                                        'segment_type': 'static',
                                        'segmentationId': 5009,
                                        'type': 'vxlan',
                                        'id': 'segment-id-5009'},
                                       {'networkId': 'network-id-9',
                                        'segment_type': 'dynamic',
                                        'segmentationId': 509,
                                        'type': 'vlan',
                                        'id': 'segment-id-509'}],
                           'host': 'host_4'}]}]),

            ('region/RegionOne/port/port-id-5-0/binding',
             'POST', [{'portId': 'port-id-5-0',
                       'hostBinding': [{
                           'segment': [{'networkId': 'network-id-10',
                                        'segment_type': 'static',
                                        'segmentationId': 5010,
                                        'type': 'vxlan',
                                        'id': 'segment-id-5010'},
                                       {'networkId': 'network-id-10',
                                        'segment_type': 'dynamic',
                                        'segmentationId': 510,
                                        'type': 'vlan',
                                        'id': 'segment-id-510'}],
                           'host': 'host_5'}]}]),
            ('region/RegionOne/port/port-id-5-1/binding',
             'POST', [{'portId': 'port-id-5-1',
                       'hostBinding': [{
                           'segment': [{'networkId': 'network-id-11',
                                        'segment_type': 'static',
                                        'segmentationId': 5011,
                                        'type': 'vxlan',
                                        'id': 'segment-id-5011'},
                                       {'networkId': 'network-id-11',
                                        'segment_type': 'dynamic',
                                        'segmentationId': 511,
                                        'type': 'vlan',
                                        'id': 'segment-id-511'}],
                           'host': 'host_5'}]}]),

            ('region/RegionOne/port/port-id-6-0/binding',
             'POST', [{'portId': 'port-id-6-0',
                       'switchBinding': [{
                           'interface': u'Ethernet1',
                           'host': 'host_6',
                           'segment': [{'networkId': 'network-id-12',
                                        'segment_type': 'static',
                                        'segmentationId': 5012,
                                        'type': 'vxlan',
                                        'id': 'segment-id-5012'},
                                       {'networkId': 'network-id-12',
                                        'segment_type': 'dynamic',
                                        'segmentationId': 512,
                                        'type': 'vlan',
                                        'id': 'segment-id-512'}],
                           'switch': u'switch01'}]}]),
            ('region/RegionOne/port/port-id-6-1/binding',
             'POST', [{'portId': 'port-id-6-1',
                       'switchBinding': [{
                           'interface': u'Ethernet1',
                           'host': 'host_6',
                           'segment': [{'networkId': 'network-id-13',
                                        'segment_type': 'static',
                                        'segmentationId': 5013,
                                        'type': 'vxlan',
                                        'id': 'segment-id-5013'},
                                       {'networkId': 'network-id-13',
                                        'segment_type': 'dynamic',
                                        'segmentationId': 513,
                                        'type': 'vlan',
                                        'id': 'segment-id-513'}],
                           'switch': u'switch01'}]}]),

            ('region/RegionOne/port/port-id-7-0/binding',
             'POST', [{'portId': 'port-id-7-0',
                       'hostBinding': [{
                           'segment': [{'networkId': 'network-id-14',
                                        'segment_type': 'static',
                                        'segmentationId': 5014,
                                        'type': 'vxlan',
                                        'id': 'segment-id-5014'},
                                       {'networkId': 'network-id-14',
                                        'segment_type': 'dynamic',
                                        'segmentationId': 514,
                                        'type': 'vlan',
                                        'id': 'segment-id-514'}],
                           'host': 'host_7'}]}]),
            ('region/RegionOne/port/port-id-7-1/binding',
             'POST', [{'portId': 'port-id-7-1',
                       'hostBinding': [{
                           'segment': [{'networkId': 'network-id-15',
                                        'segment_type': 'static',
                                        'segmentationId': 5015,
                                        'type': 'vxlan',
                                        'id': 'segment-id-5015'},
                                       {'networkId': 'network-id-15',
                                        'segment_type': 'dynamic',
                                        'segmentationId': 515,
                                        'type': 'vlan',
                                        'id': 'segment-id-515'}],
                           'host': 'host_7'}]}]),
        ]
        self._verify_send_api_request_call(mock_send_api_req, calls, True)

    @patch(JSON_SEND_FUNC)
    def test_delete_vm_bulk(self, mock_send_api_req):
        self.drv.delete_vm_bulk('t1', ['vm1', 'vm2'])
        calls = [
            ('region/RegionOne/vm', 'DELETE',
             [{'id': 'vm1'}, {'id': 'vm2'}])
        ]
        self._verify_send_api_request_call(mock_send_api_req, calls)

    @patch(JSON_SEND_FUNC)
    def test_delete_dhcp_bulk(self, mock_send_api_req):
        self.drv.delete_dhcp_bulk('t1', ['dhcp1', 'dhcp2'])
        calls = [
            ('region/RegionOne/dhcp', 'DELETE',
             [{'id': 'dhcp1'}, {'id': 'dhcp2'}])
        ]
        self._verify_send_api_request_call(mock_send_api_req, calls)

    @patch(JSON_SEND_FUNC)
    def test_delete_port(self, mock_send_api_req):
        self.drv.delete_port('p1', 'inst1', 'vm')
        self.drv.delete_port('p2', 'inst2', 'dhcp')
        calls = [
            ('region/RegionOne/port?portId=p1&id=inst1&type=vm',
             'DELETE',
             [{'hosts': [], 'id': 'p1', 'tenantId': None, 'networkId': None,
               'instanceId': 'inst1', 'name': None, 'instanceType': 'vm',
               'vlanType': 'allowed'}]),
            ('region/RegionOne/port?portId=p2&id=inst2&type=dhcp',
             'DELETE',
             [{'hosts': [], 'id': 'p2', 'tenantId': None, 'networkId': None,
               'instanceId': 'inst2', 'name': None, 'instanceType': 'dhcp',
               'vlanType': 'allowed'}])
        ]
        self._verify_send_api_request_call(mock_send_api_req, calls)

    @patch(JSON_SEND_FUNC)
    def test_get_port(self, mock_send_api_req):
        self.drv.get_instance_ports('inst1', 'vm')
        calls = [
            ('region/RegionOne/port?id=inst1&type=vm',
             'GET')
        ]
        self._verify_send_api_request_call(mock_send_api_req, calls)

    @patch(JSON_SEND_FUNC)
    def test_plug_virtual_port_into_network(self, mock_send_api_req):
        segments = [{'segmentation_id': 101,
                     'id': 'segment_id_1',
                     'network_type': 'vlan',
                     'is_dynamic': False}]
        self.drv.plug_port_into_network('vm1', 'h1', 'p1', 'n1', 't1', 'port1',
                                        'compute', None, None, None, segments)
        calls = [
            ('region/RegionOne/vm?tenantId=t1', 'POST',
             [{'id': 'vm1', 'hostId': 'h1'}]),
            ('region/RegionOne/port', 'POST',
             [{'id': 'p1', 'hosts': ['h1'], 'tenantId': 't1',
               'networkId': 'n1', 'instanceId': 'vm1', 'name': 'port1',
               'instanceType': 'vm', 'vlanType': 'allowed'}]),
            ('region/RegionOne/port/p1/binding', 'POST',
             [{'portId': 'p1', 'hostBinding': [{'host': 'h1', 'segment': [{
               'id': 'segment_id_1', 'type': 'vlan', 'segmentationId': 101,
               'networkId': 'n1', 'segment_type': 'static'}]}]}]),
        ]
        self._verify_send_api_request_call(mock_send_api_req, calls)

    @patch(JSON_SEND_FUNC)
    @patch('networking_arista.ml2.rpc.arista_json.AristaRPCWrapperJSON.'
           'get_instance_ports')
    def test_unplug_virtual_port_from_network(self, mock_get_instance_ports,
                                              mock_send_api_req):
        mock_get_instance_ports.return_value = []
        self.drv.unplug_port_from_network('vm1', 'compute', 'h1', 'p1', 'n1',
                                          't1', None, None)
        port = self.drv._create_port_data('p1', None, None, 'vm1', None, 'vm',
                                          None)
        calls = [
            ('region/RegionOne/port/p1/binding', 'DELETE',
             [{'portId': 'p1', 'hostBinding': [{'host': 'h1'}]}]),
            ('region/RegionOne/port?portId=p1&id=vm1&type=vm',
             'DELETE', [port]),
            ('region/RegionOne/vm', 'DELETE', [{'id': 'vm1'}])
        ]
        self._verify_send_api_request_call(mock_send_api_req, calls)

    @patch(JSON_SEND_FUNC)
    def test_plug_baremetal_port_into_network(self, mock_send_api_req):
        segments = [{'segmentation_id': 101,
                     'id': 'segment_id_1',
                     'network_type': 'vlan',
                     'is_dynamic': False}]
        sg = {'id': 'security-group-1'}
        switch_bindings = [{'switch_id': 'switch01', 'port_id': 'Ethernet1',
                            'switch_info': 'switch01'}]
        self.drv.plug_port_into_network('bm1', 'h1', 'p1', 'n1', 't1', 'port1',
                                        'baremetal', sg, None, 'baremetal',
                                        segments,
                                        switch_bindings=switch_bindings)
        calls = [
            ('region/RegionOne/baremetal?tenantId=t1', 'POST',
             [{'id': 'bm1', 'hostId': 'h1'}]),
            ('region/RegionOne/port', 'POST',
             [{'id': 'p1', 'hosts': ['h1'], 'tenantId': 't1',
               'networkId': 'n1', 'instanceId': 'bm1', 'name': 'port1',
               'instanceType': 'baremetal', 'vlanType': 'native'}]),
            ('region/RegionOne/port/p1/binding', 'POST',
             [{'portId': 'p1', 'switchBinding': [{'host': 'h1',
               'switch': 'switch01', 'interface': 'Ethernet1', 'segment': [{
                   'id': 'segment_id_1', 'type': 'vlan', 'segmentationId': 101,
                   'networkId': 'n1', 'segment_type': 'static'}]}]}]),
        ]
        self._verify_send_api_request_call(mock_send_api_req, calls)

    @patch(JSON_SEND_FUNC)
    @patch('networking_arista.ml2.rpc.arista_json.AristaRPCWrapperJSON.'
           'get_instance_ports')
    def test_unplug_baremetal_port_from_network(self, mock_get_instance_ports,
                                                mock_send_api_req):
        mock_get_instance_ports.return_value = []
        switch_bindings = [{'switch_id': 'switch01', 'port_id': 'Ethernet1'}]
        self.drv.unplug_port_from_network('bm1', 'baremetal', 'h1', 'p1', 'n1',
                                          't1', None, 'baremetal',
                                          switch_bindings)
        port = self.drv._create_port_data('p1', None, None, 'bm1', None,
                                          'baremetal', None)
        calls = [
            ('region/RegionOne/port/p1/binding', 'DELETE',
             [{'portId': 'p1', 'switchBinding':
              [{'host': 'h1', 'switch': 'switch01', 'segment': [],
                'interface': 'Ethernet1'}]}]),
            ('region/RegionOne/port?portId=p1&id=bm1&type=baremetal',
             'DELETE', [port]),
            ('region/RegionOne/baremetal', 'DELETE', [{'id': 'bm1'}])
        ]
        self._verify_send_api_request_call(mock_send_api_req, calls)

    @patch(JSON_SEND_FUNC)
    def test_plug_dhcp_port_into_network(self, mock_send_api_req):
        segments = [{'segmentation_id': 101,
                     'id': 'segment_id_1',
                     'network_type': 'vlan',
                     'is_dynamic': False}]
        self.drv.plug_port_into_network('vm1', 'h1', 'p1', 'n1', 't1', 'port1',
                                        n_const.DEVICE_OWNER_DHCP, None, None,
                                        None, segments)
        calls = [
            ('region/RegionOne/dhcp?tenantId=t1', 'POST',
             [{'id': 'vm1', 'hostId': 'h1'}]),
            ('region/RegionOne/port', 'POST',
             [{'id': 'p1', 'hosts': ['h1'], 'tenantId': 't1',
               'networkId': 'n1', 'instanceId': 'vm1', 'name': 'port1',
               'instanceType': 'dhcp', 'vlanType': 'allowed'}])
        ]
        self._verify_send_api_request_call(mock_send_api_req, calls)

    @patch(JSON_SEND_FUNC)
    @patch('networking_arista.ml2.rpc.arista_json.AristaRPCWrapperJSON.'
           'get_instance_ports')
    def test_unplug_dhcp_port_from_network(self, mock_get_instance_ports,
                                           mock_send_api_req):
        mock_get_instance_ports.return_value = []
        self.drv.unplug_port_from_network('dhcp1', n_const.DEVICE_OWNER_DHCP,
                                          'h1', 'p1', 'n1', 't1', None, None)
        calls = [
            ('region/RegionOne/port?portId=p1&id=dhcp1&type=dhcp',
             'DELETE',
             [{'id': 'p1', 'hosts': [], 'tenantId': None, 'networkId': None,
               'instanceId': 'dhcp1', 'name': None, 'instanceType': 'dhcp',
               'vlanType': 'allowed'}]),
            ('region/RegionOne/dhcp', 'DELETE',
             [{'id': 'dhcp1'}])
        ]
        self._verify_send_api_request_call(mock_send_api_req, calls)

    @patch(JSON_SEND_FUNC)
    def test_plug_router_port_into_network(self, mock_send_api_req):
        segments = [{'segmentation_id': 101,
                     'id': 'segment_id_1',
                     'network_type': 'vlan',
                     'is_dynamic': False}]
        self.drv.plug_port_into_network('router1', 'h1', 'p1', 'n1', 't1',
                                        'port1',
                                        n_const.DEVICE_OWNER_DVR_INTERFACE,
                                        None, None, None, segments)
        calls = [
            ('region/RegionOne/router?tenantId=t1', 'POST',
             [{'id': 'router1', 'hostId': 'h1'}]),
            ('region/RegionOne/port', 'POST',
             [{'id': 'p1', 'hosts': ['h1'], 'tenantId': 't1',
               'networkId': 'n1', 'instanceId': 'router1', 'name': 'port1',
               'instanceType': 'router', 'vlanType': 'allowed'}])
        ]
        self._verify_send_api_request_call(mock_send_api_req, calls)

    @patch(JSON_SEND_FUNC)
    @patch('networking_arista.ml2.rpc.arista_json.AristaRPCWrapperJSON.'
           'get_instance_ports')
    def test_unplug_router_port_from_network(self, mock_get_instance_ports,
                                             mock_send_api_req):
        mock_get_instance_ports.return_value = []
        self.drv.unplug_port_from_network('router1',
                                          n_const.DEVICE_OWNER_DVR_INTERFACE,
                                          'h1', 'p1', 'n1', 't1', None, None)
        calls = [
            ('region/RegionOne/port?portId=p1&id=router1&type=router',
             'DELETE',
             [{'id': 'p1', 'hosts': [], 'tenantId': None, 'networkId': None,
               'instanceId': 'router1', 'name': None, 'instanceType': 'router',
               'vlanType': 'allowed'}]),
            ('region/RegionOne/router', 'DELETE',
             [{'id': 'router1'}])
        ]
        self._verify_send_api_request_call(mock_send_api_req, calls)

    @patch('requests.get')
    @patch(BASE_RPC + '_get_eos_master')
    def test_get_value_error(self, mock_get_eos_master, mock_requests_get):
        mock_get_eos_master.return_value = 'fake_master'
        mock_requests_get.return_value = requests.Response()
        self.assertIsNotNone(self.drv.get_vms_for_tenant(''))
        self.assertIsNotNone(self.drv.get_dhcps_for_tenant(''))
        self.assertIsNotNone(self.drv.get_baremetals_for_tenant(''))
        self.assertIsNotNone(self.drv.get_routers_for_tenant(''))
        self.assertIsNotNone(self.drv.get_ports_for_tenant('', 'vm'))
        self.assertIsNotNone(self.drv.get_tenants())
        self.assertIsNotNone(self.drv.get_networks(''))
        self.assertIsNotNone(self.drv.get_instance_ports('', 'vm'))

    @patch(BASE_RPC + '_get_eos_master')
    def test_get_exception(self, mock_get_eos_master):
        mock_get_eos_master.return_value = 'fake_master'
        self.assertIsNotNone(self.drv.get_vms_for_tenant(''))
        self.assertIsNotNone(self.drv.get_dhcps_for_tenant(''))
        self.assertIsNotNone(self.drv.get_baremetals_for_tenant(''))
        self.assertIsNotNone(self.drv.get_routers_for_tenant(''))
        self.assertIsNotNone(self.drv.get_ports_for_tenant('', 'vm'))
        self.assertIsNotNone(self.drv.get_tenants())
        self.assertIsNotNone(self.drv.get_networks(''))
        self.assertIsNotNone(self.drv.get_instance_ports('', 'vm'))


class RPCWrapperJSONValidConfigTrunkTestCase(testlib_api.SqlTestCase):
    """Test cases to test plug trunk port into network. """

    def setUp(self):
        super(RPCWrapperJSONValidConfigTrunkTestCase, self).setUp()
        setup_valid_config()
        ndb = mock.MagicMock()
        self.drv = arista_json.AristaRPCWrapperJSON(ndb)
        self.drv._server_ip = "10.11.12.13"
        self.region = 'RegionOne'

    @patch(JSON_SEND_FUNC)
    @patch(DB_LIB_MODULE)
    def test_plug_virtual_trunk_port_into_network(self, mock_db_lib,
                                                  mock_send_api_req):
        # vm
        tenant_id = 'ten-1'
        network_id = 'net-id-1'
        vm_id = 'vm-1'
        port_id = 'p1'
        host = 'host'
        port_name = 'name_p1'

        subport_net_id = 'net-id-2'

        segments = [{'segmentation_id': 1001,
                     'id': 'segment_id_1',
                     'network_type': 'vlan',
                     'is_dynamic': False}]

        subport_segments = [{'id': 'sub_segment_id_1',
                             'segmentation_id': 1002,
                             'network_type': 'vlan',
                             'is_dynamic': False}]

        trunk_details = {'sub_ports': [{'mac_address': 'mac_address',
                                        'port_id': 'p2',
                                        'segmentation_id': 1002,
                                        'segmentation_type': 'vlan'}],
                         'trunk_id': 'trunk_id'}
        self.drv._ndb.get_network_id_from_port_id.return_value = subport_net_id
        mock_db_lib.get_network_segments_by_port_id.return_value = (
            subport_segments)

        self.drv.plug_port_into_network(vm_id, host, port_id, network_id,
                                        tenant_id, port_name,
                                        'compute', None, None, None, segments,
                                        trunk_details=trunk_details)
        calls = [
            ('region/RegionOne/vm?tenantId=ten-1', 'POST',
             [{'id': 'vm-1', 'hostId': 'host'}]),
            ('region/RegionOne/port', 'POST',
             [{'id': 'p1', 'hosts': ['host'], 'tenantId': 'ten-1',
               'networkId': 'net-id-1', 'instanceId': 'vm-1',
               'name': 'name_p1',
               'instanceType': 'vm', 'vlanType': 'allowed'}]),
            ('region/RegionOne/port', 'POST',
             [{'id': 'p2', 'hosts': ['host'], 'tenantId': 'ten-1',
               'networkId': 'net-id-2', 'instanceId': 'vm-1',
               'name': 'name_p2',
               'instanceType': 'vm', 'vlanType': 'allowed'}]),
            ('region/RegionOne/port/p1/binding', 'POST',
             [{'portId': 'p1', 'hostBinding': [{'host': 'host', 'segment': [{
                 'id': 'segment_id_1', 'type': 'vlan', 'segmentationId': 1001,
                 'networkId': 'net-id-1', 'segment_type': 'static'}]}]}]),
            ('region/RegionOne/port/p2/binding', 'POST',
             [{'portId': 'p2', 'hostBinding': [{'host': 'host', 'segment': [{
                 'id': 'sub_segment_id_1', 'type': 'vlan',
                 'segmentationId': 1002,
                 'networkId': 'net-id-2', 'segment_type': 'static'}]}]}]),
        ]
        self._verify_send_api_request_call(mock_send_api_req, calls)

    @patch(JSON_SEND_FUNC)
    @patch(DB_LIB_MODULE)
    def test_plug_baremetal_trunk_port_into_network(self, mock_db_lib,
                                                    mock_send_api_req):
        # baremetal
        tenant_id = 'ten-2'
        network_id = 'net-id-1'
        bm_id = 'bm-1'
        port_id = 'p1'
        host = 'host'
        port_name = 'name_p1'
        sg = {'id': 'security-group-1'}
        segments = [{'segmentation_id': 1111,
                     'id': 'segment_id_1',
                     'network_type': 'vlan',
                     'is_dynamic': False}]

        subport_net_id = 'net-id-2'
        subport_segments = [{'id': 'sub_segment_id_1',
                             'segmentation_id': 1112,
                             'network_type': 'vlan',
                             'is_dynamic': False}]

        trunk_details = {'sub_ports': [{'mac_address': 'mac_address',
                                        'port_id': 'p2',
                                        'segmentation_id': 1112,
                                        'segmentation_type': 'vlan'}],
                         'trunk_id': 'trunk_id'}
        switch_bindings = {'local_link_information': [
            {'port_id': 'Eth1', 'switch_id': 'switch-id-1',
             'switch_info': 'switch-1'}]}
        bindings = switch_bindings['local_link_information']
        self.drv._ndb.get_network_id_from_port_id.return_value = subport_net_id
        mock_db_lib.get_network_segments_by_port_id.return_value = (
            subport_segments)

        self.drv.plug_port_into_network(bm_id, host, port_id, network_id,
                                        tenant_id, port_name,
                                        'baremetal', sg, None, 'baremetal',
                                        segments, bindings,
                                        trunk_details=trunk_details)

        calls = [
            ('region/RegionOne/baremetal?tenantId=ten-2', 'POST',
             [{'id': 'bm-1', 'hostId': 'host'}]),
            ('region/RegionOne/port', 'POST',
             [{'id': 'p1', 'hosts': ['host'], 'tenantId': 'ten-2',
               'networkId': 'net-id-1', 'instanceId': 'bm-1',
               'name': 'name_p1',
               'instanceType': 'baremetal', 'vlanType': 'native'}]),
            ('region/RegionOne/port', 'POST',
             [{'id': 'p2', 'hosts': ['host'], 'tenantId': 'ten-2',
               'networkId': 'net-id-2', 'instanceId': 'bm-1',
               'name': 'name_p2',
               'instanceType': 'baremetal', 'vlanType': 'allowed'}]),
            ('region/RegionOne/port/p1/binding', 'POST',
             [{'portId': 'p1', 'switchBinding': [
                 {'host': 'host', 'switch': 'switch-id-1',
                  'interface': 'Eth1', 'segment':
                      [{'id': 'segment_id_1', 'type': 'vlan',
                        'segmentationId': 1111, 'networkId': 'net-id-1',
                        'segment_type': 'static'}]}]}]),
            ('region/RegionOne/port/p2/binding', 'POST',
             [{'portId': 'p2', 'switchBinding':
                 [{'host': 'host', 'switch': 'switch-id-1',
                   'interface': 'Eth1', 'segment':
                       [{'id': 'sub_segment_id_1', 'type': 'vlan',
                         'segmentationId': 1112, 'networkId': 'net-id-2',
                         'segment_type': 'static'}]}]}]),
        ]
        self._verify_send_api_request_call(mock_send_api_req, calls)

    @patch(JSON_SEND_FUNC)
    @patch('networking_arista.ml2.rpc.arista_json.AristaRPCWrapperJSON.'
           'get_instance_ports')
    def test_unplug_virtual_trunk_port_from_network(self,
                                                    mock_get_instance_ports,
                                                    mock_send_api_req):
        # trunk port
        trunk_details = {'sub_ports': [{'mac_address': 'mac_address',
                                        'port_id': 'subport',
                                        'segmentation_id': 1001,
                                        'segmentation_type': 'vlan'}],
                         'trunk_id': 'trunk_id'}
        mock_get_instance_ports.return_value = []
        self.drv.unplug_port_from_network('vm1', 'compute', 'h1', 'trunk_port',
                                          'n1', 't1', None, None,
                                          trunk_details=trunk_details)
        subport = self.drv._create_port_data('subport', None, None, 'vm1',
                                             None, 'vm', None)
        trunk_port = self.drv._create_port_data('trunk_port', None, None,
                                                'vm1', None, 'vm', None)
        calls = [
            ('region/RegionOne/port/subport/binding', 'DELETE',
             [{'portId': 'subport', 'hostBinding': [{'host': 'h1'}]}]),
            ('region/RegionOne/port?portId=subport&id=vm1&type=vm',
             'DELETE', [subport]),
            ('region/RegionOne/port/trunk_port/binding', 'DELETE',
             [{'portId': 'trunk_port', 'hostBinding': [{'host': 'h1'}]}]),
            ('region/RegionOne/port?portId=trunk_port&id=vm1&type=vm',
             'DELETE', [trunk_port]),
            ('region/RegionOne/vm', 'DELETE', [{'id': 'vm1'}])
        ]
        self._verify_send_api_request_call(mock_send_api_req, calls)

    @patch(JSON_SEND_FUNC)
    @patch('networking_arista.ml2.rpc.arista_json.AristaRPCWrapperJSON.'
           'get_instance_ports')
    def test_unplug_baremetal_trunk_port_from_network(self,
                                                      mock_get_instance_ports,
                                                      mock_send_api_req):
        # trunk port
        trunk_details = {'sub_ports': [{'mac_address': 'mac_address',
                                        'port_id': 'subport',
                                        'segmentation_id': 1001,
                                        'segmentation_type': 'vlan'}],
                         'trunk_id': 'trunk_id'}
        mock_get_instance_ports.return_value = []
        switch_bindings = [{'switch_id': 'switch01', 'port_id': 'Ethernet1'}]
        self.drv.unplug_port_from_network('bm1', 'baremetal', 'h1', 'p1', 'n1',
                                          't1', None, 'baremetal',
                                          switch_bindings, trunk_details)
        subport = self.drv._create_port_data('subport', None, None, 'bm1',
                                             None, 'baremetal', None,
                                             'trunk:subport')
        trunk_port = self.drv._create_port_data('p1', None, None, 'bm1',
                                                None, 'baremetal', None)
        calls = [
            ('region/RegionOne/port/subport/binding', 'DELETE',
             [{'portId': 'subport', 'switchBinding':
                 [{'host': 'h1', 'switch': 'switch01', 'segment': [],
                   'interface': 'Ethernet1'}]}]),
            ('region/RegionOne/port?portId=subport&id=bm1&type=baremetal',
             'DELETE', [subport]),
            ('region/RegionOne/port/p1/binding', 'DELETE',
             [{'portId': 'p1', 'switchBinding':
                 [{'host': 'h1', 'switch': 'switch01', 'segment': [],
                   'interface': 'Ethernet1'}]}]),
            ('region/RegionOne/port?portId=p1&id=bm1&type=baremetal',
             'DELETE', [trunk_port]),
            ('region/RegionOne/baremetal', 'DELETE', [{'id': 'bm1'}])
        ]
        self._verify_send_api_request_call(mock_send_api_req, calls)

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
