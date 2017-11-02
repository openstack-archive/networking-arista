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

import mock
from mock import patch
from neutron_lib import constants as n_const
from oslo_config import cfg
import six

from neutron.tests import base
from neutron.tests.unit import testlib_api

from networking_arista.common import constants
from networking_arista.common import db_lib
from networking_arista.common import exceptions as arista_exc
from networking_arista.ml2.rpc import arista_eapi
from networking_arista.tests.unit.ml2.test_arista_mechanism_driver import \
    FakePortBindingLevel
import networking_arista.tests.unit.ml2.utils as utils


EAPI_SEND_FUNC = ('networking_arista.ml2.rpc.arista_eapi.AristaRPCWrapperEapi'
                  '._send_eapi_req')
EAPI_DB_LIB_MODULE = 'networking_arista.ml2.rpc.arista_eapi.db_lib'


def setup_valid_config():
    utils.setup_arista_wrapper_config(cfg)


class PositiveRPCWrapperValidConfigTestCase(testlib_api.SqlTestCase):
    """Test cases to test the RPC between Arista Driver and EOS.

    Tests all methods used to send commands between Arista Driver and EOS
    """

    def setUp(self):
        super(PositiveRPCWrapperValidConfigTestCase, self).setUp()
        setup_valid_config()
        ndb = db_lib.NeutronNets()
        self.drv = arista_eapi.AristaRPCWrapperEapi(ndb)
        self.drv._server_ip = "10.11.12.13"
        self.region = 'RegionOne'

    def _get_exit_mode_cmds(self, modes):
        return ['exit'] * len(modes)

    def _verify_send_eapi_request_calls(self, mock_send_eapi_req, cmds,
                                        commands_to_log=None):
        calls = []
        calls.extend(
            mock.call(cmds=cmd, commands_to_log=log_cmd)
            for cmd, log_cmd in six.moves.zip(cmds, commands_to_log or cmds))
        mock_send_eapi_req.assert_has_calls(calls)

    def test_no_exception_on_correct_configuration(self):
        self.assertIsNotNone(self.drv)

    @patch(EAPI_SEND_FUNC)
    def test_plug_host_into_network(self, mock_send_eapi_req):
        tenant_id = 'ten-1'
        vm_id = 'vm-1'
        port_id = 123
        network_id = 'net-id'
        host = 'host'
        port_name = '123-port'
        segment_id = 'segment_id_1'
        segments = [{'network_type': 'vlan', 'physical_network': 'default',
                     'segmentation_id': 1234, 'id': segment_id}]

        self.drv.plug_host_into_network(vm_id, host, port_id,
                                        network_id, tenant_id, segments,
                                        port_name)
        cmd1 = ['show openstack agent uuid']
        cmd2 = ['enable', 'configure', 'cvx', 'service openstack',
                'region RegionOne',
                'tenant ten-1', 'vm id vm-1 hostid host',
                'port id 123 name "123-port" network-id net-id',
                ]
        for level, segment in enumerate(segments):
            cmd2.append('segment level %s id %s' % (level, segment['id']))

        self._verify_send_eapi_request_calls(mock_send_eapi_req, [cmd1, cmd2])

    @patch(EAPI_SEND_FUNC)
    def test_plug_dhcp_port_into_network(self, mock_send_eapi_req):
        tenant_id = 'ten-1'
        vm_id = 'vm-1'
        port_id = 123
        network_id = 'net-id'
        host = 'host'
        port_name = '123-port'
        segments = []

        self.drv.plug_port_into_network(vm_id, host, port_id, network_id,
                                        tenant_id, port_name,
                                        n_const.DEVICE_OWNER_DHCP, None, None,
                                        None, segments)
        cmd1 = ['show openstack agent uuid']
        cmd2 = ['enable', 'configure', 'cvx', 'service openstack',
                'region RegionOne',
                'tenant ten-1', 'network id net-id',
                'dhcp id vm-1 hostid host port-id 123 name "123-port"',
                ]
        self._verify_send_eapi_request_calls(mock_send_eapi_req, [cmd1, cmd2])

    @patch(EAPI_SEND_FUNC)
    def test_plug_baremetal_into_network(self, mock_send_eapi_req):
        tenant_id = 'ten-1'
        network_id = 'net-id-1'
        bm_id = 'bm-1'
        port_id = 'p1'
        host = 'host'
        port_name = 'name_p1'
        device_owner = 'compute:None'

        segments = [{'segmentation_id': 1001,
                     'id': 'segment_id_1',
                     'network_type': 'vlan',
                     'is_dynamic': False}]

        switch_bindings = {'local_link_information': [
            {'port_id': 'Eth1', 'switch_id': 'switch-id-1',
             'switch_info': 'switch-1'}]}
        bindings = switch_bindings['local_link_information']

        self.drv.bm_and_dvr_supported = mock.MagicMock(return_value=True)

        self.drv.plug_baremetal_into_network(bm_id, host, port_id,
                                             network_id, tenant_id,
                                             segments, port_name,
                                             device_owner,
                                             None, None, 'baremetal',
                                             bindings)

        cmd1 = ['show openstack agent uuid']
        cmd2 = ['enable', 'configure', 'cvx', 'service openstack',
                'region RegionOne',
                'tenant ten-1',
                'instance id bm-1 hostid host type baremetal',
                'port id p1 name "name_p1" network-id net-id-1 '
                'type native switch-id switch-id-1 switchport Eth1',
                ]
        for level, segment in enumerate(segments):
            cmd2.append('segment level %s id %s' % (level, segment['id']))
        cmd2.append('exit')

        self._verify_send_eapi_request_calls(mock_send_eapi_req, [cmd1, cmd2])

    @patch(EAPI_SEND_FUNC)
    def test_unplug_baremetal_from_network(self, mock_send_eapi_req):
        tenant_id = 'ten-1'
        network_id = 'net-id-1'
        bm_id = 'bm-1'
        port_id = 111
        host = 'host'
        switch_bindings = {'local_link_information': [
            {'port_id': 'Eth1', 'switch_id': 'switch-id-1',
             'switch_info': 'switch-1'}]}
        bindings = switch_bindings['local_link_information']
        self.drv.bm_and_dvr_supported = mock.MagicMock(return_value=True)
        self.drv.unplug_baremetal_from_network(bm_id, host, port_id,
                                               network_id, tenant_id,
                                               None, 'baremetal',
                                               bindings)
        cmd1 = ['show openstack agent uuid']
        cmd2 = ['enable', 'configure', 'cvx', 'service openstack',
                'region RegionOne',
                'tenant ten-1',
                'instance id bm-1 hostid host type baremetal',
                'no port id 111',
                ]
        self._verify_send_eapi_request_calls(mock_send_eapi_req, [cmd1, cmd2])

    @patch(EAPI_SEND_FUNC)
    def test_unplug_host_from_network(self, mock_send_eapi_req):
        tenant_id = 'ten-1'
        vm_id = 'vm-1'
        port_id = 123
        network_id = 'net-id'
        host = 'host'
        self.drv.unplug_host_from_network(vm_id, host, port_id,
                                          network_id, tenant_id)
        cmd1 = ['show openstack agent uuid']
        cmd2 = ['enable', 'configure', 'cvx', 'service openstack',
                'region RegionOne',
                'tenant ten-1', 'vm id vm-1 hostid host',
                'no port id 123',
                ]
        self._verify_send_eapi_request_calls(mock_send_eapi_req, [cmd1, cmd2])

    @patch(EAPI_SEND_FUNC)
    def test_unplug_dhcp_port_from_network(self, mock_send_eapi_req):
        tenant_id = 'ten-1'
        vm_id = 'vm-1'
        port_id = 123
        network_id = 'net-id'
        host = 'host'

        self.drv.unplug_dhcp_port_from_network(vm_id, host, port_id,
                                               network_id, tenant_id)
        cmd1 = ['show openstack agent uuid']
        cmd2 = ['enable', 'configure', 'cvx', 'service openstack',
                'region RegionOne',
                'tenant ten-1', 'network id net-id',
                'no dhcp id vm-1 port-id 123',
                ]
        self._verify_send_eapi_request_calls(mock_send_eapi_req, [cmd1, cmd2])

    @patch(EAPI_SEND_FUNC)
    def test_create_network(self, mock_send_eapi_req):
        tenant_id = 'ten-1'
        self.drv.cli_commands['features'] = {'hierarchical-port-binding': 1}
        network = {
            'network_id': 'net-id',
            'network_name': 'net-name',
            'segments': [{'segmentation_id': 123,
                          'physical_network': 'default',
                          'network_type': 'vlan',
                          'id': 'segment_id_1'}],
            'shared': False,
            }
        self.drv.create_network(tenant_id, network)
        cmd1 = ['show openstack agent uuid']
        cmd2 = ['enable', 'configure', 'cvx', 'service openstack',
                'region RegionOne',
                'tenant ten-1', 'network id net-id name "net-name"',
                ]
        for seg in network['segments']:
            is_dynamic = seg.get('is_dynamic', False)
            cmd2.append('segment %s type %s id %d %s' % (seg['id'],
                        seg['network_type'], seg['segmentation_id'],
                        'dynamic' if is_dynamic else 'static'))
        cmd2.append('no shared')

        self._verify_send_eapi_request_calls(mock_send_eapi_req, [cmd1, cmd2])

    @patch(EAPI_SEND_FUNC)
    def test_create_shared_network(self, mock_send_eapi_req):
        tenant_id = 'ten-1'
        segment_id = 'abcd-cccc'
        segmentation_id = 123
        network_type = 'vlan'
        segments = [{'segmentation_id': segmentation_id,
                     'id': segment_id,
                     'network_type': network_type}]
        network = {
            'network_id': 'net-id',
            'network_name': 'net-name',
            'segments': segments,
            'shared': True}
        self.drv.cli_commands['features'] = {'hierarchical-port-binding': 1}
        self.drv.create_network(tenant_id, network)
        cmd1 = ['show openstack agent uuid']
        cmd2 = ['enable', 'configure', 'cvx', 'service openstack',
                'region RegionOne',
                'tenant ten-1', 'network id net-id name "net-name"',
                'segment %s type %s id %d %s' % (segment_id, network_type,
                                                 segmentation_id, 'static'),
                'shared',
                ]
        self._verify_send_eapi_request_calls(mock_send_eapi_req, [cmd1, cmd2])

    @patch(EAPI_SEND_FUNC)
    def test_create_network_bulk(self, mock_send_eapi_req):
        tenant_id = 'ten-2'
        num_networks = 10
        network_type = 'vlan'
        segment_id = 'abcd-eeee-%s'
        self.drv.cli_commands['features'] = {'hierarchical-port-binding': 1}
        networks = [{
            'network_id': 'net-id-%d' % net_id,
            'network_name': 'net-name-%d' % net_id,
            'segments': [{'segmentation_id': net_id,
                          'network_type': 'vlan',
                          'id': segment_id % net_id}],
            'shared': True,
            } for net_id in range(1, num_networks)
        ]

        self.drv.create_network_bulk(tenant_id, networks)
        cmd1 = ['show openstack agent uuid']
        cmd2 = ['enable',
                'configure',
                'cvx',
                'service openstack',
                'region RegionOne',
                'tenant ten-2']
        for net_id in range(1, num_networks):
            cmd2.append('network id net-id-%d name "net-name-%d"' %
                        (net_id, net_id))
            cmd2.append('segment %s type %s id %d %s' % (
                        segment_id % net_id, network_type, net_id, 'static'))
            cmd2.append('shared')
        self._verify_send_eapi_request_calls(mock_send_eapi_req, [cmd1, cmd2])

    @patch(EAPI_SEND_FUNC)
    def test_delete_network(self, mock_send_eapi_req):
        tenant_id = 'ten-1'
        network_id = 'net-id'
        segments = [{'segmentation_id': 101,
                     'physical_network': 'default',
                     'id': 'segment_id_1',
                     'network_type': 'vlan'}]
        self.drv.delete_network(tenant_id, network_id, segments)
        cmd1 = ['show openstack agent uuid']
        cmd2 = ['enable', 'configure', 'cvx', 'service openstack',
                'region RegionOne',
                'tenant ten-1',
                'network id net-id',
                'no segment segment_id_1',
                ]
        cmd3 = ['enable', 'configure', 'cvx', 'service openstack',
                'region RegionOne',
                'tenant ten-1',
                'no network id net-id',
                ]
        self._verify_send_eapi_request_calls(mock_send_eapi_req,
                                             [cmd1, cmd2, cmd1, cmd3])

    @patch(EAPI_SEND_FUNC)
    def test_delete_network_bulk(self, mock_send_eapi_req):
        tenant_id = 'ten-2'
        num_networks = 10

        networks = ['net-id-%d' % net_id for net_id in range(1, num_networks)]
        self.drv.delete_network_bulk(tenant_id, networks)
        cmd1 = ['show openstack agent uuid']
        cmd2 = ['enable',
                'configure',
                'cvx',
                'service openstack',
                'region RegionOne',
                'tenant ten-2']
        for net_id in range(1, num_networks):
            cmd2.append('no network id net-id-%d' % net_id)
        self._verify_send_eapi_request_calls(mock_send_eapi_req, [cmd1, cmd2])

    @patch(EAPI_SEND_FUNC)
    def test_delete_vm(self, mock_send_eapi_req):
        tenant_id = 'ten-1'
        vm_id = 'vm-id'
        self.drv.delete_vm(tenant_id, vm_id)
        cmd1 = ['show openstack agent uuid']
        cmd2 = ['enable', 'configure', 'cvx', 'service openstack',
                'region RegionOne',
                'tenant ten-1', 'no vm id vm-id',
                ]
        self._verify_send_eapi_request_calls(mock_send_eapi_req, [cmd1, cmd2])

    @patch(EAPI_SEND_FUNC)
    def test_delete_vm_bulk(self, mock_send_eapi_req):
        tenant_id = 'ten-2'
        num_vms = 10
        vm_ids = ['vm-id-%d' % vm_id for vm_id in range(1, num_vms)]
        self.drv.delete_vm_bulk(tenant_id, vm_ids)

        cmd1 = ['show openstack agent uuid']
        cmd2 = ['enable',
                'configure',
                'cvx',
                'service openstack',
                'region RegionOne',
                'tenant ten-2']

        for vm_id in range(1, num_vms):
            cmd2.append('no vm id vm-id-%d' % vm_id)
        self._verify_send_eapi_request_calls(mock_send_eapi_req, [cmd1, cmd2])

    @patch(EAPI_SEND_FUNC)
    @patch(EAPI_DB_LIB_MODULE)
    def test_hpb_create_port_bulk(self, mock_db_lib, mock_send_eapi_req):
        tenant_id = 'ten-3'
        num_devices = 10
        num_ports_per_device = 2
        device_owners = [n_const.DEVICE_OWNER_DHCP, 'compute',
                         n_const.DEVICE_OWNER_DVR_INTERFACE]
        port_list = []
        devices = {}
        for device_id in range(1, num_devices):
            dev_id = 'dev-id-%d' % device_id
            devices[dev_id] = {'vmId': dev_id,
                               'baremetal_instance': False,
                               'ports': []}
            for port_id in range(1, num_ports_per_device):
                pid = 'port-id-%d-%d' % (device_id, port_id)
                port = {
                    'device_id': 'dev-id-%d' % device_id,
                    'hosts': ['host_%d' % device_id],
                    'portId': pid,
                    'device_owner': device_owners[(device_id + port_id) % 3],
                    'network_id': 'network-id-%d' % port_id,
                    'name': 'port-%d-%d' % (device_id, port_id),
                    'tenant_id': tenant_id,
                    'segments': [FakePortBindingLevel(pid, 0, 'vendor-0',
                                                      5000 + port_id),
                                 FakePortBindingLevel(pid, 1, 'vendor-1',
                                                      500 + port_id)]
                }
                port_list.append(port)
                devices[dev_id]['ports'].append(port)

        create_ports = {}
        port_profiles = {}
        for port in port_list:
            create_ports.update(utils.port_dict_representation(port))
            port_profiles[port['portId']] = {'vnic_type': 'normal'}

        self.drv.cli_commands[constants.CMD_INSTANCE] = 'instance'
        self.drv.cli_commands['features'] = {'hierarchical-port-binding': 1}
        mock_db_lib.get_port_binding_level.side_effect = (
            lambda x: create_ports.get(x['port_id']).get('segments'))
        self.drv.create_instance_bulk(tenant_id, create_ports, devices,
                                      port_profiles=port_profiles)
        cmd1 = ['show openstack agent uuid']
        cmd2 = ['enable',
                'configure',
                'cvx',
                'service openstack',
                'region RegionOne',
                'tenant ten-3']

        for device in devices.values():
            for v_port in device['ports']:
                port_id = v_port['portId']
                port = create_ports[port_id]
                host = v_port['hosts'][0]
                device_owner = port['device_owner']
                port_name = port['name']
                network_id = port['network_id']
                device_id = port['device_id']
                if device_owner == 'network:dhcp':
                    cmd2.append('network id %s' % network_id)
                    cmd2.append('dhcp id %s hostid %s port-id %s name "%s"' % (
                                device_id, host, port_id, port_name))
                elif device_owner == 'compute':
                    cmd2.append('vm id %s hostid %s' % (device_id, host))
                    cmd2.append('port id %s name "%s" network-id %s' % (
                                port_id, port_name, network_id))
                elif device_owner == n_const.DEVICE_OWNER_DVR_INTERFACE:
                    cmd2.append('instance id %s type router' % device_id)
                    cmd2.append('port id %s network-id %s hostid %s' % (
                                port_id, network_id, host))
                if self.drv.hpb_supported():
                    cmd2.extend('segment level %d id %s' % (
                        segment.level, segment.segment_id)
                        for segment in v_port.get('segments'))

        self._verify_send_eapi_request_calls(mock_send_eapi_req, [cmd1, cmd2])

    @patch(EAPI_SEND_FUNC)
    def test_create_port_bulk(self, mock_send_eapi_req):
        tenant_id = 'ten-3'
        num_devices = 10
        num_ports_per_device = 2

        device_count = 0
        devices = {}
        for device_id in range(1, num_devices):
            device_count += 1
            dev_id = 'dev-id-%d' % device_id
            devices[dev_id] = {'vmId': dev_id,
                               'baremetal_instance': False,
                               'ports': []
                               }
            for port_id in range(1, num_ports_per_device):
                port_id = 'port-id-%d-%d' % (device_id, port_id)
                port = {
                    'device_id': 'dev-id-%d' % device_id,
                    'hosts': ['host_%d' % (device_count)],
                    'portId': port_id
                }
                devices[dev_id]['ports'].append(port)

        device_owners = [n_const.DEVICE_OWNER_DHCP, 'compute',
                         n_const.DEVICE_OWNER_DVR_INTERFACE]
        port_list = []

        net_count = 1
        for device_id in range(1, num_devices):
            for port_id in range(1, num_ports_per_device):
                port = {
                    'portId': 'port-id-%d-%d' % (device_id, port_id),
                    'device_id': 'dev-id-%d' % device_id,
                    'device_owner': device_owners[(device_id + port_id) % 3],
                    'network_id': 'network-id-%d' % net_count,
                    'name': 'port-%d-%d' % (device_id, port_id),
                    'tenant_id': tenant_id
                }
                port_list.append(port)
                net_count += 1

        create_ports = {}
        port_profiles = {}
        for port in port_list:
            create_ports.update(utils.port_dict_representation(port))
            port_profiles[port['portId']] = {'vnic_type': 'normal'}

        self.drv.cli_commands[constants.CMD_INSTANCE] = 'instance'
        self.drv.create_instance_bulk(tenant_id, create_ports, devices,
                                      port_profiles=port_profiles)
        cmd1 = ['show openstack agent uuid']
        cmd2 = ['enable',
                'configure',
                'cvx',
                'service openstack',
                'region RegionOne',
                'tenant ten-3']

        for device in devices.values():
            for v_port in device['ports']:
                port_id = v_port['portId']
                port = create_ports[port_id]
                host = v_port['hosts'][0]
                device_owner = port['device_owner']
                port_name = port['name']
                network_id = port['network_id']
                device_id = port['device_id']
                if device_owner == 'network:dhcp':
                    cmd2.append('network id %s' % network_id)
                    cmd2.append('dhcp id %s hostid %s port-id %s name "%s"' % (
                                device_id, host, port_id, port_name))
                elif device_owner == 'compute':
                    cmd2.append('vm id %s hostid %s' % (device_id, host))
                    cmd2.append('port id %s name "%s" network-id %s' % (
                                port_id, port_name, network_id))
                elif device_owner == n_const.DEVICE_OWNER_DVR_INTERFACE:
                    cmd2.append('instance id %s type router' % device_id)
                    cmd2.append('port id %s network-id %s hostid %s' % (
                                port_id, network_id, host))
                net_count += 1

        self._verify_send_eapi_request_calls(mock_send_eapi_req, [cmd1, cmd2])

    @patch(EAPI_SEND_FUNC)
    def test_delete_tenant(self, mock_send_eapi_req):
        tenant_id = 'ten-1'
        self.drv.delete_tenant(tenant_id)
        cmd1 = ['show openstack agent uuid']
        cmd2 = ['enable', 'configure', 'cvx', 'service openstack',
                'region RegionOne', 'no tenant ten-1',
                ]
        self._verify_send_eapi_request_calls(mock_send_eapi_req, [cmd1, cmd2])

    @patch(EAPI_SEND_FUNC)
    def test_delete_tenant_bulk(self, mock_send_eapi_req):
        num_tenants = 10
        tenant_list = ['ten-%d' % t_id for t_id in range(1, num_tenants)]
        self.drv.delete_tenant_bulk(tenant_list)
        cmd1 = ['show openstack agent uuid']
        cmd2 = ['enable',
                'configure',
                'cvx',
                'service openstack',
                'region RegionOne']
        for ten_id in range(1, num_tenants):
            cmd2.append('no tenant ten-%d' % ten_id)

        self._verify_send_eapi_request_calls(mock_send_eapi_req, [cmd1, cmd2])

    def test_get_network_info_returns_none_when_no_such_net(self):
        expected = []
        self.drv.get_tenants = mock.MagicMock()
        self.drv.get_tenants.return_value = []

        net_info = self.drv.get_tenants()

        self.drv.get_tenants.assert_called_once_with()
        self.assertEqual(net_info, expected, ('Network info must be "None"'
                                              'for unknown network'))

    def test_get_network_info_returns_info_for_available_net(self):
        valid_network_id = '12345'
        valid_net_info = {'network_id': valid_network_id,
                          'some_info': 'net info'}
        known_nets = valid_net_info

        self.drv.get_tenants = mock.MagicMock()
        self.drv.get_tenants.return_value = known_nets

        net_info = self.drv.get_tenants()
        self.assertEqual(net_info, valid_net_info,
                         ('Must return network info for a valid net'))

    @patch(EAPI_SEND_FUNC)
    def test_check_supported_features(self, mock_send_eapi_req):
        self.drv._get_random_name = mock.MagicMock()
        self.drv._get_random_name.return_value = 'RegionOne'

        self.drv.check_supported_features()

        get_eos_master_cmd = ['show openstack agent uuid']
        instance_command = ['show openstack instances']
        cmds = [get_eos_master_cmd, instance_command]

        calls = []
        calls.extend(mock.call(cmds=cmd, commands_to_log=cmd) for cmd in cmds)
        mock_send_eapi_req.assert_has_calls(calls)

    @patch(EAPI_SEND_FUNC)
    def test_register_with_eos(self, mock_send_eapi_req):
        self.drv.register_with_eos()
        cmd1 = ['show openstack agent uuid']
        cmd2 = ['enable',
                'configure',
                'cvx',
                'service openstack',
                'region %s' % self.region,
                'sync interval %d' % cfg.CONF.ml2_arista.sync_interval,
                ]
        self._verify_send_eapi_request_calls(
            mock_send_eapi_req,
            [cmd1, cmd2],
            commands_to_log=[cmd1, cmd2])

    def _enable_sync_cmds(self):
        self.drv.cli_commands[
            constants.CMD_REGION_SYNC] = 'region RegionOne sync'
        self.drv.cli_commands[constants.CMD_SYNC_HEARTBEAT] = 'sync heartbeat'
        self.drv.cli_commands['baremetal'] = ''

    @patch(EAPI_SEND_FUNC)
    def test_create_network_bulk_during_sync(self, mock_send_eapi_req):
        self._enable_sync_cmds()
        self.drv.cli_commands['features'] = {'hierarchical-port-binding': 1}
        tenant_id = 'ten-10'
        num_networks = 101
        segments = [{'segmentation_id': 101,
                     'physical_network': 'default',
                     'id': 'segment_id_1',
                     'network_type': 'vlan'}]
        networks = [{
            'network_id': 'net-id-%d' % net_id,
            'network_name': 'net-name-%d' % net_id,
            'segments': segments,
            'shared': True,
            } for net_id in range(1, num_networks + 1)
        ]

        self.drv.create_network_bulk(tenant_id, networks, sync=True)
        cmd1 = ['show openstack agent uuid']
        cmd2 = ['enable',
                'configure',
                'cvx',
                'service openstack',
                'region RegionOne sync',
                'tenant ten-10']

        # Send 100 create network commands
        for net_id in range(1, 101):
            cmd2.append('network id net-id-%d name "net-name-%d"' %
                        (net_id, net_id))
            for seg in segments:
                is_dynamic = seg.get('is_dynamic', False)
                cmd2.append('segment %s type %s id %d %s' % (seg['id'],
                            seg['network_type'], seg['segmentation_id'],
                            'dynamic' if is_dynamic else 'static'))
            cmd2.append('shared')

        # Send heartbeat
        cmd2.append('sync heartbeat')
        # Send the remaining network
        cmd2.append('network id net-id-101 name "net-name-101"')
        for seg in segments:
            is_dynamic = seg.get('is_dynamic', False)
            cmd2.append('segment %s type %s id %d %s' % (seg['id'],
                        seg['network_type'], seg['segmentation_id'],
                        'dynamic' if is_dynamic else 'static'))
        cmd2.append('shared')
        # Send the final heartbeat
        cmd2.append('sync heartbeat')

        self._verify_send_eapi_request_calls(mock_send_eapi_req, [cmd1, cmd2])

    @patch(EAPI_SEND_FUNC)
    def test_delete_network_bulk_during_sync(self, mock_send_eapi_req):
        self._enable_sync_cmds()
        tenant_id = 'ten-10'
        num_networks = 101
        networks = ['nid-%d' % net_id for net_id in range(1, num_networks + 1)]

        self.drv.delete_network_bulk(tenant_id, networks, sync=True)
        cmd1 = ['show openstack agent uuid']
        cmd2 = ['enable',
                'configure',
                'cvx',
                'service openstack',
                'region RegionOne sync',
                'tenant ten-10']

        # Send 100 create network commands
        for net_id in range(1, 101):
            cmd2.append('no network id nid-%d' % (net_id))

        # Send heartbeat
        cmd2.append('sync heartbeat')
        # Send the remaining network
        cmd2.append('no network id nid-101')
        # Send the final heartbeat
        cmd2.append('sync heartbeat')

        self._verify_send_eapi_request_calls(mock_send_eapi_req, [cmd1, cmd2])

    @patch(EAPI_SEND_FUNC)
    def test_delete_vm_bulk_during_sync(self, mock_send_eapi_req):
        self._enable_sync_cmds()
        tenant_id = 'ten-2'
        num_vms = 101
        vm_ids = ['vm-id-%d' % vm_id for vm_id in range(1, num_vms + 1)]
        self.drv.delete_vm_bulk(tenant_id, vm_ids, sync=True)

        cmd1 = ['show openstack agent uuid']
        cmd2 = ['enable',
                'configure',
                'cvx',
                'service openstack',
                'region RegionOne sync',
                'tenant ten-2']

        for vm_id in range(1, 101):
            cmd2.append('no vm id vm-id-%d' % vm_id)

        # Send heartbeat
        cmd2.append('sync heartbeat')
        # Send the remaining vm
        cmd2.append('no vm id vm-id-101')
        # Send the final heartbeat
        cmd2.append('sync heartbeat')

        self._verify_send_eapi_request_calls(mock_send_eapi_req, [cmd1, cmd2])

    @patch(EAPI_SEND_FUNC)
    def test_create_port_bulk_during_sync(self, mock_send_eapi_req):
        self._enable_sync_cmds()
        tenant_id = 'ten-3'
        num_devices = 101
        num_ports_per_device = 2

        device_count = 0
        devices = {}
        for device_id in range(1, num_devices):
            device_count += 1
            dev_id = 'dev-id-%d' % device_id
            devices[dev_id] = {'vmId': dev_id,
                               'baremetal_instance': False,
                               'ports': []
                               }
            for port_id in range(1, num_ports_per_device + 1):
                port_id = 'port-id-%d-%d' % (device_id, port_id)
                port = {
                    'device_id': 'dev-id-%d' % device_id,
                    'hosts': ['host_%d' % (device_count)],
                    'portId': port_id
                }
                devices[dev_id]['ports'].append(port)

        device_owners = [n_const.DEVICE_OWNER_DHCP, 'compute',
                         n_const.DEVICE_OWNER_DVR_INTERFACE]

        port_list = []
        net_count = 1
        for device_id in range(1, num_devices):
            for port_id in range(1, num_ports_per_device + 1):
                port = {
                    'portId': 'port-id-%d-%d' % (device_id, port_id),
                    'device_id': 'dev-id-%d' % device_id,
                    'device_owner': device_owners[(device_id + port_id) % 3],
                    'network_id': 'network-id-%d' % net_count,
                    'name': 'port-%d-%d' % (device_id, port_id),
                    'tenant_id': tenant_id
                    }
                port_list.append(port)
                net_count += 1

        create_ports = {}
        port_profiles = {}
        for port in port_list:
            create_ports.update(utils.port_dict_representation(port))
            port_profiles[port['portId']] = {'vnic_type': 'normal'}

        self.drv.cli_commands[constants.CMD_INSTANCE] = 'instance'
        self.drv.create_instance_bulk(tenant_id, create_ports, devices,
                                      port_profiles=port_profiles, sync=True)
        cmd1 = ['show openstack agent uuid']
        cmd2 = ['enable',
                'configure',
                'cvx',
                'service openstack',
                'region RegionOne sync',
                'tenant ten-3']

        for count, device in enumerate(devices.values(), 1):
            for v_port in device['ports']:
                port_id = v_port['portId']
                port = create_ports[port_id]
                host = v_port['hosts'][0]
                vm_id = device['vmId']
                port_name = port['name']
                network_id = port['network_id']
                device_owner = port['device_owner']
                device_id = port['device_id']

                if device_owner == n_const.DEVICE_OWNER_DHCP:
                    cmd2.append('network id %s' % network_id)
                    cmd2.append('dhcp id %s hostid %s port-id %s name "%s"' % (
                                vm_id, host, port_id, port_name))
                elif device_owner == 'compute':
                    cmd2.append('vm id %s hostid %s' % (vm_id, host))
                    cmd2.append('port id %s name "%s" network-id %s' % (
                                port_id, port_name, network_id))
                elif device_owner == n_const.DEVICE_OWNER_DVR_INTERFACE:
                    cmd2.append('instance id %s type router' % device_id)
                    cmd2.append('port id %s network-id %s hostid %s' % (
                                port_id, network_id, host))
                if count == (num_devices - 1):
                    # Send heartbeat
                    cmd2.append('sync heartbeat')

        # Send the final heartbeat
        cmd2.append('sync heartbeat')

        self._verify_send_eapi_request_calls(mock_send_eapi_req, [cmd1, cmd2])

    @patch(EAPI_SEND_FUNC)
    def test_delete_tenant_bulk_during_sync(self, mock_send_eapi_req):
        self._enable_sync_cmds()
        num_tenants = 101
        tenant_list = ['ten-%d' % t_id for t_id in range(1, num_tenants + 1)]
        self.drv.delete_tenant_bulk(tenant_list, sync=True)
        cmd1 = ['show openstack agent uuid']
        cmd2 = ['enable',
                'configure',
                'cvx',
                'service openstack',
                'region RegionOne sync']
        for ten_id in range(1, num_tenants + 1):
            cmd2.append('no tenant ten-%d' % ten_id)

        cmd2.append('sync heartbeat')

        self._verify_send_eapi_request_calls(mock_send_eapi_req, [cmd1, cmd2])


class AristaRPCWrapperInvalidConfigTestCase(base.BaseTestCase):
    """Negative test cases to test the Arista Driver configuration."""

    def setUp(self):
        super(AristaRPCWrapperInvalidConfigTestCase, self).setUp()
        self.setup_invalid_config()  # Invalid config, required options not set

    def setup_invalid_config(self):
        utils.setup_arista_wrapper_config(cfg, host='', user='')

    def test_raises_exception_on_wrong_configuration(self):
        ndb = db_lib.NeutronNets()
        self.assertRaises(arista_exc.AristaConfigError,
                          arista_eapi.AristaRPCWrapperEapi, ndb)


class NegativeRPCWrapperTestCase(testlib_api.SqlTestCase):
    """Negative test cases to test the RPC between Arista Driver and EOS."""

    def setUp(self):
        super(NegativeRPCWrapperTestCase, self).setUp()
        setup_valid_config()

    def test_exception_is_raised_on_json_server_error(self):
        ndb = db_lib.NeutronNets()
        drv = arista_eapi.AristaRPCWrapperEapi(ndb)

        drv._send_api_request = mock.MagicMock(
            side_effect=Exception('server error')
        )
        with mock.patch.object(arista_eapi.LOG, 'error') as log_err:
            self.assertRaises(arista_exc.AristaRpcError, drv.get_tenants)
            log_err.assert_called_once_with(mock.ANY)


class RPCWrapperEapiValidConfigTrunkTestCase(testlib_api.SqlTestCase):
    """Test cases to test plug trunk port into network."""

    def setUp(self):
        super(RPCWrapperEapiValidConfigTrunkTestCase, self).setUp()
        setup_valid_config()
        ndb = mock.MagicMock()
        self.drv = arista_eapi.AristaRPCWrapperEapi(ndb)
        self.drv._server_ip = "10.11.12.13"
        self.region = 'RegionOne'
        arista_eapi.db_lib = mock.MagicMock()

    @patch(EAPI_SEND_FUNC)
    def test_plug_host_into_network(self, mock_send_eapi_req):
        tenant_id = 'ten-1'
        network_id = 'net-id-1'
        vm_id = 'vm-1'
        port_id = 111
        host = 'host'
        port_name = '111-port'
        sub_segment_id = 'sub_segment_id_1'
        sub_segmentation_id = 1002
        sub_network_id = 'subnet-id'
        subport_id = 222
        segment_id = 'segment_id_1'
        segments = [{'network_type': 'vlan', 'physical_network': 'default',
                     'segmentation_id': 1234, 'id': segment_id}]
        binding_level = FakePortBindingLevel(subport_id, 0, 'vendor-1',
                                             sub_segment_id)
        subport_segments = [binding_level]
        trunk_details = {'sub_ports': [{'mac_address': 'mac_address',
                                        'port_id': subport_id,
                                        'segmentation_id': sub_segmentation_id,
                                        'segmentation_type': 'vlan'}],
                         'trunk_id': 'trunk_id'}
        self.drv._ndb.get_network_id_from_port_id.return_value = sub_network_id
        arista_eapi.db_lib.get_port_binding_level.return_value = \
            subport_segments

        self.drv.plug_host_into_network(vm_id, host, port_id,
                                        network_id, tenant_id, segments,
                                        port_name, trunk_details=trunk_details)

        cmd1 = ['show openstack agent uuid']
        cmd2 = ['enable', 'configure', 'cvx', 'service openstack',
                'region RegionOne',
                'tenant ten-1', 'vm id vm-1 hostid host',
                'port id 111 name "111-port" network-id net-id-1',
                ]
        for level, segment in enumerate(segments):
            cmd2.append('segment level %s id %s' % (level, segment['id']))
        cmd2.append('port id 222 network-id subnet-id')
        for segment in subport_segments:
            cmd2.append('segment level %s id %s' % (segment.level,
                                                    segment.segment_id))

        self._verify_send_eapi_request_calls(mock_send_eapi_req, [cmd1, cmd2])

    @patch(EAPI_SEND_FUNC)
    def test_plug_baremetal_into_network(self, mock_send_eapi_req):
        tenant_id = 'ten-2'
        network_id = 'net-id-1'
        bm_id = 'bm-1'
        port_id = 'p1'
        host = 'host'
        port_name = 'name_p1'
        device_owner = 'compute:None'
        subport_id = 222
        sub_segment_id = 'sub_segment_id_1'

        segments = [{'segmentation_id': 1001,
                     'id': 'segment_id_1',
                     'network_type': 'vlan',
                     'is_dynamic': False}]

        subport_net_id = 'net-id-2'
        binding_level = FakePortBindingLevel(subport_id, 0, 'vendor-1',
                                             sub_segment_id)
        subport_segments = [binding_level]

        trunk_details = {'sub_ports': [{'mac_address': 'mac_address',
                                        'port_id': 'p2',
                                        'segmentation_id': 1002,
                                        'segmentation_type': 'vlan'}],
                         'trunk_id': 'trunk_id'}
        switch_bindings = {'local_link_information': [
            {'port_id': 'Eth1', 'switch_id': 'switch-id-1',
             'switch_info': 'switch-1'}]}
        bindings = switch_bindings['local_link_information']
        self.drv._ndb.get_network_id_from_port_id.return_value = subport_net_id
        arista_eapi.db_lib.get_port_binding_level.return_value = \
            subport_segments

        self.drv.bm_and_dvr_supported = mock.MagicMock(return_value=True)

        self.drv.plug_baremetal_into_network(bm_id, host, port_id,
                                             network_id, tenant_id,
                                             segments, port_name,
                                             device_owner,
                                             None, None, 'baremetal',
                                             bindings, trunk_details)

        cmd1 = ['show openstack agent uuid']
        cmd2 = ['enable', 'configure', 'cvx', 'service openstack',
                'region RegionOne',
                'tenant ten-2',
                'instance id bm-1 hostid host type baremetal',
                'port id p1 name "name_p1" network-id net-id-1 '
                'type native switch-id switch-id-1 switchport Eth1',
                ]
        for level, segment in enumerate(segments):
            cmd2.append('segment level %s id %s' % (level, segment['id']))
        cmd2.append('port id p2 network-id net-id-2 '
                    'type allowed switch-id switch-id-1 switchport Eth1', )
        for segment in subport_segments:
            cmd2.append('segment level %s id %s' % (segment.level,
                                                    segment.segment_id))
        cmd2.append('exit')

        self._verify_send_eapi_request_calls(mock_send_eapi_req, [cmd1, cmd2])

    @patch(EAPI_SEND_FUNC)
    def test_unplug_host_from_network(self, mock_send_eapi_req):
        tenant_id = 'ten-2'
        network_id = 'net-id-1'
        vm_id = 'vm-2'
        port_id = 111
        host = 'host'
        subport_id = 222

        trunk_details = {'sub_ports': [{'mac_address': 'mac_address',
                                        'port_id': subport_id,
                                        'segmentation_id': 123,
                                        'segmentation_type': 'vlan'}],
                         'trunk_id': 'trunk_id'}
        self.drv.unplug_host_from_network(vm_id, host, port_id,
                                          network_id, tenant_id,
                                          trunk_details)
        cmd1 = ['show openstack agent uuid']
        cmd2 = ['enable', 'configure', 'cvx', 'service openstack',
                'region RegionOne',
                'tenant ten-2', 'vm id vm-2 hostid host',
                'no port id 222',
                'no port id 111',
                ]
        self._verify_send_eapi_request_calls(mock_send_eapi_req, [cmd1, cmd2])

    @patch(EAPI_SEND_FUNC)
    def test_unplug_baremetal_from_network(self, mock_send_eapi_req):
        tenant_id = 'ten-2'
        network_id = 'net-id-1'
        bm_id = 'bm-2'
        port_id = 111
        host = 'host'
        subport_id = 222

        trunk_details = {'sub_ports': [{'mac_address': 'mac_address',
                                        'port_id': subport_id,
                                        'segmentation_id': 123,
                                        'segmentation_type': 'vlan'}],
                         'trunk_id': 'trunk_id'}
        switch_bindings = {'local_link_information': [
            {'port_id': 'Eth1', 'switch_id': 'switch-id-1',
             'switch_info': 'switch-1'}]}
        bindings = switch_bindings['local_link_information']
        self.drv.bm_and_dvr_supported = mock.MagicMock(return_value=True)
        self.drv.unplug_baremetal_from_network(bm_id, host, port_id,
                                               network_id, tenant_id,
                                               None, 'baremetal',
                                               bindings, trunk_details)
        cmd1 = ['show openstack agent uuid']
        cmd2 = ['enable', 'configure', 'cvx', 'service openstack',
                'region RegionOne',
                'tenant ten-2',
                'instance id bm-2 hostid host type baremetal',
                'no port id 222',
                'no port id 111',
                ]
        self._verify_send_eapi_request_calls(mock_send_eapi_req, [cmd1, cmd2])

    def _verify_send_eapi_request_calls(self, mock_send_eapi_req, cmds,
                                        commands_to_log=None):
        calls = []
        calls.extend(
            mock.call(cmds=cmd, commands_to_log=log_cmd)
            for cmd, log_cmd in six.moves.zip(cmds, commands_to_log or cmds))
        mock_send_eapi_req.assert_has_calls(calls)
