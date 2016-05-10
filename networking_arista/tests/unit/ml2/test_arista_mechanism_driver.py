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
from oslo_config import cfg

from neutron.common import constants as n_const
import neutron.db.api as db
from neutron.extensions import portbindings
from neutron.tests import base
from neutron.tests.unit import testlib_api

from networking_arista.common import db_lib
from networking_arista.common import exceptions as arista_exc
from networking_arista.ml2 import arista_ml2
from networking_arista.ml2 import mechanism_arista


def setup_arista_wrapper_config(value=''):
    cfg.CONF.keystone_authtoken = fake_keystone_info_class()
    cfg.CONF.set_override('eapi_host', value, "ml2_arista")
    cfg.CONF.set_override('eapi_username', value, "ml2_arista")
    cfg.CONF.set_override('sync_interval', 10, "ml2_arista")
    cfg.CONF.set_override('conn_timeout', 20, "ml2_arista")


def setup_valid_config():
    # Config is not valid if value is not set
    setup_arista_wrapper_config('value')


class AristaProvisionedVlansStorageTestCase(testlib_api.SqlTestCase):
    """Test storing and retriving functionality of Arista mechanism driver.

    Tests all methods of this class by invoking them separately as well
    as a group.
    """

    def test_tenant_is_remembered(self):
        tenant_id = 'test'

        db_lib.remember_tenant(tenant_id)
        net_provisioned = db_lib.is_tenant_provisioned(tenant_id)
        self.assertTrue(net_provisioned, 'Tenant must be provisioned')

    def test_tenant_is_removed(self):
        tenant_id = 'test'

        db_lib.remember_tenant(tenant_id)
        db_lib.forget_tenant(tenant_id)
        net_provisioned = db_lib.is_tenant_provisioned(tenant_id)
        self.assertFalse(net_provisioned, 'The Tenant should be deleted')

    def test_network_is_remembered(self):
        tenant_id = 'test'
        network_id = '123'
        segmentation_id = 456

        db_lib.remember_network(tenant_id, network_id, segmentation_id)
        net_provisioned = db_lib.is_network_provisioned(tenant_id,
                                                        network_id)
        self.assertTrue(net_provisioned, 'Network must be provisioned')

    def test_network_is_removed(self):
        tenant_id = 'test'
        network_id = '123'

        db_lib.remember_network(tenant_id, network_id, '123')
        db_lib.forget_network(tenant_id, network_id)
        net_provisioned = db_lib.is_network_provisioned(tenant_id, network_id)
        self.assertFalse(net_provisioned, 'The network should be deleted')

    def test_vm_is_remembered(self):
        vm_id = 'VM-1'
        tenant_id = 'test'
        network_id = '123'
        port_id = 456
        host_id = 'ubuntu1'

        db_lib.remember_vm(vm_id, host_id, port_id, network_id, tenant_id)
        vm_provisioned = db_lib.is_vm_provisioned(vm_id, host_id, port_id,
                                                  network_id, tenant_id)
        self.assertTrue(vm_provisioned, 'VM must be provisioned')

    def test_vm_is_removed(self):
        vm_id = 'VM-1'
        tenant_id = 'test'
        network_id = '123'
        port_id = 456
        host_id = 'ubuntu1'

        db_lib.remember_vm(vm_id, host_id, port_id, network_id, tenant_id)
        db_lib.forget_port(port_id, host_id)
        vm_provisioned = db_lib.is_vm_provisioned(vm_id, host_id, port_id,
                                                  network_id, tenant_id)
        self.assertFalse(vm_provisioned, 'The vm should be deleted')

    def test_remembers_multiple_networks(self):
        tenant_id = 'test'
        expected_num_nets = 100
        nets = ['id%s' % n for n in range(expected_num_nets)]
        for net_id in nets:
            db_lib.remember_network(tenant_id, net_id, 123)

        num_nets_provisioned = db_lib.num_nets_provisioned(tenant_id)
        self.assertEqual(expected_num_nets, num_nets_provisioned,
                         'There should be %d nets, not %d' %
                         (expected_num_nets, num_nets_provisioned))

    def test_removes_all_networks(self):
        tenant_id = 'test'
        num_nets = 100
        old_nets = db_lib.num_nets_provisioned(tenant_id)
        nets = ['id_%s' % n for n in range(num_nets)]
        for net_id in nets:
            db_lib.remember_network(tenant_id, net_id, 123)
        for net_id in nets:
            db_lib.forget_network(tenant_id, net_id)

        num_nets_provisioned = db_lib.num_nets_provisioned(tenant_id)
        expected = old_nets
        self.assertEqual(expected, num_nets_provisioned,
                         'There should be %d nets, not %d' %
                         (expected, num_nets_provisioned))

    def test_remembers_multiple_tenants(self):
        expected_num_tenants = 100
        tenants = ['id%s' % n for n in range(expected_num_tenants)]
        for tenant_id in tenants:
            db_lib.remember_tenant(tenant_id)

        num_tenants_provisioned = db_lib.num_provisioned_tenants()
        self.assertEqual(expected_num_tenants, num_tenants_provisioned,
                         'There should be %d tenants, not %d' %
                         (expected_num_tenants, num_tenants_provisioned))

    def test_removes_multiple_tenants(self):
        num_tenants = 100
        tenants = ['id%s' % n for n in range(num_tenants)]
        for tenant_id in tenants:
            db_lib.remember_tenant(tenant_id)
        for tenant_id in tenants:
            db_lib.forget_tenant(tenant_id)

        num_tenants_provisioned = db_lib.num_provisioned_tenants()
        expected = 0
        self.assertEqual(expected, num_tenants_provisioned,
                         'There should be %d tenants, not %d' %
                         (expected, num_tenants_provisioned))

    def test_num_vm_is_valid(self):
        tenant_id = 'test'
        network_id = '123'
        port_id_base = 'port-id'
        host_id = 'ubuntu1'

        vm_to_remember = ['vm1', 'vm2', 'vm3']
        vm_to_forget = ['vm2', 'vm1']

        for vm in vm_to_remember:
            port_id = port_id_base + vm
            db_lib.remember_vm(vm, host_id, port_id, network_id, tenant_id)
        for vm in vm_to_forget:
            port_id = port_id_base + vm
            db_lib.forget_port(port_id, host_id)

        num_vms = len(db_lib.get_vms(tenant_id))
        expected = len(vm_to_remember) - len(vm_to_forget)

        self.assertEqual(expected, num_vms,
                         'There should be %d records, '
                         'got %d records' % (expected, num_vms))
        # clean up afterwards
        db_lib.forget_port(port_id, host_id)

    def test_get_network_list_returns_eos_compatible_data(self):
        tenant = u'test-1'
        segm_type = 'vlan'
        network_id = u'123'
        network2_id = u'1234'
        vlan_id = 123
        vlan2_id = 1234
        expected_eos_net_list = {network_id: {u'networkId': network_id,
                                              u'segmentationTypeId': vlan_id,
                                              u'segmentationType': segm_type},
                                 network2_id: {u'networkId': network2_id,
                                               u'segmentationTypeId': vlan2_id,
                                               u'segmentationType': segm_type}}

        db_lib.remember_network(tenant, network_id, vlan_id)
        db_lib.remember_network(tenant, network2_id, vlan2_id)

        net_list = db_lib.get_networks(tenant)
        self.assertNotEqual(net_list != expected_eos_net_list, ('%s != %s' %
                            (net_list, expected_eos_net_list)))


class PositiveRPCWrapperValidConfigTestCase(base.BaseTestCase):
    """Test cases to test the RPC between Arista Driver and EOS.

    Tests all methods used to send commands between Arista Driver and EOS
    """

    def setUp(self):
        super(PositiveRPCWrapperValidConfigTestCase, self).setUp()
        setup_valid_config()
        self.drv = arista_ml2.AristaRPCWrapper()
        self.drv._server_ip = "10.11.12.13"
        self.region = 'RegionOne'

    def _get_exit_mode_cmds(self, modes):
        return ['exit'] * len(modes)

    def _verify_send_eapi_request_calls(self, mock_send_eapi_req, cmds):
        # Need this method as unfortunately, a direct comparison between
        # Mock calls and expected call objects doesn't compare the list of
        # commands that have been sent
        for cmd in cmds:
            found = False
            for call in mock_send_eapi_req.mock_calls:
                if cmd == call[2]['cmds']:
                    found = True
                    break
            if not found:
                assert (0,
                        "Failed to find command '%s' in %s" % (
                            cmd, mock_send_eapi_req.mock_calls))

    def test_no_exception_on_correct_configuration(self):
        self.assertIsNotNone(self.drv)

    @patch('networking_arista.ml2.arista_ml2.AristaRPCWrapper._send_eapi_req')
    def test_plug_host_into_network(self, mock_send_eapi_req):
        tenant_id = 'ten-1'
        vm_id = 'vm-1'
        port_id = 123
        network_id = 'net-id'
        host = 'host'
        port_name = '123-port'

        self.drv.plug_host_into_network(vm_id, host, port_id,
                                        network_id, tenant_id, port_name)
        cmd1 = ['show openstack agent uuid']
        cmd2 = ['enable', 'configure', 'cvx', 'service openstack',
                'region RegionOne',
                'tenant ten-1', 'vm id vm-1 hostid host',
                'port id 123 name "123-port" network-id net-id',
                ]
        self._verify_send_eapi_request_calls(mock_send_eapi_req, [cmd1, cmd2])

    @patch('networking_arista.ml2.arista_ml2.AristaRPCWrapper._send_eapi_req')
    def test_plug_dhcp_port_into_network(self, mock_send_eapi_req):
        tenant_id = 'ten-1'
        vm_id = 'vm-1'
        port_id = 123
        network_id = 'net-id'
        host = 'host'
        port_name = '123-port'

        self.drv.plug_dhcp_port_into_network(vm_id, host, port_id,
                                             network_id, tenant_id, port_name)
        cmd1 = ['show openstack agent uuid']
        cmd2 = ['enable', 'configure', 'cvx', 'service openstack',
                'region RegionOne',
                'tenant ten-1', 'network id net-id',
                'dhcp id vm-1 hostid host port-id 123 name "123-port"',
                ]
        self._verify_send_eapi_request_calls(mock_send_eapi_req, [cmd1, cmd2])

    @patch('networking_arista.ml2.arista_ml2.AristaRPCWrapper._send_eapi_req')
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

    @patch('networking_arista.ml2.arista_ml2.AristaRPCWrapper._send_eapi_req')
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

    @patch('networking_arista.ml2.arista_ml2.AristaRPCWrapper._send_eapi_req')
    def test_create_network(self, mock_send_eapi_req):
        tenant_id = 'ten-1'
        network = {
            'network_id': 'net-id',
            'network_name': 'net-name',
            'segmentation_id': 123,
            'shared': False,
            }
        self.drv.create_network(tenant_id, network)
        cmd1 = ['show openstack agent uuid']
        cmd2 = ['enable', 'configure', 'cvx', 'service openstack',
                'region RegionOne',
                'tenant ten-1', 'network id net-id name "net-name"',
                'segment 1 type vlan id 123',
                'no shared',
                ]

        self._verify_send_eapi_request_calls(mock_send_eapi_req, [cmd1, cmd2])

    @patch('networking_arista.ml2.arista_ml2.AristaRPCWrapper._send_eapi_req')
    def test_create_shared_network(self, mock_send_eapi_req):
        tenant_id = 'ten-1'
        network = {
            'network_id': 'net-id',
            'network_name': 'net-name',
            'segmentation_id': 123,
            'shared': True}
        self.drv.create_network(tenant_id, network)
        cmd1 = ['show openstack agent uuid']
        cmd2 = ['enable', 'configure', 'cvx', 'service openstack',
                'region RegionOne',
                'tenant ten-1', 'network id net-id name "net-name"',
                'segment 1 type vlan id 123',
                'shared',
                ]
        self._verify_send_eapi_request_calls(mock_send_eapi_req, [cmd1, cmd2])

    @patch('networking_arista.ml2.arista_ml2.AristaRPCWrapper._send_eapi_req')
    def test_create_network_bulk(self, mock_send_eapi_req):
        tenant_id = 'ten-2'
        num_networks = 10
        networks = [{
            'network_id': 'net-id-%d' % net_id,
            'network_name': 'net-name-%d' % net_id,
            'segmentation_id': net_id,
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
            cmd2.append('segment 1 type vlan id %d' % net_id)
            cmd2.append('shared')
        self._verify_send_eapi_request_calls(mock_send_eapi_req, [cmd1, cmd2])

    @patch('networking_arista.ml2.arista_ml2.AristaRPCWrapper._send_eapi_req')
    def test_delete_network(self, mock_send_eapi_req):
        tenant_id = 'ten-1'
        network_id = 'net-id'
        self.drv.delete_network(tenant_id, network_id)
        cmd1 = ['show openstack agent uuid']
        cmd2 = ['enable', 'configure', 'cvx', 'service openstack',
                'region RegionOne',
                'tenant ten-1', 'no network id net-id',
                ]
        self._verify_send_eapi_request_calls(mock_send_eapi_req, [cmd1, cmd2])

    @patch('networking_arista.ml2.arista_ml2.AristaRPCWrapper._send_eapi_req')
    def test_delete_network_bulk(self, mock_send_eapi_req):
        tenant_id = 'ten-2'
        num_networks = 10
        networks = [{
            'network_id': 'net-id-%d' % net_id,
            'network_name': 'net-name-%d' % net_id,
            'segmentation_id': net_id} for net_id in range(1, num_networks)
        ]

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

    @patch('networking_arista.ml2.arista_ml2.AristaRPCWrapper._send_eapi_req')
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

    @patch('networking_arista.ml2.arista_ml2.AristaRPCWrapper._send_eapi_req')
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

    @patch('networking_arista.ml2.arista_ml2.AristaRPCWrapper._send_eapi_req')
    def test_create_port_bulk(self, mock_send_eapi_req):
        tenant_id = 'ten-3'
        num_devices = 10
        num_ports_per_device = 2

        ports = {}
        device_count = 0
        for device_id in range(1, num_devices):
            device_count += 1
            for port_id in range(1, num_ports_per_device):
                port_id = 'port-id-%d-%d' % (device_id, port_id)
                ports[port_id] = {
                    'deviceId': 'dev-id-%d' % device_id,
                    'hosts': ['host_%d' % (device_count)]
                }

        devices = [n_const.DEVICE_OWNER_DHCP, 'compute',
                   n_const.DEVICE_OWNER_DVR_INTERFACE]
        port_list = []

        net_count = 1
        for device_id in range(1, num_devices):
            for port_id in range(1, num_ports_per_device):
                port = {
                    'id': 'port-id-%d-%d' % (device_id, port_id),
                    'device_id': 'dev-id-%d' % device_id,
                    'device_owner': devices[(device_id + port_id) % 3],
                    'network_id': 'network-id-%d' % net_count,
                    'name': 'port-%d-%d' % (device_id, port_id)
                }
                port_list.append(port)
                net_count += 1

        self.drv.cli_commands[arista_ml2.CMD_INSTANCE] = 'instance'
        self.drv.create_port_bulk(tenant_id, port_list, ports)
        cmd1 = ['show openstack agent uuid']
        cmd2 = ['enable',
                'configure',
                'cvx',
                'service openstack',
                'region RegionOne',
                'tenant ten-3']

        net_count = 1
        for vm_count in range(1, num_devices):
            host = 'host_%s' % vm_count
            for port_count in range(1, num_ports_per_device):
                device_id = 'dev-id-%d' % vm_count
                device_owner = devices[(vm_count + port_count) % 2]
                port_name = '"port-%d-%d"' % (vm_count, port_count)
                network_id = 'network-id-%d' % net_count
                port_id = 'port-id-%d-%d' % (vm_count, port_count)
                if device_owner == 'network:dhcp':
                    cmd2.append('network id %s' % network_id)
                    cmd2.append('dhcp id %s hostid %s port-id %s name %s' % (
                                device_id, host, port_id, port_name))
                elif device_owner == 'compute':
                    cmd2.append('vm id %s hostid %s' % (device_id, host))
                    cmd2.append('port id %s name %s network-id %s' % (
                                port_id, port_name, network_id))
                elif device_owner == n_const.DEVICE_OWNER_DVR_INTERFACE:
                    cmd2.append('instance id %s type router' % device_id)
                    cmd2.append('port id %s network-id %s hostid %s' % (
                                port_id, network_id, host))
                net_count += 1

        self._verify_send_eapi_request_calls(mock_send_eapi_req, [cmd1, cmd2])

    @patch('networking_arista.ml2.arista_ml2.AristaRPCWrapper._send_eapi_req')
    def test_delete_tenant(self, mock_send_eapi_req):
        tenant_id = 'ten-1'
        self.drv.delete_tenant(tenant_id)
        cmd1 = ['show openstack agent uuid']
        cmd2 = ['enable', 'configure', 'cvx', 'service openstack',
                'region RegionOne', 'no tenant ten-1',
                ]
        self._verify_send_eapi_request_calls(mock_send_eapi_req, [cmd1, cmd2])

    @patch('networking_arista.ml2.arista_ml2.AristaRPCWrapper._send_eapi_req')
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

    @patch('networking_arista.ml2.arista_ml2.AristaRPCWrapper._send_eapi_req')
    def test_check_cli_commands(self, mock_send_eapi_req):
        self.drv._get_random_name = mock.MagicMock()
        self.drv._get_random_name.return_value = 'RegionOne'

        self.drv.check_cli_commands()

        timestamp_cmd = ['show openstack config region RegionOne timestamp']
        sync_lock_cmd = ['enable', 'configure', 'cvx', 'service openstack',
                         'region RegionOne', 'sync lock clientid requestid',
                         'exit', 'region RegionOne sync', 'sync end', 'exit']
        delete_region_cmd = ['enable', 'configure', 'cvx', 'service openstack',
                             'no region RegionOne']
        instance_command = ['enable', 'configure', 'cvx', 'service openstack',
                            'region RegionOne', 'tenant t1',
                            'instance id i1 type router']
        cmds = [timestamp_cmd, sync_lock_cmd, delete_region_cmd,
                instance_command, delete_region_cmd]

        for cmd in cmds:
            found = False
            for call in mock_send_eapi_req.mock_calls:
                if cmd == call[2]['cmds']:
                    found = True
                    break
            if not found:
                assert 0, "Failed to find a command that should've been called"

    @patch('networking_arista.ml2.arista_ml2.AristaRPCWrapper._send_eapi_req')
    def test_register_with_eos(self, mock_send_eapi_req):
        self.drv.register_with_eos()
        auth = fake_keystone_info_class()
        keystone_url = '%s://%s:%s/v2.0/' % (auth.auth_protocol,
                                             auth.auth_host,
                                             auth.auth_port)
        auth_cmd = ('auth url %s user %s password %s tenant %s' % (
                    keystone_url,
                    auth.admin_user,
                    auth.admin_password,
                    auth.admin_tenant_name))
        cmd1 = ['show openstack agent uuid']
        cmd2 = ['enable',
                'configure',
                'cvx',
                'service openstack',
                'region %s' % self.region,
                auth_cmd,
                'sync interval %d' % cfg.CONF.ml2_arista.sync_interval,
                ]
        self._verify_send_eapi_request_calls(mock_send_eapi_req, [cmd1, cmd2])

    def _enable_sync_cmds(self):
        self.drv.cli_commands[
            arista_ml2.CMD_REGION_SYNC] = 'region RegionOne sync'
        self.drv.cli_commands[arista_ml2.CMD_SYNC_HEARTBEAT] = 'sync heartbeat'

    @patch('networking_arista.ml2.arista_ml2.AristaRPCWrapper._send_eapi_req')
    def test_create_network_bulk_during_sync(self, mock_send_eapi_req):
        self._enable_sync_cmds()
        tenant_id = 'ten-10'
        num_networks = 101
        networks = [{
            'network_id': 'net-id-%d' % net_id,
            'network_name': 'net-name-%d' % net_id,
            'segmentation_id': net_id,
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
            cmd2.append('segment 1 type vlan id %d' % net_id)
            cmd2.append('shared')

        # Send heartbeat
        cmd2.append('sync heartbeat')
        # Send the remaining network
        cmd2.append('network id net-id-101 name "net-name-101"')
        cmd2.append('segment 1 type vlan id 101')
        cmd2.append('shared')
        # Send the final heartbeat
        cmd2.append('sync heartbeat')

        self._verify_send_eapi_request_calls(mock_send_eapi_req, [cmd1, cmd2])

    @patch('networking_arista.ml2.arista_ml2.AristaRPCWrapper._send_eapi_req')
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

    @patch('networking_arista.ml2.arista_ml2.AristaRPCWrapper._send_eapi_req')
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

    @patch('networking_arista.ml2.arista_ml2.AristaRPCWrapper._send_eapi_req')
    def test_create_port_bulk_during_sync(self, mock_send_eapi_req):
        self._enable_sync_cmds()
        tenant_id = 'ten-3'
        num_ports = 101

        ports = dict(
            ('pid-%d' % id, {
                'deviceId': 'vm-id-%d' % id,
                'hosts': ['host_%d' % id],
            }
            ) for id in range(1, num_ports + 1)
        )

        port_list = []

        for id in range(1, num_ports + 1):
            port = {
                'id': 'pid-%d' % id,
                'device_id': 'vm-id-%d' % id,
                'device_owner': 'compute',
                'network_id': 'nid-%d' % id,
                'name': 'pname-%d' % id,
            }
            port_list.append(port)

        self.drv.create_port_bulk(tenant_id, port_list, ports, sync=True)
        cmd1 = ['show openstack agent uuid']
        cmd2 = ['enable',
                'configure',
                'cvx',
                'service openstack',
                'region RegionOne sync',
                'tenant ten-3']

        for id in range(1, 101):
            cmd2.append('vm id vm-id-%d hostid host_%d' % (id, id))
            cmd2.append('port id pid-%d name "pname-%d" network-id nid-%s' % (
                        id, id, id))

        # Send heartbeat
        cmd2.append('sync heartbeat')
        # Send the remaining vm port
        cmd2.append('vm id vm-id-101 hostid host_101')
        cmd2.append('port id pid-101 name "pname-101" network-id nid-101')
        # Send the final heartbeat
        cmd2.append('sync heartbeat')

        self._verify_send_eapi_request_calls(mock_send_eapi_req, [cmd1, cmd2])

    @patch('networking_arista.ml2.arista_ml2.AristaRPCWrapper._send_eapi_req')
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
        setup_arista_wrapper_config('')

    def test_raises_exception_on_wrong_configuration(self):
        self.assertRaises(arista_exc.AristaConfigError,
                          arista_ml2.AristaRPCWrapper)


class NegativeRPCWrapperTestCase(base.BaseTestCase):
    """Negative test cases to test the RPC between Arista Driver and EOS."""

    def setUp(self):
        super(NegativeRPCWrapperTestCase, self).setUp()
        setup_valid_config()

    def test_exception_is_raised_on_json_server_error(self):
        drv = arista_ml2.AristaRPCWrapper()

        drv._server = mock.MagicMock()
        drv._server.runCmds.side_effect = Exception('server error')
        self.assertRaises(arista_exc.AristaRpcError, drv.get_tenants)


class RealNetStorageAristaDriverTestCase(testlib_api.SqlTestCase):
    """Main test cases for Arista Mechanism driver.

    Tests all mechanism driver APIs supported by Arista Driver. It invokes
    all the APIs as they would be invoked in real world scenarios and
    verifies the functionality.
    """
    def setUp(self):
        super(RealNetStorageAristaDriverTestCase, self).setUp()
        setup_valid_config()
        self.fake_rpc = mock.MagicMock()
        self.drv = mechanism_arista.AristaDriver(self.fake_rpc)

    def tearDown(self):
        super(RealNetStorageAristaDriverTestCase, self).tearDown()
        self.drv.stop_synchronization_thread()

    def test_create_and_delete_network(self):
        tenant_id = 'ten-1'
        network_id = 'net1-id'
        segmentation_id = 1001

        network_context = self._get_network_context(tenant_id,
                                                    network_id,
                                                    segmentation_id)
        self.drv.create_network_precommit(network_context)
        net_provisioned = db_lib.is_network_provisioned(tenant_id, network_id)
        self.assertTrue(net_provisioned, 'The network should be created')

        expected_num_nets = 1
        num_nets_provisioned = db_lib.num_nets_provisioned(tenant_id)
        self.assertEqual(expected_num_nets, num_nets_provisioned,
                         'There should be %d nets, not %d' %
                         (expected_num_nets, num_nets_provisioned))

        # Now test the delete network
        self.drv.delete_network_precommit(network_context)
        net_provisioned = db_lib.is_network_provisioned(tenant_id, network_id)
        self.assertFalse(net_provisioned, 'The network should be created')

        expected_num_nets = 0
        num_nets_provisioned = db_lib.num_nets_provisioned(tenant_id)
        self.assertEqual(expected_num_nets, num_nets_provisioned,
                         'There should be %d nets, not %d' %
                         (expected_num_nets, num_nets_provisioned))

    def test_create_and_delete_multiple_networks(self):
        tenant_id = 'ten-1'
        expected_num_nets = 100
        segmentation_id = 1001
        nets = ['id%s' % n for n in range(expected_num_nets)]
        for net_id in nets:
            network_context = self._get_network_context(tenant_id,
                                                        net_id,
                                                        segmentation_id)
            self.drv.create_network_precommit(network_context)

        num_nets_provisioned = db_lib.num_nets_provisioned(tenant_id)
        self.assertEqual(expected_num_nets, num_nets_provisioned,
                         'There should be %d nets, not %d' %
                         (expected_num_nets, num_nets_provisioned))

        # Now test the delete networks
        for net_id in nets:
            network_context = self._get_network_context(tenant_id,
                                                        net_id,
                                                        segmentation_id)
            self.drv.delete_network_precommit(network_context)

        num_nets_provisioned = db_lib.num_nets_provisioned(tenant_id)
        expected_num_nets = 0
        self.assertEqual(expected_num_nets, num_nets_provisioned,
                         'There should be %d nets, not %d' %
                         (expected_num_nets, num_nets_provisioned))

    def test_create_and_delete_ports(self):
        tenant_id = 'ten-1'
        network_id = 'net1-id'
        segmentation_id = 1001
        vms = ['vm1', 'vm2', 'vm3']

        network_context = self._get_network_context(tenant_id,
                                                    network_id,
                                                    segmentation_id)
        self.drv.create_network_precommit(network_context)

        for vm_id in vms:
            port_context = self._get_port_context(tenant_id,
                                                  network_id,
                                                  vm_id,
                                                  network_context)
            self.drv.create_port_precommit(port_context)

        vm_list = db_lib.get_vms(tenant_id)
        provisioned_vms = len(vm_list)
        expected_vms = len(vms)
        self.assertEqual(expected_vms, provisioned_vms,
                         'There should be %d '
                         'hosts, not %d' % (expected_vms, provisioned_vms))

        # Now test the delete ports
        for vm_id in vms:
            port_context = self._get_port_context(tenant_id,
                                                  network_id,
                                                  vm_id,
                                                  network_context)
            self.drv.delete_port_precommit(port_context)

        vm_list = db_lib.get_vms(tenant_id)
        provisioned_vms = len(vm_list)
        expected_vms = 0
        self.assertEqual(expected_vms, provisioned_vms,
                         'There should be %d '
                         'VMs, not %d' % (expected_vms, provisioned_vms))

    def test_cleanup_on_start(self):
        """Ensures that the driver cleans up the arista database on startup."""
        ndb = db_lib.NeutronNets()

        # Create some networks in neutron db
        n1_context = self._get_network_context('t1', 'n1', 10)
        ndb.create_network(n1_context, {'network': n1_context.current})
        n2_context = self._get_network_context('t2', 'n2', 20)
        ndb.create_network(n2_context, {'network': n2_context.current})
        n3_context = self._get_network_context('', 'ha-network', 100)
        ndb.create_network(n3_context, {'network': n3_context.current})

        # Create some networks in Arista db
        db_lib.remember_network('t1', 'n1', 10)
        db_lib.remember_network('t2', 'n2', 20)
        db_lib.remember_network('admin', 'ha-network', 100)
        db_lib.remember_network('t3', 'n3', 30)

        # Initialize the driver which should clean up the extra networks
        self.drv.initialize()

        adb_networks = db_lib.get_networks(tenant_id='any')

        # 'n3' should now be deleted from the Arista DB
        assert(set(('n1', 'n2', 'ha-network')) == set(adb_networks.keys()))

    def _get_network_context(self, tenant_id, net_id, seg_id):
        network = {'id': net_id,
                   'tenant_id': tenant_id,
                   'name': net_id,
                   'admin_state_up': True,
                   'shared': False,
                   }
        network_segments = [{'segmentation_id': seg_id,
                             'network_type': 'vlan'}]
        return FakeNetworkContext(network, network_segments, network)

    def _get_port_context(self, tenant_id, net_id, vm_id, network):
        port = {'device_id': vm_id,
                'device_owner': 'compute',
                'binding:host_id': 'ubuntu1',
                'tenant_id': tenant_id,
                'id': 101,
                'network_id': net_id
                }
        return FakePortContext(port, port, network)


class FakeNetworkContext(object):
    """To generate network context for testing purposes only."""

    def __init__(self, network, segments=None, original_network=None):
        self._network = network
        self._original_network = original_network
        self._segments = segments
        self.is_admin = False
        self.tenant_id = network['tenant_id']
        self.session = db.get_session()

    @property
    def current(self):
        return self._network

    @property
    def original(self):
        return self._original_network

    @property
    def network_segments(self):
        return self._segments


class FakePortContext(object):
    """To generate port context for testing purposes only."""

    def __init__(self, port, original_port, network):
        self._port = port
        self._original_port = original_port
        self._network_context = network

    @property
    def current(self):
        return self._port

    @property
    def original(self):
        return self._original_port

    @property
    def network(self):
        return self._network_context

    @property
    def host(self):
        return self._port.get(portbindings.HOST_ID)

    @property
    def original_host(self):
        return self._original_port.get(portbindings.HOST_ID)


class SyncServiceTest(testlib_api.SqlTestCase):
    """Test cases for the sync service."""

    def setUp(self):
        super(SyncServiceTest, self).setUp()
        self.rpc = mock.MagicMock()
        ndb = db_lib.NeutronNets()
        self.sync_service = arista_ml2.SyncService(self.rpc, ndb)
        self.sync_service._force_sync = False

    def test_region_in_sync(self):
        """Tests whether the region_in_sync() behaves as expected."""
        region_updated_time = {
            'regionName': 'RegionOne',
            'regionTimestamp': '12345'
        }
        self.rpc.get_region_updated_time.return_value = region_updated_time
        self.sync_service._region_updated_time = None
        assert not self.sync_service._region_in_sync()
        self.sync_service._region_updated_time = region_updated_time
        assert self.sync_service._region_in_sync()

    def test_synchronize_required(self):
        """Tests whether synchronize() sends the right commands.

           This test verifies a scenario when the sync is required.
        """
        region_updated_time = {
            'regionName': 'RegionOne',
            'regionTimestamp': '12345'
        }
        self.rpc.get_region_updated_time.return_value = region_updated_time
        self.sync_service._region_updated_time = {
            'regionName': 'RegionOne',
            'regionTimestamp': '0',
        }

        tenant_id = 'tenant-1'
        network_id = 'net-1'
        segmentation_id = 42
        db_lib.remember_tenant(tenant_id)
        db_lib.remember_network(tenant_id, network_id, segmentation_id)

        self.rpc.get_tenants.return_value = {}

        self.rpc.sync_start.return_value = True
        self.rpc.sync_end.return_value = True

        self.sync_service.do_synchronize()

        expected_calls = [
            mock.call.get_region_updated_time(),
            mock.call.sync_start(),
            mock.call.register_with_eos(sync=True),
            mock.call.check_cli_commands(),
            mock.call.get_tenants(),
            mock.call.create_network_bulk(
                tenant_id,
                [{'network_id': network_id,
                  'segmentation_id': segmentation_id,
                  'network_name': '',
                  'shared': False}],
                sync=True),
            mock.call.sync_end(),
            mock.call.get_region_updated_time()
        ]
        assert self.rpc.mock_calls == expected_calls

        db_lib.forget_network(tenant_id, network_id)
        db_lib.forget_tenant(tenant_id)

    def test_synchronize_not_required(self):
        """Tests whether synchronize() sends the right commands.

           This test verifies a scenario when the sync is not required.
        """
        region_updated_time = {
            'regionName': 'RegionOne',
            'regionTimestamp': '424242'
        }
        self.rpc.get_region_updated_time.return_value = region_updated_time
        self.sync_service._region_updated_time = {
            'regionName': 'RegionOne',
            'regionTimestamp': '424242',
        }

        self.rpc.sync_start.return_value = True
        self.rpc.sync_end.return_value = True

        self.sync_service.do_synchronize()

        # If the timestamps do match, then the sync should not be executed.
        expected_calls = [
            mock.call.get_region_updated_time(),
        ]
        self.assertTrue(self.rpc.method_calls == expected_calls)

    def test_synchronize_one_network(self):
        """Test to ensure that only the required resources are sent to EOS."""

        # Store two tenants in a db and a single tenant in EOS.
        # The sync should send details of the second tenant to EOS
        tenant_1_id = 'tenant-1'
        tenant_1_net_1_id = 'ten-1-net-1'
        tenant_1_net_1_seg_id = 11
        db_lib.remember_tenant(tenant_1_id)
        db_lib.remember_network(tenant_1_id, tenant_1_net_1_id,
                                tenant_1_net_1_seg_id)

        tenant_2_id = 'tenant-2'
        tenant_2_net_1_id = 'ten-2-net-1'
        tenant_2_net_1_seg_id = 21
        db_lib.remember_tenant(tenant_2_id)
        db_lib.remember_network(tenant_2_id, tenant_2_net_1_id,
                                tenant_2_net_1_seg_id)

        self.rpc.get_tenants.return_value = {
            tenant_1_id: {
                'tenantVmInstances': {},
                'tenantNetworks': {
                    tenant_1_net_1_id: {
                        'networkId': tenant_1_net_1_id,
                        'shared': False,
                        'networkName': 'Net1',
                        'segmenationType': 'vlan',
                        'segmentationTypeId': tenant_1_net_1_seg_id,
                    }
                }
            }
        }

        self.rpc.sync_start.return_value = True
        self.rpc.sync_end.return_value = True

        self.sync_service.do_synchronize()

        expected_calls = [
            mock.call.get_region_updated_time(),
            mock.call.get_region_updated_time().__nonzero__(),
            mock.call.sync_start(),
            mock.call.register_with_eos(sync=True),
            mock.call.check_cli_commands(),
            mock.call.get_tenants(),
            mock.call.create_network_bulk(
                tenant_2_id,
                [{'network_id': tenant_2_net_1_id,
                  'segmentation_id': tenant_2_net_1_seg_id,
                  'network_name': '',
                  'shared': False}],
                sync=True),
            mock.call.sync_end(),
            mock.call.get_region_updated_time()
        ]

        self.assertTrue(self.rpc.mock_calls == expected_calls,
                        "Seen: %s\nExpected: %s" % (
                            self.rpc.mock_calls,
                            expected_calls,
                            )
                        )

        db_lib.forget_network(tenant_1_id, tenant_1_net_1_id)
        db_lib.forget_network(tenant_2_id, tenant_2_net_1_id)
        db_lib.forget_tenant(tenant_1_id)
        db_lib.forget_tenant(tenant_2_id)

    def test_synchronize_all_networks(self):
        """Test to ensure that only the required resources are sent to EOS."""

        # Store two tenants in a db and none on EOS.
        # The sync should send details of all tenants to EOS
        tenant_1_id = u'tenant-1'
        tenant_1_net_1_id = u'ten-1-net-1'
        tenant_1_net_1_seg_id = 11
        db_lib.remember_tenant(tenant_1_id)
        db_lib.remember_network(tenant_1_id, tenant_1_net_1_id,
                                tenant_1_net_1_seg_id)

        tenant_2_id = u'tenant-2'
        tenant_2_net_1_id = u'ten-2-net-1'
        tenant_2_net_1_seg_id = 21
        db_lib.remember_tenant(tenant_2_id)
        db_lib.remember_network(tenant_2_id, tenant_2_net_1_id,
                                tenant_2_net_1_seg_id)

        self.rpc.get_tenants.return_value = {}

        self.rpc.sync_start.return_value = True
        self.rpc.sync_end.return_value = True

        self.sync_service.do_synchronize()

        expected_calls = [
            mock.call.get_region_updated_time(),
            mock.call.get_region_updated_time().__nonzero__(),
            mock.call.sync_start(),
            mock.call.register_with_eos(sync=True),
            mock.call.check_cli_commands(),
            mock.call.get_tenants(),
            mock.call.create_network_bulk(
                tenant_1_id,
                [{'network_id': tenant_1_net_1_id,
                  'segmentation_id': tenant_1_net_1_seg_id,
                  'network_name': '',
                  'shared': False}],
                sync=True),
            mock.call.create_network_bulk(
                tenant_2_id,
                [{'network_id': tenant_2_net_1_id,
                  'segmentation_id': tenant_2_net_1_seg_id,
                  'network_name': '',
                  'shared': False}],
                sync=True),
            mock.call.sync_end(),
            mock.call.get_region_updated_time()
        ]

        # The create_network_bulk() can be called in different order. So split
        # it up. The first part checks if the initial set of methods are
        # invoked.
        self.assertTrue(self.rpc.mock_calls[:5] == expected_calls[:5],
                        "Seen: %s\nExpected: %s" % (
                            self.rpc.mock_calls,
                            expected_calls,
                            )
                        )
        # Check if tenant 1 networks are created. It must be one of the two
        # methods.
        self.assertTrue(self.rpc.mock_calls[5] in expected_calls[5:7],
                        "Seen: %s\nExpected: %s" % (
                            self.rpc.mock_calls,
                            expected_calls,
                            )
                        )
        # Check if tenant 2 networks are created. It must be one of the two
        # methods.
        self.assertTrue(self.rpc.mock_calls[6] in expected_calls[6:8],
                        "Seen: %s\nExpected: %s" % (
                            self.rpc.mock_calls[6],
                            expected_calls[6:8],
                            )
                        )
        # Check if the sync end methods are invoked.
        self.assertTrue(self.rpc.mock_calls[8:10] == expected_calls[8:10],
                        "Seen: %s\nExpected: %s" % (
                            self.rpc.mock_calls,
                            expected_calls,
                            )
                        )

        db_lib.forget_network(tenant_1_id, tenant_1_net_1_id)
        db_lib.forget_network(tenant_2_id, tenant_2_net_1_id)
        db_lib.forget_tenant(tenant_1_id)
        db_lib.forget_tenant(tenant_2_id)


class fake_keystone_info_class(object):
    """To generate fake Keystone Authentication token information

    Arista Driver expects Keystone auth info. This fake information
    is for testing only
    """
    auth_uri = False
    auth_protocol = 'abc'
    auth_host = 'host'
    auth_port = 5000
    admin_user = 'neutron'
    admin_password = 'fun'
    admin_tenant_name = 'tenant_name'
