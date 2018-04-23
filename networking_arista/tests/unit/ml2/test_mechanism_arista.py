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

from neutron_lib import constants as n_const
from oslo_config import cfg

from networking_arista.tests.unit.ml2 import ml2_test_base


class BasicMechDriverTestCase(ml2_test_base.MechTestBase):

    def test_create_network(self):
        # Test create regular network
        tenant_id = 'tid'
        reg_net_dict = {'network': {'name': 'net1',
                                    'tenant_id': tenant_id,
                                    'admin_state_up': True,
                                    'shared': False,
                                    'provider:physical_network': self.physnet,
                                    'provider:network_type': 'vlan'}}
        reg_network, reg_n_ctx = self.create_network(reg_net_dict)
        self.assertTenantCreated(tenant_id)
        self.assertNetworkCreated(reg_network['id'])
        for segment in reg_n_ctx.network_segments:
            self.assertSegmentCreated(segment['id'])

        # Test create shared network
        shrd_net_dict = {'network': {'name': 'shared_net',
                                     'tenant_id': tenant_id,
                                     'admin_state_up': True,
                                     'shared': True,
                                     'provider:physical_network': self.physnet,
                                     'provider:network_type': 'vlan'}}
        shared_network, shared_n_ctx = self.create_network(shrd_net_dict)
        self.assertTenantCreated(tenant_id)
        self.assertNetworkCreated(shared_network['id'])
        for segment in shared_n_ctx.network_segments:
            self.assertSegmentCreated(segment['id'])

        # Test delete regular network
        self.delete_network(reg_network['id'])
        self.assertTenantCreated(tenant_id)
        self.assertNetworkDeleted(reg_network['id'])
        for segment in reg_n_ctx.network_segments:
            self.assertSegmentDeleted(segment['id'])

        # Test delete shared network
        self.delete_network(shared_network['id'])
        self.assertTenantDeleted(tenant_id)
        self.assertNetworkDeleted(shared_network['id'])
        for segment in shared_n_ctx.network_segments:
            self.assertSegmentDeleted(segment['id'])

    def test_basic_dhcp_port(self):
        network_tenant = 'net-ten'
        net_dict = {'network': {'name': 'net',
                                'tenant_id': network_tenant,
                                'admin_state_up': True,
                                'shared': False,
                                'provider:physical_network': self.physnet,
                                'provider:network_type': 'vlan'}}
        network, _ = self.create_network(net_dict)

        # Create DHCP port
        device_id = 'dhcp-1'
        port_tenant = 'port-ten'
        port_host = self.host1
        port_dict = {'name': 'port1',
                     'tenant_id': port_tenant,
                     'network_id': network['id'],
                     'admin_state_up': True,
                     'fixed_ips': [],
                     'device_id': device_id,
                     'device_owner': n_const.DEVICE_OWNER_DHCP,
                     'binding:host_id': port_host}
        port, _ = self.create_port(port_dict)
        self.assertTenantCreated(port_tenant)
        self.assertDhcpCreated(device_id)
        self.assertDhcpPortCreated(port['id'])
        self.assertPortBindingCreated((port['id'], port_host))

        # Delete DHCP port
        self.delete_port(port['id'])
        self.assertTenantDeleted(port_tenant)
        self.assertDhcpDeleted(device_id)
        self.assertDhcpPortDeleted(port['id'])
        self.assertPortBindingDeleted((port['id'], port_host))

    def test_basic_dvr_port(self):
        network_tenant = 'net-ten'
        net_dict = {'network': {'name': 'net',
                                'tenant_id': network_tenant,
                                'admin_state_up': True,
                                'shared': False,
                                'provider:physical_network': self.physnet,
                                'provider:network_type': 'vlan'}}
        network, _ = self.create_network(net_dict)

        # Create DVR port
        device_id = 'router-1'
        port_tenant = 'port-ten'
        port_host_1 = self.host1
        port_dict = {'name': 'port1',
                     'tenant_id': port_tenant,
                     'network_id': network['id'],
                     'admin_state_up': True,
                     'fixed_ips': [],
                     'device_id': device_id,
                     'device_owner': n_const.DEVICE_OWNER_DVR_INTERFACE}
        port, _ = self.create_port(port_dict)
        self.bind_dvr_to_host(port, port_host_1)
        self.assertTenantCreated(port_tenant)
        self.assertRouterCreated(device_id)
        self.assertRouterPortCreated(port['id'])
        self.assertPortBindingCreated((port['id'], port_host_1))

        # Bring up a second DVR host
        port_host_2 = self.host2
        port, port_ctx = self.bind_dvr_to_host(port, port_host_2)
        self.assertPortBindingCreated((port['id'], port_host_2))

        # Delete the port
        self.delete_port(port['id'])
        self.assertTenantDeleted(port_tenant)
        self.assertRouterDeleted(device_id)
        self.assertRouterPortDeleted(port['id'])
        self.assertPortBindingDeleted((port['id'], port_host_1))
        self.assertPortBindingDeleted((port['id'], port_host_2))

    def test_dvr_port_host_bind_unbind(self):
        network_tenant = 'net-ten'
        net_dict = {'network': {'name': 'net',
                                'tenant_id': network_tenant,
                                'admin_state_up': True,
                                'shared': False,
                                'provider:physical_network': self.physnet,
                                'provider:network_type': 'vlan'}}
        network, _ = self.create_network(net_dict)

        # Create DVR port
        device_id = 'router-1'
        port_tenant = 'port-ten'
        port_host_1 = self.host1
        port_dict = {'name': 'port1',
                     'tenant_id': port_tenant,
                     'network_id': network['id'],
                     'admin_state_up': True,
                     'fixed_ips': [],
                     'device_id': device_id,
                     'device_owner': n_const.DEVICE_OWNER_DVR_INTERFACE}
        port, _ = self.create_port(port_dict)
        port, port_ctx = self.bind_dvr_to_host(port, port_host_1)
        self.assertTenantCreated(port_tenant)
        self.assertRouterCreated(device_id)
        self.assertRouterPortCreated(port['id'])
        self.assertPortBindingCreated((port['id'], port_host_1))

        # Bring up a second DVR host
        port_host_2 = self.host2
        port, port_ctx = self.bind_dvr_to_host(port, port_host_2)
        self.assertPortBindingCreated((port['id'], port_host_2))

        # Removed the second host
        self.unbind_dvr_from_host(port, port_host_2)
        self.assertPortBindingDeleted((port['id'], port_host_2))
        self.assertTenantCreated(port_tenant)
        self.assertRouterCreated(device_id)
        self.assertRouterPortCreated(port['id'])
        self.assertPortBindingCreated((port['id'], port_host_1))

        # Delete the port
        self.delete_port(port['id'])
        self.assertTenantDeleted(port_tenant)
        self.assertRouterDeleted(device_id)
        self.assertRouterPortDeleted(port['id'])
        self.assertPortBindingDeleted((port['id'], port_host_1))

    def test_basic_vm_port(self):
        network_tenant = 'net-ten'
        net_dict = {'network': {'name': 'net',
                                'tenant_id': network_tenant,
                                'admin_state_up': True,
                                'shared': False,
                                'provider:physical_network': self.physnet,
                                'provider:network_type': 'vlan'}}
        network, _ = self.create_network(net_dict)

        # Create VM port
        device_id = 'vm-1'
        port_tenant = 'port-ten'
        port_host = self.host1
        port_dict = {'name': 'port1',
                     'tenant_id': port_tenant,
                     'network_id': network['id'],
                     'admin_state_up': True,
                     'fixed_ips': [],
                     'device_id': device_id,
                     'device_owner': 'compute:',
                     'binding:host_id': port_host}
        port, _ = self.create_port(port_dict)
        self.assertTenantCreated(port_tenant)
        self.assertVmCreated(device_id)
        self.assertVmPortCreated(port['id'])
        self.assertPortBindingCreated((port['id'], port_host))

        # Delete VM port
        self.delete_port(port['id'])
        self.assertTenantDeleted(port_tenant)
        self.assertVmDeleted(device_id)
        self.assertVmPortDeleted(port['id'])
        self.assertPortBindingDeleted((port['id'], port_host))

    def test_basic_baremetal_port(self):
        network_tenant = 'net-ten'
        net_dict = {'network': {'name': 'net',
                                'tenant_id': network_tenant,
                                'admin_state_up': True,
                                'shared': False,
                                'provider:physical_network': self.physnet,
                                'provider:network_type': 'vlan'}}
        network, _ = self.create_network(net_dict)

        # Create baremetal port
        device_id = 'baremetal-1'
        port_tenant = 'port-ten'
        port_host = 'bm-host'
        switch_id = '00:11:22:33:44:55'
        switch_port = 'Ethernet1/1'
        port_dict = {'name': 'port1',
                     'tenant_id': port_tenant,
                     'network_id': network['id'],
                     'admin_state_up': True,
                     'fixed_ips': [],
                     'device_id': device_id,
                     'device_owner': n_const.DEVICE_OWNER_BAREMETAL_PREFIX,
                     'binding:host_id': port_host,
                     'binding:profile': {'local_link_information': [
                         {'switch_id': switch_id,
                          'port_id': switch_port}]},
                     'binding:vnic_type': 'baremetal'}
        port, _ = self.create_port(port_dict)
        self.assertTenantCreated(port_tenant)
        self.assertBaremetalCreated(device_id)
        self.assertBaremetalPortCreated(port['id'])
        self.assertPortBindingCreated((port['id'], (switch_id, switch_port)))

        # Delete baremetal port
        self.delete_port(port['id'])
        self.assertTenantDeleted(port_tenant)
        self.assertBaremetalDeleted(device_id)
        self.assertBaremetalPortDeleted(port['id'])
        self.assertPortBindingDeleted((port['id'], (switch_id, switch_port)))

    def test_basic_baremetal_mlag(self):
        network_tenant = 'net-ten'
        net_dict = {'network': {'name': 'net',
                                'tenant_id': network_tenant,
                                'admin_state_up': True,
                                'shared': False,
                                'provider:physical_network': self.physnet,
                                'provider:network_type': 'vlan'}}
        network, _ = self.create_network(net_dict)

        # Create baremetal port
        device_id = 'baremetal-1'
        port_tenant = 'port-ten'
        port_host = 'bm-host'
        switch_1_id = '00:11:22:33:44:55'
        switch_1_port = 'Ethernet1/1'
        switch_2_id = '55:44:33:22:11:00'
        switch_2_port = 'Ethernet2'
        port_dict = {'name': 'port1',
                     'tenant_id': port_tenant,
                     'network_id': network['id'],
                     'admin_state_up': True,
                     'fixed_ips': [],
                     'device_id': device_id,
                     'device_owner': n_const.DEVICE_OWNER_BAREMETAL_PREFIX,
                     'binding:host_id': port_host,
                     'binding:profile': {'local_link_information': [
                         {'switch_id': switch_1_id,
                          'port_id': switch_1_port},
                         {'switch_id': switch_2_id,
                          'port_id': switch_2_port}]},
                     'binding:vnic_type': 'baremetal'}
        port, _ = self.create_port(port_dict)
        self.assertTenantCreated(port_tenant)
        self.assertBaremetalCreated(device_id)
        self.assertBaremetalPortCreated(port['id'])
        self.assertPortBindingCreated(
            (port['id'], (switch_1_id, switch_1_port)))
        self.assertPortBindingCreated(
            (port['id'], (switch_2_id, switch_2_port)))

        # Delete baremetal port
        self.delete_port(port['id'])
        self.assertTenantDeleted(port_tenant)
        self.assertBaremetalDeleted(device_id)
        self.assertBaremetalPortDeleted(port['id'])
        self.assertPortBindingDeleted(
            (port['id'], (switch_1_id, switch_2_port)))
        self.assertPortBindingDeleted(
            (port['id'], (switch_2_id, switch_2_port)))

    def test_host_migration(self):
        network_tenant = 'net-ten'
        net_dict = {'network': {'name': 'net',
                                'tenant_id': network_tenant,
                                'admin_state_up': True,
                                'shared': False,
                                'provider:physical_network': self.physnet,
                                'provider:network_type': 'vlan'}}
        network, _ = self.create_network(net_dict)

        # Create VM port
        device_id = 'vm-1'
        port_tenant = 'port-ten'
        port_host = self.host1
        port_dict = {'name': 'port1',
                     'tenant_id': port_tenant,
                     'network_id': network['id'],
                     'admin_state_up': True,
                     'fixed_ips': [],
                     'device_id': device_id,
                     'device_owner': 'compute:',
                     'binding:host_id': port_host}
        port, _ = self.create_port(port_dict)
        self.assertTenantCreated(port_tenant)
        self.assertVmCreated(device_id)
        self.assertVmPortCreated(port['id'])
        self.assertPortBindingCreated((port['id'], port_host))

        # Migrate the port
        new_port_host = self.host2
        port, _ = self.migrate_port(port['id'], new_port_host)
        self.assertTenantCreated(port_tenant)
        self.assertVmCreated(device_id)
        self.assertVmPortCreated(port['id'])
        self.assertPortBindingDeleted((port['id'], port_host))
        self.assertPortBindingCreated((port['id'], new_port_host))

        # Delete VM port
        self.delete_port(port['id'])
        self.assertTenantDeleted(port_tenant)
        self.assertVmDeleted(device_id)
        self.assertVmPortDeleted(port['id'])
        self.assertPortBindingDeleted((port['id'], new_port_host))

    def test_dhcp_migration(self):
        network_tenant = 'net-ten'
        net_dict = {'network': {'name': 'net',
                                'tenant_id': network_tenant,
                                'admin_state_up': True,
                                'shared': False,
                                'provider:physical_network': 'physnet1',
                                'provider:network_type': 'vlan'}}
        network, _ = self.create_network(net_dict)

        # Create DHCP port
        device_id = 'dhcp-1'
        port_tenant = 'port-ten'
        port_host = self.host1
        port_dict = {'name': 'port1',
                     'tenant_id': port_tenant,
                     'network_id': network['id'],
                     'admin_state_up': True,
                     'fixed_ips': [],
                     'device_id': device_id,
                     'device_owner': n_const.DEVICE_OWNER_DHCP,
                     'binding:host_id': port_host,
                     'binding:vnic_type': 'normal'}
        port, _ = self.create_port(port_dict)
        self.assertTenantCreated(port_tenant)
        self.assertDhcpCreated(device_id)
        self.assertDhcpPortCreated(port['id'])
        self.assertPortBindingCreated((port['id'], port_host))

        # Migrate the DHCP port to a new dhcp instance
        new_device_id = 'dhcp-2'
        self.migrate_dhcp_device(port['id'], new_device_id)
        self.assertTenantCreated(port_tenant)
        self.assertDhcpCreated(new_device_id)
        self.assertDhcpDeleted(device_id)
        self.assertDhcpPortCreated(port['id'])
        self.assertPortBindingCreated((port['id'], port_host))

        # Delete DHCP port
        self.delete_port(port['id'])
        self.assertTenantDeleted(port_tenant)
        self.assertDhcpDeleted(device_id)
        self.assertDhcpPortDeleted(port['id'])
        self.assertPortBindingDeleted((port['id'], port_host))

    def test_vm_trunk_port(self):
        network_tenant = 'net-ten'
        net_dict = {'network': {'name': 'net1',
                                'tenant_id': network_tenant,
                                'admin_state_up': True,
                                'shared': False,
                                'provider:physical_network': self.physnet,
                                'provider:network_type': 'vlan'}}
        network1, _ = self.create_network(net_dict)
        net_dict = {'network': {'name': 'net2',
                                'tenant_id': network_tenant,
                                'admin_state_up': True,
                                'shared': False,
                                'provider:physical_network': self.physnet,
                                'provider:network_type': 'vlan'}}
        network2, _ = self.create_network(net_dict)

        # Create trunk port with subport
        device_id = 'vm-1'
        port_tenant = 'port-ten'
        port_host = self.host1
        trunkport_dict = {'name': 'port1',
                          'tenant_id': port_tenant,
                          'network_id': network1['id'],
                          'admin_state_up': True,
                          'fixed_ips': [],
                          'device_id': '',
                          'device_owner': ''}
        trunkport, _ = self.create_port(trunkport_dict)
        subport_dict = {'name': 'port2',
                        'tenant_id': port_tenant,
                        'network_id': network2['id'],
                        'admin_state_up': True,
                        'fixed_ips': [],
                        'device_id': '',
                        'device_owner': ''}
        subport, _ = self.create_port(subport_dict)
        trunk_dict = {'trunk': {'port_id': trunkport['id'],
                                'tenant_id': port_tenant,
                                'sub_ports': [{'port_id': subport['id'],
                                               'segmentation_type': 'vlan',
                                               'segmentation_id': 123}]}}
        trunk = self.trunk_plugin.create_trunk(self.context, trunk_dict)
        self.bind_trunk_to_host(trunkport, device_id, port_host)
        self.assertTenantCreated(port_tenant)
        self.assertVmCreated(device_id)
        self.assertVmPortCreated(trunkport['id'])
        self.assertPortBindingCreated((trunkport['id'], port_host))
        self.assertVmPortCreated(subport['id'])
        self.assertPortBindingCreated((subport['id'], port_host))

        # Delete the trunk and subport
        self.unbind_port_from_host(trunkport['id'])
        self.trunk_plugin.delete_trunk(self.context, trunk['id'])
        self.delete_port(trunkport['id'])
        self.delete_port(subport['id'])
        self.assertTenantDeleted(port_tenant)
        self.assertVmDeleted(device_id)
        self.assertVmPortDeleted(trunkport['id'])
        self.assertPortBindingDeleted((trunkport['id'], port_host))
        self.assertVmPortDeleted(subport['id'])
        self.assertPortBindingDeleted((subport['id'], port_host))

    def test_trunk_add_remove_subport(self):
        network_tenant = 'net-ten'
        net_dict = {'network': {'name': 'net1',
                                'tenant_id': network_tenant,
                                'admin_state_up': True,
                                'shared': False,
                                'provider:physical_network': self.physnet,
                                'provider:network_type': 'vlan'}}
        network1, _ = self.create_network(net_dict)
        net_dict = {'network': {'name': 'net2',
                                'tenant_id': network_tenant,
                                'admin_state_up': True,
                                'shared': False,
                                'provider:physical_network': self.physnet,
                                'provider:network_type': 'vlan'}}
        network2, _ = self.create_network(net_dict)
        net_dict = {'network': {'name': 'net3',
                                'tenant_id': network_tenant,
                                'admin_state_up': True,
                                'shared': False,
                                'provider:physical_network': self.physnet,
                                'provider:network_type': 'vlan'}}
        network3, _ = self.create_network(net_dict)

        # Create trunk port with subport, add subport after initial binding
        device_id = 'vm-1'
        port_tenant = 'port-ten'
        port_host = self.host1
        trunkport_dict = {'name': 'port1',
                          'tenant_id': port_tenant,
                          'network_id': network1['id'],
                          'admin_state_up': True,
                          'fixed_ips': [],
                          'device_id': '',
                          'device_owner': ''}
        trunkport, _ = self.create_port(trunkport_dict)
        subport_dict = {'name': 'port2',
                        'tenant_id': port_tenant,
                        'network_id': network2['id'],
                        'admin_state_up': True,
                        'fixed_ips': [],
                        'device_id': '',
                        'device_owner': ''}
        subport, _ = self.create_port(subport_dict)
        trunk_dict = {'trunk': {'port_id': trunkport['id'],
                                'tenant_id': port_tenant,
                                'sub_ports': [{'port_id': subport['id'],
                                               'segmentation_type': 'vlan',
                                               'segmentation_id': 123}]}}
        subport_dict2 = {'name': 'port3',
                         'tenant_id': port_tenant,
                         'network_id': network3['id'],
                         'admin_state_up': True,
                         'fixed_ips': [],
                         'device_id': '',
                         'device_owner': ''}
        trunk = self.trunk_plugin.create_trunk(self.context, trunk_dict)
        self.bind_trunk_to_host(trunkport, device_id, port_host)
        subport2, _ = self.create_port(subport_dict2)
        self.trunk_plugin.add_subports(self.context, trunk['id'],
                                       {'sub_ports':
                                        [{'port_id': subport2['id'],
                                          'segmentation_type': 'vlan',
                                          'segmentation_id': 111}]})
        self.bind_subport_to_trunk(subport2, trunk)
        self.assertTenantCreated(port_tenant)
        self.assertVmCreated(device_id)
        self.assertVmPortCreated(trunkport['id'])
        self.assertPortBindingCreated((trunkport['id'], port_host))
        self.assertVmPortCreated(subport['id'])
        self.assertPortBindingCreated((subport['id'], port_host))
        self.assertVmPortCreated(subport2['id'])
        self.assertPortBindingCreated((subport2['id'], port_host))

        # Remove the trunk subport
        self.trunk_plugin.remove_subports(self.context, trunk['id'],
                                          {'sub_ports':
                                           [{'port_id': subport2['id']}]})
        self.unbind_port_from_host(subport2['id'])
        self.assertPortBindingDeleted((subport2['id'], port_host))

        # Delete the trunk and remaining subport
        self.unbind_port_from_host(trunkport['id'])
        self.trunk_plugin.delete_trunk(self.context, trunk['id'])
        self.delete_port(trunkport['id'])
        self.delete_port(subport['id'])
        self.delete_port(subport2['id'])
        self.assertTenantDeleted(port_tenant)
        self.assertVmDeleted(device_id)
        self.assertVmPortDeleted(trunkport['id'])
        self.assertPortBindingDeleted((trunkport['id'], port_host))
        self.assertVmPortDeleted(subport['id'])
        self.assertPortBindingDeleted((subport['id'], port_host))

    def test_baremetal_trunk_basic(self):
        network_tenant = 'net-ten'
        net_dict = {'network': {'name': 'net1',
                                'tenant_id': network_tenant,
                                'admin_state_up': True,
                                'shared': False,
                                'provider:physical_network': self.physnet,
                                'provider:network_type': 'vlan'}}
        network1, _ = self.create_network(net_dict)
        net_dict = {'network': {'name': 'net2',
                                'tenant_id': network_tenant,
                                'admin_state_up': True,
                                'shared': False,
                                'provider:physical_network': self.physnet,
                                'provider:network_type': 'vlan'}}
        network2, _ = self.create_network(net_dict)

        # Create baremetal port
        device_id = 'baremetal-1'
        port_tenant = 'port-ten'
        port_host = 'bm-host'
        switch_id = '00:11:22:33:44:55'
        switch_port = 'Ethernet1/1'
        trunkport_dict = {'name': 'port1',
                          'tenant_id': port_tenant,
                          'network_id': network1['id'],
                          'admin_state_up': True,
                          'fixed_ips': [],
                          'device_id': '',
                          'device_owner': ''}
        trunkport, _ = self.create_port(trunkport_dict)
        subport_dict = {'name': 'port2',
                        'tenant_id': port_tenant,
                        'network_id': network2['id'],
                        'admin_state_up': True,
                        'fixed_ips': [],
                        'device_id': '',
                        'device_owner': ''}
        subport, _ = self.create_port(subport_dict)
        trunk_dict = {'trunk': {'port_id': trunkport['id'],
                                'tenant_id': port_tenant,
                                'sub_ports': [{'port_id': subport['id'],
                                               'segmentation_type': 'inherit',
                                               'segmentation_id': 'inherit'}]}}
        self.trunk_plugin.create_trunk(self.context, trunk_dict)
        self.bind_trunk_to_baremetal(trunkport['id'], device_id, port_host,
                                     switch_id, switch_port)
        self.assertTenantCreated(port_tenant)
        self.assertBaremetalCreated(device_id)
        self.assertBaremetalPortCreated(trunkport['id'])
        self.assertPortBindingCreated(
            (trunkport['id'], (switch_id, switch_port)))
        self.assertBaremetalPortCreated(subport['id'])
        self.assertPortBindingCreated(
            (subport['id'], (switch_id, switch_port)))

        # Simulate baremetal shutdown
        self.unbind_trunk_from_baremetal(trunkport['id'])
        self.assertBaremetalDeleted(device_id)
        self.assertPortBindingDeleted(
            (trunkport['id'], (switch_id, switch_port)))
        self.assertPortBindingDeleted(
            (subport['id'], (switch_id, switch_port)))

    def test_baremetal_trunk_bind_unbind(self):
        network_tenant = 'net-ten'
        net_dict = {'network': {'name': 'net1',
                                'tenant_id': network_tenant,
                                'admin_state_up': True,
                                'shared': False,
                                'provider:physical_network': self.physnet,
                                'provider:network_type': 'vlan'}}
        network1, _ = self.create_network(net_dict)
        net_dict = {'network': {'name': 'net2',
                                'tenant_id': network_tenant,
                                'admin_state_up': True,
                                'shared': False,
                                'provider:physical_network': self.physnet,
                                'provider:network_type': 'vlan'}}
        network2, _ = self.create_network(net_dict)
        net_dict = {'network': {'name': 'net3',
                                'tenant_id': network_tenant,
                                'admin_state_up': True,
                                'shared': False,
                                'provider:physical_network': self.physnet,
                                'provider:network_type': 'vlan'}}
        network3, _ = self.create_network(net_dict)

        # Create baremetal port
        device_id = 'baremetal-1'
        port_tenant = 'port-ten'
        port_host = 'bm-host'
        switch_id = '00:11:22:33:44:55'
        switch_port = 'Ethernet1/1'
        trunkport_dict = {'name': 'port1',
                          'tenant_id': port_tenant,
                          'network_id': network1['id'],
                          'admin_state_up': True,
                          'fixed_ips': [],
                          'device_id': '',
                          'device_owner': ''}
        trunkport, _ = self.create_port(trunkport_dict)
        subport_dict = {'name': 'port2',
                        'tenant_id': port_tenant,
                        'network_id': network2['id'],
                        'admin_state_up': True,
                        'fixed_ips': [],
                        'device_id': '',
                        'device_owner': ''}
        subport, _ = self.create_port(subport_dict)
        trunk_dict = {'trunk': {'port_id': trunkport['id'],
                                'tenant_id': port_tenant,
                                'sub_ports': [{'port_id': subport['id'],
                                               'segmentation_type': 'inherit',
                                               'segmentation_id': 'inherit'}]}}
        trunk = self.trunk_plugin.create_trunk(self.context, trunk_dict)
        self.bind_trunk_to_baremetal(trunkport['id'], device_id, port_host,
                                     switch_id, switch_port)
        self.assertTenantCreated(port_tenant)
        self.assertBaremetalCreated(device_id)
        self.assertBaremetalPortCreated(trunkport['id'])
        self.assertPortBindingCreated(
            (trunkport['id'], (switch_id, switch_port)))
        self.assertBaremetalPortCreated(subport['id'])
        self.assertPortBindingCreated(
            (subport['id'], (switch_id, switch_port)))

        subport_dict2 = {'name': 'port3',
                         'tenant_id': port_tenant,
                         'network_id': network3['id'],
                         'admin_state_up': True,
                         'fixed_ips': [],
                         'device_id': '',
                         'device_owner': ''}
        subport2, _ = self.create_port(subport_dict2)
        self.trunk_plugin.add_subports(self.context, trunk['id'],
                                       {'sub_ports':
                                        [{'port_id': subport2['id'],
                                          'segmentation_type': 'inherit',
                                          'segmentation_id': 'inherit'}]})
        self.assertBaremetalPortCreated(subport2['id'])
        self.assertPortBindingCreated(
            (subport2['id'], (switch_id, switch_port)))

        self.trunk_plugin.remove_subports(self.context, trunk['id'],
                                          {'sub_ports':
                                           [{'port_id': subport2['id']}]})
        self.assertPortBindingDeleted(
            (subport2['id'], (switch_id, switch_port)))

        # Simulate baremetal shutdown
        self.unbind_trunk_from_baremetal(trunkport['id'])
        self.assertBaremetalDeleted(device_id)
        self.assertPortBindingDeleted(
            (trunkport['id'], (switch_id, switch_port)))
        self.assertPortBindingDeleted(
            (subport['id'], (switch_id, switch_port)))

    def test_baremetal_trunk_pre_bound(self):
        network_tenant = 'net-ten'
        net_dict = {'network': {'name': 'net1',
                                'tenant_id': network_tenant,
                                'admin_state_up': True,
                                'shared': False,
                                'provider:physical_network': self.physnet,
                                'provider:network_type': 'vlan'}}
        network1, _ = self.create_network(net_dict)
        net_dict = {'network': {'name': 'net2',
                                'tenant_id': network_tenant,
                                'admin_state_up': True,
                                'shared': False,
                                'provider:physical_network': self.physnet,
                                'provider:network_type': 'vlan'}}
        network2, _ = self.create_network(net_dict)

        # Create baremetal port
        device_id = 'baremetal-1'
        port_tenant = 'port-ten'
        port_host = 'bm-host'
        switch_id = '00:11:22:33:44:55'
        switch_port = 'Ethernet1/1'
        trunkport_dict = {'name': 'port1',
                          'tenant_id': port_tenant,
                          'network_id': network1['id'],
                          'admin_state_up': True,
                          'fixed_ips': [],
                          'device_id': '',
                          'device_owner': ''}
        trunkport, _ = self.create_port(trunkport_dict)
        subport_dict = {'name': 'port2',
                        'tenant_id': port_tenant,
                        'network_id': network2['id'],
                        'admin_state_up': True,
                        'fixed_ips': [],
                        'device_id': '',
                        'device_owner': ''}
        subport, _ = self.create_port(subport_dict)
        trunk_dict = {'trunk': {'port_id': trunkport['id'],
                                'tenant_id': port_tenant,
                                'sub_ports': [{'port_id': subport['id'],
                                               'segmentation_type': 'inherit',
                                               'segmentation_id': 'inherit'}]}}
        self.bind_trunk_to_baremetal(trunkport['id'], device_id, port_host,
                                     switch_id, switch_port)
        self.trunk_plugin.create_trunk(self.context, trunk_dict)
        self.assertTenantCreated(port_tenant)
        self.assertBaremetalCreated(device_id)
        self.assertBaremetalPortCreated(trunkport['id'])
        self.assertPortBindingCreated(
            (trunkport['id'], (switch_id, switch_port)))
        self.assertBaremetalPortCreated(subport['id'])
        self.assertPortBindingCreated(
            (subport['id'], (switch_id, switch_port)))

        # Simulate baremetal shutdown
        self.unbind_trunk_from_baremetal(trunkport['id'])
        self.assertBaremetalDeleted(device_id)
        self.assertPortBindingDeleted(
            (trunkport['id'], (switch_id, switch_port)))
        self.assertPortBindingDeleted(
            (subport['id'], (switch_id, switch_port)))


class BasicHpbMechDriverTestCase(ml2_test_base.MechTestBase):

    def setUp(self):
        cfg.CONF.set_override('manage_fabric', True, "ml2_arista")
        super(BasicHpbMechDriverTestCase, self).setUp()

    def test_basic_hpb_port(self):
        network_tenant = 'net-ten'
        net_dict = {'network': {'name': 'net',
                                'tenant_id': network_tenant,
                                'admin_state_up': True,
                                'shared': False,
                                'provider:physical_network': None,
                                'provider:network_type': 'vxlan'}}
        network, _ = self.create_network(net_dict)
        self.assertNetworkCreated(network['id'])

        # Create HPB port
        device_id = 'vm-1'
        port_tenant = 'port-ten'
        port_host = self.host1
        port_dict = {'name': 'port1',
                     'tenant_id': port_tenant,
                     'network_id': network['id'],
                     'admin_state_up': True,
                     'fixed_ips': [],
                     'device_id': device_id,
                     'device_owner': 'compute:',
                     'binding:host_id': port_host}
        with mock.patch.object(self.drv.eapi,
                               'get_host_physnet',
                               return_value=self.physnet):
            port, port_ctx = self.create_port(port_dict)
        self.assertTenantCreated(port_tenant)
        self.assertVmCreated(device_id)
        self.assertVmPortCreated(port['id'])
        self.assertPortBindingCreated((port['id'], port_host))

        # Check that the dynamic segment was created
        network_segments = [level['bound_segment']
                            for level in port_ctx.binding_levels]
        self.assertTrue(len(network_segments) == 2)
        for segment in network_segments:
            self.assertSegmentCreated(segment['id'])

        # Delete HPB port
        self.delete_port(port['id'])
        self.assertTenantDeleted(port_tenant)
        self.assertVmDeleted(device_id)
        self.assertVmPortDeleted(port['id'])
        self.assertPortBindingDeleted((port['id'], port_host))

    def test_hpb_dvr_port(self):
        network_tenant = 'net-ten'
        net_dict = {'network': {'name': 'net',
                                'tenant_id': network_tenant,
                                'admin_state_up': True,
                                'shared': False,
                                'provider:physical_network': None,
                                'provider:network_type': 'vxlan'}}
        network, _ = self.create_network(net_dict)

        # Create DVR port
        device_id = 'router-1'
        port_tenant = 'port-ten'
        port_host_1 = self.host1
        port_dict = {'name': 'port1',
                     'tenant_id': port_tenant,
                     'network_id': network['id'],
                     'admin_state_up': True,
                     'fixed_ips': [],
                     'device_id': device_id,
                     'device_owner': n_const.DEVICE_OWNER_DVR_INTERFACE}
        port, _ = self.create_port(port_dict)
        with mock.patch.object(self.drv.eapi,
                               'get_host_physnet',
                               return_value=self.physnet):
            port, port_ctx = self.bind_dvr_to_host(port, port_host_1)
        self.assertTenantCreated(port_tenant)
        self.assertRouterCreated(device_id)
        self.assertRouterPortCreated(port['id'])
        self.assertPortBindingCreated((port['id'], port_host_1))
        network_segments = [level['bound_segment']
                            for level in port_ctx.binding_levels]
        self.assertTrue(len(network_segments) == 2)
        for segment in network_segments:
            self.assertSegmentCreated(segment['id'])

        # Bring up a second DVR host
        port_host_2 = self.host3
        with mock.patch.object(self.drv.eapi,
                               'get_host_physnet',
                               return_value=self.physnet2):
            port, port_ctx = self.bind_dvr_to_host(port, port_host_2)
        self.assertPortBindingCreated((port['id'], port_host_2))
        network_segments = [level['bound_segment']
                            for level in port_ctx.binding_levels]
        self.assertTrue(len(network_segments) == 2)
        for segment in network_segments:
            self.assertSegmentCreated(segment['id'])

        # Delete the port
        self.delete_port(port['id'])
        self.assertTenantDeleted(port_tenant)
        self.assertRouterDeleted(device_id)
        self.assertRouterPortDeleted(port['id'])
        self.assertPortBindingDeleted((port['id'], port_host_1))
        self.assertPortBindingDeleted((port['id'], port_host_2))


class UnmanagedFabricUnmanagedPhysnetHpbTestCase(ml2_test_base.MechTestBase):

    _mechanism_drivers = ['arista_test_fabric', 'arista', 'openvswitch']

    def setUp(self):
        cfg.CONF.set_override('manage_fabric', False, "ml2_arista")
        cfg.CONF.set_override('managed_physnets', ['other_physnet'],
                              "ml2_arista")
        super(UnmanagedFabricUnmanagedPhysnetHpbTestCase, self).setUp()

    def test_unmanaged_fabric_unmanaged_hpb_port(self):
        network_tenant = 'net-ten'
        net_dict = {'network': {'name': 'net',
                                'tenant_id': network_tenant,
                                'admin_state_up': True,
                                'shared': False,
                                'provider:physical_network': None,
                                'provider:network_type': 'vxlan'}}
        network, _ = self.create_network(net_dict)
        self.assertNetworkCreated(network['id'])

        # Create HPB port
        device_id = 'vm-1'
        port_tenant = 'port-ten'
        port_host = self.host1
        port_dict = {'name': 'port1',
                     'tenant_id': port_tenant,
                     'network_id': network['id'],
                     'admin_state_up': True,
                     'fixed_ips': [],
                     'device_id': device_id,
                     'device_owner': 'compute:',
                     'binding:host_id': port_host}
        port, port_ctx = self.create_port(port_dict)
        self.assertTenantCreated(port_tenant)
        # Check that the dynamic segment was created
        network_segments = [level['bound_segment']
                            for level in port_ctx.binding_levels]
        self.assertTrue(len(network_segments) == 2)
        for segment in network_segments:
            self.assertSegmentCreated(segment['id'])

        # The VM/Port should not have been created
        self.assertVmDeleted(device_id)
        self.assertVmPortDeleted(port['id'])
        self.assertPortBindingDeleted((port['id'], port_host))

        # Delete HPB port
        self.delete_port(port['id'])
        self.assertTenantDeleted(port_tenant)
        self.assertVmDeleted(device_id)
        self.assertVmPortDeleted(port['id'])
        self.assertPortBindingDeleted((port['id'], port_host))


class ManagedFabricUnmanagedPhysnetHpbTestCase(ml2_test_base.MechTestBase):

    def setUp(self):
        cfg.CONF.set_override('manage_fabric', True, "ml2_arista")
        cfg.CONF.set_override('managed_physnets', ['other_physnet'],
                              "ml2_arista")
        super(ManagedFabricUnmanagedPhysnetHpbTestCase, self).setUp()

    def test_managed_fabric_unmanaged_hpb_port(self):
        network_tenant = 'net-ten'
        net_dict = {'network': {'name': 'net',
                                'tenant_id': network_tenant,
                                'admin_state_up': True,
                                'shared': False,
                                'provider:physical_network': None,
                                'provider:network_type': 'vxlan'}}
        network, _ = self.create_network(net_dict)
        self.assertNetworkCreated(network['id'])

        # Create HPB port
        device_id = 'vm-1'
        port_tenant = 'port-ten'
        port_host = self.host1
        port_dict = {'name': 'port1',
                     'tenant_id': port_tenant,
                     'network_id': network['id'],
                     'admin_state_up': True,
                     'fixed_ips': [],
                     'device_id': device_id,
                     'device_owner': 'compute:',
                     'binding:host_id': port_host}
        with mock.patch.object(self.drv.eapi,
                               'get_host_physnet',
                               return_value=self.physnet):
            port, port_ctx = self.create_port(port_dict)
        self.assertTenantCreated(port_tenant)
        # Check that the dynamic segment was created
        network_segments = [level['bound_segment']
                            for level in port_ctx.binding_levels]
        self.assertTrue(len(network_segments) == 2)
        for segment in network_segments:
            self.assertSegmentCreated(segment['id'])

        # The VM/Port should not have been created
        self.assertVmDeleted(device_id)
        self.assertVmPortDeleted(port['id'])
        self.assertPortBindingDeleted((port['id'], port_host))

        # Delete HPB port
        self.delete_port(port['id'])
        self.assertTenantDeleted(port_tenant)
        self.assertVmDeleted(device_id)
        self.assertVmPortDeleted(port['id'])
        self.assertPortBindingDeleted((port['id'], port_host))


class UnmanagedFabricManagedPhysnetHpbTestCase(ml2_test_base.MechTestBase):

    _mechanism_drivers = ['arista_test_fabric', 'arista', 'openvswitch']

    def setUp(self):
        self.physnet = 'physnet1'
        cfg.CONF.set_override('manage_fabric', False, "ml2_arista")
        cfg.CONF.set_override('managed_physnets', [self.physnet],
                              "ml2_arista")
        super(UnmanagedFabricManagedPhysnetHpbTestCase, self).setUp()

    def test_unmanaged_fabric_managed_hpb_port(self):
        network_tenant = 'net-ten'
        net_dict = {'network': {'name': 'net',
                                'tenant_id': network_tenant,
                                'admin_state_up': True,
                                'shared': False,
                                'provider:physical_network': None,
                                'provider:network_type': 'vxlan'}}
        network, _ = self.create_network(net_dict)
        self.assertNetworkCreated(network['id'])

        # Create HPB port
        device_id = 'vm-1'
        port_tenant = 'port-ten'
        port_host = self.host1
        port_dict = {'name': 'port1',
                     'tenant_id': port_tenant,
                     'network_id': network['id'],
                     'admin_state_up': True,
                     'fixed_ips': [],
                     'device_id': device_id,
                     'device_owner': 'compute:',
                     'binding:host_id': port_host}
        port, port_ctx = self.create_port(port_dict)
        self.assertTenantCreated(port_tenant)
        self.assertVmCreated(device_id)
        self.assertVmPortCreated(port['id'])
        self.assertPortBindingCreated((port['id'], port_host))

        # Check that the dynamic segment was created
        network_segments = [level['bound_segment']
                            for level in port_ctx.binding_levels]
        self.assertTrue(len(network_segments) == 2)
        for segment in network_segments:
            self.assertSegmentCreated(segment['id'])

        # Delete HPB port
        self.delete_port(port['id'])
        self.assertTenantDeleted(port_tenant)
        self.assertVmDeleted(device_id)
        self.assertVmPortDeleted(port['id'])
        self.assertPortBindingDeleted((port['id'], port_host))


class ManagedFabricManagedFabricHpbTestCase(ml2_test_base.MechTestBase):

    def setUp(self):
        self.physnet = 'physnet1'
        cfg.CONF.set_override('manage_fabric', True, "ml2_arista")
        cfg.CONF.set_override('managed_physnets', [self.physnet],
                              "ml2_arista")
        super(ManagedFabricManagedFabricHpbTestCase, self).setUp()

    def test_managed_fabric_managed_hpb_port(self):
        network_tenant = 'net-ten'
        net_dict = {'network': {'name': 'net',
                                'tenant_id': network_tenant,
                                'admin_state_up': True,
                                'shared': False,
                                'provider:physical_network': None,
                                'provider:network_type': 'vxlan'}}
        network, _ = self.create_network(net_dict)
        self.assertNetworkCreated(network['id'])

        # Create HPB port
        device_id = 'vm-1'
        port_tenant = 'port-ten'
        port_host = self.host1
        port_dict = {'name': 'port1',
                     'tenant_id': port_tenant,
                     'network_id': network['id'],
                     'admin_state_up': True,
                     'fixed_ips': [],
                     'device_id': device_id,
                     'device_owner': 'compute:',
                     'binding:host_id': port_host}
        with mock.patch.object(self.drv.eapi,
                               'get_host_physnet',
                               return_value=self.physnet):
            port, port_ctx = self.create_port(port_dict)
        self.assertTenantCreated(port_tenant)
        self.assertVmCreated(device_id)
        self.assertVmPortCreated(port['id'])
        self.assertPortBindingCreated((port['id'], port_host))

        # Check that the dynamic segment was created
        network_segments = [level['bound_segment']
                            for level in port_ctx.binding_levels]
        self.assertTrue(len(network_segments) == 2)
        for segment in network_segments:
            self.assertSegmentCreated(segment['id'])

        # Delete HPB port
        self.delete_port(port['id'])
        self.assertTenantDeleted(port_tenant)
        self.assertVmDeleted(device_id)
        self.assertVmPortDeleted(port['id'])
        self.assertPortBindingDeleted((port['id'], port_host))
