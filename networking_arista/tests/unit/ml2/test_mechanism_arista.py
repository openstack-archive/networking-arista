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


import cProfile
import mock
from pstats import Stats

from neutron_lib.api.definitions import portbindings
from neutron_lib import constants as n_const
import neutron_lib.context
from neutron_lib.plugins import directory
from oslo_config import cfg

from neutron.common import utils as common_utils
from neutron.plugins.ml2.drivers import type_vxlan  # noqa
from neutron.services.trunk import constants as trunk_const
from neutron.tests.common import helpers
from neutron.tests.unit.plugins.ml2 import test_plugin

from networking_arista.ml2 import arista_sync
from networking_arista.ml2 import mechanism_arista
from networking_arista.tests.unit import utils


ENABLE_PROFILER = False


class AristaDriverTestCase(test_plugin.Ml2PluginV2TestCase):
    """Main test cases for Arista Mechanism driver.

    Tests all mechanism driver APIs supported by Arista Driver. It invokes
    all the APIs as they would be invoked in real world scenarios and
    verifies the functionality.
    """

    _mechanism_drivers = ['arista', 'openvswitch']

    def get_additional_service_plugins(self):
        p = super(AristaDriverTestCase, self).get_additional_service_plugins()
        p.update({'trunk_plugin_name': 'trunk'})
        return p

    def setUp(self):
        if ENABLE_PROFILER:
            self.pr = cProfile.Profile()
            self.pr.enable()
        utils.setup_arista_wrapper_config(cfg)
        cfg.CONF.set_override('vni_ranges',
                              ['10000:11000'],
                              group='ml2_type_vxlan')
        super(AristaDriverTestCase, self).setUp()
        self.plugin.notifier.port_update = self._mock_port_update
        self.plugin.start_rpc_listeners()
        self.host1 = 'host1'
        self.host2 = 'host2'
        self.host3 = 'host3'
        # Hack to ensure agents report being alive
        cfg.CONF.set_override('agent_down_time', 1000)
        helpers.register_ovs_agent(
            host=self.host1, bridge_mappings={self.physnet: 'br-eth1'})
        helpers.register_ovs_agent(
            host=self.host2, bridge_mappings={self.physnet: 'br-eth1'})
        helpers.register_ovs_agent(
            host=self.host3, bridge_mappings={self.physnet2: 'br-eth1'})
        self.region = 'region'
        self.cvx = utils.MockCvx(self.region)
        self.drv = self.driver.mechanism_manager.mech_drivers['arista'].obj
        for worker in self.driver._workers:
            if isinstance(worker, arista_sync.AristaSyncWorker):
                self.ar_sync = worker
                self.ar_sync._rpc = self.cvx
            worker.start()
        self.trunk_plugin = directory.get_plugin('trunk')
        self.net_count = 0

    def tearDown(self):
        for worker in self.driver._workers:
            worker.stop()
            worker.wait()
        self.cvx.endpoint_data.clear()
        super(AristaDriverTestCase, self).tearDown()
        if ENABLE_PROFILER:
            p = Stats(self.pr)
            p.strip_dirs()
            p.sort_stats('cumtime')
            p.print_stats()

    def _mock_port_update(self, context, port, network_type, segmentation_id,
                          physical_network):
        '''Simulates an L2 agent's response to a port_update notification

        After binding a port, the ML2 plugin notifies all L2 agents of the
        binding so that they can configure the datapath. Once they have
        done so, the call either update_devices_up or update_devices_list
        which brings the port status to ACTIVE. This function simply calls
        update_devices_list in response to a binding without actually doing
        any datapath manipulation.
        '''
        plugin = directory.get_plugin()
        rpc_plugin = plugin.endpoints[0]
        host = port.get(portbindings.HOST_ID)
        agent_id = 'ovs-agent-%s' % host
        vif_type = port.get(portbindings.VIF_TYPE)
        if port.get('device_owner') == trunk_const.TRUNK_SUBPORT_OWNER:
            return
        if vif_type == 'ovs':
            device_list = []
            device_list.append(port['id'])
            if port.get('trunk_details'):
                trunk_rpc = self.trunk_plugin._rpc_backend._skeleton
                for s in port['trunk_details']['sub_ports']:
                    s['trunk_id'] = port['trunk_details']['trunk_id']
                    trunk_rpc.update_subport_bindings(
                        self.context, port['trunk_details']['sub_ports'])
                    device_list.append(s['port_id'])
            devices_dict = {'devices_up': device_list,
                            'agent_id': agent_id,
                            'host': port.get(portbindings.HOST_ID)}

            # This is a hack. When calling update_port_status from the rpc
            # handler, the trunk_details db extension gets a new admin context
            # in order to query the parent port's subports' mac address.
            # Querying within the new context's session seems to somehow
            # invalidate the transaction in update_port_status, which causes
            # the status in the db to remain 'DOWN' in spite of an
            # update_port_[pre/post]commit being sent indicating that the
            # status is 'ACTIVE'. For now, I've found that using the same admin
            # context in all queries resolves the issue. In my testing, this
            # doesn't affect real environments using mysql and seems to be
            # limited to sqlite
            #
            # Additional notes: If there is no transaction in progress when a
            # query in the new context is issued, the update_port_status
            # commit succeeds (ie. comment out the context.session.flush() in
            # update_individual_port_db_status
            with mock.patch.object(neutron_lib.context, 'get_admin_context',
                                   return_value=self.context):
                rpc_plugin.update_device_list(context, **devices_dict)

            if port.get('trunk_details'):
                trunk_rpc = self.trunk_plugin._rpc_backend._skeleton
                trunk_rpc.update_trunk_status(
                    self.context, port['trunk_details']['trunk_id'], 'ACTIVE')
        elif (port.get(portbindings.VNIC_TYPE) == 'normal'
              and vif_type == 'unbound'):
            device_dict = {'agent_id': agent_id,
                           'device': port['id'],
                           'host': port.get(portbindings.HOST_ID)}
            rpc_plugin.update_device_down(context, **device_dict)

    def create_network(self, net_dict):
        net = self.plugin.create_network(self.context, net_dict)
        n_ctxs = self.plugin.get_network_contexts(self.context, [net['id']])
        self.plugin.create_subnet(self.context,
                                  {'subnet':
                                   {'tenant_id': net['tenant_id'],
                                    'name': net['name'],
                                    'network_id': net['id'],
                                    'ip_version': 4,
                                    'cidr': '10.0.%d.0/24' % self.net_count,
                                    'allocation_pools': None,
                                    'enable_dhcp': False,
                                    'dns_nameservers': None,
                                    'host_routes': None}})
        return net, n_ctxs[net['id']]

    def delete_network(self, net_id):
        self.plugin.delete_network(self.context, net_id)

    def create_port(self, port_dict):
        minimal_port = {'port':
                        {'name': port_dict.get('name'),
                         'tenant_id': port_dict.get('tenant_id'),
                         'device_id': port_dict.get('device_id'),
                         'fixed_ips': port_dict.get('fixed_ips'),
                         'network_id': port_dict.get('network_id'),
                         'device_owner': '',
                         'admin_state_up': True}}
        port = self.plugin.create_port(self.context, minimal_port)
        full_port = {'port': port_dict}
        port = self.plugin.update_port(self.context, port['id'], full_port)
        p_ctx = self.plugin.get_bound_port_context(self.context, port['id'])
        return port, p_ctx

    def migrate_port(self, port_id, new_host):
        port_dict = {'port': {'binding:host_id': new_host}}
        port = self.plugin.update_port(self.context, port_id, port_dict)
        p_ctx = self.plugin.get_bound_port_context(self.context, port_id)
        return port, p_ctx

    def migrate_dhcp_device(self, port_id, new_device):
        port_dict = {'port':
                     {'device_id': n_const.DEVICE_ID_RESERVED_DHCP_PORT}}
        port = self.plugin.update_port(self.context, port_id, port_dict)
        port_dict = {'port': {'device_id': new_device}}
        port = self.plugin.update_port(self.context, port_id, port_dict)
        p_ctx = self.plugin.get_bound_port_context(self.context, port_id)
        return port, p_ctx

    def bind_trunk_to_host(self, port, device_id, host):
        p_dict = {'port':
                  {'device_owner': n_const.DEVICE_OWNER_COMPUTE_PREFIX,
                   portbindings.HOST_ID: host,
                   'device_id': device_id}}
        port = self.plugin.update_port(self.context, port['id'], p_dict)
        p_ctx = self.plugin.get_bound_port_context(self.context, port['id'])
        return port, p_ctx

    def bind_subport_to_trunk(self, port, trunk):
        parent = self.plugin.get_port(self.context, trunk['port_id'])
        p_dict = {'port':
                  {portbindings.HOST_ID: parent.get(portbindings.HOST_ID),
                   'device_owner': trunk_const.TRUNK_SUBPORT_OWNER}}
        port = self.plugin.update_port(self.context, port['id'], p_dict)
        self.plugin.update_port_status(self.context, port['id'],
                                       n_const.PORT_STATUS_ACTIVE)

    def unbind_port_from_host(self, port_id):
        p_dict = {'port':
                  {portbindings.HOST_ID: None,
                   'device_id': ''}}
        port = self.plugin.update_port(self.context, port_id, p_dict)
        return port

    def bind_trunk_to_baremetal(self, port_id, device_id, host,
                                switch_id, switch_port):
        p_dict = {'port':
                  {'device_id': device_id,
                   'device_owner': n_const.DEVICE_OWNER_BAREMETAL_PREFIX,
                   'binding:host_id': host,
                   'binding:profile': {'local_link_information': [
                       {'switch_id': switch_id,
                        'port_id': switch_port}]},
                   'binding:vnic_type': 'baremetal'}}
        port = self.plugin.update_port(self.context, port_id, p_dict)
        return port

    def unbind_trunk_from_baremetal(self, port_id):
        p_dict = {'port':
                  {'device_id': '',
                   'device_owner': '',
                   'binding:host_id': None,
                   'binding:profile': None,
                   'binding:vnic_type': None,
                   'status': n_const.PORT_STATUS_DOWN,
                   portbindings.VIF_TYPE: portbindings.VIF_TYPE_UNBOUND}}
        self.plugin.update_port(self.context, port_id, p_dict)

    def bind_dvr_to_host(self, port, host):
        p_dict = {'port':
                  {'device_id': port['device_id'],
                   'device_owner': port['device_owner'],
                   portbindings.HOST_ID: host}}
        self.plugin.update_distributed_port_binding(self.context,
                                                    port['id'], p_dict)
        self.plugin.update_port_status(self.context, port['id'],
                                       n_const.PORT_STATUS_ACTIVE,
                                       host)
        p_ctx = self.plugin.get_bound_port_context(self.context, port['id'],
                                                   host)
        return port, p_ctx

    def unbind_dvr_from_host(self, port, host):
        self.plugin.update_port_status(
            self.context, port['id'], n_const.PORT_STATUS_DOWN, host)

    def delete_port(self, port_id):
        self.plugin.delete_port(self.context, port_id)

    def _get_endpoint(self, resource_type):
        endpoint_map = {
            'tenant': 'region/%s/tenant' % self.region,
            'network': 'region/%s/network' % self.region,
            'segment': 'region/%s/segment' % self.region,
            'dhcp': 'region/%s/dhcp' % self.region,
            'router': 'region/%s/router' % self.region,
            'vm': 'region/%s/vm' % self.region,
            'baremetal': 'region/%s/baremetal' % self.region,
            'dhcp_port': 'region/%s/port?type=dhcp' % self.region,
            'router_port': 'region/%s/port?type=router' % self.region,
            'vm_port': 'region/%s/port?type=vm' % self.region,
            'baremetal_port': 'region/%s/port?type=baremetal' % self.region,
            'port_binding': 'region/%s/portbinding' % self.region}
        return endpoint_map[resource_type]

    def _assertResourceCreated(self, resource_type, resource_id):
        endpoint = self._get_endpoint(resource_type)

        def resource_created():
            return resource_id in self.cvx.endpoint_data[endpoint].keys()
        common_utils.wait_until_true(resource_created)

    def _assertResourceDeleted(self, resource_type, resource_id):
        endpoint = self._get_endpoint(resource_type)

        def resource_deleted():
            return resource_id not in self.cvx.endpoint_data[endpoint].keys()
        common_utils.wait_until_true(resource_deleted)

    def assertTenantCreated(self, tenant_id):
        self._assertResourceCreated('tenant', tenant_id)

    def assertTenantDeleted(self, tenant_id):
        self._assertResourceDeleted('tenant', tenant_id)

    def assertNetworkCreated(self, network_id):
        self._assertResourceCreated('network', network_id)

    def assertNetworkDeleted(self, network_id):
        self._assertResourceDeleted('network', network_id)

    def assertSegmentCreated(self, segment_id):
        self._assertResourceCreated('segment', segment_id)

    def assertSegmentDeleted(self, segment_id):
        self._assertResourceDeleted('segment', segment_id)

    def assertDhcpCreated(self, instance_id):
        self._assertResourceCreated('dhcp', instance_id)

    def assertDhcpDeleted(self, instance_id):
        self._assertResourceDeleted('dhcp', instance_id)

    def assertRouterCreated(self, instance_id):
        self._assertResourceCreated('router', instance_id)

    def assertRouterDeleted(self, instance_id):
        self._assertResourceDeleted('router', instance_id)

    def assertVmCreated(self, instance_id):
        self._assertResourceCreated('vm', instance_id)

    def assertVmDeleted(self, instance_id):
        self._assertResourceDeleted('vm', instance_id)

    def assertBaremetalCreated(self, instance_id):
        self._assertResourceCreated('baremetal', instance_id)

    def assertBaremetalDeleted(self, instance_id):
        self._assertResourceDeleted('baremetal', instance_id)

    def assertDhcpPortCreated(self, port_id):
        self._assertResourceCreated('dhcp_port', port_id)

    def assertDhcpPortDeleted(self, port_id):
        self._assertResourceDeleted('dhcp_port', port_id)

    def assertRouterPortCreated(self, port_id):
        self._assertResourceCreated('router_port', port_id)

    def assertRouterPortDeleted(self, port_id):
        self._assertResourceDeleted('router_port', port_id)

    def assertVmPortCreated(self, port_id):
        self._assertResourceCreated('vm_port', port_id)

    def assertVmPortDeleted(self, port_id):
        self._assertResourceDeleted('vm_port', port_id)

    def assertBaremetalPortCreated(self, port_id):
        self._assertResourceCreated('baremetal_port', port_id)

    def assertBaremetalPortDeleted(self, port_id):
        self._assertResourceDeleted('baremetal_port', port_id)

    def assertPortBindingCreated(self, pb_key):
        self._assertResourceCreated('port_binding', pb_key)

    def assertPortBindingDeleted(self, pb_key):
        self._assertResourceDeleted('port_binding', pb_key)


class BasicMechDriverTestCase(AristaDriverTestCase):

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


class BasicHpbMechDriverTestCase(AristaDriverTestCase):

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
        with mock.patch.object(mechanism_arista.AristaDriver,
                               '_get_physnet',
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
        with mock.patch.object(mechanism_arista.AristaDriver,
                               '_get_physnet',
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
        with mock.patch.object(mechanism_arista.AristaDriver,
                               '_get_physnet',
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


class UnmanagedFabricUnmanagedPhysnetHpbTestCase(AristaDriverTestCase):

    _mechanism_drivers = ['test_fabric', 'arista', 'openvswitch']

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


class ManagedFabricUnmanagedPhysnetHpbTestCase(AristaDriverTestCase):

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
        with mock.patch.object(mechanism_arista.AristaDriver,
                               '_get_physnet',
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


class UnmanagedFabricManagedPhysnetHpbTestCase(AristaDriverTestCase):

    _mechanism_drivers = ['test_fabric', 'arista', 'openvswitch']

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


class ManagedFabricManagedFabricHpbTestCase(AristaDriverTestCase):

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
        with mock.patch.object(mechanism_arista.AristaDriver,
                               '_get_physnet',
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
