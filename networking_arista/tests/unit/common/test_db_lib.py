# Copyright (c) 2017 OpenStack Foundation
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

from neutron_lib.plugins import constants as plugin_constants
from neutron_lib.plugins import directory
from oslo_utils import importutils

from neutron.tests.unit import testlib_api

from networking_arista.common import db_lib
from networking_arista.tests.unit import utils


class DbLibTest(testlib_api.SqlTestCase):
    """Test cases for database helper functions."""

    def setUp(self):
        super(DbLibTest, self).setUp()
        plugin_klass = importutils.import_class(
            "neutron.db.db_base_plugin_v2.NeutronDbPluginV2")
        directory.add_plugin(plugin_constants.CORE, plugin_klass())

    def test_binding_level_and_network_segments(self):
        """Test get_port_binding_level and get_network_segments_by_port_id"""

        tenant_id = 't1'
        network_id = '11111111-2222-3333-4444-555555555555'
        network_ctx = utils.create_network(tenant_id,
                                           network_id,
                                           5000,
                                           network_type='vxlan',
                                           physical_network=None)
        segments = [{'id': network_id,
                     'segmentation_id': 5000,
                     'physical_network': None,
                     'network_type': 'vxlan',
                     'is_dynamic': False},
                    {'id': None,
                     'segmentation_id': 500,
                     'physical_network': 'physnet1',
                     'network_type': 'vlan',
                     'is_dynamic': True},
                    {'id': None,
                     'segmentation_id': 600,
                     'physical_network': 'physnet2',
                     'network_type': 'vlan',
                     'is_dynamic': True}]

        for segment in segments:
            if segment['is_dynamic']:
                dyn_seg = utils.create_dynamic_segment(
                    network_id, segment['segmentation_id'],
                    segment['network_type'], segment['physical_network'])
                segment['id'] = dyn_seg['id']

        # create ports with different dynamic segments on different hosts
        device_id_1 = 'dev1'
        port_id_1 = 'p1'
        host_1 = 'h1'
        utils.create_port(tenant_id, network_id, device_id_1,
                          port_id_1, network_ctx, host=host_1,
                          dynamic_segment=segments[1])
        device_id_2 = 'dev2'
        port_id_2 = 'p2'
        host_2 = 'h2'
        utils.create_port(tenant_id, network_id, device_id_2,
                          port_id_2, network_ctx, host=host_2,
                          dynamic_segment=segments[2])

        # Verify get_port_binding_level result
        filters = {'port_id': port_id_1,
                   'host': host_1}
        res_binding_level = db_lib.get_port_binding_level(filters)
        self.assertEqual(len(res_binding_level), 2)
        expected_ctxt = utils.get_port_context(
            tenant_id, network_id, device_id_1, network_ctx, port_id_1,
            host=host_1, dynamic_segment=segments[1])
        for i in range(0, len(res_binding_level)):
            self.assertEqual(dict(res_binding_level[i]),
                             vars(expected_ctxt._binding_levels[i]))

        # Verify get_network_segments_by_port_id result
        res_segs = db_lib.get_network_segments_by_port_id(port_id_1)
        self.assertEqual(len(res_segs), 2)
        subset_keys = {'id', 'network_type', 'physical_network',
                       'segmentation_id', 'is_dynamic'}
        for i, rs in enumerate(res_segs):
                self.assertEqual(segments[i],
                                 {k: v for k, v in rs if k in subset_keys})

    def test_get_tenants_empty(self):
        tenants = db_lib.get_tenants()
        self.assertEqual(tenants, set())

    def test_get_tenants_from_networks(self):
        tenant_1_id = 't1'
        network_1_id = 'n1'
        seg_1_id = 11
        utils.create_network(tenant_1_id,
                             network_1_id,
                             seg_1_id)
        tenant_2_id = 't2'
        network_2_id = 'n2'
        seg_2_id = 21
        utils.create_network(tenant_2_id,
                             network_2_id,
                             seg_2_id)

        tenants = db_lib.get_tenants()
        self.assertEqual(tenants, set([tenant_1_id, tenant_2_id]))

    def test_get_tenants_with_shared_network_ports(self):
        tenant_1_id = 't1'
        port_1_id = 'p1'
        device_1_id = 'v1'

        tenant_2_id = 't2'
        port_2_id = 'p2'
        device_2_id = 'v2'

        network_id = 'n1'
        seg_id = 11
        network_ctx = utils.create_network(tenant_1_id,
                                           network_id,
                                           seg_id,
                                           shared=True)

        utils.create_port(tenant_1_id, network_id, device_1_id,
                          port_1_id, network_ctx)
        utils.create_port(tenant_2_id, network_id, device_2_id,
                          port_2_id, network_ctx)

        tenants = db_lib.get_tenants()
        self.assertEqual(tenants, set([tenant_1_id, tenant_2_id]))

    def test_get_tenants_uniqueness(self):
        tenant_1_id = 't1'
        network_1_id = 'n1'
        seg_1_id = 11
        network_1_ctx = utils.create_network(tenant_1_id,
                                             network_1_id,
                                             seg_1_id)
        tenant_2_id = 't2'
        network_2_id = 'n2'
        seg_2_id = 21
        network_2_ctx = utils.create_network(tenant_2_id,
                                             network_2_id,
                                             seg_2_id)
        device_1_id = 'v1'
        port_1_id = 'p1'
        device_2_id = 'v2'
        port_2_id = 'p2'
        utils.create_port(tenant_1_id, network_1_id, device_1_id,
                          port_1_id, network_1_ctx)
        utils.create_port(tenant_2_id, network_2_id, device_2_id,
                          port_2_id, network_2_ctx)

        tenants = db_lib.get_tenants()
        self.assertEqual(tenants, set([tenant_1_id, tenant_2_id]))

    def test_get_tenants_port_network_union(self):
        tenant_1_id = 't1'
        network_1_id = 'n1'
        seg_1_id = 11
        network_1_ctx = utils.create_network(tenant_1_id,
                                             network_1_id,
                                             seg_1_id,
                                             shared=True)
        tenant_2_id = 't2'
        network_2_id = 'n2'
        seg_2_id = 21
        network_2_ctx = utils.create_network(tenant_2_id,
                                             network_2_id,
                                             seg_2_id,
                                             shared=True)
        tenant_3_id = 't3'
        port_1_id = 'p1'
        device_1_id = 'v1'
        utils.create_port(tenant_3_id, network_1_id, device_1_id, port_1_id,
                          network_1_ctx)
        tenant_4_id = 't4'
        port_2_id = 'p2'
        device_2_id = 'v2'
        utils.create_port(tenant_4_id, network_2_id, device_2_id, port_2_id,
                          network_2_ctx)

        tenants = db_lib.get_tenants()
        self.assertEqual(tenants, set([tenant_1_id, tenant_2_id,
                                       tenant_3_id, tenant_4_id]))

    def test_tenant_provisioned(self):
        tenant_1_id = 't1'
        port_1_id = 'p1'
        tenant_2_id = 't2'
        port_2_id = 'p2'
        network_id = 'network-id'
        self.assertFalse(db_lib.tenant_provisioned(tenant_1_id))
        self.assertFalse(db_lib.tenant_provisioned(tenant_2_id))
        n_ctx = utils.create_network(tenant_1_id, network_id, 11, shared=True)
        self.assertTrue(db_lib.tenant_provisioned(tenant_1_id))
        self.assertFalse(db_lib.tenant_provisioned(tenant_2_id))
        p1_ctx = utils.create_port(tenant_1_id, network_id, 'vm1',
                                   port_1_id, n_ctx)
        self.assertTrue(db_lib.tenant_provisioned(tenant_1_id))
        self.assertFalse(db_lib.tenant_provisioned(tenant_2_id))
        p2_ctx = utils.create_port(tenant_2_id, network_id, 'vm2',
                                   port_2_id, n_ctx)
        self.assertTrue(db_lib.tenant_provisioned(tenant_1_id))
        self.assertTrue(db_lib.tenant_provisioned(tenant_2_id))
        utils.delete_port(p1_ctx, port_1_id)
        utils.delete_port(p2_ctx, port_2_id)
        utils.delete_network(n_ctx, network_id)
        self.assertFalse(db_lib.tenant_provisioned(tenant_1_id))
        self.assertFalse(db_lib.tenant_provisioned(tenant_2_id))

    def test_get_instances(self):
        # First check that get_instances initially returns an empty set
        tenant_1_id = 't1'
        self.assertEqual(db_lib.get_instances(tenant_1_id), set())

        # Create two ports for two instances and check that both are returned
        port_1_id = 'p1'
        network_1_id = 'n1'
        device_1_id = 'vm1'
        port_2_id = 'p2'
        network_2_id = 'n2'
        device_2_id = 'vm2'
        n1_ctx = utils.create_network(tenant_1_id, network_1_id, 11,
                                      shared=True)
        p1_ctx = utils.create_port(tenant_1_id, network_1_id, device_1_id,
                                   port_1_id, n1_ctx)
        n2_ctx = utils.create_network(tenant_1_id, network_2_id, 21)
        p2_ctx = utils.create_port(tenant_1_id, network_2_id, device_2_id,
                                   port_2_id, n2_ctx)
        self.assertEqual(db_lib.get_instances(tenant_1_id),
                         set([device_1_id, device_2_id]))

        # Add another port on an existing instance, instance set should not
        # change
        port_3_id = 'p3'
        p3_ctx = utils.create_port(tenant_1_id, network_1_id, device_2_id,
                                   port_3_id, n1_ctx)
        self.assertEqual(db_lib.get_instances(tenant_1_id),
                         set([device_1_id, device_2_id]))

        # Add ports under another tenant, the first tenants instances should
        # remain the same
        tenant_2_id = 't2'
        port_4_id = 'p4'
        device_3_id = 'vm3'
        p4_ctx = utils.create_port(tenant_2_id, network_1_id, device_3_id,
                                   port_4_id, n1_ctx)
        self.assertEqual(db_lib.get_instances(tenant_1_id),
                         set([device_1_id, device_2_id]))
        self.assertEqual(db_lib.get_instances(tenant_2_id),
                         set([device_3_id]))

        # Delete all ports and check that an empty set is once again returned
        utils.delete_port(p1_ctx, port_1_id)
        utils.delete_port(p2_ctx, port_2_id)
        utils.delete_port(p3_ctx, port_3_id)
        utils.delete_port(p4_ctx, port_4_id)
        self.assertEqual(db_lib.get_instances(tenant_1_id), set())
        self.assertEqual(db_lib.get_instances(tenant_2_id), set())

    def test_get_instance_ports(self):
        # Create 3 ports on two VMs, validate the dict returned
        host = 'ubuntu1'
        tenant_1_id = 't1'
        port_1_id = 'p1'
        network_1_id = 'n1'
        device_1_id = 'vm1'
        port_2_id = 'p2'
        network_2_id = 'n2'
        device_2_id = 'vm2'
        port_3_id = 'p3'
        n1_ctx = utils.create_network(tenant_1_id, network_1_id, 11,
                                      shared=True)
        n2_ctx = utils.create_network(tenant_1_id, network_2_id, 21)
        p1_ctx = utils.create_port(tenant_1_id, network_1_id, device_1_id,
                                   port_1_id, n1_ctx)
        p2_ctx = utils.create_port(tenant_1_id, network_2_id, device_2_id,
                                   port_2_id, n2_ctx)
        p3_ctx = utils.create_port(tenant_1_id, network_1_id, device_2_id,
                                   port_3_id, n1_ctx)
        instance_ports = db_lib.get_instance_ports(tenant_1_id)
        expected_instance_ports = {
            device_1_id: {'vmId': device_1_id,
                          'baremetal_instance': False,
                          'ports': {port_1_id: {'portId': port_1_id,
                                                'deviceId': device_1_id,
                                                'hosts': set([host]),
                                                'networkId': network_1_id}}},
            device_2_id: {'vmId': device_2_id,
                          'baremetal_instance': False,
                          'ports': {port_2_id: {'portId': port_2_id,
                                                'deviceId': device_2_id,
                                                'hosts': set([host]),
                                                'networkId': network_2_id},
                                    port_3_id: {'portId': port_3_id,
                                                'deviceId': device_2_id,
                                                'hosts': set([host]),
                                                'networkId': network_1_id}}}}
        self.assertEqual(instance_ports, expected_instance_ports)

        # Add ports under another tenant, the first tenant's instances should
        # remain the same
        tenant_2_id = 't2'
        port_4_id = 'p4'
        device_3_id = 'vm3'
        p4_ctx = utils.create_port(tenant_2_id, network_1_id, device_3_id,
                                   port_4_id, n1_ctx)
        instance_ports = db_lib.get_instance_ports(tenant_1_id)
        expected_instance_ports = {
            device_1_id: {'vmId': device_1_id,
                          'baremetal_instance': False,
                          'ports': {port_1_id: {'portId': port_1_id,
                                                'deviceId': device_1_id,
                                                'hosts': set([host]),
                                                'networkId': network_1_id}}},
            device_2_id: {'vmId': device_2_id,
                          'baremetal_instance': False,
                          'ports': {port_2_id: {'portId': port_2_id,
                                                'deviceId': device_2_id,
                                                'hosts': set([host]),
                                                'networkId': network_2_id},
                                    port_3_id: {'portId': port_3_id,
                                                'deviceId': device_2_id,
                                                'hosts': set([host]),
                                                'networkId': network_1_id}}}}
        self.assertEqual(instance_ports, expected_instance_ports)
        instance_ports = db_lib.get_instance_ports(tenant_2_id)
        expected_instance_ports = {
            device_3_id: {'vmId': device_3_id,
                          'baremetal_instance': False,
                          'ports': {port_4_id: {'portId': port_4_id,
                                                'deviceId': device_3_id,
                                                'hosts': set([host]),
                                                'networkId': network_1_id}}}}
        self.assertEqual(instance_ports, expected_instance_ports)

        # Delete all ports and check that an empty set is once again returned
        utils.delete_port(p1_ctx, port_1_id)
        utils.delete_port(p2_ctx, port_2_id)
        utils.delete_port(p3_ctx, port_3_id)
        utils.delete_port(p4_ctx, port_4_id)
        self.assertEqual(db_lib.get_instance_ports(tenant_1_id), dict())
        self.assertEqual(db_lib.get_instance_ports(tenant_2_id), dict())

    def test_get_instance_ports_device_owner(self):
        # Create a port with an unsupported device owner, check that no ports
        # are returned
        tenant_id = 'tid'
        network_id = 'nid'
        device_id = 'vm'
        port_id = 'pid'
        n_ctx = utils.create_network(tenant_id, network_id, 11)
        utils.create_port(tenant_id, network_id, device_id,
                          port_id, n_ctx, device_owner='compute:probe')
        self.assertEqual(db_lib.get_instance_ports(tenant_id), dict())

    def test_get_instance_ports_dvr(self):
        # Create a port bound to 3 hosts, ensure that all 3 hosts are in
        # the dict returned
        tenant_id = 'tid'
        network_id = 'nid'
        device_id = 'rtr'
        port_id = 'pid'
        host_1 = 'h1'
        host_2 = 'h2'
        host_3 = 'h3'
        n_ctx = utils.create_network(tenant_id, network_id, 11)
        p_ctx = utils.create_port(tenant_id, network_id, device_id,
                                  port_id, n_ctx, host=host_1)
        utils.bind_port_to_host(port_id, host_2, n_ctx)
        utils.bind_port_to_host(port_id, host_3, n_ctx)
        instance_ports = db_lib.get_instance_ports(tenant_id)
        expected_instance_ports = {
            device_id: {'vmId': device_id,
                        'baremetal_instance': False,
                        'ports': {port_id: {'portId': port_id,
                                            'deviceId': device_id,
                                            'hosts': set([host_1, host_2,
                                                          host_3]),
                                            'networkId': network_id}}}}
        self.assertEqual(instance_ports, expected_instance_ports)

        # Unbind a host from the port, check that the host is not returned
        utils.unbind_port_from_host(port_id, host_1)
        instance_ports = db_lib.get_instance_ports(tenant_id)
        expected_instance_ports = {
            device_id: {'vmId': device_id,
                        'baremetal_instance': False,
                        'ports': {port_id: {'portId': port_id,
                                            'deviceId': device_id,
                                            'hosts': set([host_2, host_3]),
                                            'networkId': network_id}}}}
        self.assertEqual(instance_ports, expected_instance_ports)

        # Delete the port, check that an empty dict is returned
        utils.delete_port(p_ctx, port_id)
        self.assertEqual(db_lib.get_instance_ports(tenant_id), dict())

    def test_get_instance_ports_hpb(self):
        # Create network with multiple segments, bind a port to the network
        # and validate the dictionary
        host = 'ubuntu1'
        tenant_id = 'tid'
        network_id = 'nid'
        device_id = 'vm'
        port_id = 'pid'
        n_ctx = utils.create_network(tenant_id, network_id, 10001,
                                     network_type='vxlan',
                                     physical_network=None)
        dyn_seg = utils.create_dynamic_segment(network_id, 11, 'vlan',
                                               'default')
        p_ctx = utils.create_port(tenant_id, network_id, device_id,
                                  port_id, n_ctx, dynamic_segment=dyn_seg)
        instance_ports = db_lib.get_instance_ports(tenant_id)
        expected_instance_ports = {
            device_id: {'vmId': device_id,
                        'baremetal_instance': False,
                        'ports': {port_id: {'portId': port_id,
                                            'deviceId': device_id,
                                            'hosts': set([host]),
                                            'networkId': network_id}}}}
        self.assertEqual(instance_ports, expected_instance_ports)

        # Delete the port, check that an empty dict is returned
        utils.delete_port(p_ctx, port_id)
        self.assertEqual(db_lib.get_instance_ports(tenant_id), dict())

    def test_get_instance_ports_manage_fabric(self):
        # Create a network with only a fabric segment, check that no ports
        # are returned
        host = 'ubuntu1'
        tenant_id = 'tid'
        network_id = 'nid'
        device_id = 'vm'
        port_id = 'pid'
        n_ctx = utils.create_network(tenant_id, network_id, 10001,
                                     network_type='vxlan',
                                     physical_network=None)
        p_ctx = utils.create_port(tenant_id, network_id, device_id,
                                  port_id, n_ctx)
        instance_ports = db_lib.get_instance_ports(tenant_id,
                                                   manage_fabric=False)
        self.assertEqual(instance_ports, dict())

        # Add a VLAN segment, check that the port is now returned
        utils.delete_port(p_ctx, port_id)
        dyn_seg = utils.create_dynamic_segment(network_id, 11, 'vlan',
                                               'default')
        p_ctx = utils.create_port(tenant_id, network_id, device_id,
                                  port_id, n_ctx, dynamic_segment=dyn_seg)
        instance_ports = db_lib.get_instance_ports(tenant_id,
                                                   manage_fabric=False)
        expected_instance_ports = {
            device_id: {'vmId': device_id,
                        'baremetal_instance': False,
                        'ports': {port_id: {'portId': port_id,
                                            'deviceId': device_id,
                                            'hosts': set([host]),
                                            'networkId': network_id}}}}
        self.assertEqual(instance_ports, expected_instance_ports)

        # Delete the port, check that an empty dict is returned
        utils.delete_port(p_ctx, port_id)
        self.assertEqual(db_lib.get_instance_ports(tenant_id,
                                                   manage_fabric=False),
                         dict())

    def test_get_instance_ports_managed_physnets(self):
        # Bind a port to an unmananaged physnet, check that no ports are
        # returned
        physnet_1 = 'physnet1'
        physnet_2 = 'physnet2'
        managed_physnets = [physnet_2]
        tenant_id = 'tid'
        network_id = 'nid'
        host_1 = 'host1'
        device_1_id = 'vm1'
        port_1_id = 'p1'
        n_ctx = utils.create_network(tenant_id, network_id, 10001,
                                     network_type='vxlan',
                                     physical_network=None)
        dyn_seg_1 = utils.create_dynamic_segment(network_id, 11, 'vlan',
                                                 physnet_1)
        utils.create_port(tenant_id, network_id, device_1_id,
                          port_1_id, n_ctx, host=host_1,
                          dynamic_segment=dyn_seg_1)
        instance_ports = db_lib.get_instance_ports(
            tenant_id, manage_fabric=False, managed_physnets=managed_physnets)
        self.assertEqual(instance_ports, dict())

        # Bind a port to a managed physnet on the same network, check that
        # only the managed host is returned
        host_2 = 'host2'
        device_2_id = 'vm2'
        port_2_id = 'p2'
        dyn_seg_2 = utils.create_dynamic_segment(network_id, 21, 'vlan',
                                                 physnet_2)
        p2_ctx = utils.create_port(tenant_id, network_id, device_2_id,
                                   port_2_id, n_ctx, host=host_2,
                                   dynamic_segment=dyn_seg_2)
        instance_ports = db_lib.get_instance_ports(
            tenant_id, manage_fabric=True, managed_physnets=managed_physnets)
        expected_instance_ports = {
            device_2_id: {'vmId': device_2_id,
                          'baremetal_instance': False,
                          'ports': {port_2_id: {'portId': port_2_id,
                                                'deviceId': device_2_id,
                                                'hosts': set([host_2]),
                                                'networkId': network_id}}}}
        self.assertEqual(instance_ports, expected_instance_ports)

        # Delete the port, check that an empty dict is returned
        utils.delete_port(p2_ctx, port_2_id)
        self.assertEqual(db_lib.get_instance_ports(
            tenant_id, manage_fabric=False,
            managed_physnets=managed_physnets), dict())
