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
        tenants = db_lib.get_tenants.__func__()
        self.assertEqual(tenants, [])

    def test_get_tenants_from_networks(self):
        tenant_1_id = 't1'
        tenant_2_id = 't2'
        utils.create_networks([{'id': 'n1',
                                'project_id': tenant_1_id},
                               {'id': 'n2',
                                'project_id': tenant_2_id}])
        tenants = db_lib.get_tenants.__func__()
        expected_tenants = [{'project_id': tenant_1_id},
                            {'project_id': tenant_2_id}]
        self.assertItemsEqual(tenants, expected_tenants)

    def test_get_tenants_with_shared_network_ports(self):
        tenant_1_id = 't1'
        tenant_2_id = 't2'
        utils.create_networks([{'id': 'n1',
                                'project_id': tenant_1_id}])
        utils.create_ports([{'admin_state_up': True,
                             'status': 'ACTIVE',
                             'device_id': 'vm1',
                             'device_owner': 'compute:None',
                             'tenant_id': tenant_2_id,
                             'id': 'p1',
                             'network_id': 'n1',
                             'mac_address': '00:00:00:00:00:01'}])
        tenants = db_lib.get_tenants.__func__()
        expected_tenants = [{'project_id': tenant_1_id},
                            {'project_id': tenant_2_id}]
        self.assertItemsEqual(tenants, expected_tenants)

    def test_get_tenants_uniqueness(self):
        tenant_1_id = 't1'
        tenant_2_id = 't2'
        utils.create_networks([{'id': 'n1',
                                'project_id': tenant_1_id},
                               {'id': 'n2',
                                'project_id': tenant_2_id}])
        utils.create_ports([{'admin_state_up': True,
                             'status': 'ACTIVE',
                             'device_id': 'vm1',
                             'device_owner': 'compute:None',
                             'tenant_id': tenant_1_id,
                             'id': 'p1',
                             'network_id': 'n1',
                             'mac_address': '00:00:00:00:00:01'},
                            {'admin_state_up': True,
                             'status': 'ACTIVE',
                             'device_id': 'vm2',
                             'device_owner': 'compute:None',
                             'tenant_id': tenant_2_id,
                             'id': 'p2',
                             'network_id': 'n2',
                             'mac_address': '00:00:00:00:00:02'}])
        tenants = db_lib.get_tenants.__func__()
        expected_tenants = [{'project_id': tenant_1_id},
                            {'project_id': tenant_2_id}]
        self.assertItemsEqual(tenants, expected_tenants)

    def test_get_tenants_port_network_union(self):
        tenant_1_id = 't1'
        tenant_2_id = 't2'
        tenant_3_id = 't3'
        tenant_4_id = 't4'
        utils.create_networks([{'id': 'n1',
                                'project_id': tenant_1_id},
                               {'id': 'n2',
                                'project_id': tenant_2_id}])
        utils.create_ports([{'admin_state_up': True,
                             'status': 'ACTIVE',
                             'device_id': 'vm1',
                             'device_owner': 'compute:None',
                             'tenant_id': tenant_3_id,
                             'id': 'p1',
                             'network_id': 'n1',
                             'mac_address': '00:00:00:00:00:01'},
                            {'admin_state_up': True,
                             'status': 'ACTIVE',
                             'device_id': 'vm2',
                             'device_owner': 'compute:None',
                             'tenant_id': tenant_4_id,
                             'id': 'p2',
                             'network_id': 'n2',
                             'mac_address': '00:00:00:00:00:02'}])

        tenants = db_lib.get_tenants.__func__()
        expected_tenants = [{'project_id': tenant_1_id},
                            {'project_id': tenant_2_id},
                            {'project_id': tenant_3_id},
                            {'project_id': tenant_4_id}]
        self.assertItemsEqual(tenants, expected_tenants)

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
        utils.create_port(tenant_1_id, network_id, 'vm1', port_1_id, n_ctx)
        self.assertTrue(db_lib.tenant_provisioned(tenant_1_id))
        self.assertFalse(db_lib.tenant_provisioned(tenant_2_id))
        utils.create_port(tenant_2_id, network_id, 'vm2', port_2_id, n_ctx)
        self.assertTrue(db_lib.tenant_provisioned(tenant_1_id))
        self.assertTrue(db_lib.tenant_provisioned(tenant_2_id))
        utils.delete_port(port_1_id)
        utils.delete_port(port_2_id)
        utils.delete_network(network_id)
        self.assertFalse(db_lib.tenant_provisioned(tenant_1_id))
        self.assertFalse(db_lib.tenant_provisioned(tenant_2_id))
