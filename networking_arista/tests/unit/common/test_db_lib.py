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

    '''def test_get_segments(self):
        utils.setup_scenario()
        db_segments = db_lib.get_segments.__func__().all()
        expected_segments = []
        self.assertEqual(db_segments, expected_segments)

    def test_get_dhcp_instances(self):
        utils.setup_scenario()
        db_dhcp_instances = db_lib.get_dhcp_instances.__func__().all()
        expected_dhcp_instances = []
        self.assertEqual(db_dhcp_instances, expected_dhcp_instances)

    def test_get_router_instances(self):
        utils.setup_scenario()
        db_router_instances = db_lib.get_router_instances.__func__().all()
        expected_router_instances = []
        self.assertEqual(db_router_instances, expected_router_instances)

    def test_get_vm_instances(self):
        utils.setup_scenario()
        db_vm_instances = db_lib.get_vm_instances.__func__().all()
        expected_vm_instances = []
        self.assertEqual(db_vm_instances, expected_vm_instances)

    def test_get_baremetal_instances(self):
        utils.setup_scenario()
        db_baremetal_instances = (
            db_lib.get_baremetal_instances.__func__().all())
        expected_baremetal_instances = []
        self.assertEqual(db_baremetal_instances, expected_baremetal_instances)

    def test_get_dhcp_ports(self):
        utils.setup_scenario()
        db_dhcp_ports = db_lib.get_dhcp_ports.__func__().all()
        expected_dhcp_ports = []
        self.assertEqual(db_dhcp_ports, expected_dhcp_ports)

    def test_get_router_ports(self):
        utils.setup_scenario()
        db_router_ports = db_lib.get_router_ports.__func__().all()
        expected_router_ports = []
        self.assertEqual(db_router_ports, expected_router_ports)

    def test_get_vm_ports(self):
        utils.setup_scenario()
        db_vm_ports = db_lib.get_vm_ports.__func__().all()
        expected_vm_ports = []
        self.assertEqual(db_vm_ports, expected_vm_ports)

    def test_get_baremetal_ports(self):
        utils.setup_scenario()
        db_baremetal_ports = db_lib.get_baremetal_ports.__func__().all()
        expected_baremetal_ports = []
        self.assertEqual(db_baremetal_ports, expected_baremetal_ports)

    def test_get_port_bindings(self):
        utils.setup_scenario()
        db_port_bindings = db_lib.get_port_bindings.__func__().all()
        expected_port_bindings = []
        self.assertEqual(db_port_bindings, expected_port_bindings)

    def test_get_port_bindings_managed_physnets(self):
        raise NotImplementedError'''
