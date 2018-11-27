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

import copy
import mock

from neutron.db import rbac_db_models as rbac_models
from neutron.tests import base
from neutron.tests.unit import testlib_api
from neutron_lib import constants as n_const
from neutron_lib.plugins import constants as plugin_constants
from neutron_lib.plugins import directory

from oslo_config import cfg
from oslo_utils import importutils

import networking_arista.ml2.arista_resources as resources
from networking_arista.tests.unit import utils


class TestAristaResourcesType(resources.AristaResourcesBase):

    f1 = mock.MagicMock()
    f1.return_value = 'data1Prime'

    formatter = [resources.AttributeFormatter('id', 'id'),
                 resources.AttributeFormatter('n_key1', 'c_key1', f1),
                 resources.AttributeFormatter('n_key2', 'c_key2')]


class AristaResourcesClassAttrTest(base.BaseTestCase):
    """Ensure arista resources have class attributes"""

    def test_attributes(self):
        whitelist = ['AristaResourcesBase',
                     'PortResourcesBase',
                     'AttributeFormatter']
        for cls in resources.__dict__.values():
            if (isinstance(cls, type) and
                    cls.__module__ == resources.__name__ and
                    cls.__name__ not in whitelist):
                self.assertIsNotNone(cls.formatter)
                self.assertIsNotNone(cls.id_key)
                self.assertIsNotNone(cls.endpoint)


class AristaResourcesBaseTest(base.BaseTestCase):
    """Test cases for resource manipulation"""

    def setUp(self):
        super(AristaResourcesBaseTest, self).setUp()
        self.rpc = mock.MagicMock()
        self.rpc.region = 'region'

    def test_clear_cvx_data(self):
        # Setup
        ar = resources.AristaResourcesBase(self.rpc)
        ar.cvx_ids = set([i for i in range(10)])
        # Check that clear_cvx_data restores cvx_ids to a NULL set
        ar.clear_cvx_data()
        self.assertEqual(ar.cvx_ids, set())

    def test_clear_neutron_data(self):
        # Setup
        ar = resources.AristaResourcesBase(self.rpc)
        ar.neutron_resources = {i: {'id': i} for i in range(10)}
        # Check that clear_neutron_data restores neutron resources to an
        # empty dict
        ar.clear_neutron_data()
        self.assertEqual(ar.neutron_resources, dict())

    def test_clear_all_data(self):
        # Setup
        ar = resources.AristaResourcesBase(self.rpc)
        ar.cvx_ids = set(i for i in range(10))
        ar.neutron_resources = {i: {'id': i} for i in range(10)}
        # Check that clear_all_data restores neutron resources to an
        # empty dict and cvx_ids to an empty set
        ar.clear_all_data()
        self.assertEqual(ar.neutron_resources, dict())
        self.assertEqual(ar.cvx_ids, set())

    def test_add_neutron_resource(self):
        # Setup
        ar = resources.AristaResourcesBase(self.rpc)
        # Check that the resource is added to neutron_resources
        ar._add_neutron_resource({'id': 1})
        self.assertEqual(ar.neutron_resources, {1: {'id': 1}})

    def test_force_resource_update(self):
        # Setup
        neutron_resources = {i: {'id': i} for i in range(10)}
        ar = resources.AristaResourcesBase(self.rpc)
        ar.cvx_data_stale = False
        ar.neutron_data_stale = False
        ar.cvx_ids = set(range(10))
        ar.neutron_resources = neutron_resources
        resource_to_update = 5
        ar.get_db_resources = mock.MagicMock()
        ar.get_db_resources.return_value = [{'id': resource_to_update}]
        # Ensure that calling force_resource_update would result in that
        # resource being resent to CVX (with any updated data)
        self.assertEqual(ar.resource_ids_to_create(), set())
        ar.force_resource_update(resource_to_update)
        self.assertEqual(ar.resource_ids_to_create(),
                         set([resource_to_update]))

    def test_delete_neutron_resource(self):
        # Setup
        neutron_resources = {i: {'id': i} for i in range(10)}
        ar = resources.AristaResourcesBase(self.rpc)
        ar.get_db_resources = mock.MagicMock()
        ar.get_db_resources.return_value = []
        ar.neutron_resources = copy.copy(neutron_resources)
        id_to_delete = 5
        del neutron_resources[id_to_delete]
        # Delete neutron resource and check that it's no longer in
        # neutron_resources
        ar._delete_neutron_resource(id_to_delete)
        self.assertEqual(ar.neutron_resources, neutron_resources)

    def test_get_endpoint(self):
        # Setup
        regionName = 'region'
        ar = resources.AristaResourcesBase(self.rpc)
        ar.endpoint = '%(region)s'
        self.assertEqual(ar.get_endpoint(), regionName)

    def test_get_resource_ids(self):
        ar = resources.AristaResourcesBase(self.rpc)
        self.assertEqual(ar.get_resource_ids({'id': 1}), set([1]))

    def test_get_cvx_ids(self):
        # Setup
        cvx_ids = range(10)
        ar = resources.AristaResourcesBase(self.rpc)
        ar.endpoint = 'region/%(region)s'
        self.rpc.send_api_request.return_value = [{'id': i} for i in cvx_ids]
        # Check that get_cvx_ids returns the expected value
        self.assertEqual(ar.get_cvx_ids(), set(cvx_ids))
        self.assertEqual(ar.cvx_ids, set(cvx_ids))
        # Check that a second call uses the cached value
        ar.get_cvx_ids()
        self.rpc.send_api_request.assert_called_once()

    def test_get_neutron_ids(self):
        # Setup
        neutron_ids = range(10)
        neutron_resources = [{'id': i} for i in neutron_ids]
        ar = resources.AristaResourcesBase(self.rpc)
        ar.get_db_resources = mock.MagicMock()
        ar.get_db_resources.return_value = neutron_resources
        # Check that get_neutron_resources returns the expected value
        self.assertEqual(ar.get_neutron_ids(), set(neutron_ids))
        # Check that a second call uses the cached value
        ar.get_neutron_ids()
        ar.get_db_resources.assert_called_once()

    def test_get_neutron_resources(self):
        # Setup
        neutron_ids = range(10)
        db_resources = [{'id': i} for i in neutron_ids]
        ar = resources.AristaResourcesBase(self.rpc)
        ar.get_db_resources = mock.MagicMock()
        ar.get_db_resources.return_value = db_resources
        neutron_resources = {i: {'id': i} for i in neutron_ids}
        # Check that get_neutron_resources returns the expected value
        self.assertEqual(ar.get_neutron_resources(), neutron_resources)
        self.assertEqual(ar.neutron_resources, neutron_resources)
        # Check that a second call uses the cached value
        ar.get_neutron_resources()
        ar.get_db_resources.assert_called_once()

    def test_resources_ids_to_delete(self):
        # Setup
        neutron_ids = set(range(7))
        cvx_ids = set(range(3, 10))
        ar = resources.AristaResourcesBase(self.rpc)
        ar.get_cvx_ids = mock.MagicMock()
        ar.get_cvx_ids.return_value = cvx_ids
        ar.get_neutron_ids = mock.MagicMock()
        ar.get_neutron_ids.return_value = neutron_ids
        # Check that the return is the list of ids in cvx but not neutron
        self.assertItemsEqual(ar.resource_ids_to_delete(),
                              cvx_ids - neutron_ids)

    def test_resource_ids_to_create(self):
        # Setup
        cvx_resource_ids = set(range(0, 20, 2))
        neutron_resource_ids = set(range(10))
        ar = resources.AristaResourcesBase(self.rpc)
        ar.cvx_data_stale = False
        ar.neutron_data_stale = False
        ar.cvx_ids = cvx_resource_ids
        ar.neutron_resources = {i: {'id': i} for i in neutron_resource_ids}
        # Ensure that resource ids to create returns the set of ids present in
        # neutron, but not cvx
        self.assertEqual(ar.resource_ids_to_create(), set(range(1, 10, 2)))

    def test_format_for_create(self):
        # Setup
        ar = TestAristaResourcesType(self.rpc)
        neutron_data = [{'id': 'id1',
                         'n_key1': 'data1',
                         'n_key2': 'data2'},
                        {'id': 'id2',
                         'n_key1': 'data1',
                         'n_key2': 'data2',
                         'extra_key': 'data'}]
        expected_cvx_data = [{'id1': {'id': 'id1',
                                      'c_key1': 'data1Prime',
                                      'c_key2': 'data2'}},
                             {'id2': {'id': 'id2',
                                      'c_key1': 'data1Prime',
                                      'c_key2': 'data2'}}]
        test_cases = [(neutron_data[i], expected_cvx_data[i])
                      for i in range(len(neutron_data))]

        # Check that data is correctly formatted for cvx
        for neutron_resource, expected_resource in test_cases:
            formatted_resource = ar.format_for_create(neutron_resource)
            self.assertEqual(formatted_resource, expected_resource)

        # Check that an exception is raised if neutron is missing data that CVX
        # requires
        neutron_data = [{'n_key1': 'data1'},
                        {'n_key1': 'data1',
                         'extra_key': 'data'}]
        for resource in neutron_data:
            self.assertRaises(KeyError, ar.format_for_create, resource)

    def test_format_for_delete(self):
        ar = resources.AristaResourcesBase(self.rpc)
        id_to_format = 1
        self.assertEqual(ar.format_for_delete(id_to_format),
                         {ar.id_key: id_to_format})

    def test_create_cvx_resources(self):
        # Setup
        neutron_ids = set(range(7))
        cvx_ids = set(range(3, 10))
        neutron_resources = [{'id': i} for i in neutron_ids]
        ar = resources.AristaResourcesBase(self.rpc)
        ar.get_db_resources = mock.MagicMock()
        ar.get_db_resources.return_value = neutron_resources
        ar.get_cvx_ids = mock.MagicMock()
        ar.get_cvx_ids.return_value = cvx_ids
        # Check that the return is the resources in neutron but not cvx
        self.assertEqual(ar.create_cvx_resources(),
                         list(neutron_resources[k] for k in
                              neutron_ids - cvx_ids))

    def test_delete_cvx_resources(self):
        # Setup
        neutron_ids = set(range(7))
        cvx_ids = set(range(3, 10))
        neutron_resources = [{'id': i} for i in neutron_ids]
        ar = resources.AristaResourcesBase(self.rpc)
        ar.get_db_resources = mock.MagicMock()
        ar.get_db_resources.return_value = neutron_resources
        ar.cvx_ids = cvx_ids.copy()
        # Check that the return is the list of ids in cvx but not neutron
        self.assertEqual(ar.delete_cvx_resources(),
                         [{'id': i} for i in (cvx_ids - neutron_ids)])


class AristaResourcesTestBase(testlib_api.SqlTestCase):

    def setUp(self):
        super(AristaResourcesTestBase, self).setUp()
        plugin_klass = importutils.import_class(
            "neutron.db.db_base_plugin_v2.NeutronDbPluginV2")
        directory.add_plugin(plugin_constants.CORE, plugin_klass())
        self.rpc = utils.MockCvx('region')

    def run_scenario(self, expect_created):
        utils.setup_scenario()
        # Create resource tests
        resources_created = self.ar.create_cvx_resources()
        self.assertItemsEqual(resources_created,
                              expect_created.values())
        self.ar.clear_cvx_data()

        # Ensure existing resources aren't created
        resources_created = self.ar.create_cvx_resources()
        self.assertEqual(resources_created, [])

        # Delete resource tests
        for resource_id_to_delete in expect_created.keys():
            expect_deleted = [self.ar.format_for_delete(resource_id_to_delete)]
            self.delete_helper(resource_id_to_delete)
            self.ar.clear_all_data()
            resources_deleted = self.ar.delete_cvx_resources()
            self.assertEqual(resources_deleted,
                             expect_deleted)

            # Ensure non-existent resources aren't deleted
            self.ar.clear_all_data()
            resources_deleted = self.ar.delete_cvx_resources()
            self.assertEqual(resources_deleted, [])

    def verify_format_for_create(self, test_cases):
        for neutron_resource, expected_resource in test_cases:
            formatted_resource = self.ar.format_for_create(neutron_resource)
            self.assertEqual(formatted_resource, expected_resource)

    def verify_format_for_delete(self, test_cases):
        for neutron_resource_id, expected_resource in test_cases:
            formatted_resource = self.ar.format_for_delete(neutron_resource_id)
            self.assertEqual(formatted_resource, expected_resource)


class AristaTenantTest(AristaResourcesTestBase):
    """Test cases for creation & deletion of arista tenants"""

    def setUp(self):
        super(AristaTenantTest, self).setUp()
        self.ar = resources.Tenants(self.rpc)

    def delete_helper(self, tenant_id):
        utils.delete_ports_for_tenant(tenant_id)
        utils.delete_segments_for_tenant(tenant_id)
        utils.delete_networks_for_tenant(tenant_id)

    def test_scenario_tenants(self):
        expect_created = {'t1': {'id': 't1'},
                          't2': {'id': 't2'}}
        self.run_scenario(expect_created)

    def test_format_tenants(self):
        # format_for_create test setup
        neutron_data = [{'project_id': '1'},
                        {'project_id': '2'}]
        expected_cvx_data = [{'1': {'id': '1'}},
                             {'2': {'id': '2'}}]
        test_cases = [(neutron_data[i], expected_cvx_data[i])
                      for i in range(len(neutron_data))]
        self.verify_format_for_create(test_cases)

    def test_format_tenants_for_delete(self):
        # format_for_delete test setup
        neutron_tenant_id = 't3'
        expected_tenant = {'id': 't3'}
        test_case = [(neutron_tenant_id, expected_tenant)]
        self.verify_format_for_delete(test_case)


class AristaNetworkTest(AristaResourcesTestBase):
    """Test cases for creation & deletion of arista networks"""

    def setUp(self):
        super(AristaNetworkTest, self).setUp()
        self.ar = resources.Networks(self.rpc)

    def delete_helper(self, network_id):
        utils.delete_ports_on_network(network_id)
        utils.delete_segments_for_network(network_id)
        utils.delete_network(network_id)

    def test_networks_scenario(self):
        expect_created = {'n1': {'id': 'n1',
                                 'tenantId': 't1',
                                 'name': 'regular',
                                 'shared': False},
                          'n2': {'id': 'n2',
                                 'tenantId': 't2',
                                 'name': 'hpb',
                                 'shared': False}}
        self.run_scenario(expect_created)

    def test_format_networks_for_create(self):
        # format_for_create test setup
        # Basic test case
        net1_neutron = {'id': 'n1',
                        'project_id': 't1',
                        'name': 'n1_name',
                        'admin_state_up': True,
                        'rbac_entries': []}
        net1_expected = {'n1': {'id': 'n1',
                                'tenantId': 't1',
                                'name': 'n1_name',
                                'shared': False}}
        # Shared network
        shared_rbac = rbac_models.NetworkRBAC(**{'id': 1,
                                                 'project_id': 't2',
                                                 'target_tenant': '*',
                                                 'action': 'access_as_shared'})
        net2_neutron = {'id': 'n2',
                        'project_id': 't2',
                        'name': '',
                        'admin_state_up': True,
                        'rbac_entries': [shared_rbac]}
        net2_expected = {'n2': {'id': 'n2',
                                'tenantId': 't2',
                                'name': '',
                                'shared': True}}
        # Other RBAC
        other_rbac1 = rbac_models.NetworkRBAC(**{'id': 2,
                                                 'project_id': 't3',
                                                 'target_tenant': 't1',
                                                 'action': 'access_as_shared'})
        other_rbac2 = rbac_models.NetworkRBAC(**{'id': 3,
                                                 'project_id': 't3',
                                                 'target_tenant': 't2',
                                                 'action': 'access_as_shared'})
        net3_neutron = {'id': 'n3',
                        'project_id': 't3',
                        'name': 'n3_name',
                        'admin_state_up': True,
                        'rbac_entries': [other_rbac1, other_rbac2]}
        net3_expected = {'n3': {'id': 'n3',
                                'tenantId': 't3',
                                'name': 'n3_name',
                                'shared': False}}
        test_cases = [(net1_neutron, net1_expected),
                      (net2_neutron, net2_expected),
                      (net3_neutron, net3_expected)]
        self.verify_format_for_create(test_cases)

    def test_format_networks_for_delete(self):
        # format_for_delete test setup
        neutron_net_id = 'n4'
        expected_net = {'id': 'n4'}
        test_case = [(neutron_net_id, expected_net)]
        self.verify_format_for_delete(test_case)


class AristaSegmentTest(AristaResourcesTestBase):
    """Test cases for creation & deletion of arista segments"""

    def setUp(self):
        super(AristaSegmentTest, self).setUp()
        self.ar = resources.Segments(self.rpc)

    def delete_helper(self, segment_id):
        utils.delete_segment(segment_id)

    def test_segments_scenario(self):
        expect_created = {'s1': {'id': 's1',
                                 'networkId': 'n1',
                                 'segmentType': 'static',
                                 'segmentationId': 11,
                                 'type': 'vlan'},
                          's2': {'id': 's2',
                                 'networkId': 'n2',
                                 'segmentType': 'static',
                                 'segmentationId': 20001,
                                 'type': 'vxlan'},
                          's3': {'id': 's3',
                                 'networkId': 'n2',
                                 'segmentType': 'dynamic',
                                 'segmentationId': 21,
                                 'type': 'vlan'},
                          's4': {'id': 's4',
                                 'networkId': 'n2',
                                 'segmentType': 'dynamic',
                                 'segmentationId': 31,
                                 'type': 'vlan'}}
        self.run_scenario(expect_created)

    def test_format_segments_for_create(self):
        seg1_neutron = {'id': 's1',
                        'network_id': 'nid',
                        'is_dynamic': False,
                        'segmentation_id': 10001,
                        'network_type': 'vxlan',
                        'physical_network': None}
        seg1_expected = {'s1': {'id': 's1',
                                'type': 'vxlan',
                                'segmentationId': 10001,
                                'networkId': 'nid',
                                'segmentType': 'static'}}
        seg2_neutron = {'id': 's2',
                        'network_id': 'nid',
                        'is_dynamic': True,
                        'segmentation_id': 11,
                        'network_type': 'vlan',
                        'physical_network': 'default'}
        seg2_expected = {'s2': {'id': 's2',
                                'type': 'vlan',
                                'segmentationId': 11,
                                'networkId': 'nid',
                                'segmentType': 'dynamic'}}
        test_cases = [(seg1_neutron, seg1_expected),
                      (seg2_neutron, seg2_expected)]
        self.verify_format_for_create(test_cases)

    def test_format_segments_for_delete(self):
        neutron_seg_id = 's3'
        expected_seg = {'id': 's3'}
        test_case = [(neutron_seg_id, expected_seg)]
        self.verify_format_for_delete(test_case)


class AristaInstancesTestBase(AristaResourcesTestBase):

    def delete_helper(self, instance_id):
        utils.delete_ports_for_instance(instance_id)


class AristaDhcpTest(AristaInstancesTestBase):
    """Test cases for creation & deletion of arista dhcp instances"""

    def setUp(self):
        super(AristaDhcpTest, self).setUp()
        self.ar = resources.Dhcps(self.rpc)

    def test_dhcps_scenario(self):
        id_base = n_const.DEVICE_OWNER_DHCP + 'normal'
        expect_created = {'%s1' % id_base:
                          {'tenantId': 't1',
                           'hostId': 'host1',
                           'id': '%s1' % id_base},
                          '%s2' % id_base:
                          {'tenantId': 't2',
                           'hostId': 'host2',
                           'id': '%s2' % id_base}}
        self.run_scenario(expect_created)

    def test_dhcps_managed_physnets_scenario(self):
        cfg.CONF.set_override('managed_physnets', 'switch1', 'ml2_arista')
        id_base = n_const.DEVICE_OWNER_DHCP + 'normal'
        expect_created = {'%s2' % id_base:
                          {'tenantId': 't2',
                           'hostId': 'host2',
                           'id': '%s2' % id_base}}
        self.run_scenario(expect_created)


class AristaRouterTest(AristaInstancesTestBase):
    """Test cases for creation & deletion of arista routers"""

    def setUp(self):
        super(AristaRouterTest, self).setUp()
        self.ar = resources.Routers(self.rpc)

    def test_routers_scenario(self):
        id_base = n_const.DEVICE_OWNER_DVR_INTERFACE + 'normal'
        expect_created = {'%s1' % id_base:
                          {'tenantId': 't1',
                           'hostId': 'distributed',
                           'id': '%s1' % id_base},
                          '%s2' % id_base:
                          {'tenantId': 't2',
                           'hostId': 'distributed',
                           'id': '%s2' % id_base}}
        self.run_scenario(expect_created)

    def test_routers_managed_physnets_scenario(self):
        cfg.CONF.set_override('managed_physnets', 'switch1', 'ml2_arista')
        id_base = n_const.DEVICE_OWNER_DVR_INTERFACE + 'normal'
        expect_created = {'%s2' % id_base:
                          {'tenantId': 't2',
                           'hostId': 'distributed',
                           'id': '%s2' % id_base}}
        self.run_scenario(expect_created)


class AristaVmTest(AristaInstancesTestBase):
    """Test cases for creation & deletion of arista vms"""

    def setUp(self):
        super(AristaVmTest, self).setUp()
        self.ar = resources.Vms(self.rpc)

    def test_vms_scenario(self):
        id_base = n_const.DEVICE_OWNER_COMPUTE_PREFIX + 'normal'
        expect_created = {'%s1' % id_base:
                          {'tenantId': 't1',
                           'hostId': 'host1',
                           'id': '%s1' % id_base},
                          '%s2' % id_base:
                          {'tenantId': 't2',
                           'hostId': 'host2',
                           'id': '%s2' % id_base}}
        self.run_scenario(expect_created)

    def test_vms_managed_physnets_scenario(self):
        cfg.CONF.set_override('managed_physnets', 'switch1', 'ml2_arista')
        id_base = n_const.DEVICE_OWNER_COMPUTE_PREFIX + 'normal'
        expect_created = {'%s2' % id_base:
                          {'tenantId': 't2',
                           'hostId': 'host2',
                           'id': '%s2' % id_base}}
        self.run_scenario(expect_created)


class AristaBaremetalTest(AristaInstancesTestBase):
    """Test cases for creation & deletion of arista baremetal instances"""

    def setUp(self):
        super(AristaBaremetalTest, self).setUp()
        self.ar = resources.Baremetals(self.rpc)

    def test_baremetals_scenario(self):
        id_base = n_const.DEVICE_OWNER_COMPUTE_PREFIX + 'baremetal'
        legacy_id_base = n_const.DEVICE_OWNER_BAREMETAL_PREFIX + 'baremetal'
        expect_created = {'%s1' % id_base:
                          {'tenantId': 't1',
                           'hostId': 'host1',
                           'id': '%s1' % id_base},
                          '%s2' % id_base:
                          {'tenantId': 't2',
                           'hostId': 'host2',
                           'id': '%s2' % id_base},
                          '%s1' % legacy_id_base:
                          {'tenantId': 't1',
                           'hostId': 'host1',
                           'id': '%s1' % legacy_id_base},
                          '%s2' % legacy_id_base:
                          {'tenantId': 't2',
                           'hostId': 'host2',
                           'id': '%s2' % legacy_id_base}}
        self.run_scenario(expect_created)

    def test_baremetals_managed_physnets_scenario(self):
        cfg.CONF.set_override('managed_physnets', 'switch1', 'ml2_arista')
        id_base = n_const.DEVICE_OWNER_COMPUTE_PREFIX + 'baremetal'
        legacy_id_base = n_const.DEVICE_OWNER_BAREMETAL_PREFIX + 'baremetal'
        expect_created = {'%s2' % id_base:
                          {'tenantId': 't2',
                           'hostId': 'host2',
                           'id': '%s2' % id_base},
                          '%s2' % legacy_id_base:
                          {'tenantId': 't2',
                           'hostId': 'host2',
                           'id': '%s2' % legacy_id_base}}
        self.run_scenario(expect_created)


class AristaPortTestBase(AristaResourcesTestBase):

    def delete_helper(self, port_id):
        utils.delete_port(port_id)


class AristaDhcpPortTest(AristaPortTestBase):
    """Test cases for creation & deletion of arista dhcp ports"""

    def setUp(self):
        super(AristaDhcpPortTest, self).setUp()
        self.ar = resources.DhcpPorts(self.rpc)

    def test_dhcp_ports_scenario(self):
        id_base = n_const.DEVICE_OWNER_DHCP + 'normal'
        expect_created = {'p1': {'id': 'p1',
                                 'portName': 'regular_port',
                                 'tenantId': 't1',
                                 'instanceType': 'dhcp',
                                 'instanceId': '%s1' % id_base,
                                 'networkId': 'n1',
                                 'vlanType': 'allowed'},
                          'p2': {'id': 'p2',
                                 'portName': 'hpb_port',
                                 'tenantId': 't2',
                                 'instanceType': 'dhcp',
                                 'instanceId': '%s2' % id_base,
                                 'networkId': 'n2',
                                 'vlanType': 'allowed'}}
        self.run_scenario(expect_created)

    def test_dhcp_ports_managed_physnets_scenario(self):
        cfg.CONF.set_override('managed_physnets', 'switch1', 'ml2_arista')
        id_base = n_const.DEVICE_OWNER_DHCP + 'normal'
        expect_created = {'p2': {'id': 'p2',
                                 'portName': 'hpb_port',
                                 'tenantId': 't2',
                                 'instanceType': 'dhcp',
                                 'instanceId': '%s2' % id_base,
                                 'networkId': 'n2',
                                 'vlanType': 'allowed'}}
        self.run_scenario(expect_created)


class AristaRouterPortTest(AristaPortTestBase):
    """Test cases for creation & deletion of arista router ports"""

    def setUp(self):
        super(AristaRouterPortTest, self).setUp()
        self.ar = resources.RouterPorts(self.rpc)

    def test_router_ports_scenario(self):
        id_base = n_const.DEVICE_OWNER_DVR_INTERFACE + 'normal'
        expect_created = {'p3': {'id': 'p3',
                                 'portName': 'regular_port',
                                 'tenantId': 't1',
                                 'instanceType': 'router',
                                 'instanceId': '%s1' % id_base,
                                 'networkId': 'n1',
                                 'vlanType': 'allowed'},
                          'p4': {'id': 'p4',
                                 'portName': 'hpb_port',
                                 'tenantId': 't2',
                                 'instanceType': 'router',
                                 'instanceId': '%s2' % id_base,
                                 'networkId': 'n2',
                                 'vlanType': 'allowed'}}
        self.run_scenario(expect_created)

    def test_router_ports_managed_physnets_scenario(self):
        cfg.CONF.set_override('managed_physnets', 'switch1', 'ml2_arista')
        id_base = n_const.DEVICE_OWNER_DVR_INTERFACE + 'normal'
        expect_created = {'p4': {'id': 'p4',
                                 'portName': 'hpb_port',
                                 'tenantId': 't2',
                                 'instanceType': 'router',
                                 'instanceId': '%s2' % id_base,
                                 'networkId': 'n2',
                                 'vlanType': 'allowed'}}
        self.run_scenario(expect_created)


class AristaVmPortTest(AristaPortTestBase):
    """Test cases for creation & deletion of arista vm ports"""

    def setUp(self):
        super(AristaVmPortTest, self).setUp()
        self.ar = resources.VmPorts(self.rpc)

    def test_vm_ports_scenario(self):
        id_base = n_const.DEVICE_OWNER_COMPUTE_PREFIX + 'normal'
        expect_created = {'p5': {'id': 'p5',
                                 'portName': 'regular_port',
                                 'tenantId': 't1',
                                 'instanceType': 'vm',
                                 'instanceId': '%s1' % id_base,
                                 'networkId': 'n1',
                                 'vlanType': 'allowed'},
                          'p6': {'id': 'p6',
                                 'portName': 'hpb_port',
                                 'tenantId': 't2',
                                 'instanceType': 'vm',
                                 'instanceId': '%s2' % id_base,
                                 'networkId': 'n2',
                                 'vlanType': 'allowed'},
                          'p7': {'id': 'p7',
                                 'portName': 'trunk_subport',
                                 'tenantId': 't1',
                                 'instanceType': 'vm',
                                 'instanceId': '%s1' % id_base,
                                 'networkId': 'n1',
                                 'vlanType': 'allowed'}}
        self.run_scenario(expect_created)

    def test_vm_ports_managed_physnets_scenario(self):
        cfg.CONF.set_override('managed_physnets', 'switch1', 'ml2_arista')
        id_base = n_const.DEVICE_OWNER_COMPUTE_PREFIX + 'normal'
        expect_created = {'p6': {'id': 'p6',
                                 'portName': 'hpb_port',
                                 'tenantId': 't2',
                                 'instanceType': 'vm',
                                 'instanceId': '%s2' % id_base,
                                 'networkId': 'n2',
                                 'vlanType': 'allowed'}}
        self.run_scenario(expect_created)


class AristaBaremetalPortTest(AristaPortTestBase):
    """Test cases for creation & deletion of arista baremetal ports"""

    def setUp(self):
        super(AristaBaremetalPortTest, self).setUp()
        self.ar = resources.BaremetalPorts(self.rpc)

    def test_baremetal_ports_scenario(self):
        id_base = n_const.DEVICE_OWNER_COMPUTE_PREFIX + 'baremetal'
        legacy_id_base = n_const.DEVICE_OWNER_BAREMETAL_PREFIX + 'baremetal'
        expect_created = {'p8': {'id': 'p8',
                                 'portName': 'regular_port',
                                 'tenantId': 't1',
                                 'instanceType': 'baremetal',
                                 'instanceId': '%s1' % id_base,
                                 'networkId': 'n1',
                                 'vlanType': 'native'},
                          'p9': {'id': 'p9',
                                 'portName': 'hpb_port',
                                 'tenantId': 't2',
                                 'instanceType': 'baremetal',
                                 'instanceId': '%s2' % id_base,
                                 'networkId': 'n2',
                                 'vlanType': 'native'},
                          'p10': {'id': 'p10',
                                  'portName': 'trunk_subport',
                                  'tenantId': 't1',
                                  'instanceType': 'baremetal',
                                  'instanceId': '%s1' % id_base,
                                  'networkId': 'n1',
                                  'vlanType': 'allowed'},
                          'p11': {'id': 'p11',
                                  'portName': 'regular_port',
                                  'tenantId': 't1',
                                  'instanceType': 'baremetal',
                                  'instanceId': '%s1' % legacy_id_base,
                                  'networkId': 'n1',
                                  'vlanType': 'native'},
                          'p12': {'id': 'p12',
                                  'portName': 'hpb_port',
                                  'tenantId': 't2',
                                  'instanceType': 'baremetal',
                                  'instanceId': '%s2' % legacy_id_base,
                                  'networkId': 'n2',
                                  'vlanType': 'native'}}
        self.run_scenario(expect_created)

    def test_baremetal_ports_managed_physnets_scenario(self):
        cfg.CONF.set_override('managed_physnets', 'switch1', 'ml2_arista')
        id_base = n_const.DEVICE_OWNER_COMPUTE_PREFIX + 'baremetal'
        legacy_id_base = n_const.DEVICE_OWNER_BAREMETAL_PREFIX + 'baremetal'
        expect_created = {'p9': {'id': 'p9',
                                 'portName': 'hpb_port',
                                 'tenantId': 't2',
                                 'instanceType': 'baremetal',
                                 'instanceId': '%s2' % id_base,
                                 'networkId': 'n2',
                                 'vlanType': 'native'},
                          'p12': {'id': 'p12',
                                  'portName': 'hpb_port',
                                  'tenantId': 't2',
                                  'instanceType': 'baremetal',
                                  'instanceId': '%s2' % legacy_id_base,
                                  'networkId': 'n2',
                                  'vlanType': 'native'}}
        self.run_scenario(expect_created)


class AristaPortBindingTest(AristaResourcesTestBase):
    """Test cases for creation & deletion of arista port bindings"""

    def setUp(self):
        super(AristaPortBindingTest, self).setUp()
        self.ar = resources.PortBindings(self.rpc)

    def delete_helper(self, binding_key):
        if type(binding_key[1]) == tuple:
            utils.remove_switch_binding(binding_key[0],
                                        *binding_key[1])
        else:
            utils.delete_port_binding(*binding_key)

    def test_port_binding_scenario(self):
        expect_created = {
            # DHCP ports
            ('p1', 'host1'):
            {'portId': 'p1',
             'hostBinding': [{'host': 'host1',
                              'segment': [{'id': 's1'}]}],
             'switchBinding': []},
            ('p2', 'host2'):
            {'portId': 'p2',
             'hostBinding': [{'host': 'host2',
                              'segment': [{'id': 's2'},
                                          {'id': 's3'}]}],
             'switchBinding': []},
            # DVR ports
            ('p3', 'host1'):
            {'portId': 'p3',
             'hostBinding': [{'host': 'host1',
                              'segment': [{'id': 's1'}]}],
             'switchBinding': []},
            ('p3', 'host2'):
            {'portId': 'p3',
             'hostBinding': [{'host': 'host2',
                              'segment': [{'id': 's1'}]}],
             'switchBinding': []},
            ('p4', 'host1'):
            {'portId': 'p4',
             'hostBinding': [{'host': 'host1',
                              'segment': [{'id': 's2'},
                                          {'id': 's3'}]}],
             'switchBinding': []},
            ('p4', 'host2'):
            {'portId': 'p4',
             'hostBinding': [{'host': 'host2',
                              'segment': [{'id': 's2'},
                                          {'id': 's4'}]}],
             'switchBinding': []},
            # VM ports
            ('p5', 'host1'):
            {'portId': 'p5',
             'hostBinding': [{'host': 'host1',
                              'segment': [{'id': 's1'}]}],
             'switchBinding': []},
            ('p6', 'host2'):
            {'portId': 'p6',
             'hostBinding': [{'host': 'host2',
                              'segment': [{'id': 's2'},
                                          {'id': 's3'}]}],
             'switchBinding': []},
            ('p7', 'host1'):
            {'portId': 'p7',
             'hostBinding': [{'host': 'host1',
                              'segment': [{'id': 's1'}]}],
             'switchBinding': []},
            # Baremetal ports
            ('p8', ('00:11:22:33:44:55', 'Ethernet1')):
            {'portId': 'p8',
             'hostBinding': [],
             'switchBinding': [{'host': 'host1',
                                'interface': 'Ethernet1',
                                'switch': '00:11:22:33:44:55',
                                'segment': [{'id': 's1'}]}]},
            ('p8', ('00:11:22:33:44:55', 'Ethernet2')):
            {'portId': 'p8',
             'hostBinding': [],
             'switchBinding': [{'host': 'host1',
                                'interface': 'Ethernet2',
                                'segment': [{'id': 's1'}],
                                'switch': '00:11:22:33:44:55'}]},
            ('p8', ('55:44:33:22:11:00', 'Ethernet1/1')):
            {'portId': 'p8',
             'hostBinding': [],
             'switchBinding': [{'host': 'host1',
                                'interface': 'Ethernet1/1',
                                'segment': [{'id': 's1'}],
                                'switch': '55:44:33:22:11:00'}]},
            ('p8', ('55:44:33:22:11:00', 'Ethernet1/2')):
            {'portId': 'p8',
             'hostBinding': [],
             'switchBinding': [{'host': 'host1',
                                'interface': 'Ethernet1/2',
                                'segment': [{'id': 's1'}],
                                'switch': '55:44:33:22:11:00'}]},
            ('p9', ('00:11:22:33:44:55', 'Ethernet1')):
            {'portId': 'p9',
             'hostBinding': [],
             'switchBinding': [{'host': 'host2',
                                'interface': 'Ethernet1',
                                'switch': '00:11:22:33:44:55',
                                'segment': [{'id': 's2'}, {'id': 's3'}]}]},
            ('p9', ('00:11:22:33:44:55', 'Ethernet2')):
            {'portId': 'p9',
             'hostBinding': [],
             'switchBinding': [{'host': 'host2',
                                'interface': 'Ethernet2',
                                'segment': [{'id': 's2'}, {'id': 's3'}],
                                'switch': '00:11:22:33:44:55'}]},
            ('p9', ('55:44:33:22:11:00', 'Ethernet1/1')):
            {'portId': 'p9',
             'hostBinding': [],
             'switchBinding': [{'host': 'host2',
                                'interface': 'Ethernet1/1',
                                'segment': [{'id': 's2'}, {'id': 's3'}],
                                'switch': '55:44:33:22:11:00'}]},
            ('p9', ('55:44:33:22:11:00', 'Ethernet1/2')):
            {'portId': 'p9',
             'hostBinding': [],
             'switchBinding': [{'host': 'host2',
                                'interface': 'Ethernet1/2',
                                'segment': [{'id': 's2'}, {'id': 's3'}],
                                'switch': '55:44:33:22:11:00'}]},
            ('p10', ('00:11:22:33:44:55', 'Ethernet1')):
            {'portId': 'p10',
             'hostBinding': [],
             'switchBinding': [{'host': 'host1',
                                'interface': 'Ethernet1',
                                'switch': '00:11:22:33:44:55',
                                'segment': [{'id': 's1'}]}]},
            ('p10', ('00:11:22:33:44:55', 'Ethernet2')):
            {'portId': 'p10',
             'hostBinding': [],
             'switchBinding': [{'host': 'host1',
                                'interface': 'Ethernet2',
                                'segment': [{'id': 's1'}],
                                'switch': '00:11:22:33:44:55'}]},
            ('p10', ('55:44:33:22:11:00', 'Ethernet1/1')):
            {'portId': 'p10',
             'hostBinding': [],
             'switchBinding': [{'host': 'host1',
                                'interface': 'Ethernet1/1',
                                'segment': [{'id': 's1'}],
                                'switch': '55:44:33:22:11:00'}]},
            ('p10', ('55:44:33:22:11:00', 'Ethernet1/2')):
            {'portId': 'p10',
             'hostBinding': [],
             'switchBinding': [{'host': 'host1',
                                'interface': 'Ethernet1/2',
                                'segment': [{'id': 's1'}],
                                'switch': '55:44:33:22:11:00'}]},
            # Legacy baremetal ports
            ('p11', ('00:11:22:33:44:55', 'Ethernet1')):
            {'portId': 'p11',
             'hostBinding': [],
             'switchBinding': [{'host': 'host1',
                                'interface': 'Ethernet1',
                                'switch': '00:11:22:33:44:55',
                                'segment': [{'id': 's1'}]}]},
            ('p11', ('00:11:22:33:44:55', 'Ethernet2')):
            {'portId': 'p11',
             'hostBinding': [],
             'switchBinding': [{'host': 'host1',
                                'interface': 'Ethernet2',
                                'segment': [{'id': 's1'}],
                                'switch': '00:11:22:33:44:55'}]},
            ('p11', ('55:44:33:22:11:00', 'Ethernet1/1')):
            {'portId': 'p11',
             'hostBinding': [],
             'switchBinding': [{'host': 'host1',
                                'interface': 'Ethernet1/1',
                                'segment': [{'id': 's1'}],
                                'switch': '55:44:33:22:11:00'}]},
            ('p11', ('55:44:33:22:11:00', 'Ethernet1/2')):
            {'portId': 'p11',
             'hostBinding': [],
             'switchBinding': [{'host': 'host1',
                                'interface': 'Ethernet1/2',
                                'segment': [{'id': 's1'}],
                                'switch': '55:44:33:22:11:00'}]},
            ('p12', ('00:11:22:33:44:55', 'Ethernet1')):
            {'portId': 'p12',
             'hostBinding': [],
             'switchBinding': [{'host': 'host2',
                                'interface': 'Ethernet1',
                                'switch': '00:11:22:33:44:55',
                                'segment': [{'id': 's2'}, {'id': 's3'}]}]},
            ('p12', ('00:11:22:33:44:55', 'Ethernet2')):
            {'portId': 'p12',
             'hostBinding': [],
             'switchBinding': [{'host': 'host2',
                                'interface': 'Ethernet2',
                                'segment': [{'id': 's2'}, {'id': 's3'}],
                                'switch': '00:11:22:33:44:55'}]},
            ('p12', ('55:44:33:22:11:00', 'Ethernet1/1')):
            {'portId': 'p12',
             'hostBinding': [],
             'switchBinding': [{'host': 'host2',
                                'interface': 'Ethernet1/1',
                                'segment': [{'id': 's2'}, {'id': 's3'}],
                                'switch': '55:44:33:22:11:00'}]},
            ('p12', ('55:44:33:22:11:00', 'Ethernet1/2')):
            {'portId': 'p12',
             'hostBinding': [],
             'switchBinding': [{'host': 'host2',
                                'interface': 'Ethernet1/2',
                                'segment': [{'id': 's2'}, {'id': 's3'}],
                                'switch': '55:44:33:22:11:00'}]}}
        self.run_scenario(expect_created)

    def test_port_binding_managed_physnets_scenario(self):
        cfg.CONF.set_override('managed_physnets', 'switch1', 'ml2_arista')
        expect_created = {
            # DHCP ports
            ('p2', 'host2'):
            {'portId': 'p2',
             'hostBinding': [{'host': 'host2',
                              'segment': [{'id': 's2'},
                                          {'id': 's3'}]}],
             'switchBinding': []},
            # DVR ports
            ('p4', 'host1'):
            {'portId': 'p4',
             'hostBinding': [{'host': 'host1',
                              'segment': [{'id': 's2'},
                                          {'id': 's3'}]}],
             'switchBinding': []},
            # VM ports
            ('p6', 'host2'):
            {'portId': 'p6',
             'hostBinding': [{'host': 'host2',
                              'segment': [{'id': 's2'},
                                          {'id': 's3'}]}],
             'switchBinding': []},
            # Baremetal ports
            ('p9', ('00:11:22:33:44:55', 'Ethernet1')):
            {'portId': 'p9',
             'hostBinding': [],
             'switchBinding': [{'host': 'host2',
                                'interface': 'Ethernet1',
                                'switch': '00:11:22:33:44:55',
                                'segment': [{'id': 's2'}, {'id': 's3'}]}]},
            ('p9', ('00:11:22:33:44:55', 'Ethernet2')):
            {'portId': 'p9',
             'hostBinding': [],
             'switchBinding': [{'host': 'host2',
                                'interface': 'Ethernet2',
                                'segment': [{'id': 's2'}, {'id': 's3'}],
                                'switch': '00:11:22:33:44:55'}]},
            ('p9', ('55:44:33:22:11:00', 'Ethernet1/1')):
            {'portId': 'p9',
             'hostBinding': [],
             'switchBinding': [{'host': 'host2',
                                'interface': 'Ethernet1/1',
                                'segment': [{'id': 's2'}, {'id': 's3'}],
                                'switch': '55:44:33:22:11:00'}]},
            ('p9', ('55:44:33:22:11:00', 'Ethernet1/2')):
            {'portId': 'p9',
             'hostBinding': [],
             'switchBinding': [{'host': 'host2',
                                'interface': 'Ethernet1/2',
                                'segment': [{'id': 's2'}, {'id': 's3'}],
                                'switch': '55:44:33:22:11:00'}]},
            # Legacy baremetal ports
            ('p12', ('00:11:22:33:44:55', 'Ethernet1')):
            {'portId': 'p12',
             'hostBinding': [],
             'switchBinding': [{'host': 'host2',
                                'interface': 'Ethernet1',
                                'switch': '00:11:22:33:44:55',
                                'segment': [{'id': 's2'}, {'id': 's3'}]}]},
            ('p12', ('00:11:22:33:44:55', 'Ethernet2')):
            {'portId': 'p12',
             'hostBinding': [],
             'switchBinding': [{'host': 'host2',
                                'interface': 'Ethernet2',
                                'segment': [{'id': 's2'}, {'id': 's3'}],
                                'switch': '00:11:22:33:44:55'}]},
            ('p12', ('55:44:33:22:11:00', 'Ethernet1/1')):
            {'portId': 'p12',
             'hostBinding': [],
             'switchBinding': [{'host': 'host2',
                                'interface': 'Ethernet1/1',
                                'segment': [{'id': 's2'}, {'id': 's3'}],
                                'switch': '55:44:33:22:11:00'}]},
            ('p12', ('55:44:33:22:11:00', 'Ethernet1/2')):
            {'portId': 'p12',
             'hostBinding': [],
             'switchBinding': [{'host': 'host2',
                                'interface': 'Ethernet1/2',
                                'segment': [{'id': 's2'}, {'id': 's3'}],
                                'switch': '55:44:33:22:11:00'}]}}
        self.run_scenario(expect_created)
