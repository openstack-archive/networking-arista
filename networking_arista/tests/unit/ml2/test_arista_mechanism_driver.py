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
from neutron_lib.api.definitions import portbindings
from neutron_lib.db import api as db_api
from neutron_lib.plugins.ml2 import api as driver_api
from oslo_config import cfg

from neutron.tests.unit import testlib_api

from networking_arista.common import db_lib
from networking_arista.ml2 import mechanism_arista
import networking_arista.tests.unit.ml2.utils as utils


def setup_valid_config():
    utils.setup_arista_wrapper_config(cfg)


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
        segment_id = 'segment_id_%s' % segmentation_id

        db_lib.remember_network_segment(tenant_id, network_id, segmentation_id,
                                        segment_id)
        net_provisioned = db_lib.is_network_provisioned(tenant_id,
                                                        network_id)
        self.assertTrue(net_provisioned, 'Network must be provisioned')

    def test_network_is_removed(self):
        tenant_id = 'test'
        network_id = '123'
        segment_id = 'segment_id_1'

        db_lib.remember_network_segment(tenant_id, network_id, '123',
                                        segment_id)
        db_lib.forget_network_segment(tenant_id, network_id)
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
        segment_id = 'segment_%s'
        nets = ['id%s' % n for n in range(expected_num_nets)]
        for net_id in nets:
            db_lib.remember_network_segment(tenant_id, net_id, 123,
                                            segment_id % net_id)

        num_nets_provisioned = db_lib.num_nets_provisioned(tenant_id)
        self.assertEqual(expected_num_nets, num_nets_provisioned,
                         'There should be %d nets, not %d' %
                         (expected_num_nets, num_nets_provisioned))

    def test_removes_all_networks(self):
        tenant_id = 'test'
        num_nets = 100
        old_nets = db_lib.num_nets_provisioned(tenant_id)
        nets = ['id_%s' % n for n in range(num_nets)]
        segment_id = 'segment_%s'
        for net_id in nets:
            db_lib.remember_network_segment(tenant_id, net_id, 123,
                                            segment_id % net_id)
        for net_id in nets:
            db_lib.forget_network_segment(tenant_id, net_id)

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
        segment_id1 = '11111-%s' % vlan_id
        segment_id2 = '11111-%s' % vlan2_id
        expected_eos_net_list = {network_id: {u'networkId': network_id,
                                              u'segmentationTypeId': vlan_id,
                                              u'tenantId': tenant,
                                              u'segmentId': segment_id1,
                                              u'segmentationType': segm_type},
                                 network2_id: {u'networkId': network2_id,
                                               u'tenantId': tenant,
                                               u'segmentId': segment_id2,
                                               u'segmentationTypeId': vlan2_id,
                                               u'segmentationType': segm_type}}

        db_lib.remember_network_segment(tenant,
                                        network_id, vlan_id, segment_id1)
        db_lib.remember_network_segment(tenant,
                                        network2_id, vlan2_id, segment_id2)

        net_list = db_lib.get_networks(tenant)
        self.assertEqual(net_list, expected_eos_net_list, ('%s != %s' %
                         (net_list, expected_eos_net_list)))


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
            port_id = '%s_%s' % (vm_id, 101)
            port_context = self._get_port_context(port_id,
                                                  tenant_id,
                                                  network_id,
                                                  vm_id,
                                                  network_context)
            self.drv.update_port_precommit(port_context)

        vm_list = db_lib.get_vms(tenant_id)
        provisioned_vms = len(vm_list)
        expected_vms = len(vms)
        self.assertEqual(expected_vms, provisioned_vms,
                         'There should be %d '
                         'hosts, not %d' % (expected_vms, provisioned_vms))

        # Now test the delete ports
        for vm_id in vms:
            port_id = '%s_%s' % (vm_id, 101)
            port_context = self._get_port_context(port_id,
                                                  tenant_id,
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

        # create a shared session
        session = db_api.get_writer_session()

        # Create some networks in neutron db
        n1_context = self._get_network_context('t1', 'n1', 10, session)
        ndb.create_network(n1_context, {'network': n1_context.current})
        n2_context = self._get_network_context('t2', 'n2', 20, session)
        ndb.create_network(n2_context, {'network': n2_context.current})
        n3_context = self._get_network_context('', 'ha-network', 100, session)
        ndb.create_network(n3_context, {'network': n3_context.current})

        # Objects were created in different sessions, but Neutron no longer
        # implicitly flushes subtransactions.
        session.flush()

        # Create some networks in Arista db
        db_lib.remember_network_segment('t1', 'n1', 10, 'segment_id_10')
        db_lib.remember_network_segment('t2', 'n2', 20, 'segment_id_20')
        db_lib.remember_network_segment('admin',
                                        'ha-network', 100, 'segment_id_100')
        db_lib.remember_network_segment('t3', 'n3', 30, 'segment_id_30')

        # Initialize the driver which should clean up the extra networks
        self.drv.initialize()

        worker = self.drv.get_workers()[0]

        with mock.patch.object(worker.sync_service, 'do_synchronize') as ds:
            worker.start()
            adb_networks = db_lib.get_networks(tenant_id='any')

            # 'n3' should now be deleted from the Arista DB
            self.assertEqual(
                set(('n1', 'n2', 'ha-network')),
                set(adb_networks.keys())
            )

            ds.assert_called_once_with()

    def _get_network_context(self, tenant_id, net_id, seg_id, session=None):
        network = {'id': net_id,
                   'tenant_id': tenant_id,
                   'name': net_id,
                   'admin_state_up': True,
                   'shared': False,
                   }
        network_segments = [{'segmentation_id': seg_id,
                             'id': 'segment_%s' % net_id,
                             'network_type': 'vlan'}]
        return FakeNetworkContext(network, network_segments, network, session)

    def _get_port_context(self, port_id, tenant_id, net_id, vm_id, network):
        port = {'device_id': vm_id,
                'device_owner': 'compute',
                'binding:host_id': 'ubuntu1',
                'binding:vnic_type': 'normal',
                'tenant_id': tenant_id,
                'id': port_id,
                'network_id': net_id,
                'name': '',
                'status': 'ACTIVE',
                }
        binding_levels = []
        for level, segment in enumerate(network.network_segments):
            binding_levels.append(FakePortBindingLevel(port['id'],
                                                       level,
                                                       'vendor-1',
                                                       segment['id']))
        return FakePortContext(port, port, network, port['status'],
                               binding_levels)


class FakeNetworkContext(object):
    """To generate network context for testing purposes only."""

    def __init__(self, network, segments=None, original_network=None,
                 session=None):
        self._network = network
        self._original_network = original_network
        self._segments = segments
        self.is_admin = False
        self.tenant_id = network['tenant_id']
        self.session = session or db_api.get_reader_session()

    @property
    def current(self):
        return self._network

    @property
    def original(self):
        return self._original_network

    @property
    def network_segments(self):
        return self._segments


class FakePluginContext(object):
    """Plugin context for testing purposes only."""

    def __init__(self, tenant_id):
        self.tenant_id = tenant_id
        self.session = mock.MagicMock()


class FakePortContext(object):
    """To generate port context for testing purposes only."""

    def __init__(self, port, original_port, network, status,
                 binding_levels):
        self._plugin_context = None
        self._port = port
        self._original_port = original_port
        self._network_context = network
        self._status = status
        self._binding_levels = binding_levels

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

    @property
    def status(self):
        return self._status

    @property
    def original_status(self):
        if self._original_port:
            return self._original_port['status']

    @property
    def binding_levels(self):
        if self._binding_levels:
            return [{
                driver_api.BOUND_DRIVER: level.driver,
                driver_api.BOUND_SEGMENT:
                    self._expand_segment(level.segment_id)
            } for level in self._binding_levels]

    @property
    def original_binding_levels(self):
        if self._original_binding_levels:
            return [{
                driver_api.BOUND_DRIVER: level.driver,
                driver_api.BOUND_SEGMENT: (
                    self._expand_segment(level.segment_id))
            } for level in self._original_binding_levels]

    @property
    def bottom_bound_segment(self):
        if self._binding_levels:
            return self._expand_segment(self._binding_levels[-1].segment_id)

    def _expand_segment(self, segment_id):
        for segment in self._network_context.network_segments:
            if segment[driver_api.ID] == segment_id:
                return segment


class FakePortBindingLevel(object):
    """Port binding object for testing purposes only."""

    def __init__(self, port_id, level, driver, segment_id):
        self.port_id = port_id
        self.level = level
        self.driver = driver
        self.segment_id = segment_id
