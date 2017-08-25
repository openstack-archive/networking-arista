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
from oslo_config import cfg

from neutron.tests.unit import testlib_api

from networking_arista.common import db_lib
from networking_arista.ml2 import mechanism_arista
from networking_arista.tests.unit import utils


def setup_valid_config():
    utils.setup_arista_wrapper_config(cfg)


class AristaProvisionedVlansStorageTestCase(testlib_api.SqlTestCase):
    """Test storing and retriving functionality of Arista mechanism driver.

    Tests all methods of this class by invoking them separately as well
    as a group.
    """

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

    def test_create_and_delete_ports(self):
        tenant_id = 'ten-1'
        network_id = 'net1-id'
        segmentation_id = 1001
        vms = ['vm1', 'vm2', 'vm3']

        network_context = utils.get_network_context(tenant_id,
                                                    network_id,
                                                    segmentation_id)
        self.drv.create_network_precommit(network_context)

        for vm_id in vms:
            port_id = '%s_%s' % (vm_id, 101)
            port_context = utils.get_port_context(tenant_id,
                                                  network_id,
                                                  vm_id,
                                                  network_context,
                                                  port_id=port_id)
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
            port_context = utils.get_port_context(tenant_id,
                                                  network_id,
                                                  vm_id,
                                                  network_context,
                                                  port_id=port_id)
            self.drv.delete_port_precommit(port_context)

        vm_list = db_lib.get_vms(tenant_id)
        provisioned_vms = len(vm_list)
        expected_vms = 0
        self.assertEqual(expected_vms, provisioned_vms,
                         'There should be %d '
                         'VMs, not %d' % (expected_vms, provisioned_vms))

    def test_cleanup_on_start(self):
        """Ensures that the driver cleans up the arista database on startup."""

        # Create some networks in neutron db
        utils.create_network('t1', 'n1', 10)
        utils.create_network('t2', 'n2', 20)
        utils.create_network('', 'ha-network', 100)

        db_lib.remember_vm('v1', 'h1', 'p1', 'n1', 't1')
        db_lib.remember_vm('v2', 'h2', 'p2', 'n2', 't1')
        db_lib.remember_vm('ha-instance', 'ha-host', 'ha-port',
                           'ha-network', 'admin')
        db_lib.remember_vm('v3', 'h3', 'p3', 'n3', 't3')

        # Initialize the driver which should clean up the extra networks
        self.drv.initialize()

        worker = self.drv.get_workers()[0]

        with mock.patch.object(worker.sync_service, 'do_synchronize') as ds:
            worker.start()
            adb_ports = db_lib.get_ports()

            # 'p3' should now be deleted from the Arista DB
            self.assertEqual(
                set(('p1', 'p2', 'ha-port')),
                set(adb_ports.keys())
            )

            ds.assert_called_once_with()
