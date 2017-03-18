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

from neutron.common import constants as neutron_const
from neutron.extensions import portbindings
from neutron.plugins.ml2 import driver_api as api
from neutron.tests.unit import testlib_api

from networking_arista.ml2 import mechanism_arista

INTERNAL_TENANT_ID = 'INTERNAL-TENANT-ID'


class AristaDriverTestCase(testlib_api.SqlTestCase):
    """Main test cases for Arista Mechanism driver.

    Tests all mechanism driver APIs supported by Arista Driver. It invokes
    all the APIs as they would be invoked in real world scenarios and
    verifies the functionality.
    """
    def setUp(self):
        super(AristaDriverTestCase, self).setUp()
        self.fake_rpc = mock.MagicMock()
        mechanism_arista.db_lib = self.fake_rpc
        self.drv = mechanism_arista.AristaDriver(self.fake_rpc)
        self.drv.ndb = mock.MagicMock()

    def tearDown(self):
        super(AristaDriverTestCase, self).tearDown()
        self.drv.stop_synchronization_thread()

    def test_create_network_precommit(self):
        tenant_id = 'ten-1'
        network_id = 'net1-id'
        segmentation_id = 1001

        self.drv.rpc.hpb_supported.return_value = True
        network_context = self._get_network_context(tenant_id,
                                                    network_id,
                                                    segmentation_id,
                                                    False)
        self.drv.create_network_precommit(network_context)
        segment_id = network_context.network_segments[0]['id']

        expected_calls = [
            mock.call.hpb_supported(),
            mock.call.remember_tenant(tenant_id),
            mock.call.remember_network_segment(tenant_id,
                                               network_id,
                                               segmentation_id,
                                               segment_id)
        ]

        mechanism_arista.db_lib.assert_has_calls(expected_calls)

        # If there is no tenant id associated with the network, then the
        # network should be created under the tenant id in the context.
        tenant_id = 'ten-2'
        network_id = 'net2-id'
        segmentation_id = 1002

        network_context = self._get_network_context(tenant_id,
                                                    network_id,
                                                    segmentation_id,
                                                    False)
        network_context.current['tenant_id'] = ''
        self.drv.create_network_precommit(network_context)
        segment_id = network_context.network_segments[0]['id']

        expected_calls += [
            mock.call.hpb_supported(),
            mock.call.remember_tenant(INTERNAL_TENANT_ID),
            mock.call.remember_network_segment(INTERNAL_TENANT_ID,
                                               network_id,
                                               segmentation_id,
                                               segment_id)
        ]

        mechanism_arista.db_lib.assert_has_calls(expected_calls)

    def test_create_network_postcommit(self):
        tenant_id = 'ten-1'
        network_id = 'net1-id'
        segmentation_id = 1001

        network_context = self._get_network_context(tenant_id,
                                                    network_id,
                                                    segmentation_id,
                                                    False)
        mechanism_arista.db_lib.is_network_provisioned.return_value = True
        network = network_context.current
        segments = network_context.network_segments
        net_dict = {
            'network_id': network['id'],
            'segments': segments,
            'network_name': network['name'],
            'shared': network['shared']}

        self.drv.create_network_postcommit(network_context)

        expected_calls = [
            mock.call.is_network_provisioned(tenant_id, network_id),
            mock.call.create_network(tenant_id, net_dict),
        ]

        mechanism_arista.db_lib.assert_has_calls(expected_calls)

        # If there is no tenant id associated with the network, then the
        # network should be created under the tenant id in the context.
        tenant_id = 'ten-2'
        network_id = 'net2-id'
        segmentation_id = 1002

        network_context = self._get_network_context(tenant_id,
                                                    network_id,
                                                    segmentation_id,
                                                    False)
        network_context.current['tenant_id'] = ''
        mechanism_arista.db_lib.is_network_provisioned.return_value = True
        network = network_context.current
        segments = network_context.network_segments
        net_dict = {
            'network_id': network['id'],
            'segments': segments,
            'network_name': network['name'],
            'shared': network['shared']}

        self.drv.create_network_postcommit(network_context)

        expected_calls += [
            mock.call.is_network_provisioned(INTERNAL_TENANT_ID, network_id),
            mock.call.create_network(INTERNAL_TENANT_ID, net_dict),
        ]

        mechanism_arista.db_lib.assert_has_calls(expected_calls)

    def test_delete_network_precommit(self):
        tenant_id = 'ten-1'
        network_id = 'net1-id'
        segmentation_id = 1001

        network_context = self._get_network_context(tenant_id,
                                                    network_id,
                                                    segmentation_id,
                                                    False)
        mechanism_arista.db_lib.is_network_provisioned.return_value = True
        mechanism_arista.db_lib.num_nets_provisioned.return_value = 0
        mechanism_arista.db_lib.num_vms_provisioned.return_value = 0
        mechanism_arista.db_lib.are_ports_attached_to_network.return_value = (
            False)
        self.drv.delete_network_precommit(network_context)

        expected_calls = [
            mock.call.is_network_provisioned(tenant_id, network_id),
            mock.call.are_ports_attached_to_network(network_id),
            mock.call.forget_network_segment(tenant_id, network_id),
        ]

        mechanism_arista.db_lib.assert_has_calls(expected_calls)

        # If there is no tenant id associated with the network, then the
        # network should be created under the tenant id in the context.
        tenant_id = 'ten-2'
        network_id = 'net2-id'
        segmentation_id = 1002

        network_context = self._get_network_context(tenant_id,
                                                    network_id,
                                                    segmentation_id,
                                                    False)
        network_context.current['tenant_id'] = ''
        mechanism_arista.db_lib.is_network_provisioned.return_value = True
        mechanism_arista.db_lib.num_nets_provisioned.return_value = 0
        mechanism_arista.db_lib.num_vms_provisioned.return_value = 0
        mechanism_arista.db_lib.are_ports_attached_to_network.return_value = (
            False)
        self.drv.delete_network_precommit(network_context)

        expected_calls += [
            mock.call.is_network_provisioned(INTERNAL_TENANT_ID, network_id),
            mock.call.are_ports_attached_to_network(network_id),
            mock.call.forget_network_segment(INTERNAL_TENANT_ID, network_id),
        ]

        mechanism_arista.db_lib.assert_has_calls(expected_calls)

    def test_delete_network_precommit_with_ports(self):
        tenant_id = 'ten-1'
        network_id = 'net1-id'
        segmentation_id = 1001

        network_context = self._get_network_context(tenant_id,
                                                    network_id,
                                                    segmentation_id,
                                                    False)
        mechanism_arista.db_lib.is_network_provisioned.return_value = True
        mechanism_arista.db_lib.num_nets_provisioned.return_value = 0
        mechanism_arista.db_lib.num_vms_provisioned.return_value = 0
        mechanism_arista.db_lib.are_ports_attached_to_network.return_value = (
            True)
        try:
            self.drv.delete_network_precommit(network_context)
        except Exception:
            # exception is expeted in this case - as network is not
            # deleted in this case and exception is raised
            pass

        expected_calls = [
            mock.call.is_network_provisioned(tenant_id, network_id),
            mock.call.are_ports_attached_to_network(network_id),
        ]

        mechanism_arista.db_lib.assert_has_calls(expected_calls)

    def test_delete_network_postcommit(self):
        tenant_id = 'ten-1'
        network_id = 'net1-id'
        segmentation_id = 1001

        self.drv.rpc.hpb_supported.return_value = True
        network_context = self._get_network_context(tenant_id,
                                                    network_id,
                                                    segmentation_id,
                                                    False)

        mechanism_arista.db_lib.num_nets_provisioned.return_value = 0
        mechanism_arista.db_lib.num_vms_provisioned.return_value = 0
        self.drv.delete_network_postcommit(network_context)
        expected_calls = [
            mock.call.hpb_supported(),
            mock.call.delete_network(tenant_id, network_id,
                                     network_context.network_segments),
            mock.call.num_nets_provisioned(tenant_id),
            mock.call.num_vms_provisioned(tenant_id),
            mock.call.forget_tenant(tenant_id),
            mock.call.delete_tenant(tenant_id),
        ]

        mechanism_arista.db_lib.assert_has_calls(expected_calls)

        # If there is no tenant id associated with the network, then the
        # network should be created under the tenant id in the context.
        tenant_id = 'ten-2'
        network_id = 'net2-id'
        segmentation_id = 1002

        network_context = self._get_network_context(tenant_id,
                                                    network_id,
                                                    segmentation_id,
                                                    False)
        network_context.current['tenant_id'] = ''

        self.drv.delete_network_postcommit(network_context)
        expected_calls += [
            mock.call.hpb_supported(),
            mock.call.delete_network(INTERNAL_TENANT_ID, network_id,
                                     network_context.network_segments),
            mock.call.num_nets_provisioned(INTERNAL_TENANT_ID),
            mock.call.num_vms_provisioned(INTERNAL_TENANT_ID),
            mock.call.forget_tenant(INTERNAL_TENANT_ID),
            mock.call.delete_tenant(INTERNAL_TENANT_ID),
        ]

        mechanism_arista.db_lib.assert_has_calls(expected_calls)

    def _test_create_port_precommit(self):
        tenant_id = 'ten-1'
        network_id = 'net1-id'
        segmentation_id = 1001
        vm_id = 'vm1'

        network_context = self._get_network_context(tenant_id,
                                                    network_id,
                                                    segmentation_id,
                                                    False)

        port_context = self._get_port_context(tenant_id,
                                              network_id,
                                              vm_id,
                                              network_context)
        mechanism_arista.db_lib.is_network_provisioned.return_value = True

        network = {'tenant_id': tenant_id}
        self.drv.ndb.get_network_from_net_id.return_value = [network]

        host_id = port_context.current['binding:host_id']
        port_id = port_context.current['id']
        self.drv.create_port_precommit(port_context)

        expected_calls = [
            mock.call.is_network_provisioned(tenant_id, network_id, None),
            mock.call.remember_tenant(tenant_id),
            mock.call.remember_vm(vm_id, host_id, port_id,
                                  network_id, tenant_id)
        ]

        mechanism_arista.db_lib.assert_has_calls(expected_calls)

        # If there is no tenant id associated with the network, then the
        # network should be created under the tenant id in the context.
        tenant_id = 'ten-2'
        network_id = 'net2-id'
        segmentation_id = 1002
        vm_id = 'vm2'

        network_context = self._get_network_context(tenant_id,
                                                    network_id,
                                                    segmentation_id,
                                                    False)
        port_context = self._get_port_context(tenant_id,
                                              network_id,
                                              vm_id,
                                              network_context)
        port_context.current['tenant_id'] = ''
        mechanism_arista.db_lib.is_network_provisioned.return_value = True

        network = {'tenant_id': ''}
        self.drv.ndb.get_network_from_net_id.return_value = [network]

        host_id = port_context.current['binding:host_id']
        port_id = port_context.current['id']
        self.drv.create_port_precommit(port_context)

        expected_calls += [
            mock.call.is_network_provisioned(INTERNAL_TENANT_ID, network_id,
                                             None),
            mock.call.remember_tenant(INTERNAL_TENANT_ID),
            mock.call.remember_vm(vm_id, host_id, port_id,
                                  network_id, INTERNAL_TENANT_ID)
        ]
        mechanism_arista.db_lib.assert_has_calls(expected_calls)

    def _test_create_port_postcommit(self):
        tenant_id = 'ten-1'
        network_id = 'net1-id'
        segmentation_id = 1001
        vm_id = 'vm1'

        network_context = self._get_network_context(tenant_id,
                                                    network_id,
                                                    segmentation_id,
                                                    False)
        port_context = self._get_port_context(tenant_id,
                                              network_id,
                                              vm_id,
                                              network_context)
        mechanism_arista.db_lib.is_port_provisioned.return_value = True
        mechanism_arista.db_lib.is_network_provisioned.return_value = True
        mechanism_arista.db_lib.get_shared_network_owner_id.return_value = 1

        network = {'tenant_id': tenant_id}
        self.drv.ndb.get_network_from_net_id.return_value = [network]

        port = port_context.current
        device_id = port['device_id']
        device_owner = port['device_owner']
        host_id = port['binding:host_id']
        port_id = port['id']
        port_name = port['name']
        profile = port['binding:profile']

        self.drv.create_port_postcommit(port_context)

        expected_calls = [
            mock.call.NeutronNets(),
            mock.call.__nonzero__(),
            mock.call.is_port_provisioned(port_id),
            mock.call.is_network_provisioned(tenant_id, network_id, None),
            mock.call.plug_port_into_network(device_id, host_id, port_id,
                                             network_id, tenant_id,
                                             port_name, device_owner, None,
                                             [], None, switch_bindings=profile)
        ]

        mechanism_arista.db_lib.assert_has_calls(expected_calls)

        # If there is no tenant id associated with the network, then the
        # network should be created under the tenant id in the context.
        tenant_id = 'ten-2'
        network_id = 'net2-id'
        segmentation_id = 1002
        vm_id = 'vm2'

        network_context = self._get_network_context(tenant_id,
                                                    network_id,
                                                    segmentation_id,
                                                    False)
        port_context = self._get_port_context(tenant_id,
                                              network_id,
                                              vm_id,
                                              network_context)
        port_context.current['tenant_id'] = ''
        mechanism_arista.db_lib.is_port_provisioned.return_value = True
        mechanism_arista.db_lib.is_network_provisioned.return_value = True
        mechanism_arista.db_lib.get_shared_network_owner_id.return_value = 1

        network = {'tenant_id': ''}
        self.drv.ndb.get_network_from_net_id.return_value = [network]

        port = port_context.current
        device_id = port['device_id']
        device_owner = port['device_owner']
        host_id = port['binding:host_id']
        port_id = port['id']
        port_name = port['name']

        self.drv.create_port_postcommit(port_context)

        expected_calls += [
            mock.call.is_port_provisioned(port_id),
            mock.call.is_network_provisioned(INTERNAL_TENANT_ID, network_id,
                                             None),
            mock.call.plug_port_into_network(device_id, host_id, port_id,
                                             network_id, INTERNAL_TENANT_ID,
                                             port_name, device_owner, None,
                                             [], None, switch_bindings=profile)
        ]

        mechanism_arista.db_lib.assert_has_calls(expected_calls)

        # Now test the delete ports
    def test_delete_port_precommit(self):
        tenant_id = 'ten-1'
        network_id = 'net1-id'
        segmentation_id = 1001
        vm_id = 'vm1'

        network_context = self._get_network_context(tenant_id,
                                                    network_id,
                                                    segmentation_id,
                                                    False)

        port_context = self._get_port_context(tenant_id,
                                              network_id,
                                              vm_id,
                                              network_context)
        mechanism_arista.db_lib.is_port_provisioned.return_value = True
        mechanism_arista.db_lib.num_nets_provisioned.return_value = 0
        mechanism_arista.db_lib.num_vms_provisioned.return_value = 0
        self.drv.delete_port_precommit(port_context)

        port_id = port_context.current['id']
        expected_calls = [
            mock.call.is_port_provisioned(port_id),
            mock.call.forget_port(port_id, port_context.host),
        ]

        mechanism_arista.db_lib.assert_has_calls(expected_calls)

        # If there is no tenant id associated with the network, then the
        # network should be created under the tenant id in the context.
        tenant_id = 'ten-2'
        network_id = 'net2-id'
        segmentation_id = 1002
        vm_id = 'vm2'

        network_context = self._get_network_context(tenant_id,
                                                    network_id,
                                                    segmentation_id,
                                                    False)
        port_context = self._get_port_context(tenant_id,
                                              network_id,
                                              vm_id,
                                              network_context)
        port_context.current['tenant_id'] = ''
        mechanism_arista.db_lib.is_port_provisioned.return_value = True
        mechanism_arista.db_lib.num_nets_provisioned.return_value = 0
        mechanism_arista.db_lib.num_vms_provisioned.return_value = 0
        self.drv.delete_port_precommit(port_context)

        port_id = port_context.current['id']
        expected_calls += [
            mock.call.is_port_provisioned(port_id),
            mock.call.forget_port(port_id, port_context.host),
        ]

        mechanism_arista.db_lib.assert_has_calls(expected_calls)

    def test_delete_port_postcommit(self):
        tenant_id = 'ten-1'
        network_id = 'net1-id'
        segmentation_id = 1001
        vm_id = 'vm1'

        network_context = self._get_network_context(tenant_id,
                                                    network_id,
                                                    segmentation_id,
                                                    False)
        port_context = self._get_port_context(tenant_id,
                                              network_id,
                                              vm_id,
                                              network_context)
        mechanism_arista.db_lib.num_nets_provisioned.return_value = 0
        mechanism_arista.db_lib.num_vms_provisioned.return_value = 0
        mechanism_arista.db_lib.is_network_provisioned.return_value = True
        port = port_context.current
        device_id = port['device_id']
        host_id = port['binding:host_id']
        port_id = port['id']
        vnic_type = port['binding:vnic_type']
        profile = port['binding:profile']

        network = {'tenant_id': tenant_id}
        self.drv.ndb.get_network_from_net_id.return_value = [network]
        physnet = dict(physnet='default')
        self.fake_rpc.get_physical_network.return_value = physnet
        self.drv.rpc.hpb_supported.return_value = True

        self.drv.delete_port_postcommit(port_context)

        expected_calls = [
            mock.call.NeutronNets(),
            mock.call.__nonzero__(),
            mock.call.get_physical_network(host_id),
            mock.call.is_network_provisioned(tenant_id, network_id, None,
                                             None),
            mock.call.unplug_port_from_network(device_id, 'compute', host_id,
                                               port_id, network_id, tenant_id,
                                               None, vnic_type,
                                               switch_bindings=profile),
            mock.call.remove_security_group(None, profile),
            mock.call.num_nets_provisioned(tenant_id),
            mock.call.num_vms_provisioned(tenant_id),
            mock.call.forget_tenant(tenant_id),
            mock.call.delete_tenant(tenant_id),
            mock.call.hpb_supported(),
        ]
        for binding_level in port_context.binding_levels:
            expected_calls.append(mock.call.is_network_provisioned(tenant_id,
                                  network_id, None,
                                  binding_level['bound_segment']['id']))
        mechanism_arista.db_lib.assert_has_calls(expected_calls)

        # If there is no tenant id associated with the network, then the
        # network should be created under the tenant id in the context.
        tenant_id = 'ten-2'
        network_id = 'net2-id'
        segmentation_id = 1002
        vm_id = 'vm2'

        network_context = self._get_network_context(tenant_id,
                                                    network_id,
                                                    segmentation_id,
                                                    False)
        port_context = self._get_port_context(tenant_id,
                                              network_id,
                                              vm_id,
                                              network_context)
        port_context.current['tenant_id'] = ''
        port = port_context.current
        device_id = port['device_id']
        host_id = port['binding:host_id']
        port_id = port['id']

        network = {'tenant_id': ''}
        self.drv.ndb.get_network_from_net_id.return_value = [network]
        physnet = dict(physnet='default')
        self.fake_rpc.get_physical_network.return_value = physnet

        self.drv.delete_port_postcommit(port_context)

        expected_calls += [
            mock.call.get_physical_network(host_id),
            mock.call.is_network_provisioned(INTERNAL_TENANT_ID, network_id,
                                             None, None),
            mock.call.unplug_port_from_network(device_id, 'compute', host_id,
                                               port_id, network_id,
                                               INTERNAL_TENANT_ID, None,
                                               vnic_type,
                                               switch_bindings=profile),
            mock.call.remove_security_group(None, profile),
            mock.call.num_nets_provisioned(INTERNAL_TENANT_ID),
            mock.call.num_vms_provisioned(INTERNAL_TENANT_ID),
            mock.call.forget_tenant(INTERNAL_TENANT_ID),
            mock.call.delete_tenant(INTERNAL_TENANT_ID),
            mock.call.hpb_supported(),
        ]
        for binding_level in port_context.binding_levels:
            expected_calls.append(mock.call.is_network_provisioned(
                                  INTERNAL_TENANT_ID, network_id, None,
                                  binding_level['bound_segment']['id']))

        mechanism_arista.db_lib.assert_has_calls(expected_calls)

    def test_update_port_precommit(self):

        # Test the case where the port was not provisioned previsouly
        # If port is not provisioned, we should bail out
        mechanism_arista.db_lib.is_port_provisioned.return_value = False
        mechanism_arista.db_lib.is_network_provisioned.return_value = False

        tenant_id = 'ten-1'
        network_id = 'net1-id'
        segmentation_id = 1001
        vm_id = 'vm1'

        network_context = self._get_network_context(tenant_id,
                                                    network_id,
                                                    segmentation_id,
                                                    False)

        port_context = self._get_port_context(tenant_id,
                                              network_id,
                                              vm_id,
                                              network_context)
        host_id = port_context.current['binding:host_id']
        port_context.original['binding:host_id'] = 'ubuntu0'
        port_id = port_context.current['id']

        network = {'tenant_id': tenant_id}
        self.drv.ndb.get_network_from_net_id.return_value = [network]

        # Make sure the port is not found
        mechanism_arista.db_lib.is_port_provisioned.return_value = False

        self.drv.update_port_precommit(port_context)
        segment_id = network_context.network_segments[-1]['id']

        expected_calls = [
            mock.call.NeutronNets(),
            mock.call.__nonzero__(),
            mock.call.is_network_provisioned(tenant_id, network_id,
                                             segmentation_id,
                                             segment_id),
            mock.call.is_port_provisioned(port_id, None),
            mock.call.remember_tenant(tenant_id),
            mock.call.remember_vm(vm_id, host_id, port_id,
                                  network_id, tenant_id)
        ]

        mechanism_arista.db_lib.assert_has_calls(expected_calls)

        # Test the case where the port was provisioned, but it was not on
        # correct network. We should bail out in this case as well
        tenant_id = 'ten-2'
        network_id = 'net2-id'
        segmentation_id = 1002
        vm_id = 'vm2'

        network_context = self._get_network_context(tenant_id,
                                                    network_id,
                                                    segmentation_id,
                                                    False)
        port_context = self._get_port_context(tenant_id,
                                              network_id,
                                              vm_id,
                                              network_context)
        host_id = port_context.current['binding:host_id']
        port_context.original['binding:host_id'] = 'ubuntu0'
        port_id = port_context.current['id']

        # Force the check to return port found, but, network was not found
        mechanism_arista.db_lib.is_port_provisioned.return_value = True
        mechanism_arista.db_lib.is_network_provisioned.return_value = False
        network = {'tenant_id': tenant_id}
        self.drv.ndb.get_network_from_net_id.return_value = [network]

        try:
            self.drv.update_port_precommit(port_context)
        except Exception:
            # This shoud raise an exception as this is not permitted
            # operation
            pass

        segment_id = network_context.network_segments[-1]['id']
        expected_calls += [
            mock.call.is_network_provisioned(tenant_id, network_id,
                                             segmentation_id, segment_id),
            mock.call.is_port_provisioned(port_id, None),
            mock.call.update_port(vm_id, host_id, port_id,
                                  network_id, tenant_id)
        ]

        mechanism_arista.db_lib.assert_has_calls(expected_calls)

        # If the tenant id is not specified, then the port should be created
        # with internal tenant id.
        tenant_id = 'ten-3'
        network_id = 'net3-id'
        segmentation_id = 1003
        vm_id = 'vm3'

        network_context = self._get_network_context(tenant_id,
                                                    network_id,
                                                    segmentation_id,
                                                    False)
        port_context = self._get_port_context(tenant_id,
                                              network_id,
                                              vm_id,
                                              network_context)
        # Port does not contain a tenant
        port_context.current['tenant_id'] = None
        host_id = port_context.current['binding:host_id']
        port_context.original['binding:host_id'] = 'ubuntu0'
        port_id = port_context.current['id']

        # Force the check to return port and network were found
        mechanism_arista.db_lib.is_port_provisioned.return_value = True
        mechanism_arista.db_lib.is_network_provisioned.return_value = True
        network = {'tenant_id': None}
        self.drv.ndb.get_network_from_net_id.return_value = [network]

        self.drv.update_port_precommit(port_context)

        segment_id = network_context.network_segments[-1]['id']
        expected_calls += [
            mock.call.is_network_provisioned(INTERNAL_TENANT_ID, network_id,
                                             segmentation_id, segment_id),
            mock.call.is_port_provisioned(port_id, None),
            mock.call.update_port(vm_id, host_id, port_id, network_id,
                                  INTERNAL_TENANT_ID)
        ]

        mechanism_arista.db_lib.assert_has_calls(expected_calls)

        router_id = 'r1'
        # DVR ports
        # <port, host> does not exist. It should be added to the DB
        owner = n_const.DEVICE_OWNER_DVR_INTERFACE
        port_context = self._get_port_context(tenant_id,
                                              network_id,
                                              router_id,
                                              network_context,
                                              device_owner=owner)
        mechanism_arista.db_lib.is_port_provisioned.return_value = False
        self.drv.update_port_precommit(port_context)
        expected_calls += [
            mock.call.is_network_provisioned(tenant_id, network_id,
                                             segmentation_id, segment_id),
            mock.call.is_port_provisioned(port_id, host_id),
            mock.call.remember_tenant(tenant_id),
            mock.call.remember_vm(router_id, host_id, port_id,
                                  network_id, tenant_id)
        ]
        mechanism_arista.db_lib.assert_has_calls(expected_calls)

        # Unbind the port. It should be removed from the DB
        port_context._port['binding:host_id'] = None
        self.drv.update_port_precommit(port_context)
        expected_calls += [
            mock.call.is_network_provisioned(tenant_id, network_id,
                                             segmentation_id, segment_id),
            mock.call.forget_port(port_id, 'ubuntu1'),
        ]
        mechanism_arista.db_lib.assert_has_calls(expected_calls)

    def test_update_port_postcommit(self):
        tenant_id = 'ten-1'
        network_id = 'net1-id'
        segmentation_id = 1001
        vm_id = 'vm1'

        network_context = self._get_network_context(tenant_id,
                                                    network_id,
                                                    segmentation_id,
                                                    False)
        segments = network_context.network_segments
        port_context = self._get_port_context(tenant_id,
                                              network_id,
                                              vm_id,
                                              network_context)

        mechanism_arista.db_lib.is_port_provisioned.return_value = True
        mechanism_arista.db_lib.is_network_provisioned.return_value = True
        mechanism_arista.db_lib.get_shared_network_owner_id.return_value = 1
        mechanism_arista.db_lib.num_nets_provisioned.return_value = 1
        mechanism_arista.db_lib.num_vms_provisioned.return_value = 1
        self.drv.ndb.get_all_network_segments.return_value = segments

        network = {'tenant_id': tenant_id}
        self.drv.ndb.get_network_from_net_id.return_value = [network]
        port = port_context.current
        device_id = port['device_id']
        device_owner = port['device_owner']
        host_id = port['binding:host_id']
        orig_host_id = 'ubuntu0'
        port_context.original['binding:host_id'] = orig_host_id
        port_id = port['id']
        port_name = port['name']
        vnic_type = port['binding:vnic_type']
        profile = port['binding:profile']
        network_name = network_context.current['name']

        self.drv.rpc.hpb_supported.return_value = True
        self.drv.update_port_postcommit(port_context)

        expected_calls = [
            mock.call.NeutronNets(),
            mock.call.__nonzero__(),
            mock.call.is_port_provisioned(port_id, None),
            mock.call.is_network_provisioned(tenant_id, network_id,
                                             None, None),
            mock.call.is_network_provisioned(tenant_id, network_id,
                                             segmentation_id, None),
            mock.call.hpb_supported(),
            mock.call.create_network_segments(tenant_id, network_id,
                                              network_name,
                                              segments),
            mock.call.is_network_provisioned(tenant_id, network_id, None,
                                             None),
            mock.call.unplug_port_from_network(device_id, 'compute',
                                               orig_host_id, port_id,
                                               network_id, tenant_id,
                                               None, vnic_type,
                                               switch_bindings=profile),
            mock.call.remove_security_group(None, profile),
            mock.call.num_nets_provisioned(tenant_id),
            mock.call.num_vms_provisioned(tenant_id),
            mock.call.plug_port_into_network(device_id, host_id, port_id,
                                             network_id, tenant_id,
                                             port_name, device_owner, None,
                                             None, vnic_type,
                                             segments=segments,
                                             switch_bindings=profile)
        ]

        mechanism_arista.db_lib.assert_has_calls(expected_calls)

        # If there is no tenant id associated with the network, then the
        # network should be created under the tenant id in the context.
        tenant_id = 'ten-2'
        network_id = 'net2-id'
        segmentation_id = 1002
        vm_id = 'vm2'

        network_context = self._get_network_context(tenant_id,
                                                    network_id,
                                                    segmentation_id,
                                                    False)
        segments = network_context.network_segments
        port_context = self._get_port_context(tenant_id,
                                              network_id,
                                              vm_id,
                                              network_context)
        port_context.current['tenant_id'] = ''

        mechanism_arista.db_lib.is_port_provisioned.return_value = True
        mechanism_arista.db_lib.is_network_provisioned.return_value = True
        mechanism_arista.db_lib.get_shared_network_owner_id.return_value = 1
        mechanism_arista.db_lib.num_nets_provisioned.return_value = 1
        mechanism_arista.db_lib.num_vms_provisioned.return_value = 1
        self.drv.ndb.get_all_network_segments.return_value = segments

        network = {'tenant_id': ''}
        self.drv.ndb.get_network_from_net_id.return_value = [network]

        port = port_context.current
        device_id = port['device_id']
        device_owner = port['device_owner']
        host_id = port['binding:host_id']
        orig_host_id = 'ubuntu0'
        port_context.original['binding:host_id'] = orig_host_id
        port_id = port['id']
        port_name = port['name']
        network_name = network_context.current['name']

        self.drv.update_port_postcommit(port_context)

        expected_calls += [
            mock.call.is_port_provisioned(port_id, None),
            mock.call.is_network_provisioned(INTERNAL_TENANT_ID, network_id,
                                             None, None),
            mock.call.is_network_provisioned(INTERNAL_TENANT_ID, network_id,
                                             segmentation_id, None),
            mock.call.hpb_supported(),
            mock.call.create_network_segments(INTERNAL_TENANT_ID, network_id,
                                              network_name,
                                              segments),
            mock.call.is_network_provisioned(INTERNAL_TENANT_ID, network_id,
                                             None, None),
            mock.call.unplug_port_from_network(device_id, 'compute',
                                               orig_host_id,
                                               port_id, network_id,
                                               INTERNAL_TENANT_ID,
                                               None, vnic_type,
                                               switch_bindings=profile),
            mock.call.remove_security_group(None, profile),
            mock.call.num_nets_provisioned(INTERNAL_TENANT_ID),
            mock.call.num_vms_provisioned(INTERNAL_TENANT_ID),
            mock.call.plug_port_into_network(device_id, host_id, port_id,
                                             network_id, INTERNAL_TENANT_ID,
                                             port_name, device_owner, None,
                                             None, vnic_type,
                                             segments=segments,
                                             switch_bindings=profile)
        ]

        mechanism_arista.db_lib.assert_has_calls(expected_calls)

        # DVR ports
        tenant_id = 'ten-3'
        network_id = 'net3-id'
        segmentation_id = 1003
        router_id = 'r1'

        network_context = self._get_network_context(tenant_id,
                                                    network_id,
                                                    segmentation_id,
                                                    False)
        segments = network_context.network_segments
        network_name = network_context.current['name']
        owner = n_const.DEVICE_OWNER_DVR_INTERFACE
        port_context = self._get_port_context(tenant_id,
                                              network_id,
                                              router_id,
                                              network_context,
                                              device_owner=owner)

        mechanism_arista.db_lib.is_port_provisioned.return_value = True
        mechanism_arista.db_lib.is_network_provisioned.return_value = True
        mechanism_arista.db_lib.get_shared_network_owner_id.return_value = 1
        mechanism_arista.db_lib.num_nets_provisioned.return_value = 1
        mechanism_arista.db_lib.num_vms_provisioned.return_value = 1
        self.drv.ndb.get_all_network_segments.return_value = segments

        # New DVR port - context.original_host is not set and status is ACTIVE
        #                port should be plugged into the network
        port = port_context.current
        device_id = port['device_id']
        device_owner = port['device_owner']
        host_id = port['binding:host_id']
        orig_host_id = 'ubuntu1'
        port_id = port['id']
        port_name = port['name']
        vnic_type = port['binding:vnic_type']
        profile = port['binding:profile']

        self.drv.update_port_postcommit(port_context)

        expected_calls += [
            mock.call.is_port_provisioned(port_id, port_context.host),
            mock.call.is_network_provisioned(tenant_id, network_id,
                                             None, None),
            mock.call.is_network_provisioned(tenant_id, network_id,
                                             segmentation_id, None),
            mock.call.hpb_supported(),
            mock.call.create_network_segments(tenant_id, network_id,
                                              network_name,
                                              segments),
            mock.call.plug_port_into_network(device_id, host_id, port_id,
                                             network_id, tenant_id,
                                             port_name, device_owner, None,
                                             None, vnic_type,
                                             segments=segments,
                                             switch_bindings=profile)
        ]

        mechanism_arista.db_lib.assert_has_calls(expected_calls)

        # Delete DVR port - context.original is set and the status is DOWN.
        #                   port should be deleted
        port_context._status = n_const.PORT_STATUS_DOWN
        self.drv.update_port_postcommit(port_context)

        expected_calls += [
            mock.call.is_port_provisioned(port_id, port_context.host),
            mock.call.is_network_provisioned(tenant_id, network_id,
                                             None, None),
            mock.call.is_network_provisioned(tenant_id, network_id,
                                             segmentation_id, None),
            mock.call.hpb_supported(),
            mock.call.create_network_segments(tenant_id, network_id,
                                              network_name,
                                              segments),
            mock.call.is_network_provisioned(tenant_id, network_id,
                                             None, None),
            mock.call.unplug_port_from_network(device_id, owner,
                                               orig_host_id,
                                               port_id, network_id,
                                               tenant_id,
                                               None, vnic_type,
                                               switch_bindings=profile),
            mock.call.remove_security_group(None, profile),
            mock.call.num_nets_provisioned(tenant_id),
            mock.call.num_vms_provisioned(tenant_id),
        ]

        mechanism_arista.db_lib.assert_has_calls(expected_calls)

    def test_update_port_precommit_dhcp_reserved_port(self):
        '''Test to ensure the dhcp port migration is handled correctly.

        Whenever a DHCP agent dies, the port is attached to a dummy device
        identified by DEVICE_ID_RESERVED_DHCP_PORT. Once the dhcp agent is
        respawned, the port is reattached to the newly created DHCP instance.
        This deletes the old dhcp port from the old host and creates the port
        on the new host. The dhcp port transitions from

        (Active <old host, old dhcp, vif:ovs>) to
        (Active <old host, reserved, vif:ovs>) to
        (Down   <new host, new dhcp, vif:unbound>) to
        (Down   <new host, new dhcp, vif:ovs>) to
        (Build  <new host, new dhcp, vif:ovs>) to
        (Active <new host, new dhcp, vif:ovs>)

        When the port is updated to (Active <old host, reserved, vif:ovs>),
        the port needs to be removed from old host and when the port is updated
        to (Down <new host, new dhcp, vif:unbound>), it should be created on
        the new host. Removal and creation should take place in two updates
        because when the port is updated to
        (Down <new host, new dhcp, vif:unbound>), the original port would have
        the device id set to 'reserved_dhcp_port' and so it can't be removed
        from CVX at that point.

        '''

        tenant_id = 't1'
        network_id = 'n1'
        old_device_id = 'old_device_id'
        new_device_id = 'new_device_id'
        reserved_device = neutron_const.DEVICE_ID_RESERVED_DHCP_PORT
        old_host = 'ubuntu1'
        new_host = 'ubuntu2'
        port_id = 101
        segmentation_id = 1000
        network_context = self._get_network_context(tenant_id,
                                                    network_id,
                                                    segmentation_id,
                                                    False)
        segment_id = network_context.network_segments[-1]['id']

        # (Active <old host, old dhcp, vif:ovs>) to
        # (Active <old host, reserved, vif:ovs>)
        context = self._get_port_context(
            tenant_id, network_id, old_device_id,
            network_context, device_owner=n_const.DEVICE_OWNER_DHCP)
        context.current['device_id'] = reserved_device

        network = {'tenant_id': tenant_id}
        self.drv.ndb.get_network_from_net_id.return_value = [network]

        mechanism_arista.db_lib.is_port_provisioned.return_value = True
        mechanism_arista.db_lib.is_network_provisioned.return_value = True

        mechanism_arista.db_lib.reset_mock()
        self.drv.update_port_precommit(context)

        expected_calls = [
            mock.call.is_network_provisioned(tenant_id, network_id,
                                             segmentation_id,
                                             segment_id),
            mock.call.is_port_provisioned(port_id, None),
            mock.call.update_port(reserved_device,
                                  old_host, port_id,
                                  network_id, tenant_id)
        ]

        mechanism_arista.db_lib.assert_has_calls(expected_calls)

        # (Active <old host, reserved, vif:ovs>) to
        # (Down   <new host, new dhcp, vif:unbound>)
        context = self._get_port_context(
            tenant_id, network_id, reserved_device, network_context,
            device_owner=n_const.DEVICE_OWNER_DHCP)
        context.current['device_id'] = new_device_id
        context.current['binding:host_id'] = new_host
        context.current['status'] = 'DOWN'

        mechanism_arista.db_lib.reset_mock()
        self.drv.update_port_precommit(context)

        expected_calls = [
            mock.call.is_network_provisioned(tenant_id, network_id,
                                             segmentation_id,
                                             segment_id),
            mock.call.is_port_provisioned(port_id, None),
            mock.call.update_port(new_device_id,
                                  new_host, port_id,
                                  network_id, tenant_id)
        ]

        mechanism_arista.db_lib.assert_has_calls(expected_calls)

        # (Down   <new host, new dhcp, vif:unbound>) to
        # (Down   <new host, new dhcp, vif:ovs>) to
        context = self._get_port_context(
            tenant_id, network_id, new_device_id, network_context,
            device_owner=n_const.DEVICE_OWNER_DHCP, status='DOWN')

        mechanism_arista.db_lib.reset_mock()
        self.drv.update_port_precommit(context)

        expected_calls = [
            mock.call.is_network_provisioned(tenant_id, network_id,
                                             segmentation_id,
                                             segment_id),
            mock.call.is_port_provisioned(port_id, None),
        ]

        mechanism_arista.db_lib.assert_has_calls(expected_calls)

        # (Down   <new host, new dhcp, vif:ovs>) to
        # (Build  <new host, new dhcp, vif:ovs>) to
        context = self._get_port_context(
            tenant_id, network_id, new_device_id, network_context,
            device_owner=n_const.DEVICE_OWNER_DHCP, status='DOWN')

        context.current['status'] = 'BUILD'

        mechanism_arista.db_lib.reset_mock()
        self.drv.update_port_precommit(context)

        expected_calls = [
            mock.call.is_network_provisioned(tenant_id, network_id,
                                             segmentation_id,
                                             segment_id),
            mock.call.is_port_provisioned(port_id, None),
        ]

        mechanism_arista.db_lib.assert_has_calls(expected_calls)

        # (Build  <new host, new dhcp, vif:ovs>) to
        # (Active <new host, new dhcp, vif:ovs>)
        context = self._get_port_context(
            tenant_id, network_id, new_device_id, network_context,
            device_owner=n_const.DEVICE_OWNER_DHCP, status='BUILD')

        context.current['status'] = 'ACTIVE'

        mechanism_arista.db_lib.reset_mock()
        self.drv.update_port_precommit(context)

        expected_calls = [
            mock.call.is_network_provisioned(tenant_id, network_id,
                                             segmentation_id,
                                             segment_id),
            mock.call.is_port_provisioned(port_id, None),
        ]

        mechanism_arista.db_lib.assert_has_calls(expected_calls)

    def test_update_port_postcommit_dhcp_reserved_port(self):
        '''Test to ensure the dhcp port migration is handled correctly.

        Whenever a DHCP agent dies, the port is attached to a dummy device
        identified by DEVICE_ID_RESERVED_DHCP_PORT. Once the dhcp agent is
        respawned, the port is reattached to the newly created DHCP instance.
        This deletes the old dhcp port from the old host and creates the port
        on the new host. The dhcp port transitions from

        (Active <old host, old dhcp, vif:ovs>) to
        (Active <old host, reserved, vif:ovs>) to
        (Down   <new host, new dhcp, vif:unbound>) to
        (Down   <new host, new dhcp, vif:ovs>) to
        (Build  <new host, new dhcp, vif:ovs>) to
        (Active <new host, new dhcp, vif:ovs>)

        When the port is updated to (Active <old host, reserved, vif:ovs>),
        the port needs to be removed from old host and when the port is updated
        to (Down <new host, new dhcp, vif:unbound>), it should be created on
        the new host. Removal and creation should take place in two updates
        because when the port is updated to
        (Down <new host, new dhcp, vif:unbound>), the original port would have
        the device id set to 'reserved_dhcp_port' and so it can't be removed
        from CVX at that point.

        '''

        tenant_id = 't1'
        network_id = 'n1'
        old_device_id = 'old_device_id'
        new_device_id = 'new_device_id'
        reserved_device = neutron_const.DEVICE_ID_RESERVED_DHCP_PORT
        old_host = 'ubuntu1'
        new_host = 'ubuntu2'
        port_id = 101
        segmentation_id = 1000
        network_context = self._get_network_context(tenant_id,
                                                    network_id,
                                                    segmentation_id,
                                                    False)
        segments = network_context.network_segments

        # (Active <old host, old dhcp, vif:ovs>) to
        # (Active <old host, reserved, vif:ovs>)
        context = self._get_port_context(
            tenant_id, network_id, old_device_id, network_context,
            device_owner=n_const.DEVICE_OWNER_DHCP)
        context.current['device_id'] = reserved_device
        vnic_type = context.current['binding:vnic_type']
        profile = context.current['binding:profile']
        port_name = context.current['name']

        network = {'tenant_id': tenant_id}
        self.drv.ndb.get_network_from_net_id.return_value = [network]

        mechanism_arista.db_lib.is_port_provisioned.return_value = True
        mechanism_arista.db_lib.is_network_provisioned.return_value = True
        mechanism_arista.db_lib.get_shared_network_owner_id.return_value = 1
        mechanism_arista.db_lib.num_nets_provisioned.return_value = 1
        mechanism_arista.db_lib.num_vms_provisioned.return_value = 1

        self.drv.rpc.hpb_supported.return_value = False
        self.drv.ndb.get_network_segments.return_value = segments

        mechanism_arista.db_lib.reset_mock()
        self.drv.update_port_postcommit(context)

        expected_calls = [
            mock.call.is_port_provisioned(port_id, None),
            mock.call.is_network_provisioned(tenant_id, network_id,
                                             None, None),
            mock.call.is_network_provisioned(tenant_id, network_id,
                                             segmentation_id,
                                             None),
            mock.call.hpb_supported(),
            mock.call.is_network_provisioned(tenant_id, network_id,
                                             None, None),
            mock.call.unplug_port_from_network(old_device_id,
                                               n_const.DEVICE_OWNER_DHCP,
                                               old_host,
                                               port_id, network_id,
                                               tenant_id,
                                               None, vnic_type,
                                               switch_bindings=profile),
            mock.call.remove_security_group(None, profile),
            mock.call.num_nets_provisioned(tenant_id),
            mock.call.num_vms_provisioned(tenant_id),
        ]

        mechanism_arista.db_lib.assert_has_calls(expected_calls)

        # (Active <old host, reserved, vif:ovs>) to
        # (Down   <new host, new dhcp, vif:unbound>)
        context = self._get_port_context(
            tenant_id, network_id, reserved_device, network_context,
            device_owner=n_const.DEVICE_OWNER_DHCP)
        context.current['device_id'] = new_device_id
        context.current['binding:host_id'] = new_host
        context.current['status'] = 'DOWN'

        mechanism_arista.db_lib.reset_mock()
        self.drv.update_port_postcommit(context)

        expected_calls = [
            mock.call.is_port_provisioned(port_id, None),
            mock.call.is_network_provisioned(tenant_id, network_id,
                                             None, None),
            mock.call.is_network_provisioned(tenant_id, network_id,
                                             segmentation_id,
                                             None),
            mock.call.hpb_supported(),
            mock.call.is_network_provisioned(tenant_id, network_id,
                                             None, None),
            mock.call.unplug_port_from_network(reserved_device,
                                               n_const.DEVICE_OWNER_DHCP,
                                               old_host,
                                               port_id, network_id,
                                               tenant_id,
                                               None, vnic_type,
                                               switch_bindings=profile),
            mock.call.remove_security_group(None, profile),
            mock.call.num_nets_provisioned(tenant_id),
            mock.call.num_vms_provisioned(tenant_id),
            mock.call.plug_port_into_network(new_device_id,
                                             new_host,
                                             port_id, network_id,
                                             tenant_id, port_name,
                                             n_const.DEVICE_OWNER_DHCP,
                                             None, None, vnic_type,
                                             segments=[],
                                             switch_bindings=profile),
        ]

        mechanism_arista.db_lib.assert_has_calls(expected_calls)

        # (Down   <new host, new dhcp, vif:unbound>) to
        # (Down   <new host, new dhcp, vif:ovs>) to
        context = self._get_port_context(
            tenant_id, network_id, new_device_id, network_context,
            device_owner=n_const.DEVICE_OWNER_DHCP, status='DOWN')
        context.current['binding:host_id'] = new_host
        context.original['binding:host_id'] = new_host

        mechanism_arista.db_lib.reset_mock()
        self.drv.update_port_postcommit(context)

        expected_calls = [
            mock.call.is_port_provisioned(port_id, None),
            mock.call.is_network_provisioned(tenant_id, network_id,
                                             None, None),
            mock.call.is_network_provisioned(tenant_id, network_id,
                                             segmentation_id,
                                             None),
            mock.call.hpb_supported(),
            mock.call.plug_port_into_network(new_device_id,
                                             new_host,
                                             port_id, network_id,
                                             tenant_id, port_name,
                                             n_const.DEVICE_OWNER_DHCP,
                                             None, None, vnic_type,
                                             segments=[],
                                             switch_bindings=profile),
        ]

        mechanism_arista.db_lib.assert_has_calls(expected_calls)

        # (Down   <new host, new dhcp, vif:ovs>) to
        # (Build  <new host, new dhcp, vif:ovs>) to
        context = self._get_port_context(
            tenant_id, network_id, new_device_id, network_context,
            device_owner=n_const.DEVICE_OWNER_DHCP, status='DOWN')
        context.current['binding:host_id'] = new_host
        context.original['binding:host_id'] = new_host
        context.current['status'] = 'BUILD'

        mechanism_arista.db_lib.reset_mock()
        self.drv.update_port_postcommit(context)

        expected_calls = [
            mock.call.is_port_provisioned(port_id, None),
            mock.call.is_network_provisioned(tenant_id, network_id,
                                             None, None),
            mock.call.is_network_provisioned(tenant_id, network_id,
                                             segmentation_id,
                                             None),
            mock.call.hpb_supported(),
            mock.call.plug_port_into_network(new_device_id,
                                             new_host,
                                             port_id, network_id,
                                             tenant_id, port_name,
                                             n_const.DEVICE_OWNER_DHCP,
                                             None, None, vnic_type,
                                             segments=[],
                                             switch_bindings=profile),
        ]

        mechanism_arista.db_lib.assert_has_calls(expected_calls)

        # (Build  <new host, new dhcp, vif:ovs>) to
        # (Active <new host, new dhcp, vif:ovs>)
        context = self._get_port_context(
            tenant_id, network_id, new_device_id, network_context,
            device_owner=n_const.DEVICE_OWNER_DHCP, status='BUILD')
        context.current['binding:host_id'] = new_host
        context.original['binding:host_id'] = new_host
        context.current['status'] = 'ACTIVE'

        mechanism_arista.db_lib.reset_mock()
        self.drv.update_port_postcommit(context)

        expected_calls = [
            mock.call.is_port_provisioned(port_id, None),
            mock.call.is_network_provisioned(tenant_id, network_id,
                                             None, None),
            mock.call.is_network_provisioned(tenant_id, network_id,
                                             segmentation_id,
                                             None),
            mock.call.hpb_supported(),
        ]

        mechanism_arista.db_lib.assert_has_calls(expected_calls)

    def _get_network_context(self, tenant_id, net_id,
                             segmentation_id, shared):
        network = {'id': net_id,
                   'tenant_id': tenant_id,
                   'name': 'test-net',
                   'shared': shared}
        network_segments = [{'segmentation_id': segmentation_id,
                             'physical_network': u'default',
                             'id': 'segment-id-for-%s' % segmentation_id,
                             'network_type': 'vlan'}]
        return FakeNetworkContext(tenant_id, network, network_segments,
                                  network)

    def _get_port_context(self, tenant_id, net_id, device_id, network,
                          device_owner='compute', status='ACTIVE'):
        port = {'device_id': device_id,
                'device_owner': device_owner,
                'binding:host_id': 'ubuntu1',
                'name': 'test-port',
                'tenant_id': tenant_id,
                'id': 101,
                'network_id': net_id,
                'binding:vnic_type': None,
                'binding:profile': [],
                'security_groups': None,
                'status': 'ACTIVE',
                }
        orig_port = {'device_id': device_id,
                     'device_owner': device_owner,
                     'binding:host_id': 'ubuntu1',
                     'name': 'test-port',
                     'tenant_id': tenant_id,
                     'id': 101,
                     'network_id': net_id,
                     'binding:vnic_type': None,
                     'binding:profile': [],
                     'security_groups': None,
                     'status': 'ACTIVE',
                     }
        binding_levels = []
        for level, segment in enumerate(network.network_segments):
            binding_levels.append(FakePortBindingLevel(port['id'],
                                                       level,
                                                       'vendor-1',
                                                       segment['id']))
        return FakePortContext(port, dict(orig_port), network, status,
                               binding_levels)


class fake_keystone_info_class(object):
    """To generate fake Keystone Authentication token information

    Arista Driver expects Keystone auth info. This fake information
    is for testing only
    """
    auth_uri = 'abc://host:35357/v2.0/'
    identity_uri = 'abc://host:5000'
    admin_user = 'neutron'
    admin_password = 'fun'
    admin_tenant_name = 'tenant_name'


class FakeNetworkContext(object):
    """To generate network context for testing purposes only."""

    def __init__(self, tenant_id, network, segments=None,
                 original_network=None):
        self._network = network
        self._original_network = original_network
        self._segments = segments
        self._plugin_context = FakePluginContext(tenant_id)

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

    def __init__(self, port, original_port, network, status,
                 binding_levels):
        self._plugin_context = FakePluginContext('test')
        self._port = port
        self._original_port = original_port
        self._network_context = network
        self._status = status
        self._binding_levels = binding_levels
        self._original_binding_levels = []

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
                api.BOUND_DRIVER: level.driver,
                api.BOUND_SEGMENT: self._expand_segment(level.segment_id)
            } for level in self._binding_levels]

    @property
    def bottom_bound_segment(self):
        if self._binding_levels:
            return self._expand_segment(self._binding_levels[-1].segment_id)

    def _expand_segment(self, segment_id):
        for segment in self._network_context.network_segments:
            if segment[api.ID] == segment_id:
                return segment


class FakePluginContext(object):
    """Plugin context for testing purposes only."""

    def __init__(self, tenant_id):
        self.tenant_id = tenant_id
        self.session = mock.MagicMock()


class FakePortBindingLevel(object):
    """Port binding object for testing purposes only."""

    def __init__(self, port_id, level, driver, segment_id):
        self.port_id = port_id
        self.level = level
        self.driver = driver
        self.segment_id = segment_id
