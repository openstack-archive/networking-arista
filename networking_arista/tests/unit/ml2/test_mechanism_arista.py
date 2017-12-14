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

from neutron.db import models_v2
from neutron.plugins.ml2 import models as port_models
from neutron.services.trunk import callbacks
from neutron.services.trunk import models as trunk_models
from neutron.tests.unit import testlib_api


from networking_arista.common import utils as mech_utils
from networking_arista.ml2 import mechanism_arista
from networking_arista.tests.unit import utils

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

    def test_create_network_postcommit(self):
        tenant_id = 'ten-1'
        network_id = 'net1-id'
        segmentation_id = 1001

        network_context = utils.get_network_context(tenant_id,
                                                    network_id,
                                                    segmentation_id,
                                                    False)
        network = network_context.current
        segments = network_context.network_segments
        net_dict = {
            'network_id': network['id'],
            'segments': segments,
            'network_name': network['name'],
            'shared': network['shared']}

        self.drv.create_network_postcommit(network_context)

        expected_calls = [
            mock.call.create_network(tenant_id, net_dict),
        ]

        mechanism_arista.db_lib.assert_has_calls(expected_calls)

        # If there is no tenant id associated with the network, then the
        # network should be created under the tenant id in the context.
        tenant_id = 'ten-2'
        network_id = 'net2-id'
        segmentation_id = 1002

        network_context = utils.get_network_context(tenant_id,
                                                    network_id,
                                                    segmentation_id,
                                                    False)
        network_context.current['tenant_id'] = ''
        network = network_context.current
        segments = network_context.network_segments
        net_dict = {
            'network_id': network['id'],
            'segments': segments,
            'network_name': network['name'],
            'shared': network['shared']}

        self.drv.create_network_postcommit(network_context)

        expected_calls += [
            mock.call.create_network(INTERNAL_TENANT_ID, net_dict),
        ]

        mechanism_arista.db_lib.assert_has_calls(expected_calls)

    def test_delete_network_postcommit(self):
        tenant_id = 'ten-1'
        network_id = 'net1-id'
        segmentation_id = 1001

        self.drv.rpc.hpb_supported.return_value = True
        network_context = utils.get_network_context(tenant_id,
                                                    network_id,
                                                    segmentation_id,
                                                    False)

        mechanism_arista.db_lib.tenant_provisioned.return_value = False
        self.drv.delete_network_postcommit(network_context)
        expected_calls = [
            mock.call.delete_network(tenant_id, network_id,
                                     network_context.network_segments),
            mock.call.tenant_provisioned(tenant_id),
            mock.call.delete_tenant(tenant_id),
        ]

        mechanism_arista.db_lib.assert_has_calls(expected_calls)

        # If there is no tenant id associated with the network, then the
        # network should be created under the tenant id in the context.
        tenant_id = 'ten-2'
        network_id = 'net2-id'
        segmentation_id = 1002

        network_context = utils.get_network_context(tenant_id,
                                                    network_id,
                                                    segmentation_id,
                                                    False)
        network_context.current['tenant_id'] = ''

        self.drv.delete_network_postcommit(network_context)
        expected_calls += [
            mock.call.delete_network(INTERNAL_TENANT_ID, network_id,
                                     network_context.network_segments),
            mock.call.tenant_provisioned(INTERNAL_TENANT_ID),
            mock.call.delete_tenant(INTERNAL_TENANT_ID),
        ]

        mechanism_arista.db_lib.assert_has_calls(expected_calls)

    def _test_create_port_precommit(self):
        tenant_id = 'ten-1'
        network_id = 'net1-id'
        segmentation_id = 1001
        vm_id = 'vm1'

        network_context = utils.get_network_context(tenant_id,
                                                    network_id,
                                                    segmentation_id,
                                                    False)

        port_context = utils.get_port_context(tenant_id,
                                              network_id,
                                              vm_id,
                                              network_context)

        network = {'tenant_id': tenant_id}
        self.drv.ndb.get_network_from_net_id.return_value = [network]

        host_id = port_context.current['binding:host_id']
        port_id = port_context.current['id']
        self.drv.create_port_precommit(port_context)

        expected_calls = [
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

        network_context = utils.get_network_context(tenant_id,
                                                    network_id,
                                                    segmentation_id,
                                                    False)
        port_context = utils.get_port_context(tenant_id,
                                              network_id,
                                              vm_id,
                                              network_context)
        port_context.current['tenant_id'] = ''

        network = {'tenant_id': ''}
        self.drv.ndb.get_network_from_net_id.return_value = [network]

        host_id = port_context.current['binding:host_id']
        port_id = port_context.current['id']
        self.drv.create_port_precommit(port_context)

        expected_calls += [
            mock.call.remember_vm(vm_id, host_id, port_id,
                                  network_id, INTERNAL_TENANT_ID)
        ]
        mechanism_arista.db_lib.assert_has_calls(expected_calls)

    def _test_create_port_postcommit(self):
        tenant_id = 'ten-1'
        network_id = 'net1-id'
        segmentation_id = 1001
        vm_id = 'vm1'

        network_context = utils.get_network_context(tenant_id,
                                                    network_id,
                                                    segmentation_id,
                                                    False)
        port_context = utils.get_port_context(tenant_id,
                                              network_id,
                                              vm_id,
                                              network_context)

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

        network_context = utils.get_network_context(tenant_id,
                                                    network_id,
                                                    segmentation_id,
                                                    False)
        port_context = utils.get_port_context(tenant_id,
                                              network_id,
                                              vm_id,
                                              network_context)
        port_context.current['tenant_id'] = ''

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
            mock.call.plug_port_into_network(device_id, host_id, port_id,
                                             network_id, INTERNAL_TENANT_ID,
                                             port_name, device_owner, None,
                                             [], None, switch_bindings=profile)
        ]

        mechanism_arista.db_lib.assert_has_calls(expected_calls)

    def test_delete_port_postcommit(self):
        tenant_id = 'ten-1'
        network_id = 'net1-id'
        segmentation_id = 1001
        vm_id = 'vm1'

        network_context = utils.get_network_context(tenant_id,
                                                    network_id,
                                                    segmentation_id,
                                                    False)
        port_context = utils.get_port_context(tenant_id,
                                              network_id,
                                              vm_id,
                                              network_context)
        mechanism_arista.db_lib.tenant_provisioned.return_value = False
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
        self.drv.delete_port_postcommit(port_context)

        expected_calls = [
            mock.call.NeutronNets(),
            mock.call.get_physical_network(host_id),
            mock.call.unplug_port_from_network(device_id, 'compute:', host_id,
                                               port_id, network_id, tenant_id,
                                               None, vnic_type,
                                               switch_bindings=profile,
                                               trunk_details=None),
            mock.call.remove_security_group(None, profile),
            mock.call.tenant_provisioned(tenant_id),
            mock.call.delete_tenant(tenant_id),
        ]
        mechanism_arista.db_lib.assert_has_calls(expected_calls)

        # If there is no tenant id associated with the network, then the
        # network should be created under the tenant id in the context.
        tenant_id = 'ten-2'
        network_id = 'net2-id'
        segmentation_id = 1002
        vm_id = 'vm2'

        network_context = utils.get_network_context(tenant_id,
                                                    network_id,
                                                    segmentation_id,
                                                    False)
        port_context = utils.get_port_context(tenant_id,
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
            mock.call.unplug_port_from_network(device_id, 'compute:', host_id,
                                               port_id, network_id,
                                               INTERNAL_TENANT_ID, None,
                                               vnic_type,
                                               switch_bindings=profile,
                                               trunk_details=None),
            mock.call.remove_security_group(None, profile),
            mock.call.tenant_provisioned(INTERNAL_TENANT_ID),
            mock.call.delete_tenant(INTERNAL_TENANT_ID),
        ]

        mechanism_arista.db_lib.assert_has_calls(expected_calls)

    def test_delete_trunk_port_postcommit(self):
        # trunk port
        tenant_id = 'ten-3'
        network_id = 'net3-id'
        segmentation_id = 1003
        vm_id = 'vm3'

        trunk_details = {'sub_ports': [{'mac_address': 'mac_address',
                                        'port_id': 'subport_id',
                                        'segmentation_id': 123,
                                        'segmentation_type': 'vlan'}],
                         'trunk_id': 'trunk_id'}

        network_context = utils.get_network_context(tenant_id,
                                                    network_id,
                                                    segmentation_id,
                                                    False)
        port_context = utils.get_port_context(tenant_id,
                                              network_id,
                                              vm_id,
                                              network_context)

        mechanism_arista.db_lib.tenant_provisioned.return_value = False

        port = port_context.current
        port['trunk_details'] = trunk_details
        device_id = port['device_id']
        host_id = port['binding:host_id']
        port_id = port['id']
        vnic_type = port['binding:vnic_type']
        profile = port['binding:profile']

        network = {'tenant_id': tenant_id}
        self.drv.ndb.get_network_from_net_id.return_value = [network]
        physnet = dict(physnet='default')
        self.fake_rpc.get_physical_network.return_value = physnet

        self.drv.delete_port_postcommit(port_context)

        expected_calls = [
            mock.call.NeutronNets(),
            mock.call.get_physical_network(host_id),
            mock.call.unplug_port_from_network(device_id, 'compute:', host_id,
                                               port_id, network_id, tenant_id,
                                               None, vnic_type,
                                               switch_bindings=profile,
                                               trunk_details=trunk_details),
            mock.call.remove_security_group(None, profile),
            mock.call.tenant_provisioned(tenant_id),
            mock.call.delete_tenant(tenant_id),
        ]
        mechanism_arista.db_lib.assert_has_calls(expected_calls)

    def test_set_subport(self):
        tenant_id = 'ten-4'
        network_id = 'net4-id'
        vm_id = 'vm4'
        trunk_id = 111

        host_id = 'host1'
        port_id = 'p1'
        vnic_type = 'allowed'
        profile = []
        sg = ['security-groups']
        orig_sg = None

        trunk_port = models_v2.Port(
            tenant_id=tenant_id, network_id='net-trunk',
            device_id=vm_id, device_owner='compute:None')
        trunk_port.port_binding = port_models.PortBinding()
        trunk_port.port_binding.vnic_type = vnic_type
        trunk_port.port_binding.host = host_id
        trunk_port.port_binding.profile = profile

        mechanism_arista.db_lib.num_nets_provisioned.return_value = 0
        mechanism_arista.db_lib.num_vms_provisioned.return_value = 0
        mechanism_arista.db_lib.get_trunk_port_by_trunk_id.return_value = \
            trunk_port
        mechanism_arista.db_lib.is_network_provisioned.return_value = True

        resource = 'SubPort'
        event = 'AFTER_CREATE'
        trigger = 'AristaDriver'

        sp = dict(models_v2.Port(
            id=port_id,
            device_owner='trunk:subport',
            network_id=network_id,
            name='subport'))
        sp['security_groups'] = ['security-groups']
        subport = trunk_models.SubPort()
        subport.port_id = port_id
        payload = callbacks.TrunkPayload(None, trunk_id,
                                         subports=[subport])
        segments = [{'segmentation_id': 12,
                     'physical_network': 'default',
                     'id': 'segment_id',
                     'network_type': 'vlan'}]
        bindings = []

        self.drv.ndb.get_port.return_value = sp
        self.drv.ndb.get_network_id_from_port_id.return_value = network_id
        mechanism_arista.db_lib.get_network_segments_by_port_id.return_value = \
            segments

        self.drv.set_subport(resource, event, trigger, payload=payload)

        expected_calls = [
            mock.call.NeutronNets(),
            mock.call.get_trunk_port_by_trunk_id(trunk_id),
            mock.call.get_network_segments_by_port_id('p1'),
            mock.call.plug_port_into_network(vm_id, host_id, port_id,
                                             network_id, tenant_id,
                                             'subport', 'trunk:subport',
                                             sg, orig_sg, vnic_type,
                                             segments=segments,
                                             switch_bindings=bindings),
        ]

        mechanism_arista.db_lib.assert_has_calls(expected_calls)

    def test_unset_subport(self):
        tenant_id = 'ten-4'
        network_id = 'net4-id'
        vm_id = 'vm4'
        trunk_id = 111

        device_owner = 'trunk:subport'
        host_id = 'host1'
        port_id = 'p1'
        vnic_type = 'allowed'
        profile = []

        trunk_port = models_v2.Port(
            tenant_id=tenant_id, network_id=network_id,
            device_id=vm_id, device_owner='compute:None')
        trunk_port.port_binding = port_models.PortBinding()
        trunk_port.port_binding.vnic_type = vnic_type
        trunk_port.port_binding.host = host_id
        trunk_port.port_binding.profile = profile

        mechanism_arista.db_lib.tenant_provisioned.return_value = False
        mechanism_arista.db_lib.get_trunk_port_by_trunk_id.return_value = \
            trunk_port

        resource = 'SubPort'
        event = 'AFTER_DELETE'
        trigger = 'AristaDriver'
        subport = trunk_models.SubPort()
        subport.port_id = port_id
        payload = callbacks.TrunkPayload(None, trunk_id,
                                         subports=[trunk_models.SubPort()])
        sp = models_v2.Port(
            id=port_id,
            device_owner='trunk:subport',
            network_id=network_id
        )

        self.drv.ndb.get_port.return_value = sp

        self.drv.unset_subport(resource, event, trigger, payload=payload)

        expected_calls = [
            mock.call.NeutronNets(),
            mock.call.get_trunk_port_by_trunk_id(trunk_id),
            mock.call.unplug_port_from_network(vm_id, device_owner,
                                               host_id, port_id, network_id,
                                               tenant_id, [], vnic_type,
                                               switch_bindings=profile,
                                               trunk_details=None),
            mock.call.remove_security_group([], profile),
            mock.call.tenant_provisioned(tenant_id),
            mock.call.delete_tenant(tenant_id),
        ]

        mechanism_arista.db_lib.assert_has_calls(expected_calls)

    def test_update_port_postcommit(self):
        tenant_id = 'ten-1'
        network_id = 'net1-id'
        segmentation_id = 1001
        vm_id = 'vm1'

        network_context = utils.get_network_context(tenant_id,
                                                    network_id,
                                                    segmentation_id,
                                                    False)
        segments = network_context.network_segments
        port_context = utils.get_port_context(tenant_id,
                                              network_id,
                                              vm_id,
                                              network_context)

        self.drv.ndb.get_all_network_segments.return_value = segments

        network = {'tenant_id': tenant_id}
        self.drv.ndb.get_network_from_net_id.return_value = [network]
        port = port_context.current
        device_id = port['device_id']
        device_owner = port['device_owner']
        host_id = port['binding:host_id']
        orig_host_id = port_context.original_host
        port_id = port['id']
        port_name = port['name']
        vnic_type = port['binding:vnic_type']
        profile = port['binding:profile']
        network_name = network_context.current['name']

        self.drv.update_port_postcommit(port_context)

        expected_calls = [
            mock.call.NeutronNets(),
            mock.call.create_network_segments(tenant_id, network_id,
                                              network_name,
                                              segments),
            mock.call.plug_port_into_network(device_id, host_id, port_id,
                                             network_id, tenant_id,
                                             port_name, device_owner, None,
                                             None, vnic_type,
                                             segments=segments,
                                             switch_bindings=profile,
                                             trunk_details=None)
        ]

        mechanism_arista.db_lib.assert_has_calls(expected_calls)

        # If there is no tenant id associated with the network, then the
        # network should be created under the tenant id in the context.
        tenant_id = 'ten-2'
        network_id = 'net2-id'
        segmentation_id = 1002
        vm_id = 'vm2'

        network_context = utils.get_network_context(tenant_id,
                                                    network_id,
                                                    segmentation_id,
                                                    False)
        segments = network_context.network_segments
        port_context = utils.get_port_context(tenant_id,
                                              network_id,
                                              vm_id,
                                              network_context)
        port_context.current['tenant_id'] = ''

        self.drv.ndb.get_all_network_segments.return_value = segments

        network = {'tenant_id': ''}
        self.drv.ndb.get_network_from_net_id.return_value = [network]

        port = port_context.current
        device_id = port['device_id']
        device_owner = port['device_owner']
        host_id = port['binding:host_id']
        orig_host_id = port_context.original_host
        port_id = port['id']
        port_name = port['name']
        network_name = network_context.current['name']

        self.drv.update_port_postcommit(port_context)

        expected_calls += [
            mock.call.create_network_segments(INTERNAL_TENANT_ID, network_id,
                                              network_name,
                                              segments),
            mock.call.plug_port_into_network(device_id, host_id, port_id,
                                             network_id, INTERNAL_TENANT_ID,
                                             port_name, device_owner, None,
                                             None, vnic_type,
                                             segments=segments,
                                             switch_bindings=profile,
                                             trunk_details=None)
        ]

        mechanism_arista.db_lib.assert_has_calls(expected_calls)

        # DVR ports
        tenant_id = 'ten-3'
        network_id = 'net3-id'
        segmentation_id = 1003
        router_id = 'r1'

        network_context = utils.get_network_context(tenant_id,
                                                    network_id,
                                                    segmentation_id,
                                                    False)
        segments = network_context.network_segments
        network_name = network_context.current['name']
        owner = n_const.DEVICE_OWNER_DVR_INTERFACE
        port_context = utils.get_port_context(tenant_id,
                                              network_id,
                                              router_id,
                                              network_context,
                                              device_owner=owner)

        mechanism_arista.db_lib.tenant_provisioned.return_value = True
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
            mock.call.create_network_segments(tenant_id, network_id,
                                              network_name,
                                              segments),
            mock.call.plug_port_into_network(device_id, host_id, port_id,
                                             network_id, tenant_id,
                                             port_name, device_owner, None,
                                             None, vnic_type,
                                             segments=segments,
                                             switch_bindings=profile,
                                             trunk_details=None)
        ]

        mechanism_arista.db_lib.assert_has_calls(expected_calls)

        # Delete DVR port - context.original is set and the status is DOWN.
        #                   port should be deleted
        port_context._status = n_const.PORT_STATUS_DOWN
        self.drv.update_port_postcommit(port_context)

        expected_calls += [
            mock.call.unplug_port_from_network(device_id, owner,
                                               orig_host_id,
                                               port_id, network_id,
                                               tenant_id,
                                               None, vnic_type,
                                               switch_bindings=profile,
                                               trunk_details=None),
            mock.call.remove_security_group(None, profile),
            mock.call.tenant_provisioned(tenant_id),
        ]

        mechanism_arista.db_lib.assert_has_calls(expected_calls)

    def test_update_trunk_port_postcommit(self):
        # trunk port
        tenant_id = 'ten-4'
        network_id = 'net4-id'
        segmentation_id = 1004
        vm_id = 'vm4'

        trunk_details = {'sub_ports': [{'mac_address': 'mac_address',
                                        'port_id': 'subport_id',
                                        'segmentation_id': 123,
                                        'segmentation_type': 'vlan'}],
                         'trunk_id': 'trunk_id'}

        network_context = utils.get_network_context(tenant_id,
                                                    network_id,
                                                    segmentation_id,
                                                    False)
        segments = network_context.network_segments
        port_context = utils.get_port_context(tenant_id,
                                              network_id,
                                              vm_id,
                                              network_context)

        mechanism_arista.db_lib.get_shared_network_owner_id.return_value = 1
        self.drv.ndb.get_all_network_segments.return_value = segments

        network = {'tenant_id': tenant_id}
        self.drv.ndb.get_network_from_net_id.return_value = [network]
        port = port_context.current
        port['trunk_details'] = trunk_details
        device_id = port['device_id']
        device_owner = port['device_owner']
        host_id = port['binding:host_id']
        port_id = port['id']
        port_name = port['name']
        vnic_type = port['binding:vnic_type']
        profile = port['binding:profile']
        network_name = network_context.current['name']

        self.drv.update_port_postcommit(port_context)

        expected_calls = [
            mock.call.NeutronNets(),
            mock.call.create_network_segments(tenant_id, network_id,
                                              network_name,
                                              segments),
            mock.call.plug_port_into_network(device_id, host_id, port_id,
                                             network_id, tenant_id,
                                             port_name, device_owner, None,
                                             None, vnic_type,
                                             segments=segments,
                                             switch_bindings=profile,
                                             trunk_details=trunk_details)
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
        reserved_device = n_const.DEVICE_ID_RESERVED_DHCP_PORT
        old_host = 'ubuntu1'
        new_host = 'ubuntu2'
        port_id = 101
        segmentation_id = 1000
        network_context = utils.get_network_context(tenant_id,
                                                    network_id,
                                                    segmentation_id,
                                                    False)
        segments = network_context.network_segments
        network_name = network_context.current['name']

        # (Active <old host, old dhcp, vif:ovs>) to
        # (Active <old host, reserved, vif:ovs>)
        context = utils.get_port_context(
            tenant_id, network_id, old_device_id, network_context,
            device_owner=n_const.DEVICE_OWNER_DHCP)
        context.current['device_id'] = reserved_device
        vnic_type = context.current['binding:vnic_type']
        profile = context.current['binding:profile']
        port_name = context.current['name']

        network = {'tenant_id': tenant_id}
        self.drv.ndb.get_network_from_net_id.return_value = [network]

        mechanism_arista.db_lib.tenant_provisioned.return_value = True

        self.drv.ndb.get_all_network_segments.return_value = segments

        mechanism_arista.db_lib.reset_mock()
        self.drv.update_port_postcommit(context)

        expected_calls = [
            mock.call.unplug_port_from_network(old_device_id,
                                               n_const.DEVICE_OWNER_DHCP,
                                               old_host,
                                               port_id, network_id,
                                               tenant_id,
                                               None, vnic_type,
                                               switch_bindings=profile,
                                               trunk_details=None),
            mock.call.remove_security_group(None, profile),
            mock.call.tenant_provisioned(tenant_id),
        ]

        mechanism_arista.db_lib.assert_has_calls(expected_calls)

        # (Active <old host, reserved, vif:ovs>) to
        # (Down   <new host, new dhcp, vif:unbound>)
        context = utils.get_port_context(
            tenant_id, network_id, reserved_device, network_context,
            device_owner=n_const.DEVICE_OWNER_DHCP)
        context.current['device_id'] = new_device_id
        context.current['binding:host_id'] = new_host
        context.current['status'] = 'DOWN'

        physnet = dict(physnet='default')
        self.fake_rpc.get_physical_network.return_value = physnet
        context._original_binding_levels = context._binding_levels

        mechanism_arista.db_lib.reset_mock()
        self.drv.update_port_postcommit(context)

        expected_calls = []
        expected_calls += [
            mock.call.unplug_port_from_network(reserved_device,
                                               n_const.DEVICE_OWNER_DHCP,
                                               old_host,
                                               port_id, network_id,
                                               tenant_id,
                                               None, vnic_type,
                                               switch_bindings=profile,
                                               trunk_details=None),
            mock.call.remove_security_group(None, profile),
            mock.call.tenant_provisioned(tenant_id),
        ]

        mechanism_arista.db_lib.assert_has_calls(expected_calls)

        # (Down   <new host, new dhcp, vif:unbound>) to
        # (Down   <new host, new dhcp, vif:ovs>) to
        context = utils.get_port_context(
            tenant_id, network_id, new_device_id, network_context,
            device_owner=n_const.DEVICE_OWNER_DHCP, status='DOWN')
        context.current['binding:host_id'] = new_host
        context.original['binding:host_id'] = new_host

        mechanism_arista.db_lib.reset_mock()
        self.drv.update_port_postcommit(context)

        expected_calls = [
            mock.call.create_network_segments(tenant_id, network_id,
                                              network_name,
                                              segments),
            mock.call.plug_port_into_network(new_device_id,
                                             new_host,
                                             port_id, network_id,
                                             tenant_id, port_name,
                                             n_const.DEVICE_OWNER_DHCP,
                                             None, None, vnic_type,
                                             segments=segments,
                                             switch_bindings=profile,
                                             trunk_details=None),
        ]

        mechanism_arista.db_lib.assert_has_calls(expected_calls)

        # (Down   <new host, new dhcp, vif:ovs>) to
        # (Build  <new host, new dhcp, vif:ovs>) to
        context = utils.get_port_context(
            tenant_id, network_id, new_device_id, network_context,
            device_owner=n_const.DEVICE_OWNER_DHCP, status='DOWN')
        context.current['binding:host_id'] = new_host
        context.original['binding:host_id'] = new_host
        context.current['status'] = 'BUILD'

        mechanism_arista.db_lib.reset_mock()
        self.drv.update_port_postcommit(context)

        expected_calls = [
            mock.call.create_network_segments(tenant_id, network_id,
                                              network_name,
                                              segments),
            mock.call.plug_port_into_network(new_device_id,
                                             new_host,
                                             port_id, network_id,
                                             tenant_id, port_name,
                                             n_const.DEVICE_OWNER_DHCP,
                                             None, None, vnic_type,
                                             segments=segments,
                                             switch_bindings=profile,
                                             trunk_details=None),
        ]

        mechanism_arista.db_lib.assert_has_calls(expected_calls)

        # (Build  <new host, new dhcp, vif:ovs>) to
        # (Active <new host, new dhcp, vif:ovs>)
        context = utils.get_port_context(
            tenant_id, network_id, new_device_id, network_context,
            device_owner=n_const.DEVICE_OWNER_DHCP, status='BUILD')
        context.current['binding:host_id'] = new_host
        context.original['binding:host_id'] = new_host
        context.current['status'] = 'ACTIVE'

        mechanism_arista.db_lib.reset_mock()
        self.drv.update_port_postcommit(context)

    def test_supported_device_owner(self):
        device_owner_list = [n_const.DEVICE_OWNER_DHCP,
                             n_const.DEVICE_OWNER_DVR_INTERFACE,
                             'compute:*',
                             'baremetal:*',
                             'trunk:*']
        for device_owner in device_owner_list:
            self.assertTrue(mech_utils.supported_device_owner(device_owner),
                            'device_owner:%s should be a '
                            'supported device owner' % device_owner)
        device_owner = 'compute:probe'
        self.assertFalse(mech_utils.supported_device_owner(device_owner),
                         'device_owner:%s is not a '
                         'supported device owner' % device_owner)


class fake_keystone_info_class(object):
    """To generate fake Keystone Authentication token information

    Arista Driver expects Keystone auth info. This fake information
    is for testing only
    """
    auth_uri = 'abc://host:35357/v3/'
    identity_uri = 'abc://host:5000'
    admin_user = 'neutron'
    admin_password = 'fun'
    admin_tenant_name = 'tenant_name'


class FakePluginContext(object):
    """Plugin context for testing purposes only."""

    def __init__(self, tenant_id):
        self.tenant_id = tenant_id
        self.session = mock.MagicMock()
