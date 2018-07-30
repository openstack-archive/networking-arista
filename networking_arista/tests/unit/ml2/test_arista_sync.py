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
from neutron_lib.plugins import constants as plugin_constants
from neutron_lib.plugins import directory
from oslo_utils import importutils

from neutron.tests.unit import testlib_api

from networking_arista.common import db_lib
from networking_arista.ml2 import arista_sync


class SyncServiceTest(testlib_api.SqlTestCase):
    """Test cases for the sync service."""

    def setUp(self):
        super(SyncServiceTest, self).setUp()
        plugin_klass = importutils.import_class(
            "neutron.db.db_base_plugin_v2.NeutronDbPluginV2")
        directory.add_plugin(plugin_constants.CORE, plugin_klass())
        self.rpc = mock.MagicMock()
        ndb = db_lib.NeutronNets()
        self.sync_service = arista_sync.SyncService(self.rpc, ndb)
        self.sync_service._force_sync = False

    def test_region_in_sync(self):
        """Tests whether the region_in_sync() behaves as expected."""
        region_updated_time = {
            'regionName': 'RegionOne',
            'regionTimestamp': '12345'
        }
        self.rpc.get_region_updated_time.return_value = region_updated_time
        self.sync_service._region_updated_time = None
        assert not self.sync_service._region_in_sync()
        self.sync_service._region_updated_time = region_updated_time
        assert self.sync_service._region_in_sync()

    def test_synchronize_required(self):
        """Tests whether synchronize() sends the right commands.

           This test verifies a scenario when the sync is required.
        """
        region_updated_time = {
            'regionName': 'RegionOne',
            'regionTimestamp': '12345'
        }
        self.rpc.get_region_updated_time.return_value = region_updated_time
        self.sync_service._region_updated_time = {
            'regionName': 'RegionOne',
            'regionTimestamp': '0',
        }

        tenant_id = 'tenant-1'
        network_id = 'net-1'
        segmentation_id = 42
        segment_id = 'segment_id_1'
        db_lib.remember_tenant(tenant_id)
        db_lib.remember_network_segment(tenant_id, network_id, segmentation_id,
                                        segment_id)

        self.rpc.get_tenants.return_value = {}

        self.rpc.sync_start.return_value = True
        self.rpc.sync_end.return_value = True
        self.rpc.check_cvx_availability.return_value = True

        self.rpc._baremetal_supported.return_value = False
        self.rpc.get_all_baremetal_hosts.return_value = {}

        self.sync_service.do_synchronize()

        expected_calls = [
            mock.call.perform_sync_of_sg(),
            mock.call.check_cvx_availability(),
            mock.call.get_region_updated_time(),
            mock.call.sync_start(),
            mock.call.register_with_eos(sync=True),
            mock.call.check_supported_features(),
            mock.call.get_tenants(),
            mock.call.create_network_bulk(
                tenant_id,
                [{'network_id': network_id,
                  'segments': [],
                  'network_name': '',
                  'shared': False}],
                sync=True),
            mock.call.sync_end(),
            mock.call.get_region_updated_time()
        ]
        self.assertTrue(self.rpc.mock_calls == expected_calls,
                        "Seen: %s\nExpected: %s" % (
                            self.rpc.mock_calls,
                            expected_calls,
                            )
                        )

        db_lib.forget_network_segment(tenant_id, network_id)
        db_lib.forget_tenant(tenant_id)

    def test_sync_start_failure(self):
        """Tests that we force another sync when sync_start fails.

           The failure could be because a region does not exist or
           because another controller has the sync lock.
        """
        self.sync_service.synchronize = mock.MagicMock()
        region_updated_time = {
            'regionName': 'RegionOne',
            'regionTimestamp': '424242'
        }
        self.rpc.get_region_updated_time.return_value = region_updated_time
        self.rpc.check_cvx_availability.return_value = True
        self.rpc.sync_start.return_value = False
        self.sync_service.do_synchronize()
        self.assertFalse(self.sync_service.synchronize.called)
        self.assertTrue(self.sync_service._force_sync)

    def test_synchronize_not_required(self):
        """Tests whether synchronize() sends the right commands.

           This test verifies a scenario when the sync is not required.
        """
        region_updated_time = {
            'regionName': 'RegionOne',
            'regionTimestamp': '424242'
        }
        self.rpc.get_region_updated_time.return_value = region_updated_time
        self.rpc.check_cvx_availability.return_value = True
        self.sync_service._region_updated_time = {
            'regionName': 'RegionOne',
            'regionTimestamp': '424242',
        }

        self.rpc.sync_start.return_value = True
        self.rpc.sync_end.return_value = True

        self.sync_service.do_synchronize()

        # If the timestamps do match, then the sync should not be executed.
        expected_calls = [
            mock.call.perform_sync_of_sg(),
            mock.call.check_cvx_availability(),
            mock.call.get_region_updated_time(),
        ]
        self.assertTrue(self.rpc.mock_calls[:4] == expected_calls,
                        "Seen: %s\nExpected: %s" % (
                            self.rpc.mock_calls,
                            expected_calls,
                            )
                        )

    def test_synchronize_one_network(self):
        """Test to ensure that only the required resources are sent to EOS."""

        # Store two tenants in a db and a single tenant in EOS.
        # The sync should send details of the second tenant to EOS
        tenant_1_id = 'tenant-1'
        tenant_1_net_1_id = 'ten-1-net-1'
        tenant_1_net_1_seg_id = 11
        db_lib.remember_tenant(tenant_1_id)
        db_lib.remember_network_segment(tenant_1_id, tenant_1_net_1_id,
                                        tenant_1_net_1_seg_id, 'segment_id_11')

        tenant_2_id = 'tenant-2'
        tenant_2_net_1_id = 'ten-2-net-1'
        tenant_2_net_1_seg_id = 21
        db_lib.remember_tenant(tenant_2_id)
        db_lib.remember_network_segment(tenant_2_id, tenant_2_net_1_id,
                                        tenant_2_net_1_seg_id, 'segment_id_21')

        self.rpc.get_tenants.return_value = {
            tenant_1_id: {
                'tenantVmInstances': {},
                'tenantBaremetalInstances': {},
                'tenantNetworks': {
                    tenant_1_net_1_id: {
                        'networkId': tenant_1_net_1_id,
                        'shared': False,
                        'networkName': 'Net1',
                        'segmenationType': 'vlan',
                        'segmentationTypeId': tenant_1_net_1_seg_id,
                    }
                }
            }
        }

        self.rpc.sync_start.return_value = True
        self.rpc.sync_end.return_value = True
        self.rpc.check_cvx_availability.return_value = True
        self.rpc.get_region_updated_time.return_value = {'regionTimestamp': 1}

        self.rpc._baremetal_supported.return_value = False
        self.rpc.get_all_baremetal_hosts.return_value = {}

        self.sync_service.do_synchronize()

        expected_calls = [
            mock.call.perform_sync_of_sg(),
            mock.call.check_cvx_availability(),
            mock.call.get_region_updated_time(),
            mock.call.sync_start(),
            mock.call.register_with_eos(sync=True),
            mock.call.check_supported_features(),
            mock.call.get_tenants(),

            mock.call.create_network_bulk(
                tenant_2_id,
                [{'network_id': tenant_2_net_1_id,
                  'segments': [],
                  'network_name': '',
                  'shared': False}],
                sync=True),

            mock.call.sync_end(),
            mock.call.get_region_updated_time()
        ]

        self.rpc.assert_has_calls(expected_calls)

        db_lib.forget_network_segment(tenant_1_id, tenant_1_net_1_id)
        db_lib.forget_network_segment(tenant_2_id, tenant_2_net_1_id)
        db_lib.forget_tenant(tenant_1_id)
        db_lib.forget_tenant(tenant_2_id)

    def test_synchronize_all_networks(self):
        """Test to ensure that only the required resources are sent to EOS."""

        # Store two tenants in a db and none on EOS.
        # The sync should send details of all tenants to EOS
        tenant_1_id = u'tenant-1'
        tenant_1_net_1_id = u'ten-1-net-1'
        tenant_1_net_1_seg_id = 11
        db_lib.remember_tenant(tenant_1_id)
        db_lib.remember_network_segment(tenant_1_id, tenant_1_net_1_id,
                                        tenant_1_net_1_seg_id, 'segment_id_11')

        tenant_2_id = u'tenant-2'
        tenant_2_net_1_id = u'ten-2-net-1'
        tenant_2_net_1_seg_id = 21
        db_lib.remember_tenant(tenant_2_id)
        db_lib.remember_network_segment(tenant_2_id, tenant_2_net_1_id,
                                        tenant_2_net_1_seg_id, 'segment_id_21')

        self.rpc.get_tenants.return_value = {}

        self.rpc.sync_start.return_value = True
        self.rpc.sync_end.return_value = True
        self.rpc.check_cvx_availability.return_value = True
        self.rpc.get_region_updated_time.return_value = {'regionTimestamp': 1}

        self.rpc._baremetal_supported.return_value = False
        self.rpc.get_all_baremetal_hosts.return_value = {}

        self.sync_service.do_synchronize()

        expected_calls = [
            mock.call.perform_sync_of_sg(),
            mock.call.check_cvx_availability(),
            mock.call.get_region_updated_time(),
            mock.call.sync_start(),
            mock.call.register_with_eos(sync=True),
            mock.call.check_supported_features(),
            mock.call.get_tenants(),

            mock.call.create_network_bulk(
                tenant_1_id,
                [{'network_id': tenant_1_net_1_id,
                  'segments': [],
                  'network_name': '',
                  'shared': False}],
                sync=True),

            mock.call.create_network_bulk(
                tenant_2_id,
                [{'network_id': tenant_2_net_1_id,
                  'segments': [],
                  'network_name': '',
                  'shared': False}],
                sync=True),
            mock.call.sync_end(),
            mock.call.get_region_updated_time()
        ]

        # The create_network_bulk() can be called in different order. So split
        # it up. The first part checks if the initial set of methods are
        # invoked.
        idx = expected_calls.index(mock.call.get_tenants()) + 1
        self.assertTrue(self.rpc.mock_calls[:idx] == expected_calls[:idx],
                        "Seen: %s\nExpected: %s" % (
                            self.rpc.mock_calls,
                            expected_calls,
                            )
                        )
        # Check if tenant 1 networks are created. It must be one of the two
        # methods.
        self.assertTrue(self.rpc.mock_calls[idx] in
                        expected_calls[idx:idx + 2],
                        "Seen: %s\nExpected: %s" % (
                            self.rpc.mock_calls,
                            expected_calls,
                            )
                        )
        # Check if tenant 2 networks are created. It must be one of the two
        # methods.
        self.assertTrue(self.rpc.mock_calls[idx + 1] in
                        expected_calls[idx:idx + 2],
                        "Seen: %s\nExpected: %s" % (
                            self.rpc.mock_calls,
                            expected_calls,
                            )
                        )
        # Check if the sync end methods are invoked.
        self.assertTrue(self.rpc.mock_calls[idx + 2:] ==
                        expected_calls[idx + 2:],
                        "Seen: %s\nExpected: %s" % (
                            self.rpc.mock_calls,
                            expected_calls,
                            )
                        )

        db_lib.forget_network_segment(tenant_1_id, tenant_1_net_1_id)
        db_lib.forget_network_segment(tenant_2_id, tenant_2_net_1_id)
        db_lib.forget_tenant(tenant_1_id)
        db_lib.forget_tenant(tenant_2_id)

    def test_synchronize_shared_network_ports(self):
        """Test to ensure that shared network ports are synchronized.

        This is to ensure that ports whose tenant id does not match the
        network tenant id are still sync'd. The test stores a network and
        2 ports in the neutron db. The sync should send details of the ports
        to EOS.
        """
        host_id = 'host1'
        network_id = 'net-1'
        network_seg_id = 11
        tenant_1_id = 'tenant-1'
        db_lib.remember_tenant(tenant_1_id)
        db_lib.remember_network_segment(tenant_1_id, network_id,
                                        network_seg_id, 'segment_id_11')

        port_1_id = 'port-1'
        device_1_id = 'vm-1'
        db_lib.remember_vm(device_1_id, host_id, port_1_id, network_id,
                           tenant_1_id)

        port_2_id = 'port-2'
        device_2_id = 'vm-2'
        # Shared network ports are stored under the network owner tenant
        db_lib.remember_vm(device_2_id, host_id, port_2_id, network_id,
                           tenant_1_id)

        self.rpc.get_tenants.return_value = {
            tenant_1_id: {
                'tenantVmInstances': {},
                'tenantBaremetalInstances': {},
                'tenantNetworks': {
                    network_id: {
                        'networkId': network_id,
                        'shared': True,
                        'networkName': '',
                        'segmenationType': 'vlan',
                        'segmentationTypeId': network_seg_id,
                    }
                }
            }
        }

        self.rpc.sync_start.return_value = True
        self.rpc.sync_end.return_value = True
        self.rpc.check_cvx_availability.return_value = True
        self.rpc.get_region_updated_time.return_value = {'regionTimestamp': 1}

        self.rpc._baremetal_supported.return_value = False
        self.rpc.get_all_baremetal_hosts.return_value = {}

        self.sync_service.do_synchronize()

        expected_calls = [
            mock.call.perform_sync_of_sg(),
            mock.call.check_cvx_availability(),
            mock.call.get_region_updated_time(),
            mock.call.sync_start(),
            mock.call.register_with_eos(sync=True),
            mock.call.check_supported_features(),
            mock.call.get_tenants(),
            mock.call.create_instance_bulk(
                tenant_1_id,
                {},
                {'vm-1':
                 {'ports': [{'deviceId': 'vm-1',
                             'portId': 'port-1',
                             'networkId': 'net-1',
                             'hosts': ['host1']}],
                  'vmId': 'vm-1',
                  'baremetal_instance': False},
                 'vm-2':
                 {'ports': [{'deviceId': 'vm-2',
                             'portId': 'port-2',
                             'networkId': 'net-1',
                             'hosts': ['host1']}],
                  'vmId': 'vm-2',
                  'baremetal_instance': False}},
                {},
                sync=True),
            mock.call.sync_end(),
            mock.call.get_region_updated_time()
        ]

        self.rpc.assert_has_calls(expected_calls)

    def test_synchronize_deleted_instances(self):
        """Test to ensure instances are synchronized."""

        tenant_1_id = 'tenant-1'
        db_lib.remember_tenant(tenant_1_id)

        region_tenants = {
            tenant_1_id: {
                'tenantVmInstances': {
                    'vm-instance-1': {
                        'vmInstanceId': 'vm-instance-1',
                    },
                    'dhcp-instacne-1': {
                        'vmInstanceId': 'dhcp-instance-1',
                    },
                },
                'tenantBaremetalInstances': {
                    'bm-instance-1': {
                        'baremetalInstanceId': 'bm-instance-1',
                    },
                },
                'tenantRouterInstances': {
                    'router-instance-1': {
                        'routerPorts': {},
                    },
                },
                'tenantNetworks': {}
            }
        }
        self.rpc.get_tenants.return_value = region_tenants

        self.rpc.sync_start.return_value = True
        self.rpc.sync_end.return_value = True
        self.rpc.check_cvx_availability.return_value = True
        self.rpc.get_region_updated_time.return_value = {'regionTimestamp': 1}
        self.rpc.bm_and_dvr_supported.return_value = True

        self.sync_service.do_synchronize()

        expected_calls = [
            mock.call.perform_sync_of_sg(),
            mock.call.check_cvx_availability(),
            mock.call.get_region_updated_time(),
            mock.call.sync_start(),
            mock.call.register_with_eos(sync=True),
            mock.call.check_supported_features(),
            mock.call.get_tenants(),
            mock.call.delete_vm_bulk(u'tenant-1',
                                     ['vm-instance-1'],
                                     sync=True),
            mock.call.delete_dhcp_bulk(u'tenant-1',
                                       ['dhcp-instacne-1'],
                                       sync=True),
            mock.call.bm_and_dvr_supported(),
            mock.call.delete_instance_bulk(u'tenant-1',
                                           ['router-instance-1'],
                                           'router', sync=True),
            mock.call.bm_and_dvr_supported(),
            mock.call.delete_instance_bulk(u'tenant-1',
                                           ['bm-instance-1'],
                                           'baremetal', sync=True),
            mock.call.sync_end(),
            mock.call.get_region_updated_time()
        ]

        self.rpc.assert_has_calls(expected_calls)
