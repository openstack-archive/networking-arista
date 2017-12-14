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
from networking_arista.tests.unit import utils


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

        self.rpc.sync_start.return_value = True
        self.rpc.sync_end.return_value = True
        self.rpc.check_cvx_availability.return_value = True
        self.sync_service.synchronize = mock.MagicMock()
        self.sync_service.do_synchronize()
        self.sync_service.synchronize.assert_called_once()

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


class SynchronizeTest(testlib_api.SqlTestCase):

    def setUp(self):
        super(SynchronizeTest, self).setUp()
        plugin_klass = importutils.import_class(
            "neutron.db.db_base_plugin_v2.NeutronDbPluginV2")
        directory.add_plugin(plugin_constants.CORE, plugin_klass())
        utils.setup_scenario()
        self.rpc = utils.MockCvx('region')
        ndb = db_lib.NeutronNets()
        self.sync_service = arista_sync.SyncService(self.rpc, ndb)

    def test_full_sync_api_calls(self):
        for i in range(len(self.sync_service.sync_order)):
            self.sync_service.sync_order[i] = mock.MagicMock()
        self.sync_service.synchronize()
        for resource_type in self.sync_service.sync_order:
            resource_type.clear_all_data.assert_called_once()
            resource_type.delete_cvx_resources.assert_called_once()
            resource_type.create_cvx_resources.assert_called_once()

    def test_full_sync_cvx_populated(self):
        self.sync_service.synchronize()
        for endpoint, data in self.rpc.endpoint_data.items():
            self.assertNotEqual(data, {})
