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

from eventlet import greenthread
from eventlet import queue
import mock

from neutron_lib.plugins import constants as plugin_constants
from neutron_lib.plugins import directory
from oslo_config import cfg
from oslo_utils import importutils

from neutron.tests.unit import testlib_api

from networking_arista.common import constants as a_const
from networking_arista.ml2 import arista_sync
from networking_arista.ml2.mechanism_arista import MechResource
from networking_arista.tests.unit import utils


class SyncServiceTest(testlib_api.SqlTestCase):
    """Test cases for the sync service."""

    def setUp(self):
        super(SyncServiceTest, self).setUp()
        utils.setup_arista_wrapper_config(cfg)
        plugin_klass = importutils.import_class(
            "neutron.db.db_base_plugin_v2.NeutronDbPluginV2")
        directory.add_plugin(plugin_constants.CORE, plugin_klass())
        utils.setup_scenario()
        self.mech_queue = queue.LightQueue()
        self.sync_service = arista_sync.AristaSyncWorker(self.mech_queue)
        self.sync_service._rpc = utils.MockCvx('region')

    def tearDown(self):
        if self.sync_service._running:
            self.sync_service.stop()
            self.sync_service.wait()
        super(SyncServiceTest, self).tearDown()

    def test_start(self):
        self.sync_service.start()
        self.assertTrue(self.sync_service._running)
        self.assertIsNotNone(self.sync_service._thread)
        self.assertIsNotNone(self.sync_service.sync_order)
        self.assertIsNotNone(self.sync_service.done)

    def test_start_twice(self):
        self.sync_service.start()
        current_thread = self.sync_service._thread
        self.sync_service.start()
        self.assertEqual(self.sync_service._thread, current_thread)

    def test_stop_graceful(self):
        self.test_start()
        running_thread = self.sync_service._thread
        self.sync_service.stop()
        self.sync_service.wait()
        self.assertFalse(self.sync_service._running)
        self.assertTrue(running_thread.dead)
        self.assertIsNone(self.sync_service._thread)

    def test_stop_ungraceful(self):
        self.test_start()
        running_thread = self.sync_service._thread
        self.sync_service.stop(graceful=False)
        self.assertTrue(running_thread.dead)
        self.assertIsNone(self.sync_service._thread)

    def test_reset(self):
        self.test_start()
        old_thread = self.sync_service._thread
        self.sync_service.reset()
        self.assertNotEqual(self.sync_service._thread, old_thread)

    def test_resource_class_full_coverage(self):
        self.sync_service.initialize()
        for i in range(len(self.sync_service.sync_order)):
            self.sync_service.sync_order[i] = mock.MagicMock()
        self.sync_service.synchronize_resources()
        for resource_type in self.sync_service.sync_order:
            resource_type.delete_cvx_resources.assert_called_once()
            resource_type.create_cvx_resources.assert_called_once()

    def test_full_sync_cvx_populated(self):
        self.sync_service.initialize()
        self.sync_service.synchronize_resources()
        for endpoint, data in self.sync_service._rpc.endpoint_data.items():
            self.assertNotEqual(data, {})

    def test_process_mech_update(self):
        self.sync_service.initialize()
        for resource_type in a_const.ALL_RESOURCE_TYPES:
            res_cls = mock.MagicMock()
            with mock.patch.object(self.sync_service,
                                   'get_resource_class') as get:
                get.return_value = res_cls
                res = MechResource('id', resource_type, a_const.CREATE)
                self.sync_service.update_neutron_resource(res)
                get.assert_called_once_with(resource_type)
                res_cls.update_neutron_resource.assert_called_once_with(
                    'id', a_const.CREATE)
                get.reset_mock()
                get.return_value = res_cls
                res = MechResource('id', resource_type, a_const.DELETE)
                self.sync_service.update_neutron_resource(res)
                get.assert_called_once_with(resource_type)
                res_cls.update_neutron_resource.assert_called_once_with(
                    'id', a_const.DELETE)

    def test_force_full_sync(self):
        self.sync_service.initialize()
        for i in range(len(self.sync_service.sync_order)):
            self.sync_service.sync_order[i] = mock.MagicMock()
        self.sync_service.force_full_sync()
        for resource_type in self.sync_service.sync_order:
            resource_type.clear_all_data.assert_called_once()

    def test_sync_timeout(self):
        self.sync_service.initialize()
        with mock.patch.object(
                self.sync_service, 'check_if_out_of_sync') as oos:
            self.sync_service.wait_for_sync_required()
            oos.assert_called_once()

    def test_full_sync_required(self):
        self.sync_service.initialize()
        self.sync_service.cvx_uuid = 'old-id'
        self.sync_service._rpc = mock.MagicMock()
        self.sync_service._rpc.get_cvx_uuid.return_value = 'new-id'
        with mock.patch.object(self.sync_service, 'force_full_sync') as ffs:
            self.assertTrue(self.sync_service.check_if_out_of_sync())
            ffs.assert_called_once()
            self.assertEqual(self.sync_service._synchronizing_uuid, 'new-id')
            self.assertNotEqual(self.sync_service._last_sync_time, 0)

    def test_mech_queue_timeout(self):
        self.sync_service.initialize()
        self.assertFalse(self.sync_service.wait_for_mech_driver_update(1))

    def test_mech_queue_updated(self):
        self.sync_service.initialize()
        resource = MechResource('tid', a_const.TENANT_RESOURCE, a_const.CREATE)
        self.mech_queue.put(resource)
        # Must yield to allow resource to be available on the queue
        greenthread.sleep(0)
        self.assertTrue(self.sync_service.wait_for_mech_driver_update(1))
        self.assertEqual(self.sync_service._resources_to_update, [resource])

    def test_sync_start_fail(self):
        self.sync_service.initialize()
        self.sync_service._rpc = mock.MagicMock()
        self.sync_service._rpc.sync_start.return_value = False
        self.assertEqual(self.sync_service._last_sync_time, 0)
        for i in range(len(self.sync_service.sync_order)):
            self.sync_service.sync_order[i] = mock.MagicMock()
        self.sync_service.synchronize_resources()
        for resource_type in self.sync_service.sync_order:
            resource_type.delete_cvx_resources.assert_not_called()
            resource_type.create_cvx_resources.assert_not_called()
        self.sync_service._rpc.sync_end.assert_not_called()
