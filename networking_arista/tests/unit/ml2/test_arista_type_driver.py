# Copyright (c) 2016 OpenStack Foundation
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

from neutron.db import api as db_api
from neutron.plugins.ml2.drivers import type_vlan
from neutron.tests import base
from neutron.tests.unit import testlib_api

from networking_arista.ml2.drivers.driver_helpers import VlanSyncService
from networking_arista.ml2.drivers.type_arista_vlan import AristaVlanTypeDriver
import networking_arista.tests.unit.ml2.utils as utils

import mock
from mock import patch
from oslo_config import cfg

EAPI_SEND_FUNC = ('networking_arista.ml2.arista_ml2.AristaRPCWrapperEapi'
                  '._send_eapi_req')


class AristaTypeDriverTest(base.BaseTestCase):

    def setUp(self):
        super(AristaTypeDriverTest, self).setUp()
        utils.setup_arista_wrapper_config(cfg)

    @patch(EAPI_SEND_FUNC)
    def test_initialize_type_driver(self, mock_send_eapi_req):
        type_driver = AristaVlanTypeDriver()
        type_driver.sync_service._force_sync = False
        type_driver.sync_service._vlan_assignment_uuid = {'uuid': 1}
        type_driver.sync_service._rpc = mock.MagicMock()
        rpc = type_driver.sync_service._rpc
        rpc.get_vlan_assignment_uuid.return_value = {'uuid': 1}
        type_driver.initialize()

        cmds = ['show openstack instances']
        cmds += ['show openstack features']
        cmds += ['show openstack resource-pool vlan region RegionOne uuid']

        calls = []
        calls.extend(mock.call(cmds=[cmd], commands_to_log=[cmd])
                     for cmd in cmds)
        for call in calls:
            assert call in mock_send_eapi_req.mock_calls

        type_driver.timer.cancel()


class VlanSyncServiceTest(testlib_api.SqlTestCase):
    """Test that VLANs are synchronized between EOS and Neutron."""

    def _ensure_in_db(self, assigned, allocated, available):
        session = db_api.get_session()
        with session.begin():
            vlans = session.query(type_vlan.VlanAllocation).all()
            for vlan in vlans:
                assert vlan.vlan_id in assigned

                if vlan.vlan_id in available:
                    assert not vlan.allocated
                elif vlan.vlan_id in allocated:
                    assert vlan.allocated

    def test_synchronization_test(self):
        rpc = mock.MagicMock()

        rpc.get_vlan_allocation.return_value = {
            'assignedVlans': '1-10,21-30',
            'availableVlans': '1-5,21,23,25,27,29',
            'allocatedVlans': '6-10,22,24,26,28,30'
        }

        assigned = [i for i in range(1, 11)]
        assigned += [i for i in range(21, 31)]

        available = [1, 2, 3, 4, 5, 21, 23, 25, 27, 29]
        allocated = list(set(assigned) - set(available))

        sync_service = VlanSyncService(rpc)
        sync_service.synchronize()

        self._ensure_in_db(assigned, allocated, available)

        # Call synchronize again which returns different data
        rpc.get_vlan_allocation.return_value = {
            'assignedVlans': '51-60,71-80',
            'availableVlans': '51-55,71,73,75,77,79',
            'allocatedVlans': '56-60,72,74,76,78,80'
        }

        assigned = [i for i in range(51, 61)]
        assigned += [i for i in range(71, 81)]

        available = [51, 52, 53, 54, 55, 71, 73, 75, 77, 79]
        allocated = list(set(assigned) - set(available))

        sync_service = VlanSyncService(rpc)
        sync_service.synchronize()

        self._ensure_in_db(assigned, allocated, available)
