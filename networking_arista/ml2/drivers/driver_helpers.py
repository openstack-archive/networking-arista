# Copyright (c) 2016 OpenStack Foundation
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from oslo_log import log
from six import moves

from neutron.db import api as db_api
from neutron.plugins.ml2.drivers import type_vlan

from networking_arista._i18n import _LI
from networking_arista.common import exceptions as arista_exc
from networking_arista.ml2.arista_ml2 import EOS_UNREACHABLE_MSG

LOG = log.getLogger(__name__)


class VlanSyncService(object):
    """Sync vlan assignment from CVX into the OpenStack db."""

    def __init__(self, rpc_wrapper):
        self._rpc = rpc_wrapper
        self._force_sync = True
        self._vlan_assignment_uuid = None
        self._assigned_vlans = dict()

    def force_sync(self):
        self._force_sync = True

    def _parse_vlan_ranges(self, vlan_pool, return_as_ranges=False):
        vlan_ids = set()
        if return_as_ranges:
            vlan_ids = list()
        if not vlan_pool:
            return vlan_ids
        vlan_ranges = vlan_pool.split(',')
        for vlan_range in vlan_ranges:
            endpoints = vlan_range.split('-')
            if len(endpoints) == 2:
                vlan_min = int(endpoints[0])
                vlan_max = int(endpoints[1])
                if return_as_ranges:
                    vlan_ids.append((vlan_min, vlan_max))
                else:
                    vlan_ids |= set(moves.range(vlan_min, vlan_max + 1))
            elif len(endpoints) == 1:
                single_vlan = int(endpoints[0])
                if return_as_ranges:
                    vlan_ids.append((single_vlan, single_vlan))
                else:
                    vlan_ids.add(single_vlan)
        return vlan_ids

    def get_network_vlan_ranges(self):
        return self._assigned_vlans

    def _sync_required(self):
        try:
            if not self._force_sync and self._region_in_sync():
                LOG.info(_LI('VLANs are in sync!'))
                return False
        except arista_exc.AristaRpcError:
            LOG.warning(EOS_UNREACHABLE_MSG)
            self._force_sync = True
        return True

    def _region_in_sync(self):
        eos_vlan_assignment_uuid = self._rpc.get_vlan_assignment_uuid()
        return (self._vlan_assignment_uuid and
                (self._vlan_assignment_uuid['uuid'] ==
                 eos_vlan_assignment_uuid['uuid']))

    def _set_vlan_assignment_uuid(self):
        try:
            self._vlan_assignment_uuid = self._rpc.get_vlan_assignment_uuid()
        except arista_exc.AristaRpcError:
            self._force_sync = True

    def do_synchronize(self):
        if not self._sync_required():
            return

        self.synchronize()
        self._set_vlan_assignment_uuid()

    def synchronize(self):
        LOG.info(_LI('Syncing VLANs with EOS'))
        try:
            self._rpc.register_with_eos()
            vlan_pool = self._rpc.get_vlan_allocation()
        except arista_exc.AristaRpcError:
            LOG.warning(EOS_UNREACHABLE_MSG)
            self._force_sync = True
            return

        self._assigned_vlans = {
            'default': self._parse_vlan_ranges(vlan_pool['assignedVlans'],
                                               return_as_ranges=True),
        }

        assigned_vlans = (
            self._parse_vlan_ranges(vlan_pool['assignedVlans']))
        available_vlans = frozenset(
            self._parse_vlan_ranges(vlan_pool['availableVlans']))
        used_vlans = frozenset(
            self._parse_vlan_ranges(vlan_pool['allocatedVlans']))

        self._force_sync = False

        session = db_api.get_session()
        with session.begin(subtransactions=True):
            allocs = (session.query(type_vlan.VlanAllocation).with_lockmode(
                'update'))

            for alloc in allocs:
                if alloc.physical_network != 'default':
                    session.delete(alloc)

                try:
                    assigned_vlans.remove(alloc.vlan_id)
                except KeyError:
                    session.delete(alloc)
                    continue

                if alloc.allocated and alloc.vlan_id in available_vlans:
                    alloc.update({"allocated": False})
                elif not alloc.allocated and alloc.vlan_id in used_vlans:
                    alloc.update({"allocated": True})

            for vlan_id in sorted(assigned_vlans):
                allocated = vlan_id in used_vlans
                alloc = type_vlan.VlanAllocation(physical_network='default',
                                                 vlan_id=vlan_id,
                                                 allocated=allocated)
                session.add(alloc)
