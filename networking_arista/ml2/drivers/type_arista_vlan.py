# Copyright (c) 2013 OpenStack Foundation
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

import threading

from oslo_config import cfg
from oslo_log import log
import sqlalchemy as sa

from neutron.common import constants as q_const
from neutron.common import exceptions as exc
from neutron.common import utils
from neutron.db import api as db_api
from neutron.db import model_base
from neutron.i18n import _LI
from neutron.i18n import _LW
from neutron.plugins.common import constants as p_const
from neutron.plugins.ml2 import driver_api as api
from neutron.plugins.ml2.drivers.arista import config  # noqa
from neutron.plugins.ml2.drivers.arista import exceptions as arista_exc
from neutron.plugins.ml2.drivers import helpers

from networking_arista.ml2.arista_ml2 import AristaRPCWrapper
from networking_arista.ml2.arista_ml2 import EOS_UNREACHABLE_MSG

LOG = log.getLogger(__name__)

ARISTA_TYPE_DRIVER_OPTS = [
    cfg.IntOpt('vlan_sync_interval',
               default=10,
               help=_('VLAN Sync interval in seconds between Neutron plugin '
                      'and EOS. This interval defines how often the VLAN '
                      'synchronization is performed. This is an optional '
                      'field. If not set, a value of 10 seconds is '
                      'assumed.')),
]

cfg.CONF.register_opts(ARISTA_TYPE_DRIVER_OPTS, "ml2_arista")


class VlanAllocation(model_base.BASEV2):
    """Represent allocation state of a vlan_id on a physical network.

    If allocated is False, the vlan_id on the physical_network is
    available for allocation to a tenant network. If allocated is
    True, the vlan_id on the physical_network is in use, either as a
    tenant or provider network.

    When an allocation is released, if the vlan_id for the
    physical_network is inside the pool described by
    VlanTypeDriver.network_vlan_ranges, then allocated is set to
    False. If it is outside the pool, the record is deleted.
    """

    __tablename__ = 'ml2_vlan_allocations'
    __table_args__ = (
        sa.Index('ix_ml2_vlan_allocations_physical_network_allocated',
                 'physical_network', 'allocated'),
        model_base.BASEV2.__table_args__,)

    physical_network = sa.Column(sa.String(64), nullable=False,
                                 primary_key=True)
    vlan_id = sa.Column(sa.Integer, nullable=False, primary_key=True,
                        autoincrement=False)
    allocated = sa.Column(sa.Boolean, nullable=False)


class AristaVlanTypeDriver(helpers.SegmentTypeDriver):
    """Manage state for VLAN networks with ML2.

    The VlanTypeDriver implements the 'vlan' network_type. VLAN
    network segments provide connectivity between VMs and other
    devices using any connected IEEE 802.1Q conformant
    physical_network segmented into virtual networks via IEEE 802.1Q
    headers. Up to 4094 VLAN network segments can exist on each
    available physical_network.
    """

    def __init__(self):
        super(AristaVlanTypeDriver, self).__init__(VlanAllocation)
        self.rpc = AristaRPCWrapper()
        self.eos = VlanSyncService(self.rpc)
        self.sync_timeout = cfg.CONF.ml2_arista['vlan_sync_interval']

    def get_type(self):
        return p_const.TYPE_VLAN

    def initialize(self):
        self.rpc.check_cli_commands()
        self.rpc.check_vlan_type_driver_commands()
        self._synchronization_thread()
        LOG.info(_LI("AristaVlanTypeDriver initialization complete"))

    def is_partial_segment(self, segment):
        return segment.get(api.SEGMENTATION_ID) is None

    def validate_provider_segment(self, segment):
        physical_network = segment.get(api.PHYSICAL_NETWORK)
        segmentation_id = segment.get(api.SEGMENTATION_ID)
        if physical_network:
            if physical_network != 'default':
                msg = (_("physical_network '%s' unknown "
                         " for VLAN provider network") % physical_network)
                raise exc.InvalidInput(error_message=msg)
            if segmentation_id:
                if not utils.is_valid_vlan_tag(segmentation_id):
                    msg = (_("segmentation_id out of range (%(min)s through "
                             "%(max)s)") %
                           {'min': q_const.MIN_VLAN_TAG,
                            'max': q_const.MAX_VLAN_TAG})
                    raise exc.InvalidInput(error_message=msg)
        elif segmentation_id:
            msg = _("segmentation_id requires physical_network for VLAN "
                    "provider network")
            raise exc.InvalidInput(error_message=msg)

        for key, value in segment.items():
            if value and key not in [api.NETWORK_TYPE,
                                     api.PHYSICAL_NETWORK,
                                     api.SEGMENTATION_ID]:
                msg = _("%s prohibited for VLAN provider network") % key
                raise exc.InvalidInput(error_message=msg)

    def reserve_provider_segment(self, session, segment):
        filters = {}
        physical_network = segment.get(api.PHYSICAL_NETWORK)
        if physical_network is not None:
            filters['physical_network'] = physical_network
            vlan_id = segment.get(api.SEGMENTATION_ID)
            if vlan_id is not None:
                filters['vlan_id'] = vlan_id

        if self.is_partial_segment(segment):
            alloc = self.allocate_partially_specified_segment(
                session, **filters)
            if not alloc:
                raise exc.NoNetworkAvailable()
        else:
            alloc = self.allocate_fully_specified_segment(
                session, **filters)
            if not alloc:
                raise exc.VlanIdInUse(**filters)

        return {api.NETWORK_TYPE: p_const.TYPE_VLAN,
                api.PHYSICAL_NETWORK: alloc.physical_network,
                api.SEGMENTATION_ID: alloc.vlan_id,
                api.MTU: self.get_mtu(alloc.physical_network)}

    def allocate_tenant_segment(self, session):
        alloc = self.allocate_partially_specified_segment(session)
        if not alloc:
            return
        return {api.NETWORK_TYPE: p_const.TYPE_VLAN,
                api.PHYSICAL_NETWORK: alloc.physical_network,
                api.SEGMENTATION_ID: alloc.vlan_id,
                api.MTU: self.get_mtu(alloc.physical_network)}

    def release_segment(self, session, segment):
        physical_network = segment[api.PHYSICAL_NETWORK]
        vlan_id = segment[api.SEGMENTATION_ID]

        with session.begin(subtransactions=True):
            query = (session.query(VlanAllocation).
                     filter_by(physical_network=physical_network,
                               vlan_id=vlan_id))
            if vlan_id in self._allocated_vlans:
                count = query.update({"allocated": False})
                if count:
                    LOG.debug("Releasing vlan %(vlan_id)s on physical "
                              "network %(physical_network)s to pool",
                              {'vlan_id': vlan_id,
                               'physical_network': physical_network})
            else:
                count = query.delete()
                if count:
                    LOG.debug("Releasing vlan %(vlan_id)s on physical "
                              "network %(physical_network)s outside pool",
                              {'vlan_id': vlan_id,
                               'physical_network': physical_network})

        if not count:
            LOG.warning(_LW("No vlan_id %(vlan_id)s found on physical "
                            "network %(physical_network)s"),
                        {'vlan_id': vlan_id,
                         'physical_network': physical_network})

    def get_mtu(self, physical_network):
        seg_mtu = super(AristaVlanTypeDriver, self).get_mtu()
        mtu = []
        if seg_mtu > 0:
            mtu.append(seg_mtu)
        if physical_network in self.physnet_mtus:
            mtu.append(int(self.physnet_mtus[physical_network]))
        return min(mtu) if mtu else 0

    def _synchronization_thread(self):
        self._allocated_vlans = self.eos.do_synchronize()
        self.timer = threading.Timer(self.sync_timeout,
                                     self._synchronization_thread)
        self.timer.start()


class VlanSyncService(object):
    """Sync vlan allocation from CVX into the OpenStack db."""

    def __init__(self, rpc_wrapper):
        self._rpc = rpc_wrapper
        self._force_sync = True
        self._vlan_allocation_uuid = None
        self._allocated_vlans = frozenset()

    def force_sync(self):
        self._force_sync = True

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
        eos_vlan_allocation_uuid = self._rpc.get_vlan_allocation_uuid()
        return (self._vlan_allocation_uuid and
                (self._vlan_allocation_uuid['uuid'] ==
                 eos_vlan_allocation_uuid['uuid']))

    def _set_vlan_allocation_uuid(self):
        try:
            self._vlan_allocation_uuid = self._rpc.get_vlan_allocation_uuid()
        except arista_exc.AristaRpcError:
            self._force_sync = True

    def do_synchronize(self):
        if not self._sync_required():
            return self._allocated_vlans

        self.synchronize()
        self._set_vlan_allocation_uuid()
        return self._allocated_vlans

    def synchronize(self):
        LOG.info(_LI('Syncing VLANs with EOS'))
        try:
            self._rpc.register_with_eos()
            vlan_pool = self._rpc.get_vlan_allocation()
        except arista_exc.AristaRpcError:
            LOG.warning(EOS_UNREACHABLE_MSG)
            self._force_sync = True
            return

        allocated_vlans = (
            self._rpc.parse_vlan_ranges(vlan_pool['allocatedVlans']))
        available_vlans = frozenset(
            self._rpc.parse_vlan_ranges(vlan_pool['availableVlans']))
        used_vlans = frozenset(
            self._rpc.parse_vlan_ranges(vlan_pool['reservedVlans']))

        self._allocated_vlans = frozenset(allocated_vlans)
        self._force_sync = False

        session = db_api.get_session()
        with session.begin(subtransactions=True):
            allocs = (session.query(VlanAllocation).with_lockmode('update'))

            for alloc in allocs:
                if alloc.physical_network != 'default':
                    session.delete(alloc)

                try:
                    allocated_vlans.remove(alloc.vlan_id)
                except KeyError:
                    session.delete(alloc)
                    continue

                if alloc.allocated and alloc.vlan_id in available_vlans:
                    alloc.update({"allocated": False})
                elif not alloc.allocated and alloc.vlan_id in used_vlans:
                    alloc.update({"allocated": True})

            for vlan_id in sorted(allocated_vlans):
                allocated = vlan_id in used_vlans
                alloc = VlanAllocation(physical_network='default',
                                       vlan_id=vlan_id,
                                       allocated=allocated)
                session.add(alloc)
