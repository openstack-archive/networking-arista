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

import sys
import time

from oslo_config import cfg
from oslo_log import log
from six import moves
import sqlalchemy as sa

from neutron.common import exceptions as exc
from neutron.db import api as db_api
from neutron.db import model_base
from neutron.i18n import _LE, _LI, _LW
from neutron.plugins.common import constants as p_const
from neutron.plugins.common import utils as plugin_utils
from neutron.plugins.ml2 import driver_api as api
from neutron.plugins.ml2.drivers import helpers
from networking_arista.ml2.arista_ml2 import AristaRPCWrapper
from networking_arista.common import config

LOG = log.getLogger(__name__)

class AristaVlanTypeDriver(helpers.BaseTypeDriver):
    """
    The AristaVlanTypeDriver implements the 'arista_vlan'
    network_type to allow Arista EOS to control tenant
    network VLAN allocations.
    """

    def __init__(self):
        self.rpc = AristaRPCWrapper()
        self.timeout = cfg.CONF.ml2_arista.conn_timeout
        super(AristaVlanTypeDriver, self).__init__()

    def get_type(self):
        return 'arista_vlan'

    def initialize(self):
        LOG.info(_LI("AristaVlanTypeDriver initialization complete"))

    def is_partial_segment(self, segment):
        return segment.get(api.SEGMENTATION_ID) is None

    def validate_provider_segment(self, segment):
        physical_network = segment.get(api.PHYSICAL_NETWORK)
        segmentation_id = segment.get(api.SEGMENTATION_ID)
        if physical_network:
            if segmentation_id:
                if not plugin_utils.is_valid_vlan_tag(segmentation_id):
                    msg = (_("segmentation_id out of range (%(min)s through "
                             "%(max)s)") %
                           {'min': p_const.MIN_VLAN_TAG,
                            'max': p_const.MAX_VLAN_TAG})
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

    def _get_vlan_id(self, network_id):
        timeout = time.time() + self.timeout
        vlan_id = None
        cmd = [ 'show openstack reservations region %s network %s' %
                ( self.rpc.region, network_id ) ]
        while not vlan_id and time.time() < timeout:
            result = self.rpc._run_eos_cmds(cmd)[0]
            try:
                region_map = result['networkToVlanMap'][self.rpc.region]
                vlan_id = region_map['networkToVlanMap'][network_id]
            except KeyError:
                vlan_id = 0
        return vlan_id

    def allocate_partially_specified_segment(self, network_id):
        cmd = [ 'reservation %s type vlan' % network_id ]
        self.rpc._run_openstack_cmds(cmd)
        vlan_id = self._get_vlan_id(network_id)
        return vlan_id

    def allocate_fully_specified_segment(self, network_id, vlan_id):
       cmd = [ 'reservation %s type vlan id %d' % (network_id,
                                                   vlan_id) ]
       self.rpc._run_openstack_cmds(cmd)
       vlanId = self._get_vlan_id(network_id)
       return vlanId

    def reserve_provider_segment(self, session, tenant_id, network_id, segment):
        info = {}
        physical_network = segment.get(api.PHYSICAL_NETWORK)
        if physical_network is not None:
            info['physical_network'] = physical_network
            vlan_id = segment.get(api.SEGMENTATION_ID)
            if vlan_id is not None:
                info['vlan_id'] = vlan_id

        if self.is_partial_segment(segment):
            alloc = self.allocate_partially_specified_segment(network_id)
            if not alloc:
                raise exc.NoNetworkAvailable()
        else:
            alloc = self.allocate_fully_specified_segment(network_id, vlan_id)
            if not alloc:
                raise exc.VlanIdInUse(**info)

        return {api.NETWORK_TYPE: p_const.TYPE_VLAN,
                api.PHYSICAL_NETWORK: physical_network,
                api.SEGMENTATION_ID: alloc,
                api.MTU: self.get_mtu(physical_network)}

    def allocate_tenant_segment(self, session, tenant_id, network_id):
        alloc = self.allocate_partially_specified_segment(network_id)
        if not alloc:
            return
        return {api.NETWORK_TYPE: p_const.TYPE_VLAN,
                api.PHYSICAL_NETWORK: None,
                api.SEGMENTATION_ID: alloc,
                api.MTU: 0}

    def release_segment(self, session, tenant_id, network_id, segment):
        physical_network = segment[api.PHYSICAL_NETWORK]
        vlan_id = segment[api.SEGMENTATION_ID]
        segment_id = get_segment_id(session, physical_network, vlan_id)
        cmd = [ 'no reservation %d' ]
        try:
            self.rpc._run_openstack_cmds(cmd)
        except:
            LOG.warning(_LW("No vlan_id %(vlan_id)s found on physical "
                            "network %(physical_network)s"),
                        {'vlan_id': vlan_id,
                         'physical_network': physical_network})

    def get_mtu(self, physical_network):
        seg_mtu = super(AristaVlanTypeDriver, self).get_mtu()
        mtu = []
        if seg_mtu > 0:
            mtu.append(seg_mtu)
        return min(mtu) if mtu else 0
