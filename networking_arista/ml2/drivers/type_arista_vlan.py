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

import threading

from oslo_config import cfg
from oslo_log import log

from neutron.i18n import _LI
from neutron.plugins.ml2.drivers.type_vlan import VlanTypeDriver

from networking_arista.common import config  # noqa
from networking_arista.ml2.arista_ml2 import AristaRPCWrapper
from networking_arista.ml2.drivers.driver_helpers import VlanSyncService

LOG = log.getLogger(__name__)


class AristaVlanTypeDriver(VlanTypeDriver):
    """Manage state for VLAN networks with ML2.

    The VlanTypeDriver implements the 'vlan' network_type. VLAN
    network segments provide connectivity between VMs and other
    devices using any connected IEEE 802.1Q conformant
    physical_network segmented into virtual networks via IEEE 802.1Q
    headers. Up to 4094 VLAN network segments can exist on each
    available physical_network.
    """

    def __init__(self):
        super(AristaVlanTypeDriver, self).__init__()
        self.rpc = AristaRPCWrapper()
        self.sync_service = VlanSyncService(self.rpc)
        self.network_vlan_ranges = dict()
        self.sync_timeout = cfg.CONF.arista_type_driver['sync_interval']

    def initialize(self):
        self.rpc.check_cli_commands()
        self.rpc.check_vlan_type_driver_commands()
        self._synchronization_thread()
        LOG.info(_LI("AristaVlanTypeDriver initialization complete"))

    def _synchronization_thread(self):
        self.sync_service.do_synchronize()
        self.network_vlan_ranges = self.sync_service.get_network_vlan_ranges()
        self.timer = threading.Timer(self.sync_timeout,
                                     self._synchronization_thread)
        self.timer.start()
