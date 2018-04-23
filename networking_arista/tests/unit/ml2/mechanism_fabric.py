# Copyright (c) 2018 OpenStack Foundation
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

from neutron_lib.api.definitions import portbindings
from neutron_lib import constants
from neutron_lib.plugins.ml2 import api as driver_api


class TestFabricDriver(driver_api.MechanismDriver):

    def initialize(self):
        pass

    def bind_port(self, context):
        """Bind port to a network segment."""
        port = context.current
        for segment in context.segments_to_bind:
            physnet = segment.get(driver_api.PHYSICAL_NETWORK)
            if (not physnet and
                    segment[driver_api.NETWORK_TYPE] == constants.TYPE_VXLAN):
                physnet_map = {'host1': 'physnet1',
                               'host2': 'physnet2'}
                physnet = physnet_map.get(port[portbindings.HOST_ID],
                                          'other_physnet')
                next_segment = context.allocate_dynamic_segment(
                    {'network_id': context.network.current['id'],
                     'network_type': constants.TYPE_VLAN,
                     'physical_network': physnet})
                context.continue_binding(segment['id'], [next_segment])
                return True
