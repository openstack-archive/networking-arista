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

from neutron_lib.plugins import directory

from networking_arista.tests.unit.ml2 import ml2_test_base
from networking_arista.tests.unit import utils


class SecurityGroupTestBase(ml2_test_base.MechTestBase):

    def get_additional_service_plugins(self):
        p = super(SecurityGroupTestBase, self).get_additional_service_plugins()
        p.update({'arista_security_group_plugin': 'arista_security_group'})
        return p

    def setUp(self):
        super(SecurityGroupTestBase, self).setUp()
        self.arista_sec_gp_plugin = directory.get_plugin(
            'arista_security_group')
        self.switch1 = utils.MockSwitch()
        self.switch2 = utils.MockSwitch()
        self.switches = {'TOR1': self.switch1,
                         'TOR2': self.switch2}
        self.arista_sec_gp_plugin._switches = self.switches
        self.arista_sec_gp_plugin._port_group_info['TOR1'] = {
            'Ethernet1': {'interfaceMembership': ''},
            'Ethernet2': {'interfaceMembership': ''}}
        self.arista_sec_gp_plugin._port_group_info['TOR2'] = {
            'Ethernet1': {'interfaceMembership': ''},
            'Ethernet2': {'interfaceMembership': ''}}

    def create_port_channel(self, switch, interface, pc_name):
        intf_info = self.arista_sec_gp_plugin._port_group_info[switch]
        intf_info[interface]['interfaceMembership'] = 'Member of %s' % pc_name

    def create_sg_rule(self, direction, proto, cidr, range_min=None,
                       range_max=None, ethertype='IPv4', default=True,
                       sg_id=None):
        if sg_id is None:
            sec_group = {'security_group':
                         {'name': 'sg1',
                          'tenant_id': 't1',
                          'description': ''}}
            grp = self.plugin.create_security_group(self.context, sec_group,
                                                    default_sg=default)
            sg_id = grp['id']
        for switch in self.switches.values():
            switch.clear_received_commands()
        rule = {'security_group_rule':
                {'direction': direction,
                 'ethertype': ethertype,
                 'protocol': proto,
                 'remote_ip_prefix': cidr,
                 'port_range_min': range_min,
                 'port_range_max': range_max,
                 'security_group_id': sg_id,
                 'remote_group_id': None,
                 'tenant_id': 't1'}}
        rule = self.plugin.create_security_group_rule(self.context, rule)
        return sg_id, rule
