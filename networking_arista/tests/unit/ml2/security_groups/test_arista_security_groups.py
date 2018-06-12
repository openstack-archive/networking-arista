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

from neutron_lib import constants as n_const

from networking_arista.tests.unit.ml2.security_groups import sg_test_base


class SecurityGroupCallbacksTestCase(sg_test_base.SecurityGroupTestBase):

    def test_create_security_group(self):
        sec_group = {'security_group':
                     {'name': 'sg1',
                      'tenant_id': 't1',
                      'description': ''}}
        grp = self.plugin.create_security_group(self.context, sec_group,
                                                default_sg=True)
        expected_eapi_commands = [
            'enable',
            'configure',
            'ip access-list SG-INGRESS-%s dynamic' % grp['id'],
            'exit',
            'ip access-list SG-EGRESS-%s dynamic' % grp['id'],
            'exit',
            'exit']
        for switch in self.switches.values():
            self.assertEqual(expected_eapi_commands,
                             switch.received_commands)

    def test_delete_security_group(self):
        sec_group = {'security_group':
                     {'name': 'sg1',
                      'tenant_id': 't1',
                      'description': ''}}
        grp = self.plugin.create_security_group(self.context, sec_group,
                                                default_sg=True)
        for switch in self.switches.values():
            switch.clear_received_commands()
        self.plugin.delete_security_group(self.context, grp['id'])
        expected_eapi_commands = [
            'enable',
            'configure',
            'no ip access-list SG-INGRESS-%s' % grp['id'],
            'no ip access-list SG-EGRESS-%s' % grp['id'],
            'exit']
        for switch in self.switches.values():
            self.assertEqual(expected_eapi_commands,
                             switch.received_commands)

    def test_create_security_group_rule_ingress(self):
        direction = 'ingress'
        proto = 'tcp'
        cidr = '10.0.0.0/24'
        grp_id, _ = self.create_sg_rule(direction, proto, cidr)
        expected_eapi_commands = [
            'enable',
            'configure',
            'ip access-list SG-INGRESS-%s dynamic' % grp_id,
            'permit %s %s any' % (proto, cidr),
            'exit',
            'exit']
        for switch in self.switches.values():
            self.assertEqual(expected_eapi_commands,
                             switch.received_commands)

    def test_create_security_group_rule_egress(self):
        direction = 'egress'
        proto = 'tcp'
        cidr = '10.0.0.0/24'
        grp_id, _ = self.create_sg_rule(direction, proto, cidr)
        expected_eapi_commands = [
            'enable',
            'configure',
            'ip access-list SG-EGRESS-%s dynamic' % grp_id,
            'permit %s any %s' % (proto, cidr),
            'exit',
            'exit']
        for switch in self.switches.values():
            self.assertEqual(expected_eapi_commands,
                             switch.received_commands)

    def test_create_security_group_rule_tcp(self):
        direction = 'egress'
        proto = 'tcp'
        cidr = '10.0.0.0/24'
        grp_id, _ = self.create_sg_rule(direction, proto, cidr)
        expected_eapi_commands = [
            'enable',
            'configure',
            'ip access-list SG-EGRESS-%s dynamic' % grp_id,
            'permit %s any %s' % (proto, cidr),
            'exit',
            'exit']
        for switch in self.switches.values():
            self.assertEqual(expected_eapi_commands,
                             switch.received_commands)

    def test_create_security_group_rule_udp(self):
        direction = 'egress'
        proto = 'udp'
        cidr = '10.0.0.0/24'
        grp_id, _ = self.create_sg_rule(direction, proto, cidr)
        expected_eapi_commands = [
            'enable',
            'configure',
            'ip access-list SG-EGRESS-%s dynamic' % grp_id,
            'permit %s any %s' % (proto, cidr),
            'exit',
            'exit']
        for switch in self.switches.values():
            self.assertEqual(expected_eapi_commands,
                             switch.received_commands)

    def test_create_security_group_rule_port_range(self):
        direction = 'egress'
        proto = 'tcp'
        cidr = '10.0.0.0/24'
        range_min = 100
        range_max = 200
        grp_id, _ = self.create_sg_rule(direction, proto, cidr,
                                        range_min, range_max)
        expected_eapi_commands = [
            'enable',
            'configure',
            'ip access-list SG-EGRESS-%s dynamic' % grp_id,
            'permit %s any %s range %s %s' % (proto, cidr,
                                              range_min, range_max),
            'exit',
            'exit']
        for switch in self.switches.values():
            self.assertEqual(expected_eapi_commands,
                             switch.received_commands)

    def test_create_security_group_rule_basic_icmp(self):
        direction = 'egress'
        proto = 'icmp'
        cidr = '10.0.0.0/24'
        grp_id, _ = self.create_sg_rule(direction, proto, cidr)
        expected_eapi_commands = [
            'enable',
            'configure',
            'ip access-list SG-EGRESS-%s dynamic' % grp_id,
            'permit %s any %s' % (proto, cidr),
            'exit',
            'exit']
        for switch in self.switches.values():
            self.assertEqual(expected_eapi_commands,
                             switch.received_commands)

    def test_create_security_group_rule_icmp_type(self):
        direction = 'egress'
        proto = 'icmp'
        cidr = '10.0.0.0/24'
        message_type = 10
        grp_id, _ = self.create_sg_rule(direction, proto, cidr, message_type)
        expected_eapi_commands = [
            'enable',
            'configure',
            'ip access-list SG-EGRESS-%s dynamic' % grp_id,
            'permit %s any %s %s' % (proto, cidr, message_type),
            'exit',
            'exit']
        for switch in self.switches.values():
            self.assertEqual(expected_eapi_commands,
                             switch.received_commands)

    def test_create_security_group_rule_icmp_code(self):
        direction = 'egress'
        proto = 'icmp'
        cidr = '10.0.0.0/24'
        message_type = 10
        message_code = 100
        grp_id, _ = self.create_sg_rule(direction, proto, cidr, message_type,
                                        message_code)
        expected_eapi_commands = [
            'enable',
            'configure',
            'ip access-list SG-EGRESS-%s dynamic' % grp_id,
            'permit %s any %s %s %s' % (proto, cidr, message_type,
                                        message_code),
            'exit',
            'exit']
        for switch in self.switches.values():
            self.assertEqual(expected_eapi_commands,
                             switch.received_commands)

    def test_create_security_group_no_ip(self):
        direction = 'egress'
        proto = 'tcp'
        cidr = None
        grp_id, _ = self.create_sg_rule(direction, proto, cidr)
        expected_eapi_commands = [
            'enable',
            'configure',
            'ip access-list SG-EGRESS-%s dynamic' % grp_id,
            'permit %s any any' % proto,
            'exit',
            'exit']
        for switch in self.switches.values():
            self.assertEqual(expected_eapi_commands,
                             switch.received_commands)

    def test_create_security_group_ipv6(self):
        direction = 'egress'
        proto = 'tcp'
        cidr = None
        ethertype = 'IPv6'
        grp_id, _ = self.create_sg_rule(direction, proto, cidr,
                                        ethertype=ethertype)
        for switch in self.switches.values():
            self.assertEqual([], switch.received_commands)

    def test_delete_security_group_rule(self):
        direction = 'egress'
        proto = 'tcp'
        cidr = '10.0.0.0/24'
        grp_id, rule = self.create_sg_rule(direction, proto, cidr)
        for switch in self.switches.values():
            switch.clear_received_commands()
        self.plugin.delete_security_group_rule(self.context, rule['id'])
        expected_eapi_commands = [
            'enable',
            'configure',
            'ip access-list SG-EGRESS-%s dynamic' % grp_id,
            'no permit %s any %s' % (proto, cidr),
            'exit',
            'exit']
        for switch in self.switches.values():
            self.assertEqual(expected_eapi_commands,
                             switch.received_commands)

    def test_apply_security_group(self):
        switch_port = 'Ethernet1'
        switch_id = '11:22:33:44:55'
        switch_info = 'TOR1'
        grp_id, rule = self.create_sg_rule('egress', 'tcp', '10.0.0.0/24')
        for switch in self.switches.values():
            switch.clear_received_commands()
        net_dict = {'network': {'name': 'net',
                                'tenant_id': 't1',
                                'admin_state_up': True,
                                'shared': False,
                                'provider:physical_network': self.physnet,
                                'provider:network_type': 'vlan'}}
        network, _ = self.create_network(net_dict)
        port_dict = {'name': 'port1',
                     'tenant_id': 't1',
                     'network_id': network['id'],
                     'admin_state_up': True,
                     'fixed_ips': [],
                     'device_id': 'bm1',
                     'device_owner': n_const.DEVICE_OWNER_BAREMETAL_PREFIX,
                     'binding:host_id': 'bm-host',
                     'binding:profile': {'local_link_information': [
                         {'switch_id': switch_id,
                          'port_id': switch_port,
                          'switch_info': switch_info}]},
                     'binding:vnic_type': 'baremetal',
                     'security_groups': [grp_id]}
        port, _ = self.create_port(port_dict)
        expected_eapi_commands = [
            'show interfaces',
            'enable',
            'configure',
            'interface %s' % switch_port,
            'ip access-group SG-INGRESS-%s out' % grp_id,
            'ip access-group SG-EGRESS-%s in' % grp_id,
            'exit',
            'exit']
        # SGs are applied on binding and on status DOWN->UP,
        # so expect the commands twice
        expected_eapi_commands.extend(expected_eapi_commands)
        self.assertEqual(expected_eapi_commands,
                         self.switch1.received_commands)
        self.assertEqual([], self.switch2.received_commands)

    def test_apply_security_group_lag(self):
        switch_port = 'Ethernet1'
        port_channel = 'Port-Channel100'
        switch_id = '11:22:33:44:55'
        switch_info = 'TOR1'
        self.create_port_channel(switch_info, switch_port, port_channel)
        grp_id, rule = self.create_sg_rule('egress', 'tcp', '10.0.0.0/24')
        for switch in self.switches.values():
            switch.clear_received_commands()
        net_dict = {'network': {'name': 'net',
                                'tenant_id': 't1',
                                'admin_state_up': True,
                                'shared': False,
                                'provider:physical_network': self.physnet,
                                'provider:network_type': 'vlan'}}
        network, _ = self.create_network(net_dict)
        port_dict = {'name': 'port1',
                     'tenant_id': 't1',
                     'network_id': network['id'],
                     'admin_state_up': True,
                     'fixed_ips': [],
                     'device_id': 'bm1',
                     'device_owner': n_const.DEVICE_OWNER_BAREMETAL_PREFIX,
                     'binding:host_id': 'bm-host',
                     'binding:profile': {'local_link_information': [
                         {'switch_id': switch_id,
                          'port_id': switch_port,
                          'switch_info': switch_info}]},
                     'binding:vnic_type': 'baremetal',
                     'security_groups': [grp_id]}
        port, _ = self.create_port(port_dict)
        expected_eapi_commands = [
            'show interfaces',
            'enable',
            'configure',
            'interface %s' % port_channel,
            'ip access-group SG-INGRESS-%s out' % grp_id,
            'ip access-group SG-EGRESS-%s in' % grp_id,
            'exit',
            'exit']
        # SGs are applied on binding and on status DOWN->UP,
        # so expect the commands twice
        expected_eapi_commands.extend(expected_eapi_commands)
        self.assertEqual(expected_eapi_commands,
                         self.switch1.received_commands)
        self.assertEqual([], self.switch2.received_commands)

    def test_apply_security_group_mlag(self):
        switch_port = 'Ethernet1'
        port_channel = 'Port-Channel100'
        switch_id = '11:22:33:44:55'
        switch1_info = 'TOR1'
        switch2_info = 'TOR2'
        self.create_port_channel(switch1_info, switch_port, port_channel)
        self.create_port_channel(switch2_info, switch_port, port_channel)
        grp_id, rule = self.create_sg_rule('egress', 'tcp', '10.0.0.0/24')
        for switch in self.switches.values():
            switch.clear_received_commands()
        net_dict = {'network': {'name': 'net',
                                'tenant_id': 't1',
                                'admin_state_up': True,
                                'shared': False,
                                'provider:physical_network': self.physnet,
                                'provider:network_type': 'vlan'}}
        network, _ = self.create_network(net_dict)
        port_dict = {'name': 'port1',
                     'tenant_id': 't1',
                     'network_id': network['id'],
                     'admin_state_up': True,
                     'fixed_ips': [],
                     'device_id': 'bm1',
                     'device_owner': n_const.DEVICE_OWNER_BAREMETAL_PREFIX,
                     'binding:host_id': 'bm-host',
                     'binding:profile': {'local_link_information': [
                         {'switch_id': switch_id,
                          'port_id': switch_port,
                          'switch_info': switch1_info},
                         {'switch_id': switch_id,
                          'port_id': switch_port,
                          'switch_info': switch2_info}]},
                     'binding:vnic_type': 'baremetal',
                     'security_groups': [grp_id]}
        port, _ = self.create_port(port_dict)
        expected_eapi_commands = [
            'show interfaces',
            'enable',
            'configure',
            'interface %s' % port_channel,
            'ip access-group SG-INGRESS-%s out' % grp_id,
            'ip access-group SG-EGRESS-%s in' % grp_id,
            'exit',
            'exit']
        # SGs are applied on binding and on status DOWN->UP,
        # so expect the commands twice
        expected_eapi_commands.extend(expected_eapi_commands)
        self.assertEqual(expected_eapi_commands,
                         self.switch1.received_commands)
        self.assertEqual(expected_eapi_commands,
                         self.switch2.received_commands)

    def test_remove_security_group(self):
        switch_port = 'Ethernet1'
        switch_id = '11:22:33:44:55'
        switch_info = 'TOR1'
        grp_id, rule = self.create_sg_rule('egress', 'tcp', '10.0.0.0/24')
        net_dict = {'network': {'name': 'net',
                                'tenant_id': 't1',
                                'admin_state_up': True,
                                'shared': False,
                                'provider:physical_network': self.physnet,
                                'provider:network_type': 'vlan'}}
        network, _ = self.create_network(net_dict)
        port_dict = {'name': 'port1',
                     'tenant_id': 't1',
                     'network_id': network['id'],
                     'admin_state_up': True,
                     'fixed_ips': [],
                     'device_id': 'bm1',
                     'device_owner': n_const.DEVICE_OWNER_BAREMETAL_PREFIX,
                     'binding:host_id': 'bm-host',
                     'binding:profile': {'local_link_information': [
                         {'switch_id': switch_id,
                          'port_id': switch_port,
                          'switch_info': switch_info}]},
                     'binding:vnic_type': 'baremetal',
                     'security_groups': [grp_id]}
        port, _ = self.create_port(port_dict)
        for switch in self.switches.values():
            switch.clear_received_commands()
        self.delete_port(port['id'])
        expected_eapi_commands = [
            'show interfaces',
            'enable',
            'configure',
            'interface %s' % switch_port,
            'no ip access-group SG-INGRESS-%s out' % grp_id,
            'no ip access-group SG-EGRESS-%s in' % grp_id,
            'exit',
            'exit']
        self.assertEqual(expected_eapi_commands,
                         self.switch1.received_commands)
        self.assertEqual([], self.switch2.received_commands)

    def test_remove_security_group_lag(self):
        switch_port = 'Ethernet1'
        port_channel = 'Port-Channel100'
        switch_id = '11:22:33:44:55'
        switch_info = 'TOR1'
        self.create_port_channel(switch_info, switch_port, port_channel)
        grp_id, rule = self.create_sg_rule('egress', 'tcp', '10.0.0.0/24')
        net_dict = {'network': {'name': 'net',
                                'tenant_id': 't1',
                                'admin_state_up': True,
                                'shared': False,
                                'provider:physical_network': self.physnet,
                                'provider:network_type': 'vlan'}}
        network, _ = self.create_network(net_dict)
        port_dict = {'name': 'port1',
                     'tenant_id': 't1',
                     'network_id': network['id'],
                     'admin_state_up': True,
                     'fixed_ips': [],
                     'device_id': 'bm1',
                     'device_owner': n_const.DEVICE_OWNER_BAREMETAL_PREFIX,
                     'binding:host_id': 'bm-host',
                     'binding:profile': {'local_link_information': [
                         {'switch_id': switch_id,
                          'port_id': switch_port,
                          'switch_info': switch_info}]},
                     'binding:vnic_type': 'baremetal',
                     'security_groups': [grp_id]}
        port, _ = self.create_port(port_dict)
        for switch in self.switches.values():
            switch.clear_received_commands()
        self.delete_port(port['id'])
        expected_eapi_commands = [
            'show interfaces',
            'enable',
            'configure',
            'interface %s' % port_channel,
            'no ip access-group SG-INGRESS-%s out' % grp_id,
            'no ip access-group SG-EGRESS-%s in' % grp_id,
            'exit',
            'exit']
        self.assertEqual(expected_eapi_commands,
                         self.switch1.received_commands)
        self.assertEqual([], self.switch2.received_commands)

    def test_remove_security_group_mlag(self):
        switch_port = 'Ethernet1'
        port_channel = 'Port-Channel100'
        switch_id = '11:22:33:44:55'
        switch1_info = 'TOR1'
        switch2_info = 'TOR2'
        self.create_port_channel(switch1_info, switch_port, port_channel)
        self.create_port_channel(switch2_info, switch_port, port_channel)
        grp_id, rule = self.create_sg_rule('egress', 'tcp', '10.0.0.0/24')
        net_dict = {'network': {'name': 'net',
                                'tenant_id': 't1',
                                'admin_state_up': True,
                                'shared': False,
                                'provider:physical_network': self.physnet,
                                'provider:network_type': 'vlan'}}
        network, _ = self.create_network(net_dict)
        port_dict = {'name': 'port1',
                     'tenant_id': 't1',
                     'network_id': network['id'],
                     'admin_state_up': True,
                     'fixed_ips': [],
                     'device_id': 'bm1',
                     'device_owner': n_const.DEVICE_OWNER_BAREMETAL_PREFIX,
                     'binding:host_id': 'bm-host',
                     'binding:profile': {'local_link_information': [
                         {'switch_id': switch_id,
                          'port_id': switch_port,
                          'switch_info': switch1_info},
                         {'switch_id': switch_id,
                          'port_id': switch_port,
                          'switch_info': switch2_info}]},
                     'binding:vnic_type': 'baremetal',
                     'security_groups': [grp_id]}
        port, _ = self.create_port(port_dict)
        for switch in self.switches.values():
            switch.clear_received_commands()
        self.delete_port(port['id'])
        expected_eapi_commands = [
            'show interfaces',
            'enable',
            'configure',
            'interface %s' % port_channel,
            'no ip access-group SG-INGRESS-%s out' % grp_id,
            'no ip access-group SG-EGRESS-%s in' % grp_id,
            'exit',
            'exit']
        self.assertEqual(expected_eapi_commands,
                         self.switch1.received_commands)
        self.assertEqual(expected_eapi_commands,
                         self.switch2.received_commands)

    def test_apply_security_group_vm(self):
        grp_id, rule = self.create_sg_rule('egress', 'tcp', '10.0.0.0/24')
        net_dict = {'network': {'name': 'net',
                                'tenant_id': 't1',
                                'admin_state_up': True,
                                'shared': False,
                                'provider:physical_network': self.physnet,
                                'provider:network_type': 'vlan'}}
        network, _ = self.create_network(net_dict)
        port_dict = {'name': 'port1',
                     'tenant_id': 't1',
                     'network_id': network['id'],
                     'admin_state_up': True,
                     'fixed_ips': [],
                     'device_id': 'vm1',
                     'device_owner': n_const.DEVICE_OWNER_COMPUTE_PREFIX,
                     'binding:host_id': self.host1,
                     'binding:vnic_type': 'normal',
                     'security_groups': [grp_id]}
        for switch in self.switches.values():
            switch.clear_received_commands()
        self.create_port(port_dict)
        self.assertEqual([], self.switch1.received_commands)
        self.assertEqual([], self.switch2.received_commands)

    def test_apply_multiple_security_groups(self):
        switch_id = '00:11:22:33:44:55'
        switch_info = 'TOR1'
        switch_port = 'Ethernet1'
        proto = 'tcp'
        cidr = '10.0.0.0/24'
        grp1_id, _ = self.create_sg_rule('egress', proto, cidr)
        grp2_id, _ = self.create_sg_rule('ingress', proto, cidr,
                                         default=False)
        net_dict = {'network': {'name': 'net',
                                'tenant_id': 't1',
                                'admin_state_up': True,
                                'shared': False,
                                'provider:physical_network': self.physnet,
                                'provider:network_type': 'vlan'}}
        network, _ = self.create_network(net_dict)
        port_dict = {'name': 'port1',
                     'tenant_id': 't1',
                     'network_id': network['id'],
                     'admin_state_up': True,
                     'fixed_ips': [],
                     'device_id': 'bm1',
                     'device_owner': n_const.DEVICE_OWNER_BAREMETAL_PREFIX,
                     'binding:host_id': 'bm-host',
                     'binding:profile': {'local_link_information': [
                         {'switch_id': switch_id,
                          'port_id': switch_port,
                          'switch_info': switch_info}]},
                     'binding:vnic_type': 'baremetal',
                     'security_groups': [grp1_id, grp2_id]}
        for switch in self.switches.values():
            switch.clear_received_commands()
        port, _ = self.create_port(port_dict)
        self.assertEqual([], self.switch1.received_commands)
        self.assertEqual([], self.switch2.received_commands)
