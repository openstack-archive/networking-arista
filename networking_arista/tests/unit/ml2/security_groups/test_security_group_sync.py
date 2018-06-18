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

from neutron.tests import base
from neutron_lib import constants as n_const
from oslo_config import cfg

from networking_arista.ml2.security_groups import security_group_sync
from networking_arista.tests.unit.ml2.security_groups import sg_test_base
from networking_arista.tests.unit import utils


class SecurityGroupSyncTestCase(sg_test_base.SecurityGroupTestBase):

    def setUp(self):
        super(SecurityGroupSyncTestCase, self).setUp()
        self.sync_worker = security_group_sync.AristaSecurityGroupSyncWorker()
        self.sync_worker._switches = self.switches
        self.sync_worker._port_group_info = (
            self.arista_sec_gp_plugin._port_group_info)

    def assertCmdSequenceReceived(self, expected_commands, actual_commands,
                                  sg_cmd=True):
        first_cmd = expected_commands[0]
        self.assertIn(first_cmd, actual_commands)
        for idx, cmd in enumerate(actual_commands):
            if cmd == first_cmd:
                first_cmd_idx = idx
        if sg_cmd:
            first_rule_idx = first_cmd_idx + 1
            last_rule_idx = first_cmd_idx + len(expected_commands) - 1
            self.assertItemsEqual(
                expected_commands[1:-1],
                actual_commands[first_rule_idx:last_rule_idx])
        else:
            for idx in range(len(expected_commands)):
                self.assertEqual(actual_commands[first_cmd_idx + idx],
                                 expected_commands[idx])

    def test_synchronize(self):
        """Setup a scenario and ensure that sync recreates the scenario

        Scenario is:
        SG 1:
            rule 1: permit egress tcp 10.0.0.0/24
            rule 2: permit egress udp 10.0.0.0/24
        SG 2:
            rule 1: permit egress tcp 10.0.0.0/24
            rule 2: permit egress udp 10.0.0.0/24
        Port 1:
            SG1 on switch TOR1, Ethernet1
        Port 2:
            SG2 on switch TOR1 and switch TOR2, Port-Channel100
        """

        switch_port1 = 'Ethernet1'
        switch_port2 = 'Ethernet2'
        port_channel = 'Port-Channel100'
        switch_id = '11:22:33:44:55'
        switch1_info = 'TOR1'
        switch2_info = 'TOR2'
        proto1 = 'tcp'
        proto2 = 'udp'
        cidr = '10.0.0.0/24'
        self.create_port_channel(switch1_info, switch_port2, port_channel)
        self.create_port_channel(switch2_info, switch_port2, port_channel)
        grp1_id, _ = self.create_sg_rule('egress', proto1, cidr)
        self.create_sg_rule('egress', proto2, cidr, sg_id=grp1_id)
        grp2_id, _ = self.create_sg_rule('ingress', proto1, cidr,
                                         default=False)
        self.create_sg_rule('ingress', proto2, cidr, default=False,
                            sg_id=grp2_id)
        net_dict = {'network': {'name': 'net',
                                'tenant_id': 't1',
                                'admin_state_up': True,
                                'shared': False,
                                'provider:physical_network': self.physnet,
                                'provider:network_type': 'vlan'}}
        network, _ = self.create_network(net_dict)
        port1_dict = {'name': 'port1',
                      'tenant_id': 't1',
                      'network_id': network['id'],
                      'admin_state_up': True,
                      'fixed_ips': [],
                      'device_id': 'bm1',
                      'device_owner': n_const.DEVICE_OWNER_BAREMETAL_PREFIX,
                      'binding:host_id': 'bm-host1',
                      'binding:profile': {'local_link_information': [
                          {'switch_id': switch_id,
                           'port_id': switch_port1,
                           'switch_info': switch1_info}]},
                      'binding:vnic_type': 'baremetal',
                      'security_groups': [grp1_id]}
        port1, _ = self.create_port(port1_dict)
        port2_dict = {'name': 'port2',
                      'tenant_id': 't1',
                      'network_id': network['id'],
                      'admin_state_up': True,
                      'fixed_ips': [],
                      'device_id': 'bm2',
                      'device_owner': n_const.DEVICE_OWNER_BAREMETAL_PREFIX,
                      'binding:host_id': 'bm-host2',
                      'binding:profile': {'local_link_information': [
                          {'switch_id': switch_id,
                           'port_id': switch_port2,
                           'switch_info': switch1_info},
                          {'switch_id': switch_id,
                           'port_id': switch_port2,
                           'switch_info': switch2_info}]},
                      'binding:vnic_type': 'baremetal',
                      'security_groups': [grp2_id]}
        port2, _ = self.create_port(port2_dict)
        for switch in self.switches.values():
            switch.clear_received_commands()
        self.sync_worker.synchronize()
        switch1_expected_cmd_seqs = [
            ['ip access-list SG-INGRESS-%s' % grp1_id,
             'no 1-$',
             'exit'],
            ['ip access-list SG-EGRESS-%s' % grp1_id,
             'no 1-$',
             'permit %s any %s' % (proto1, cidr),
             'permit %s any %s' % (proto2, cidr),
             'exit'],
            ['ip access-list SG-INGRESS-%s' % grp2_id,
             'no 1-$',
             'permit %s %s any' % (proto1, cidr),
             'permit %s %s any' % (proto2, cidr),
             'exit'],
            ['ip access-list SG-EGRESS-%s' % grp2_id,
             'no 1-$',
             'exit'],
            ['interface %s' % switch_port1,
             'ip access-group SG-INGRESS-%s out' % grp1_id,
             'ip access-group SG-EGRESS-%s in' % grp1_id,
             'exit'],
            ['interface %s' % port_channel,
             'ip access-group SG-INGRESS-%s out' % grp2_id,
             'ip access-group SG-EGRESS-%s in' % grp2_id,
             'exit']]
        switch2_expected_cmd_seqs = [
            ['ip access-list SG-INGRESS-%s' % grp1_id,
             'no 1-$',
             'exit'],
            ['ip access-list SG-EGRESS-%s' % grp1_id,
             'no 1-$',
             'permit %s any %s' % (proto1, cidr),
             'permit %s any %s' % (proto2, cidr),
             'exit'],
            ['ip access-list SG-INGRESS-%s' % grp2_id,
             'no 1-$',
             'permit %s %s any' % (proto1, cidr),
             'permit %s %s any' % (proto2, cidr),
             'exit'],
            ['ip access-list SG-EGRESS-%s' % grp2_id,
             'no 1-$',
             'exit'],
            ['interface %s' % port_channel,
             'ip access-group SG-INGRESS-%s out' % grp2_id,
             'ip access-group SG-EGRESS-%s in' % grp2_id,
             'exit']]
        for cmd_seq in switch1_expected_cmd_seqs:
            self.assertCmdSequenceReceived(cmd_seq,
                                           self.switch1.received_commands)
        for cmd_seq in switch2_expected_cmd_seqs:
            self.assertCmdSequenceReceived(cmd_seq,
                                           self.switch2.received_commands)

    def test_sync_vm_port(self):
        proto = 'tcp'
        cidr = '10.0.0.0/24'
        grp_id, _ = self.create_sg_rule('egress', proto, cidr)
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
                     'Security_groups': [grp_id]}
        self.create_port(port_dict)
        for switch in self.switches.values():
            switch.clear_received_commands()
        self.sync_worker.synchronize()
        expected_cmds = [
            'enable',
            'configure',
            'ip access-list SG-INGRESS-%s' % grp_id,
            'no 1-$',
            'exit',
            'ip access-list SG-EGRESS-%s' % grp_id,
            'no 1-$',
            'permit %s any %s' % (proto, cidr),
            'exit',
            'exit',
            'show interfaces']
        self.assertEqual(expected_cmds, self.switch1.received_commands)
        self.assertEqual(expected_cmds, self.switch2.received_commands)

    def test_sync_multiple_sgs_per_port(self):
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
        port, _ = self.create_port(port_dict)
        self.sync_worker.synchronize()
        # The security groups may be synced in either order, so just assert
        # that neither group was applied
        unexpected_cmds = [
            'interface %s' % switch_port,
            'ip access-group SG-INGRESS-%s out' % grp1_id,
            'ip access-group SG-EGRESS-%s in' % grp1_id,
            'ip access-group SG-INGRESS-%s out' % grp2_id,
            'ip access-group SG-EGRESS-%s in' % grp2_id
            ]
        for cmd in unexpected_cmds:
            self.assertNotIn(cmd, self.switch1.received_commands)
            self.assertNotIn(cmd, self.switch2.received_commands)

    def test_sync_unsupported_rules(self):
        grp_id, _ = self.create_sg_rule('egress', 'tcp', None,
                                        ethertype='IPv6')
        for switch in self.switches.values():
            switch.clear_received_commands()
        self.sync_worker.synchronize()
        expected_cmds = [
            'enable',
            'configure',
            'ip access-list SG-INGRESS-%s' % grp_id,
            'no 1-$',
            'exit',
            'ip access-list SG-EGRESS-%s' % grp_id,
            'no 1-$',
            'exit',
            'exit',
            'show interfaces']
        self.assertEqual(expected_cmds, self.switch1.received_commands)
        self.assertEqual(expected_cmds, self.switch2.received_commands)


class SecurityGroupSyncWorkerTestCase(base.BaseTestCase):

    def setUp(self):
        utils.setup_arista_wrapper_config(cfg)
        super(SecurityGroupSyncWorkerTestCase, self).setUp()
        self.sync_worker = security_group_sync.AristaSecurityGroupSyncWorker()

    def tearDown(self):
        if self.sync_worker._loop is not None:
            self.sync_worker._loop.stop()
        super(SecurityGroupSyncWorkerTestCase, self).tearDown()

    def test_start(self):
        self.sync_worker.start()
        self.assertIsNotNone(self.sync_worker._loop)
        self.assertTrue(self.sync_worker._loop._running)
        self.assertIsNotNone(self.sync_worker._switches)
        self.assertIsNotNone(self.sync_worker._loop.done)

    def test_start_twice(self):
        self.sync_worker.start()
        current_loop = self.sync_worker._loop
        self.assertRaises(RuntimeError, self.sync_worker.start)
        self.assertEqual(self.sync_worker._loop, current_loop)

    def test_stop(self):
        self.test_start()
        running_loop = self.sync_worker._loop
        self.sync_worker.stop()
        self.sync_worker.wait()
        self.assertFalse(running_loop._running)
        self.assertIsNone(self.sync_worker._loop)

    def test_reset(self):
        self.test_start()
        old_loop = self.sync_worker._loop
        self.sync_worker.reset()
        self.assertNotEqual(self.sync_worker._loop, old_loop)
