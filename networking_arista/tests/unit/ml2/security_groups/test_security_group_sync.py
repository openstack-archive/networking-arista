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

import collections

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

    def assertAclsEqual(self, expected_acls, switch_acls):
        self.assertItemsEqual(expected_acls.keys(), switch_acls.keys())
        for acl in expected_acls.keys():
            self.assertItemsEqual(expected_acls[acl], switch_acls[acl])

    def assertBindingsEqual(self, expected_bindings, switch_bindings):
        switch_intf_to_acl = collections.defaultdict(list)
        for acl, dir_bindings in switch_bindings.items():
            for direction, intfs in dir_bindings.items():
                for intf in intfs:
                    switch_intf_to_acl[intf].append(
                        'ip access-group %s %s' % (acl, direction))
        self.assertItemsEqual(expected_bindings.keys(),
                              switch_intf_to_acl.keys())
        for intf in expected_bindings.keys():
            self.assertItemsEqual(expected_bindings[intf],
                                  switch_intf_to_acl[intf])

    def test_synchronize(self):
        """Setup a scenario and ensure that sync recreates the scenario

        Scenario is:
        SG 1:
            rule 1: permit egress tcp 10.0.0.0/24
            rule 2: permit egress udp 10.0.0.0/24
        SG 2:
            rule 1: permit ingress tcp 10.0.0.0/24
            rule 2: permit ingress udp 10.0.0.0/24
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
        self.sync_worker.synchronize()
        switch1_expected_acls = {
            'SG-INGRESS-%s' % grp1_id: [],
            'SG-EGRESS-%s' % grp1_id: [
                'permit %s any %s' % (proto1, cidr),
                'permit %s any %s' % (proto2, cidr)],
            'SG-INGRESS-%s' % grp2_id: [
                'permit %s %s any' % (proto1, cidr),
                'permit %s %s any' % (proto2, cidr)],
            'SG-EGRESS-%s' % grp2_id: []}
        switch1_expected_bindings = {
            switch_port1: [
                'ip access-group SG-INGRESS-%s out' % grp1_id,
                'ip access-group SG-EGRESS-%s in' % grp1_id],
            port_channel: [
                'ip access-group SG-INGRESS-%s out' % grp2_id,
                'ip access-group SG-EGRESS-%s in' % grp2_id]}
        switch2_expected_acls = {
            'SG-INGRESS-%s' % grp1_id: [],
            'SG-EGRESS-%s' % grp1_id: [
                'permit %s any %s' % (proto1, cidr),
                'permit %s any %s' % (proto2, cidr)],
            'SG-INGRESS-%s' % grp2_id: [
                'permit %s %s any' % (proto1, cidr),
                'permit %s %s any' % (proto2, cidr)],
            'SG-EGRESS-%s' % grp2_id: []}
        switch2_expected_bindings = {
            port_channel: [
                'ip access-group SG-INGRESS-%s out' % grp2_id,
                'ip access-group SG-EGRESS-%s in' % grp2_id]}
        self.assertAclsEqual(switch1_expected_acls, self.switch1._acl_rules)
        self.assertAclsEqual(switch2_expected_acls, self.switch2._acl_rules)
        self.assertBindingsEqual(switch1_expected_bindings,
                                 self.switch1._bindings)
        self.assertBindingsEqual(switch2_expected_bindings,
                                 self.switch2._bindings)

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
            switch.reset_switch()
        self.sync_worker.synchronize()
        expected_rules = {
            'SG-INGRESS-%s' % grp_id: [],
            'SG-EGRESS-%s' % grp_id: [
                'permit %s any %s' % (proto, cidr)]}
        self.assertAclsEqual(expected_rules, self.switch1._acl_rules)
        self.assertAclsEqual(expected_rules, self.switch2._acl_rules)

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
            switch.reset_switch()
        self.sync_worker.synchronize()
        expected_rules = {
            'SG-INGRESS-%s' % grp_id: [],
            'SG-EGRESS-%s' % grp_id: []}
        self.assertEqual(expected_rules, self.switch1._acl_rules)
        self.assertEqual(expected_rules, self.switch2._acl_rules)

    def test_sync_missing_acl(self):
        grp_id, _ = self.create_sg_rule('egress', 'tcp', None)
        self.switch1.execute(['enable',
                              'configure',
                              'no ip access-list SG-EGRESS-%s' % grp_id,
                              'exit'])
        self.assertEqual({'SG-INGRESS-%s' % grp_id: []},
                         self.switch1._acl_rules)
        self.sync_worker.synchronize()
        expected_rules = {
            'SG-INGRESS-%s' % grp_id: [],
            'SG-EGRESS-%s' % grp_id: ['permit tcp any any']}
        self.assertEqual(expected_rules, self.switch1._acl_rules)

    def test_sync_extra_acl(self):
        grp_id = 'fake-os-sg'
        extra_rule = 'permit tcp any any'
        self.switch1.execute(['enable',
                              'configure',
                              'ip access-list %s dynamic' % grp_id,
                              extra_rule,
                              'exit',
                              'exit'])
        self.assertEqual({grp_id: [extra_rule]}, self.switch1._acl_rules)
        self.sync_worker.synchronize()
        self.assertEqual({}, self.switch1._acl_rules)

    def test_sync_missing_rule(self):
        grp_id, _ = self.create_sg_rule('egress', 'tcp', None)
        self.switch1.execute(['enable',
                              'configure',
                              'ip access-list SG-EGRESS-%s dynamic' % grp_id,
                              'no permit tcp any any',
                              'exit'])
        expected_rules = {'SG-INGRESS-%s' % grp_id: [],
                          'SG-EGRESS-%s' % grp_id: []}
        self.assertEqual(expected_rules, self.switch1._acl_rules)
        self.sync_worker.synchronize()
        expected_rules = {
            'SG-INGRESS-%s' % grp_id: [],
            'SG-EGRESS-%s' % grp_id: ['permit tcp any any']}
        self.assertEqual(expected_rules, self.switch1._acl_rules)

    def test_sync_extra_rule(self):
        grp_id, _ = self.create_sg_rule('egress', 'tcp', None)
        extra_rule = 'permit udp any any'
        self.switch1.execute(['enable',
                              'configure',
                              'ip access-list SG-EGRESS-%s dynamic' % grp_id,
                              extra_rule,
                              'exit',
                              'exit'])
        expected_rules = {
            'SG-INGRESS-%s' % grp_id: [],
            'SG-EGRESS-%s' % grp_id: ['permit tcp any any', extra_rule]}
        self.assertAclsEqual(expected_rules, self.switch1._acl_rules)
        self.sync_worker.synchronize()
        expected_rules = {
            'SG-INGRESS-%s' % grp_id: [],
            'SG-EGRESS-%s' % grp_id: ['permit tcp any any']}
        self.assertEqual(expected_rules, self.switch1._acl_rules)

    def test_sync_missing_binding(self):
        switch_port = 'Ethernet1'
        switch_id = '11:22:33:44:55'
        switch_info = 'TOR1'
        grp_id, _ = self.create_sg_rule('egress', 'tcp', None)
        net_dict = {'network': {'name': 'net',
                                'tenant_id': 't1',
                                'admin_state_up': True,
                                'shared': False,
                                'provider:physical_network': self.physnet,
                                'provider:network_type': 'vlan'}}
        network, _ = self.create_network(net_dict)
        port_dict = {'name': 'port',
                     'tenant_id': 't1',
                     'network_id': network['id'],
                     'admin_state_up': True,
                     'fixed_ips': [],
                     'device_id': 'bm',
                     'device_owner': n_const.DEVICE_OWNER_BAREMETAL_PREFIX,
                     'binding:host_id': 'bm-host',
                     'binding:profile': {'local_link_information': [
                         {'switch_id': switch_id,
                          'port_id': switch_port,
                          'switch_info': switch_info}]},
                     'binding:vnic_type': 'baremetal',
                     'security_groups': [grp_id]}
        port, _ = self.create_port(port_dict)
        self.switch1.execute(['configure',
                              'interface %s' % switch_port,
                              'no ip access-group SG-EGRESS-%s in' % grp_id,
                              'exit',
                              'exit'])
        expected_bindings = {
            switch_port: [
                'ip access-group SG-INGRESS-%s out' % grp_id]}
        self.assertBindingsEqual(expected_bindings, self.switch1._bindings)
        self.sync_worker.synchronize()
        expected_bindings = {
            switch_port: [
                'ip access-group SG-INGRESS-%s out' % grp_id,
                'ip access-group SG-EGRESS-%s in' % grp_id]}
        self.assertBindingsEqual(expected_bindings, self.switch1._bindings)

    def test_sync_extra_binding(self):
        switch_port = 'Ethernet1'
        extra_acl = 'bad-acl'
        self.switch1.execute(['configure',
                              'interface %s' % switch_port,
                              'ip access-group %s in' % extra_acl,
                              'exit',
                              'exit'])
        expected_bindings = {
            switch_port: [
                'ip access-group %s in' % extra_acl]}
        self.assertBindingsEqual(expected_bindings, self.switch1._bindings)
        self.sync_worker.synchronize()
        self.assertBindingsEqual(dict(), self.switch1._bindings)

    def test_sync_binding_changed(self):
        wrong_acl = 'bad-acl'
        switch_port = 'Ethernet1'
        switch_id = '11:22:33:44:55'
        switch_info = 'TOR1'
        grp_id, _ = self.create_sg_rule('egress', 'tcp', None)
        net_dict = {'network': {'name': 'net',
                                'tenant_id': 't1',
                                'admin_state_up': True,
                                'shared': False,
                                'provider:physical_network': self.physnet,
                                'provider:network_type': 'vlan'}}
        network, _ = self.create_network(net_dict)
        port_dict = {'name': 'port',
                     'tenant_id': 't1',
                     'network_id': network['id'],
                     'admin_state_up': True,
                     'fixed_ips': [],
                     'device_id': 'bm',
                     'device_owner': n_const.DEVICE_OWNER_BAREMETAL_PREFIX,
                     'binding:host_id': 'bm-host',
                     'binding:profile': {'local_link_information': [
                         {'switch_id': switch_id,
                          'port_id': switch_port,
                          'switch_info': switch_info}]},
                     'binding:vnic_type': 'baremetal',
                     'security_groups': [grp_id]}
        port, _ = self.create_port(port_dict)
        self.switch1.execute(['configure',
                              'interface %s' % switch_port,
                              'ip access-group %s out' % wrong_acl,
                              'exit',
                              'exit'])
        expected_bindings = {
            switch_port: [
                'ip access-group %s out' % wrong_acl,
                'ip access-group SG-EGRESS-%s in' % grp_id]}
        self.assertBindingsEqual(expected_bindings, self.switch1._bindings)
        self.sync_worker.synchronize()
        expected_bindings = {
            switch_port: [
                'ip access-group SG-INGRESS-%s out' % grp_id,
                'ip access-group SG-EGRESS-%s in' % grp_id]}
        self.assertBindingsEqual(expected_bindings, self.switch1._bindings)


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
