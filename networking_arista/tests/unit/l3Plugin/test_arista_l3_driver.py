# Copyright (c) 2013 OpenStack Foundation
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

import hashlib
import itertools
import mock
from oslo_config import cfg

from neutron.tests import base
from neutron.tests.unit.db import test_db_base_plugin_v2
from neutron_lib import context
from neutron_lib.plugins import constants
from neutron_lib.plugins import directory

from networking_arista.common import exceptions as arista_exc
from networking_arista.l3Plugin import arista_l3_driver as arista
from networking_arista.l3Plugin import l3_arista
from networking_arista.tests.unit import utils


def setup_arista_config(value='', vrf=False, mlag=False):
    cfg.CONF.set_override('primary_l3_host', value, "l3_arista")
    cfg.CONF.set_override('primary_l3_host_username', value, "l3_arista")
    if vrf:
        cfg.CONF.set_override('use_vrf', vrf, "l3_arista")
    if mlag:
        cfg.CONF.set_override('secondary_l3_host', value, "l3_arista")
        cfg.CONF.set_override('mlag_config', mlag, "l3_arista")


class AristaL3DriverTestCasesDefaultVrf(base.BaseTestCase):
    """Test cases to test the RPC between Arista Driver and EOS.

    Tests all methods used to send commands between Arista L3 Driver and EOS
    to program routing functions in Default VRF.
    """

    def setUp(self):
        super(AristaL3DriverTestCasesDefaultVrf, self).setUp()
        setup_arista_config('value')
        self.drv = arista.AristaL3Driver()
        self.drv._servers = []
        self.drv._servers.append(mock.MagicMock())

    def test_no_exception_on_correct_configuration(self):
        self.assertIsNotNone(self.drv)

    def test_create_router_on_eos(self):
        router_name = 'test-router-1'
        route_domain = '123:123'

        self.drv.create_router_on_eos(router_name, route_domain,
                                      self.drv._servers[0])
        cmds = ['enable', 'configure', 'exit']

        self.drv._servers[0].execute.assert_called_once_with(cmds)

    def test_delete_router_from_eos(self):
        router_name = 'test-router-1'

        self.drv.delete_router_from_eos(router_name, self.drv._servers[0])
        cmds = ['enable', 'configure', 'exit']

        self.drv._servers[0].execute.assert_called_once_with(cmds)

    def test_add_interface_to_router_on_eos(self):
        router_name = 'test-router-1'
        segment_id = '123'
        router_ip = '10.10.10.10'
        gw_ip = '10.10.10.1'
        mask = '255.255.255.0'

        self.drv.add_interface_to_router(segment_id, router_name, gw_ip,
                                         router_ip, mask, self.drv._servers[0])
        cmds = ['enable', 'configure', 'ip routing',
                'vlan %s' % segment_id, 'exit',
                'interface vlan %s' % segment_id,
                'ip address %s/%s' % (gw_ip, mask), 'exit']

        self.drv._servers[0].execute.assert_called_once_with(cmds)

    def test_delete_interface_from_router_on_eos(self):
        router_name = 'test-router-1'
        segment_id = '123'

        self.drv.delete_interface_from_router(segment_id, router_name,
                                              self.drv._servers[0])
        cmds = ['enable', 'configure', 'no interface vlan %s' % segment_id,
                'exit']

        self.drv._servers[0].execute.assert_called_once_with(cmds)


class AristaL3DriverTestCasesUsingVRFs(base.BaseTestCase):
    """Test cases to test the RPC between Arista Driver and EOS.

    Tests all methods used to send commands between Arista L3 Driver and EOS
    to program routing functions using multiple VRFs.
    Note that the configuration commands are different when VRFs are used.
    """

    def setUp(self):
        super(AristaL3DriverTestCasesUsingVRFs, self).setUp()
        setup_arista_config('value', vrf=True)
        self.drv = arista.AristaL3Driver()
        self.drv._servers = []
        self.drv._servers.append(mock.MagicMock())

    def test_no_exception_on_correct_configuration(self):
        self.assertIsNotNone(self.drv)

    def test_create_router_on_eos(self):
        max_vrfs = 5
        routers = ['testRouter-%s' % n for n in range(max_vrfs)]
        domains = ['10%s' % n for n in range(max_vrfs)]

        for (r, d) in zip(routers, domains):
            self.drv.create_router_on_eos(r, d, self.drv._servers[0])

            cmds = ['enable', 'configure',
                    'vrf definition %s' % r,
                    'rd %(rd)s:%(rd)s' % {'rd': d}, 'exit', 'exit']

            self.drv._servers[0].execute.assert_called_with(cmds)

    def test_delete_router_from_eos(self):
        max_vrfs = 5
        routers = ['testRouter-%s' % n for n in range(max_vrfs)]

        for r in routers:
            self.drv.delete_router_from_eos(r, self.drv._servers[0])
            cmds = ['enable', 'configure', 'no vrf definition %s' % r,
                    'exit']

            self.drv._servers[0].execute.assert_called_with(cmds)

    def test_add_interface_to_router_on_eos(self):
        router_name = 'test-router-1'
        segment_id = '123'
        router_ip = '10.10.10.10'
        gw_ip = '10.10.10.1'
        mask = '255.255.255.0'

        self.drv.add_interface_to_router(segment_id, router_name, gw_ip,
                                         router_ip, mask, self.drv._servers[0])
        cmds = ['enable', 'configure',
                'ip routing vrf %s' % router_name,
                'vlan %s' % segment_id, 'exit',
                'interface vlan %s' % segment_id,
                'vrf forwarding %s' % router_name,
                'ip address %s/%s' % (gw_ip, mask), 'exit']

        self.drv._servers[0].execute.assert_called_once_with(cmds)

    def test_delete_interface_from_router_on_eos(self):
        router_name = 'test-router-1'
        segment_id = '123'

        self.drv.delete_interface_from_router(segment_id, router_name,
                                              self.drv._servers[0])
        cmds = ['enable', 'configure', 'no interface vlan %s' % segment_id,
                'exit']

        self.drv._servers[0].execute.assert_called_once_with(cmds)


class AristaL3DriverTestCasesMlagConfig(base.BaseTestCase):
    """Test cases to test the RPC between Arista Driver and EOS.

    Tests all methods used to send commands between Arista L3 Driver and EOS
    to program routing functions in Default VRF using MLAG configuration.
    MLAG configuration means that the commands will be sent to both
    primary and secondary Arista Switches.
    """

    def setUp(self):
        super(AristaL3DriverTestCasesMlagConfig, self).setUp()
        setup_arista_config('value', mlag=True)
        self.drv = arista.AristaL3Driver()
        self.drv._servers = []
        self.drv._servers.append(mock.MagicMock())
        self.drv._servers.append(mock.MagicMock())

    def test_no_exception_on_correct_configuration(self):
        self.assertIsNotNone(self.drv)

    def test_create_router_on_eos(self):
        router_name = 'test-router-1'
        route_domain = '123:123'
        router_mac = '00:11:22:33:44:55'

        for s in self.drv._servers:
            self.drv.create_router_on_eos(router_name, route_domain, s)
            cmds = ['enable', 'configure',
                    'ip virtual-router mac-address %s' % router_mac, 'exit']

            s.execute.assert_called_with(cmds)

    def test_delete_router_from_eos(self):
        router_name = 'test-router-1'

        for s in self.drv._servers:
            self.drv.delete_router_from_eos(router_name, s)
            cmds = ['enable', 'configure', 'exit']

            s.execute.assert_called_once_with(cmds)

    def test_add_interface_to_router_on_eos(self):
        router_name = 'test-router-1'
        segment_id = '123'
        router_ip = '10.10.10.10'
        gw_ip = '10.10.10.1'
        mask = '255.255.255.0'

        for s in self.drv._servers:
            self.drv.add_interface_to_router(segment_id, router_name, gw_ip,
                                             router_ip, mask, s)
            cmds = ['enable', 'configure', 'ip routing',
                    'vlan %s' % segment_id, 'exit',
                    'interface vlan %s' % segment_id,
                    'ip address %s' % router_ip,
                    'ip virtual-router address %s' % gw_ip, 'exit']

            s.execute.assert_called_once_with(cmds)

    def test_delete_interface_from_router_on_eos(self):
        router_name = 'test-router-1'
        segment_id = '123'

        for s in self.drv._servers:
            self.drv.delete_interface_from_router(segment_id, router_name, s)

            cmds = ['enable', 'configure', 'no interface vlan %s' % segment_id,
                    'exit']

            s.execute.assert_called_once_with(cmds)


class AristaL3DriverTestCasesMlagVRFConfig(base.BaseTestCase):
    """Test cases to test the RPC between Arista Driver and EOS.

    Tests all methods used to send commands between Arista L3 Driver and EOS
    to program routing functions in VRFs using MLAG configuration.
    """

    def setUp(self):
        super(AristaL3DriverTestCasesMlagVRFConfig, self).setUp()
        setup_arista_config('value', mlag=True, vrf=True)
        self.drv = arista.AristaL3Driver()
        self.drv._servers = []
        self.drv._servers.append(mock.MagicMock())
        self.drv._servers.append(mock.MagicMock())

    def test_no_exception_on_correct_configuration(self):
        self.assertIsNotNone(self.drv)

    def test_create_router_on_eos(self):
        max_vrfs = 5
        routers = ['testRouter-%s' % n for n in range(max_vrfs)]
        domains = ['10%s' % n for n in range(max_vrfs)]

        router_mac = '00:11:22:33:44:55'

        for s in self.drv._servers:
            for (r, d) in zip(routers, domains):
                self.drv.create_router_on_eos(r, d, s)

                cmds = ['enable', 'configure',
                        'vrf definition %s' % r,
                        'rd %(rd)s:%(rd)s' % {'rd': d},
                        'exit',
                        'ip virtual-router mac-address %s' % router_mac,
                        'exit']
                s.execute.assert_called_with(cmds)

    def test_delete_router_from_eos(self):
        max_vrfs = 5
        routers = ['testRouter-%s' % n for n in range(max_vrfs)]

        for s in self.drv._servers:
            for r in routers:
                self.drv.delete_router_from_eos(r, s)
                cmds = ['enable', 'configure', 'no vrf definition %s' % r,
                        'exit']

                s.execute.assert_called_with(cmds)

    def test_add_interface_to_router_on_eos(self):
        router_name = 'test-router-1'
        segment_id = '123'
        router_ip = '10.10.10.10'
        gw_ip = '10.10.10.1'
        mask = '255.255.255.0'

        for s in self.drv._servers:
            self.drv.add_interface_to_router(segment_id, router_name, gw_ip,
                                             router_ip, mask, s)
            cmds = ['enable', 'configure',
                    'ip routing vrf %s' % router_name,
                    'vlan %s' % segment_id, 'exit',
                    'interface vlan %s' % segment_id,
                    'vrf forwarding %s' % router_name,
                    'ip address %s' % router_ip,
                    'ip virtual-router address %s' % gw_ip,
                    'exit']

            s.execute.assert_called_once_with(cmds)

    def test_delete_interface_from_router_on_eos(self):
        router_name = 'test-router-1'
        segment_id = '123'

        for s in self.drv._servers:
            self.drv.delete_interface_from_router(segment_id, router_name, s)

            cmds = ['enable', 'configure', 'no interface vlan %s' % segment_id,
                    'exit']

            s.execute.assert_called_once_with(cmds)


class AristaL3DriverTestCases_v4(base.BaseTestCase):
    """Test cases to test the RPC between Arista Driver and EOS.

    Tests all methods used to send commands between Arista L3 Driver and EOS
    to program routing functions in Default VRF using IPv4.
    """

    def setUp(self):
        super(AristaL3DriverTestCases_v4, self).setUp()
        setup_arista_config('value')
        self.drv = arista.AristaL3Driver()
        self.drv._servers = []
        self.drv._servers.append(mock.MagicMock())

    def test_no_exception_on_correct_configuration(self):
        self.assertIsNotNone(self.drv)

    def test_add_v4_interface_to_router(self):
        gateway_ip = '10.10.10.1'
        cidrs = ['10.10.10.0/24', '10.11.11.0/24']

        # Add couple of IPv4 subnets to router
        for cidr in cidrs:
            router = {'id': 'r1',
                      'name': 'test-router-1',
                      'tenant_id': 'ten-a',
                      'seg_id': '123',
                      'cidr': "%s" % cidr,
                      'gip': "%s" % gateway_ip,
                      'ip_version': 4}

            self.assertFalse(self.drv.add_router_interface(None, router))

    def test_delete_v4_interface_from_router(self):
        gateway_ip = '10.10.10.1'
        cidrs = ['10.10.10.0/24', '10.11.11.0/24']

        # remove couple of IPv4 subnets from router
        for cidr in cidrs:
            router = {'id': 'r1',
                      'name': 'test-router-1',
                      'tenant_id': 'ten-a',
                      'seg_id': '123',
                      'cidr': "%s" % cidr,
                      'gip': "%s" % gateway_ip,
                      'ip_version': 4}

            self.assertFalse(self.drv.remove_router_interface(None, router))


class AristaL3DriverTestCases_v6(base.BaseTestCase):
    """Test cases to test the RPC between Arista Driver and EOS.

    Tests all methods used to send commands between Arista L3 Driver and EOS
    to program routing functions in Default VRF using IPv6.
    """

    def setUp(self):
        super(AristaL3DriverTestCases_v6, self).setUp()
        setup_arista_config('value')
        self.drv = arista.AristaL3Driver()
        self.drv._servers = []
        self.drv._servers.append(mock.MagicMock())

    def test_no_exception_on_correct_configuration(self):
        self.assertIsNotNone(self.drv)

    def test_add_v6_interface_to_router(self):
        gateway_ip = '3FFE::1'
        cidrs = ['3FFE::/16', '2001::/16']

        # Add couple of IPv6 subnets to router
        for cidr in cidrs:
            router = {'id': 'r1',
                      'name': 'test-router-1',
                      'tenant_id': 'ten-a',
                      'seg_id': '123',
                      'cidr': "%s" % cidr,
                      'gip': "%s" % gateway_ip,
                      'ip_version': 6}

            self.assertFalse(self.drv.add_router_interface(None, router))

    def test_delete_v6_interface_from_router(self):
        gateway_ip = '3FFE::1'
        cidrs = ['3FFE::/16', '2001::/16']

        # remove couple of IPv6 subnets from router
        for cidr in cidrs:
            router = {'id': 'r1',
                      'name': 'test-router-1',
                      'tenant_id': 'ten-a',
                      'seg_id': '123',
                      'cidr': "%s" % cidr,
                      'gip': "%s" % gateway_ip,
                      'ip_version': 6}

            self.assertFalse(self.drv.remove_router_interface(None, router))


class AristaL3DriverTestCases_MLAG_v6(base.BaseTestCase):
    """Test cases to test the RPC between Arista Driver and EOS.

    Tests all methods used to send commands between Arista L3 Driver and EOS
    to program routing functions in Default VRF on MLAG'ed switches using IPv6.
    """

    def setUp(self):
        super(AristaL3DriverTestCases_MLAG_v6, self).setUp()
        setup_arista_config('value', mlag=True)
        self.drv = arista.AristaL3Driver()
        self.drv._servers = []
        self.drv._servers.append(mock.MagicMock())
        self.drv._servers.append(mock.MagicMock())

    def test_no_exception_on_correct_configuration(self):
        self.assertIsNotNone(self.drv)

    def test_add_v6_interface_to_router(self):
        gateway_ip = '3FFE::1'
        cidrs = ['3FFE::/16', '2001::/16']

        # Add couple of IPv6 subnets to router
        for cidr in cidrs:
            router = {'id': 'r1',
                      'name': 'test-router-1',
                      'tenant_id': 'ten-a',
                      'seg_id': '123',
                      'cidr': "%s" % cidr,
                      'gip': "%s" % gateway_ip,
                      'ip_version': 6}

            self.assertFalse(self.drv.add_router_interface(None, router))

    def test_delete_v6_interface_from_router(self):
        gateway_ip = '3FFE::1'
        cidrs = ['3FFE::/16', '2001::/16']

        # remove couple of IPv6 subnets from router
        for cidr in cidrs:
            router = {'id': 'r1',
                      'name': 'test-router-1',
                      'tenant_id': 'ten-a',
                      'seg_id': '123',
                      'cidr': "%s" % cidr,
                      'gip': "%s" % gateway_ip,
                      'ip_version': 6}

            self.assertFalse(self.drv.remove_router_interface(None, router))


class AristaL3DriverTestCasesMlag_one_switch_failed(base.BaseTestCase):
    """Test cases to test with non redundant hardare in redundancy mode.

    In the following test cases, the driver is configured in MLAG (redundancy
    mode) but, one of the switches is mocked to throw exceptoin to mimic
    failure of the switch. Ensure that the the operation does not fail when
    one of the switches fails.
    """

    def setUp(self):
        super(AristaL3DriverTestCasesMlag_one_switch_failed, self).setUp()
        setup_arista_config('value', mlag=True)
        self.drv = arista.AristaL3Driver()
        self.drv._servers = []
        self.drv._servers.append(mock.MagicMock())
        self.drv._servers.append(mock.MagicMock())

    def test_create_router_when_one_switch_fails(self):
        router = {}
        router['id'] = 'r1'
        router['name'] = 'test-router-1'

        # Make one of the switches throw an exception - i.e. fail
        self.drv._servers[0].execute = mock.Mock(side_effect=Exception)
        with mock.patch.object(arista.LOG, 'exception') as log_exception:
            self.drv.create_router(None, router)
            log_exception.assert_called_once_with(mock.ANY)

    def test_delete_router_when_one_switch_fails(self):
        router = {}
        router['id'] = 'r1'
        router['name'] = 'test-router-1'
        router_id = '345'

        # Make one of the switches throw an exception - i.e. fail
        self.drv._servers[1].execute = mock.Mock(side_effect=Exception)
        with mock.patch.object(arista.LOG, 'exception') as log_exception:
            self.drv.delete_router(None, router_id, router)
            log_exception.assert_called_once_with(mock.ANY)

    def test_add_router_interface_when_one_switch_fails(self):
        router = {}
        router['id'] = 'r1'
        router['name'] = 'test-router-1'
        router['tenant_id'] = 'ten-1'
        router['seg_id'] = '100'
        router['ip_version'] = 4
        router['cidr'] = '10.10.10.0/24'
        router['gip'] = '10.10.10.1'

        # Make one of the switches throw an exception - i.e. fail
        self.drv._servers[1].execute = mock.Mock(side_effect=Exception)
        with mock.patch.object(arista.LOG, 'exception') as log_exception:
            self.drv.add_router_interface(None, router)
            log_exception.assert_called_once_with(mock.ANY)

    def test_remove_router_interface_when_one_switch_fails(self):
        router = {}
        router['id'] = 'r1'
        router['name'] = 'test-router-1'
        router['tenant_id'] = 'ten-1'
        router['seg_id'] = '100'
        router['ip_version'] = 4
        router['cidr'] = '10.10.10.0/24'
        router['gip'] = '10.10.10.1'

        # Make one of the switches throw an exception - i.e. fail
        self.drv._servers[0].execute = mock.Mock(side_effect=Exception)
        with mock.patch.object(arista.LOG, 'exception') as log_exception:
            self.drv.remove_router_interface(None, router)
            log_exception.assert_called_once_with(mock.ANY)


class AristaL3ProtectedVlanParserTestCases(base.BaseTestCase):
    """Test cases to test the parsing of protected_vlans config

    1.  Empty string
    2.  Single VLAN
    3.  Single VLAN range
    4.  Multiple VLANs
    5.  Multiple VLAN ranges
    6.  Hybrid VLANs + ranges
    7.  Invalid VLAN
    8.  Range with invalid min
    9.  Range with invalid max
    10. Range with min > max
    11. Non-int VLAN
    12. Non-int min
    13. Non-int max
    """

    def setUp(self):
        super(AristaL3ProtectedVlanParserTestCases, self).setUp()
        setup_arista_config('value')

    def test_empty_string(self):
        cfg.CONF.set_override('protected_vlans', '', 'l3_arista')
        self.drv = arista.AristaL3Driver()
        self.assertEqual(self.drv._protected_vlans, set([1]))

    def test_single_vlan(self):
        cfg.CONF.set_override('protected_vlans', '100', 'l3_arista')
        self.drv = arista.AristaL3Driver()
        self.assertEqual(self.drv._protected_vlans, set([1, 100]))

    def test_single_range(self):
        cfg.CONF.set_override('protected_vlans', '100:105', 'l3_arista')
        self.drv = arista.AristaL3Driver()
        self.assertEqual(self.drv._protected_vlans,
                         set([1] + [i for i in range(100, 106)]))

    def test_multiple_vlans(self):
        cfg.CONF.set_override('protected_vlans', '100,105', 'l3_arista')
        self.drv = arista.AristaL3Driver()
        self.assertEqual(self.drv._protected_vlans, set([1, 100, 105]))

    def test_multiple_ranges(self):
        cfg.CONF.set_override('protected_vlans', '100:105,110:115',
                              'l3_arista')
        self.drv = arista.AristaL3Driver()
        self.assertEqual(self.drv._protected_vlans,
                         set(itertools.chain([1], range(100, 106),
                                             range(110, 116))))

    def test_hybrid_vlan_and_range(self):
        cfg.CONF.set_override('protected_vlans', '100,110:115', 'l3_arista')
        self.drv = arista.AristaL3Driver()
        self.assertEqual(self.drv._protected_vlans,
                         set([1, 100] + list(range(110, 116))))

    def test_invalid_vlan(self):
        cfg.CONF.set_override('protected_vlans', '5000', 'l3_arista')
        self.assertRaises(arista_exc.AristaServicePluginConfigError,
                          arista.AristaL3Driver)

    def test_invalid_max(self):
        cfg.CONF.set_override('protected_vlans', '100:5000', 'l3_arista')
        self.assertRaises(arista_exc.AristaServicePluginConfigError,
                          arista.AristaL3Driver)

    def test_invalid_min(self):
        cfg.CONF.set_override('protected_vlans', '-100:100', 'l3_arista')
        self.assertRaises(arista_exc.AristaServicePluginConfigError,
                          arista.AristaL3Driver)

    def test_bad_range_bounds(self):
        cfg.CONF.set_override('protected_vlans', '200:100', 'l3_arista')
        self.assertRaises(arista_exc.AristaServicePluginConfigError,
                          arista.AristaL3Driver)

    def test_non_int_vlan(self):
        cfg.CONF.set_override('protected_vlans', 'string', 'l3_arista')
        self.assertRaises(arista_exc.AristaServicePluginConfigError,
                          arista.AristaL3Driver)

    def test_non_int_min(self):
        cfg.CONF.set_override('protected_vlans', 'string:100', 'l3_arista')
        self.assertRaises(arista_exc.AristaServicePluginConfigError,
                          arista.AristaL3Driver)

    def test_non_int_max(self):
        cfg.CONF.set_override('protected_vlans', '100:string', 'l3_arista')
        self.assertRaises(arista_exc.AristaServicePluginConfigError,
                          arista.AristaL3Driver)


class AristaL3SyncWorkerTestBase(
        test_db_base_plugin_v2.NeutronDbPluginV2TestCase):
    """Base test class for L3 Sync Worker test cases"""

    def setUp(self, cleanup=True):
        cfg.CONF.import_opt('network_vlan_ranges',
                            'neutron.plugins.ml2.drivers.type_vlan',
                            group='ml2_type_vlan')
        cfg.CONF.set_override('network_vlan_ranges', 'default',
                              'ml2_type_vlan')
        cfg.CONF.set_override('enable_cleanup', 'True' if cleanup else 'False',
                              'l3_arista')
        setup_arista_config('value', mlag=True, vrf=True)
        service_plugins = {'arista_l3': 'arista_l3'}
        super(AristaL3SyncWorkerTestBase, self).setUp(
            plugin='ml2',
            service_plugins=service_plugins)
        self.driver = directory.get_plugin(constants.L3)
        self.context = context.get_admin_context()
        self.drv = self.driver.driver
        self.switch1 = utils.MockSwitch()
        self.switch2 = utils.MockSwitch()
        self.switches = [self.switch1, self.switch2]
        self.drv._servers = self.switches
        for worker in self.driver._workers:
            if isinstance(worker, l3_arista.AristaL3SyncWorker):
                self.sync_worker = worker
        self.sync_worker._servers = self.switches

    @staticmethod
    def _get_rd(name):
        hashed = hashlib.sha256(name.encode('utf-8'))
        rdm = str(int(hashed.hexdigest(), 16) % 65536)
        return '%s:%s' % (rdm, rdm)


class AristaL3SyncWorkerCleanupTestCases(AristaL3SyncWorkerTestBase):
    """Test cases to test the L3 Sync Worker with enable_cleanup=True.

    1. Test that VRFs are not cleaned up if router exists
    2. Test that SVIs and VLANs are not cleaned up if router interface exists
    3. Test that stale VRFs are cleaned up if enable_cleanup=True
    4. Test that stale SVIs and VLANs are cleaned up if enable_cleanup=True
    5. Test that stale VRFs are not cleaned up if not name __OpenStack__<...>
    6. Test that stale SVIs and VLANs are not cleaned up if protected
    """

    def setUp(self):
        super(AristaL3SyncWorkerCleanupTestCases, self).setUp()

    def test_router_exists(self):
        router = {'router': {'id': 'r1',
                             'name': 'router1',
                             'tenant_id': 't1',
                             'admin_state_up': True}}
        self.driver.create_router(self.context, router)
        self.sync_worker.synchronize()
        eos_vrf_name = '__OpenStack__r1-router1'
        expected_vrfs = {eos_vrf_name:
                         {'rd': self._get_rd(eos_vrf_name),
                          'svis': []}}
        self.assertEqual(self.switch1._vrfs, expected_vrfs)
        self.assertEqual(self.switch2._vrfs, expected_vrfs)

    def test_router_interface_exists(self):
        router_dict = {'router': {'name': 'router1',
                                  'tenant_id': 't1',
                                  'admin_state_up': True}}
        router = self.driver.create_router(self.context, router_dict)
        net_dict = {'network': {'name': 'n1',
                                'tenant_id': 't1',
                                'admin_state_up': True,
                                'shared': False,
                                'provider:physical_network': 'default',
                                'provider:network_type': 'vlan',
                                'provider:segmentation_id': 100}}
        net = self.plugin.create_network(self.context, net_dict)
        subnet_dict = {'subnet':
                       {'tenant_id': net['tenant_id'],
                        'name': net['name'],
                        'network_id': net['id'],
                        'ip_version': 4,
                        'cidr': '10.0.0.0/24',
                        'gateway_ip': '10.0.0.1',
                        'allocation_pools': None,
                        'enable_dhcp': False,
                        'dns_nameservers': None,
                        'host_routes': None}}
        subnet = self.plugin.create_subnet(self.context, subnet_dict)
        router_interface = {'subnet_id': subnet['id']}
        self.driver.add_router_interface(self.context, router['id'],
                                         router_interface)
        self.sync_worker.synchronize()
        expected_svis_s1 = {'vlan 100': {'ip': '10.0.0.254',
                                         'mask': '24',
                                         'vip': '10.0.0.1'}}
        expected_svis_s2 = {'vlan 100': {'ip': '10.0.0.253',
                                         'mask': '24',
                                         'vip': '10.0.0.1'}}
        expected_vlans = {'100': {'dynamic': False}}
        self.assertEqual(self.switch1._svis, expected_svis_s1)
        self.assertEqual(self.switch2._svis, expected_svis_s2)
        self.assertEqual(self.switch1._vlans, expected_vlans)
        self.assertEqual(self.switch2._vlans, expected_vlans)

    def test_stale_vrf(self):
        eos_vrf_name = '__OpenStack__r1-router1'
        self.switch1._vrfs = {eos_vrf_name:
                              {'rd': self._get_rd(eos_vrf_name),
                               'svis': []}}
        self.switch2._vrfs = {eos_vrf_name:
                              {'rd': self._get_rd(eos_vrf_name),
                               'svis': []}}
        self.sync_worker.synchronize()
        self.assertEqual(self.switch1._vrfs, {})
        self.assertEqual(self.switch2._vrfs, {})

    def test_stale_svi_and_vlan(self):
        self.switch1._svis = {'vlan 100': {'ip': '10.0.0.254',
                                           'mask': '24',
                                           'vip': '10.0.0.1'}}
        self.switch1._vlans = {'100': {'dynamic': False}}
        self.switch2._svis = {'vlan 100': {'ip': '10.0.0.253',
                                           'mask': '24',
                                           'vip': '10.0.0.1'}}
        self.switch2._vlans = {'100': {'dynamic': False}}
        self.sync_worker.synchronize()
        self.assertEqual(self.switch1._svis, {})
        self.assertEqual(self.switch2._svis, {})
        self.assertEqual(self.switch1._vlans, {})
        self.assertEqual(self.switch2._vlans, {})

    def test_non_openstack_vrf(self):
        eos_vrf_name = 'other-vrf'
        expected_vrfs = {eos_vrf_name:
                         {'rd': self._get_rd(eos_vrf_name),
                          'svis': []}}
        self.switch1._vrfs = expected_vrfs
        self.switch2._vrfs = expected_vrfs
        self.sync_worker.synchronize()
        self.assertEqual(self.switch1._vrfs, expected_vrfs)
        self.assertEqual(self.switch2._vrfs, expected_vrfs)

    def test_protected_svi_and_vlan(self):
        self.sync_worker._protected_vlans = set([100])
        protected_svis = {'vlan 100': {'ip': '10.0.0.254',
                                       'mask': '24',
                                       'vip': '10.0.0.1'}}
        protected_vlans = {'100': {'dynamic': False}}
        self.switch1._svis = protected_svis
        self.switch1._vlans = protected_vlans
        self.switch2._svis = protected_svis
        self.switch2._vlans = protected_vlans
        self.sync_worker.synchronize()
        self.assertEqual(self.switch1._svis, protected_svis)
        self.assertEqual(self.switch1._vlans, protected_vlans)
        self.assertEqual(self.switch2._svis, protected_svis)
        self.assertEqual(self.switch2._vlans, protected_vlans)


class AristaL3SyncWorkerNoCleanupTestCases(AristaL3SyncWorkerTestBase):
    """Test cases for the L3 Sync Worker with enable_cleanup=False

    1. Test that stale VRFs are not cleaned up if enable_cleanup=False
    2. Test that stale SVIs and VLANs aren't cleaned up if enable_cleanup=False
    """

    def setUp(self):
        super(AristaL3SyncWorkerNoCleanupTestCases, self).setUp(cleanup=False)

    def test_stale_vrf(self):
        eos_vrf_name = '__OpenStack__r1-router1'
        expected_vrfs = {eos_vrf_name:
                         {'rd': self._get_rd(eos_vrf_name),
                          'svis': []}}
        self.switch1._vrfs = expected_vrfs
        self.switch2._vrfs = expected_vrfs
        self.sync_worker.synchronize()
        self.assertEqual(self.switch1._vrfs, expected_vrfs)
        self.assertEqual(self.switch2._vrfs, expected_vrfs)

    def test_stale_svi_and_vlan(self):
        expected_svis = {'vlan 100': {'ip': '10.0.0.254',
                                      'mask': '24',
                                      'vip': '10.0.0.1'}}
        expected_vlans = {'100': {'dynamic': False}}
        self.switch1._svis = expected_svis
        self.switch1._vlans = expected_vlans
        self.switch2._svis = expected_svis
        self.switch2._vlans = expected_vlans
        self.sync_worker.synchronize()
        self.assertEqual(self.switch1._svis, expected_svis)
        self.assertEqual(self.switch1._vlans, expected_vlans)
        self.assertEqual(self.switch2._svis, expected_svis)
        self.assertEqual(self.switch2._vlans, expected_vlans)
