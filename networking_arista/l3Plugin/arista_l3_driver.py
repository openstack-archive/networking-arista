# Copyright 2014 Arista Networks, Inc.  All rights reserved.
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

import hashlib
import socket
import struct

from neutron_lib import constants as const
from oslo_config import cfg
from oslo_log import log as logging

from networking_arista._i18n import _, _LI
from networking_arista.common import api
from networking_arista.common import exceptions as arista_exc

LOG = logging.getLogger(__name__)
cfg.CONF.import_group('l3_arista', 'networking_arista.common.config')

EOS_UNREACHABLE_MSG = _('Unable to reach EOS')
DEFAULT_VLAN = 1
MLAG_SWITCHES = 2
VIRTUAL_ROUTER_MAC = '00:11:22:33:44:55'
IPV4_BITS = 32
IPV6_BITS = 128

# This string-format-at-a-distance confuses pylint :(
# pylint: disable=too-many-format-args
router_in_vrf = {
    'router': {'create': ['vrf definition {0}',
                          'rd {1}',
                          'exit'],
               'delete': ['no vrf definition {0}']},

    'interface': {'add': ['ip routing vrf {1}',
                          'vlan {0}',
                          'exit',
                          'interface vlan {0}',
                          'vrf forwarding {1}',
                          'ip address {2}'],
                  'remove': ['no interface vlan {0}']}}

router_in_default_vrf = {
    'router': {'create': [],   # Place holder for now.
               'delete': []},  # Place holder for now.

    'interface': {'add': ['ip routing',
                          'vlan {0}',
                          'exit',
                          'interface vlan {0}',
                          'ip address {2}'],
                  'remove': ['no interface vlan {0}']}}

router_in_default_vrf_v6 = {
    'router': {'create': [],
               'delete': []},

    'interface': {'add': ['ipv6 unicast-routing',
                          'vlan {0}',
                          'exit',
                          'interface vlan {0}',
                          'ipv6 enable',
                          'ipv6 address {2}'],
                  'remove': ['no interface vlan {0}']}}

additional_cmds_for_mlag = {
    'router': {'create': ['ip virtual-router mac-address {0}'],
               'delete': []},

    'interface': {'add': ['ip virtual-router address {0}'],
                  'remove': []}}

additional_cmds_for_mlag_v6 = {
    'router': {'create': [],
               'delete': []},

    'interface': {'add': ['ipv6 virtual-router address {0}'],
                  'remove': []}}


class AristaL3Driver(object):
    """Wraps Arista JSON RPC.

    All communications between Neutron and EOS are over JSON RPC.
    EOS - operating system used on Arista hardware
    Command API - JSON RPC API provided by Arista EOS
    """
    def __init__(self):
        self._servers = []
        self._hosts = []
        self._interfaceDict = None
        self._validate_config()
        host = cfg.CONF.l3_arista.primary_l3_host
        self._hosts.append(host)
        self._servers.append(self._make_eapi_client(host))
        self._mlag_configured = cfg.CONF.l3_arista.mlag_config
        self._use_vrf = cfg.CONF.l3_arista.use_vrf
        if self._mlag_configured:
            host = cfg.CONF.l3_arista.secondary_l3_host
            self._hosts.append(host)
            self._servers.append(self._make_eapi_client(host))
            self._additionalRouterCmdsDict = additional_cmds_for_mlag['router']
            self._additionalInterfaceCmdsDict = (
                additional_cmds_for_mlag['interface'])
        if self._use_vrf:
            self.routerDict = router_in_vrf['router']
            self._interfaceDict = router_in_vrf['interface']
        else:
            self.routerDict = router_in_default_vrf['router']
            self._interfaceDict = router_in_default_vrf['interface']
        self._enable_cleanup = cfg.CONF.l3_arista.enable_cleanup
        self._protected_vlans = self._parse_protected_vlans(
            cfg.CONF.l3_arista.protected_vlans)

    @staticmethod
    def _raise_invalid_protected_vlans(vlan_string):
        msg = '%s is not a valid vlan or vlan range' % vlan_string
        LOG.error(msg)
        raise arista_exc.AristaServicePluginConfigError(msg=msg)

    def _parse_protected_vlans(self, vlan_strings):
        # VLAN 1 is always protected as it exists by default on EOS
        vlans = set([1])
        for vlan_string in vlan_strings:
            vlan_parsed = vlan_string.split(':', 2)

            if len(vlan_parsed) > 2:
                self._raise_invalid_protected_vlans(vlan_string)

            try:
                min_vlan = int(vlan_parsed[0])
            except ValueError:
                self._raise_invalid_protected_vlans(vlan_string)

            try:
                max_vlan = int(vlan_parsed[-1])
            except ValueError:
                self._raise_invalid_protected_vlans(vlan_string)

            if not (const.MIN_VLAN_TAG < min_vlan
                    <= max_vlan < const.MAX_VLAN_TAG):
                self._raise_invalid_protected_vlans(vlan_string)
            vlans.update(range(min_vlan, max_vlan + 1))
        return vlans

    @staticmethod
    def _make_eapi_client(host):
        return api.EAPIClient(
            host,
            username=cfg.CONF.l3_arista.primary_l3_host_username,
            password=cfg.CONF.l3_arista.primary_l3_host_password,
            verify=False,
            timeout=cfg.CONF.l3_arista.conn_timeout
        )

    def _validate_config(self):
        if cfg.CONF.l3_arista.get('primary_l3_host') == '':
            msg = _('Required option primary_l3_host is not set')
            LOG.error(msg)
            raise arista_exc.AristaServicePluginConfigError(msg=msg)
        if cfg.CONF.l3_arista.get('mlag_config'):
            if cfg.CONF.l3_arista.get('secondary_l3_host') == '':
                msg = _('Required option secondary_l3_host is not set')
                LOG.error(msg)
                raise arista_exc.AristaServicePluginConfigError(msg=msg)
        if cfg.CONF.l3_arista.get('primary_l3_host_username') == '':
            msg = _('Required option primary_l3_host_username is not set')
            LOG.error(msg)
            raise arista_exc.AristaServicePluginConfigError(msg=msg)

    def create_router_on_eos(self, router_name, rdm, server):
        """Creates a router on Arista HW Device.

        :param router_name: globally unique identifier for router/VRF
        :param rdm: A value generated by hashing router name
        :param server: Server endpoint on the Arista switch to be configured
        """
        cmds = []
        rd = "%s:%s" % (rdm, rdm)

        for c in self.routerDict['create']:
            cmds.append(c.format(router_name, rd))

        if self._mlag_configured:
            mac = VIRTUAL_ROUTER_MAC
            for c in self._additionalRouterCmdsDict['create']:
                cmds.append(c.format(mac))

        self._run_config_cmds(cmds, server)

    def delete_router_from_eos(self, router_name, server):
        """Deletes a router from Arista HW Device.

        :param router_name: globally unique identifier for router/VRF
        :param server: Server endpoint on the Arista switch to be configured
        """
        cmds = []
        for c in self.routerDict['delete']:
            cmds.append(c.format(router_name))
        if self._mlag_configured:
            for c in self._additionalRouterCmdsDict['delete']:
                cmds.append(c)

        self._run_config_cmds(cmds, server)

    def _select_dicts(self, ipv):
        if self._use_vrf:
            if ipv == 6:
                msg = (_('IPv6 subnets are not supported with VRFs'))
                LOG.exception(msg)
                raise arista_exc.AristaServicePluginRpcError(msg=msg)
            self._interfaceDict = router_in_vrf['interface']
        else:
            if ipv == 6:
                # for IPv6 use IPv6 commmands
                self._interfaceDict = router_in_default_vrf_v6['interface']
                self._additionalInterfaceCmdsDict = (
                    additional_cmds_for_mlag_v6['interface'])
            else:
                self._interfaceDict = router_in_default_vrf['interface']
                self._additionalInterfaceCmdsDict = (
                    additional_cmds_for_mlag['interface'])

    def add_interface_to_router(self, segment_id,
                                router_name, gip, router_ip, mask, server):
        """Adds an interface to existing HW router on Arista HW device.

        :param segment_id: VLAN Id associated with interface that is added
        :param router_name: globally unique identifier for router/VRF
        :param gip: Gateway IP associated with the subnet
        :param router_ip: IP address of the router
        :param mask: subnet mask to be used
        :param server: Server endpoint on the Arista switch to be configured
        """

        if not segment_id:
            segment_id = DEFAULT_VLAN
        cmds = []
        for c in self._interfaceDict['add']:
            if self._mlag_configured:
                # In VARP config, use router ID else, use gateway IP address.
                ip = router_ip
            else:
                ip = gip + '/' + mask
            cmds.append(c.format(segment_id, router_name, ip))
        if self._mlag_configured:
            for c in self._additionalInterfaceCmdsDict['add']:
                cmds.append(c.format(gip))

        self._run_config_cmds(cmds, server)

    def delete_interface_from_router(self, segment_id, router_name, server):
        """Deletes an interface from existing HW router on Arista HW device.

        :param segment_id: VLAN Id associated with interface that is added
        :param router_name: globally unique identifier for router/VRF
        :param server: Server endpoint on the Arista switch to be configured
        """

        if not segment_id:
            segment_id = DEFAULT_VLAN
        cmds = []
        for c in self._interfaceDict['remove']:
            cmds.append(c.format(segment_id))

        self._run_config_cmds(cmds, server)

    def create_router(self, context, router):
        """Creates a router on Arista Switch.

        Deals with multiple configurations - such as Router per VRF,
        a router in default VRF, Virtual Router in MLAG configurations
        """
        if router:
            router_name = self._arista_router_name(router['id'],
                                                   router['name'])

            hashed = hashlib.sha256(router_name.encode('utf-8'))
            rdm = str(int(hashed.hexdigest(), 16) % 65536)

            mlag_peer_failed = False
            for s in self._servers:
                try:
                    self.create_router_on_eos(router_name, rdm, s)
                    mlag_peer_failed = False
                except Exception:
                    if self._mlag_configured and not mlag_peer_failed:
                        # In paied switch, it is OK to fail on one switch
                        mlag_peer_failed = True
                    else:
                        msg = (_('Failed to create router %s on EOS') %
                               router_name)
                        LOG.exception(msg)
                        raise arista_exc.AristaServicePluginRpcError(msg=msg)

    def delete_router(self, context, router_id, router):
        """Deletes a router from Arista Switch."""

        if router:
            router_name = self._arista_router_name(router_id, router['name'])
            mlag_peer_failed = False
            for s in self._servers:
                try:
                    self.delete_router_from_eos(router_name, s)
                    mlag_peer_failed = False
                except Exception:
                    if self._mlag_configured and not mlag_peer_failed:
                        # In paied switch, it is OK to fail on one switch
                        mlag_peer_failed = True
                    else:
                        msg = (_('Failed to create router %s on EOS') %
                               router_name)
                        LOG.exception(msg)
                        raise arista_exc.AristaServicePluginRpcError(msg=msg)

    def update_router(self, context, router_id, original_router, new_router):
        """Updates a router which is already created on Arista Switch.

        TODO: (Sukhdev) - to be implemented in next release.
        """
        pass

    def add_router_interface(self, context, router_info):
        """Adds an interface to a router created on Arista HW router.

        This deals with both IPv6 and IPv4 configurations.
        """
        if router_info:
            self._select_dicts(router_info['ip_version'])
            cidr = router_info['cidr']
            subnet_mask = cidr.split('/')[1]
            router_name = self._arista_router_name(router_info['id'],
                                                   router_info['name'])
            if self._mlag_configured:
                # For MLAG, we send a specific IP address as opposed to cidr
                # For now, we are using x.x.x.253 and x.x.x.254 as virtual IP
                mlag_peer_failed = False
                for i, server in enumerate(self._servers):
                    # Get appropriate virtual IP address for this router
                    router_ip = self._get_router_ip(cidr, i,
                                                    router_info['ip_version'])
                    try:
                        self.add_interface_to_router(router_info['seg_id'],
                                                     router_name,
                                                     router_info['gip'],
                                                     router_ip, subnet_mask,
                                                     server)
                        mlag_peer_failed = False
                    except Exception:
                        if not mlag_peer_failed:
                            mlag_peer_failed = True
                        else:
                            msg = (_('Failed to add interface to router '
                                     '%s on EOS') % router_name)
                            LOG.exception(msg)
                            raise arista_exc.AristaServicePluginRpcError(
                                msg=msg)

            else:
                for s in self._servers:
                    self.add_interface_to_router(router_info['seg_id'],
                                                 router_name,
                                                 router_info['gip'],
                                                 None, subnet_mask, s)

    def remove_router_interface(self, context, router_info):
        """Removes previously configured interface from router on Arista HW.

        This deals with both IPv6 and IPv4 configurations.
        """
        if router_info:
            router_name = self._arista_router_name(router_info['id'],
                                                   router_info['name'])
            mlag_peer_failed = False
            for s in self._servers:
                try:
                    self.delete_interface_from_router(router_info['seg_id'],
                                                      router_name, s)
                    if self._mlag_configured:
                        mlag_peer_failed = False
                except Exception:
                    if self._mlag_configured and not mlag_peer_failed:
                        mlag_peer_failed = True
                    else:
                        msg = (_('Failed to add interface to router '
                                 '%s on EOS') % router_name)
                        LOG.exception(msg)
                        raise arista_exc.AristaServicePluginRpcError(msg=msg)

    def _run_config_cmds(self, commands, server):
        """Execute/sends a CAPI (Command API) command to EOS.

        In this method, list of commands is appended with prefix and
        postfix commands - to make is understandble by EOS.

        :param commands : List of command to be executed on EOS.
        :param server: Server endpoint on the Arista switch to be configured
        """
        command_start = ['enable', 'configure']
        command_end = ['exit']
        full_command = command_start + commands + command_end
        self._run_eos_cmds(full_command, server)

    def _run_eos_cmds(self, commands, server):
        LOG.info(_LI('Executing command on Arista EOS: %s'), commands)

        try:
            # this returns array of return values for every command in
            # full_command list
            ret = server.execute(commands)
            LOG.info(_LI('Results of execution on Arista EOS: %s'), ret)
            return ret
        except Exception:
            msg = (_('Error occurred while trying to execute '
                     'commands %(cmd)s on EOS %(host)s') %
                   {'cmd': commands, 'host': server})
            LOG.exception(msg)
            raise arista_exc.AristaServicePluginRpcError(msg=msg)

    def _arista_router_name(self, router_id, name):
        """Generate an arista specific name for this router.

        Use a unique name so that OpenStack created routers/SVIs
        can be distinguishged from the user created routers/SVIs
        on Arista HW. Replace spaces with underscores for CLI compatibility
        """
        return '__OpenStack__' + router_id + '-' + name.replace(' ', '_')

    def _get_binary_from_ipv4(self, ip_addr):
        """Converts IPv4 address to binary form."""

        return struct.unpack("!L", socket.inet_pton(socket.AF_INET,
                                                    ip_addr))[0]

    def _get_binary_from_ipv6(self, ip_addr):
        """Converts IPv6 address to binary form."""

        hi, lo = struct.unpack("!QQ", socket.inet_pton(socket.AF_INET6,
                                                       ip_addr))
        return (hi << 64) | lo

    def _get_ipv4_from_binary(self, bin_addr):
        """Converts binary address to Ipv4 format."""

        return socket.inet_ntop(socket.AF_INET, struct.pack("!L", bin_addr))

    def _get_ipv6_from_binary(self, bin_addr):
        """Converts binary address to Ipv6 format."""

        hi = bin_addr >> 64
        lo = bin_addr & 0xFFFFFFFF
        return socket.inet_ntop(socket.AF_INET6, struct.pack("!QQ", hi, lo))

    def _get_router_ip(self, cidr, ip_count, ip_ver):
        """For a given IP subnet and IP version type, generate IP for router.

        This method takes the network address (cidr) and selects an
        IP address that should be assigned to virtual router running
        on multiple switches. It uses upper addresses in a subnet address
        as IP for the router. Each instace of the router, on each switch,
        requires uniqe IP address. For example in IPv4 case, on a 255
        subnet, it will pick X.X.X.254 as first addess, X.X.X.253 for next,
        and so on.
        """
        start_ip = MLAG_SWITCHES + ip_count
        network_addr, prefix = cidr.split('/')
        if ip_ver == 4:
            bits = IPV4_BITS
            ip = self._get_binary_from_ipv4(network_addr)
        elif ip_ver == 6:
            bits = IPV6_BITS
            ip = self._get_binary_from_ipv6(network_addr)

        mask = (pow(2, bits) - 1) << (bits - int(prefix))

        network_addr = ip & mask

        router_ip = pow(2, bits - int(prefix)) - start_ip

        router_ip = network_addr | router_ip
        if ip_ver == 4:
            return self._get_ipv4_from_binary(router_ip) + '/' + prefix
        else:
            return self._get_ipv6_from_binary(router_ip) + '/' + prefix
