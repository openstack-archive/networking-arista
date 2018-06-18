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

import re

from neutron_lib import constants as n_const
from oslo_config import cfg
from oslo_log import log as logging

from networking_arista._i18n import _LI
from networking_arista.common import api
from networking_arista.common import constants as a_const
from networking_arista.common import exceptions as arista_exc
from networking_arista.common import utils

LOG = logging.getLogger(__name__)


class AristaSecurityGroupSwitchHelper(object):
    """Helper class for applying baremetal security groups on Arista switches

    This helper class contains methods for adding and removing security
    groups, security group rules and security group port bindings to and from
    Arista switches.
    """

    def initialize_switch_endpoints(self):
        """Initialize endpoints for switch communication"""
        self._switches = {}
        self._port_group_info = {}
        self._validate_config()
        for s in cfg.CONF.ml2_arista.switch_info:
            switch_ip, switch_user, switch_pass = s.split(":")
            if switch_pass == "''":
                switch_pass = ''
            self._switches[switch_ip] = api.EAPIClient(
                switch_ip,
                switch_user,
                switch_pass,
                verify=False,
                timeout=cfg.CONF.ml2_arista.conn_timeout)

    def _validate_config(self):
        """Ensure at least one switch is configured"""
        if len(cfg.CONF.ml2_arista.get('switch_info')) < 1:
            msg = _('Required option - when "sec_group_support" is enabled, '
                    'at least one switch must be specified ')
            LOG.exception(msg)
            raise arista_exc.AristaConfigError(msg=msg)

    def _run_openstack_sg_cmds(self, commands, switch):
        """Execute/sends a CAPI (Command API) command to EOS.

        In this method, list of commands is appended with prefix and
        postfix commands - to make is understandble by EOS.

        :param commands : List of command to be executed on EOS.
        :param switch: Endpoint on the Arista switch to be configured
        """
        if len(commands) == 0:
            return []
        command_start = ['enable', 'configure']
        command_end = ['exit']
        full_command = command_start + commands + command_end
        return self._run_eos_cmds(full_command, switch)

    def _run_eos_cmds(self, commands, switch):
        """Execute/sends a CAPI (Command API) command to EOS.

        This method is useful for running show commands that require no
        prefix or postfix commands.

        :param commands : List of commands to be executed on EOS.
        :param switch: Endpoint on the Arista switch to be configured
        """
        LOG.info(_LI('Executing command on Arista EOS: %s'), commands)

        try:
            # this returns array of return values for every command in
            # commands list
            ret = switch.execute(commands)
            LOG.info(_LI('Results of execution on Arista EOS: %s'), ret)
            return ret
        except Exception:
            msg = (_('Error occurred while trying to execute '
                     'commands %(cmd)s on EOS %(host)s') %
                   {'cmd': commands, 'host': switch})
            LOG.exception(msg)

    def run_cmds_on_all_switches(self, cmds):
        """Runs all cmds on all configured switches

        This helper is used for ACL and rule creation/deletion as ACLs
        and rules must exist on all switches.
        """
        for switch in self._switches.values():
            self._run_openstack_sg_cmds(cmds, switch)

    def run_per_switch_cmds(self, switch_cmds):
        """Applies cmds to appropriate switches

        This takes in a switch->cmds mapping and runs only the set of cmds
        specified for a switch on that switch. This helper is used for
        applying/removing ACLs to/from interfaces as this config will vary
        from switch to switch.
        """
        for switch_ip, cmds in switch_cmds.items():
            switch = self._switches[switch_ip]
            self._run_openstack_sg_cmds(cmds, switch)

    @staticmethod
    def _acl_name(name, direction):
        """Generate an arista specific name for this ACL.

        Use a unique name so that OpenStack created ACLs
        can be distinguishged from the user created ACLs
        on Arista HW.
        """
        direction = direction.upper()
        return 'SG' + '-' + direction + '-' + name

    def _get_switches(self, profile):
        """Get set of switches referenced in a port binding profile"""
        switchports = self._get_switchports(profile)
        switches = set([switchport[0] for switchport in switchports])
        return switches

    @staticmethod
    def _get_switchports(profile):
        """Return list of (switch_ip, interface) tuples from local_link_info"""
        switchports = []
        if profile.get('local_link_information'):
            for link in profile['local_link_information']:
                switch = link['switch_info']
                interface = link['port_id']
                switchports.append((switch, interface))
        return switchports

    def _update_port_group_info(self, switches=None):
        """Refresh data on switch interfaces' port group membership"""
        if switches is None:
            switches = self._switches.keys()
        for switch_ip in switches:
            client = self._switches[switch_ip]
            ret = self._run_eos_cmds(['show interfaces'], client)
            if not ret or len(ret) == 0:
                LOG.warning("Unable to retrieve interface info for %s",
                            switch_ip)
                continue
            intf_info = ret[0]
            self._port_group_info[switch_ip] = intf_info.get('interfaces', {})

    def _get_port_for_acl(self, port_id, switch):
        """Gets interface name for ACLs

        Finds the Port-Channel name if port_id is in a Port-Channel, otherwise
        ACLs are applied to Ethernet interface.

        :param port_id: Name of port from ironic db
        :param server: Server endpoint on the Arista switch to be configured
        """
        all_intf_info = self._port_group_info.get(switch, {})
        intf_info = all_intf_info.get(port_id, {})
        member_info = intf_info.get('interfaceMembership', '')
        port_group_info = re.search('Member of (?P<port_group>\S+)',
                                    member_info)
        if port_group_info:
            port_id = port_group_info.group('port_group')
        return port_id

    @staticmethod
    def _supported_rule(protocol, ethertype):
        """Checks that the rule is an IPv4 rule of a supported protocol"""
        if not protocol or protocol not in utils.SUPPORTED_SG_PROTOCOLS:
            return False

        if ethertype != n_const.IPv4:
            return False

        return True

    def _format_rule(self, protocol, cidr, min_port, max_port, direction):
        """Get EOS formatted rule"""
        if cidr is None:
            cidr = 'any'

        if direction == n_const.INGRESS_DIRECTION:
            dst_ip = 'any'
            src_ip = cidr
        elif direction == n_const.EGRESS_DIRECTION:
            dst_ip = cidr
            src_ip = 'any'

        if protocol == n_const.PROTO_NAME_ICMP:
            rule = "permit icmp %s %s" % (src_ip, dst_ip)
            if min_port:
                rule += " %s" % (min_port)
                if max_port:
                    rule += " %s" % (max_port)
        else:
            rule = "permit %s %s %s" % (protocol, src_ip, dst_ip)
            if min_port and max_port:
                rule += " range %s %s" % (min_port, max_port)
            elif min_port and not max_port:
                rule += " eq %s" % min_port
        return rule

    def _format_rules_for_eos(self, rules):
        """Format list of rules for EOS and sort into ingress/egress rules"""
        in_rules = []
        eg_rules = []
        for rule in rules:
            protocol = rule.get('protocol')
            cidr = rule.get('remote_ip_prefix', 'any')
            min_port = rule.get('port_range_min')
            max_port = rule.get('port_range_max')
            direction = rule.get('direction')
            ethertype = rule.get('ethertype')
            if not self._supported_rule(protocol, ethertype):
                continue
            formatted_rule = self._format_rule(protocol, cidr, min_port,
                                               max_port, direction)
            if rule['direction'] == n_const.INGRESS_DIRECTION:
                in_rules.append(formatted_rule)
            elif rule['direction'] == n_const.EGRESS_DIRECTION:
                eg_rules.append(formatted_rule)
        return in_rules, eg_rules

    def get_create_security_group_commands(self, sg_id, sg_rules):
        """Commands for creating ACL"""
        cmds = []
        in_rules, eg_rules = self._format_rules_for_eos(sg_rules)
        cmds.append("ip access-list %s" %
                    self._acl_name(sg_id, n_const.INGRESS_DIRECTION))
        cmds.append("no 1-$")
        for in_rule in in_rules:
            cmds.append(in_rule)
        cmds.append("exit")
        cmds.append("ip access-list %s" %
                    self._acl_name(sg_id, n_const.EGRESS_DIRECTION))
        cmds.append("no 1-$")
        for eg_rule in eg_rules:
            cmds.append(eg_rule)
        cmds.append("exit")
        return cmds

    def get_delete_security_group_commands(self, sg_id):
        """Commands for deleting ACL"""
        cmds = []
        cmds.append("no ip access-list %s" %
                    self._acl_name(sg_id, n_const.INGRESS_DIRECTION))
        cmds.append("no ip access-list %s" %
                    self._acl_name(sg_id, n_const.EGRESS_DIRECTION))
        return cmds

    def _get_rule_cmds(self, sg_id, sg_rule, delete=False):
        """Helper for getting add/delete ACL rule commands"""
        rule_prefix = ""
        if delete:
            rule_prefix = "no "
        in_rules, eg_rules = self._format_rules_for_eos([sg_rule])
        cmds = []
        if in_rules:
            cmds.append("ip access-list %s" %
                        self._acl_name(sg_id, n_const.INGRESS_DIRECTION))
            for in_rule in in_rules:
                cmds.append(rule_prefix + in_rule)
            cmds.append("exit")
        if eg_rules:
            cmds.append("ip access-list %s" %
                        self._acl_name(sg_id, n_const.EGRESS_DIRECTION))
            for eg_rule in eg_rules:
                cmds.append(rule_prefix + eg_rule)
            cmds.append("exit")
        return cmds

    def get_create_security_group_rule_commands(self, sg_id, sg_rule):
        """Commands for adding rule to ACL"""
        return self._get_rule_cmds(sg_id, sg_rule)

    def get_delete_security_group_rule_commands(self, sg_id, sg_rule):
        """Commands for removing rule from ACLS"""
        return self._get_rule_cmds(sg_id, sg_rule, delete=True)

    def _get_interface_commands(self, sg_id, profile, delete=False):
        """Helper for getting interface ACL apply/remove commands"""
        rule_prefix = ""
        if delete:
            rule_prefix = "no "
        switch_cmds = {}
        switchports = self._get_switchports(profile)
        for switch_ip, intf in switchports:
            cmds = []
            intf_id = self._get_port_for_acl(intf, switch_ip)
            cmds.append("interface %s" % intf_id)
            name = self._acl_name(sg_id, n_const.INGRESS_DIRECTION)
            cmds.append(rule_prefix + "ip access-group %s %s" %
                        (name, a_const.INGRESS_DIRECTION))
            name = self._acl_name(sg_id, n_const.EGRESS_DIRECTION)
            cmds.append(rule_prefix + "ip access-group %s %s" %
                        (name, a_const.EGRESS_DIRECTION))
            cmds.append("exit")
            if switch_ip not in switch_cmds.keys():
                switch_cmds[switch_ip] = []
            switch_cmds[switch_ip].extend(cmds)
        return switch_cmds

    def get_apply_security_group_commands(self, sg_id, profile):
        """Commands for applying ACL to interface"""
        return self._get_interface_commands(sg_id, profile)

    def get_remove_security_group_commands(self, sg_id, profile):
        """Commands for removing ACL from interface"""
        return self._get_interface_commands(sg_id, profile, delete=True)
