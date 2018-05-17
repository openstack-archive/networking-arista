# Copyright (c) 2016 OpenStack Foundation
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

import json
import re

from oslo_config import cfg
from oslo_log import log as logging

from networking_arista._i18n import _, _LI
from networking_arista.common import api
from networking_arista.common import db_lib
from networking_arista.common import exceptions as arista_exc

LOG = logging.getLogger(__name__)

EOS_UNREACHABLE_MSG = _('Unable to reach EOS')

# Note 'None,null' means default rule - i.e. deny everything
SUPPORTED_SG_PROTOCOLS = [None, 'tcp', 'udp', 'icmp']

acl_cmd = {
    'acl': {'create': ['ip access-list {0}'],
            'in_rule': ['permit {0} {1} any range {2} {3}'],
            'out_rule': ['permit {0} any {1} range {2} {3}'],
            'in_icmp_custom0': ['permit icmp {0} any'],
            'out_icmp_custom0': ['permit icmp any {0}'],
            'in_icmp_custom1': ['permit icmp {0} any {1}'],
            'out_icmp_custom1': ['permit icmp any {0} {1}'],
            'in_icmp_custom2': ['permit icmp {0} any {1} {2}'],
            'out_icmp_custom2': ['permit icmp any {0} {1} {2}'],
            'default': [],
            'delete_acl': ['no ip access-list {0}'],
            'del_in_icmp_custom0': ['ip access-list {0}',
                                    'no permit icmp {1} any',
                                    'exit'],
            'del_out_icmp_custom0': ['ip access-list {0}',
                                     'no permit icmp any {1}',
                                     'exit'],
            'del_in_icmp_custom1': ['ip access-list {0}',
                                    'no permit icmp {1} any {2}',
                                    'exit'],
            'del_out_icmp_custom1': ['ip access-list {0}',
                                     'no permit icmp any {1} {2}',
                                     'exit'],
            'del_in_icmp_custom2': ['ip access-list {0}',
                                    'no permit icmp {1} any {2} {3}',
                                    'exit'],
            'del_out_icmp_custom2': ['ip access-list {0}',
                                     'no permit icmp any {1} {2} {3}',
                                     'exit'],
            'del_in_acl_rule': ['ip access-list {0}',
                                'no permit {1} {2} any range {3} {4}',
                                'exit'],
            'del_out_acl_rule': ['ip access-list {0}',
                                 'no permit {1} any {2} range {3} {4}',
                                 'exit']},

    'apply': {'ingress': ['interface {0}',
                          'ip access-group {1} in',
                          'exit'],
              'egress': ['interface {0}',
                         'ip access-group {1} out',
                         'exit'],
              'rm_ingress': ['interface {0}',
                             'no ip access-group {1} in',
                             'exit'],
              'rm_egress': ['interface {0}',
                            'no ip access-group {1} out',
                            'exit']}}


class AristaSecGroupSwitchDriver(object):
    """Wraps Arista JSON RPC.

    All communications between Neutron and EOS are over JSON RPC.
    EOS - operating system used on Arista hardware
    Command API - JSON RPC API provided by Arista EOS
    """
    def __init__(self, neutron_db):
        self._ndb = neutron_db
        self._servers = []
        self._hosts = {}
        self.sg_enabled = cfg.CONF.ml2_arista.get('sec_group_support')
        self._validate_config()
        for s in cfg.CONF.ml2_arista.switch_info:
            switch_ip, switch_user, switch_pass = s.split(":")
            if switch_pass == "''":
                switch_pass = ''
            self._hosts[switch_ip] = (
                {'user': switch_user, 'password': switch_pass})
            self._servers.append(self._make_eapi_client(switch_ip))
        self.aclCreateDict = acl_cmd['acl']
        self.aclApplyDict = acl_cmd['apply']

    def _make_eapi_client(self, host):
        return api.EAPIClient(
            host,
            username=self._hosts[host]['user'],
            password=self._hosts[host]['password'],
            verify=False,
            timeout=cfg.CONF.ml2_arista.conn_timeout
        )

    def _validate_config(self):
        if not self.sg_enabled:
            return
        if len(cfg.CONF.ml2_arista.get('switch_info')) < 1:
            msg = _('Required option - when "sec_group_support" is enabled, '
                    'at least one switch must be specified ')
            LOG.exception(msg)
            raise arista_exc.AristaConfigError(msg=msg)

    def _get_port_for_acl(self, port_id, server):
        """Gets interface name for ACLs

        Finds the Port-Channel name if port_id is in a Port-Channel, otherwise
        ACLs are applied to Ethernet interface.

        :param port_id: Name of port from ironic db
        :param server: Server endpoint on the Arista switch to be configured
        """
        all_intf_info = self._run_eos_cmds(
            ['show interfaces %s' % port_id], server)[0]
        intf_info = all_intf_info.get('interfaces', {}).get(port_id, {})
        member_info = intf_info.get('interfaceMembership', '')
        port_group_info = re.search('Member of (?P<port_group>\S+)',
                                    member_info)
        if port_group_info:
            port_id = port_group_info.group('port_group')
        return port_id

    def _create_acl_on_eos(self, in_cmds, out_cmds, protocol, cidr,
                           from_port, to_port, direction):
        """Creates an ACL on Arista HW Device.

        :param name: Name for the ACL
        :param server: Server endpoint on the Arista switch to be configured
        """
        if protocol == 'icmp':
            # ICMP rules require special processing
            if not from_port and not to_port:
                rule = 'icmp_custom0'
            elif from_port and not to_port:
                rule = 'icmp_custom1'
            elif from_port and to_port:
                rule = 'icmp_custom2'
            else:
                msg = _('Invalid ICMP rule specified')
                LOG.exception(msg)
                raise arista_exc.AristaSecurityGroupError(msg=msg)
            rule_type = 'in'
            cmds = in_cmds
            if direction == 'egress':
                rule_type = 'out'
                cmds = out_cmds
            final_rule = rule_type + '_' + rule
            acl_dict = self.aclCreateDict[final_rule]

            # None port is probematic - should be replaced with 0
            if not from_port:
                from_port = 0
            if not to_port:
                to_port = 0

            for c in acl_dict:
                if rule == 'icmp_custom0':
                    cmds.append(c.format(cidr))
                elif rule == 'icmp_custom1':
                    cmds.append(c.format(cidr, from_port))
                else:
                    cmds.append(c.format(cidr, from_port, to_port))
            return in_cmds, out_cmds
        else:
            # Non ICMP rules processing here
            acl_dict = self.aclCreateDict['in_rule']
            cmds = in_cmds
            if direction == 'egress':
                acl_dict = self.aclCreateDict['out_rule']
                cmds = out_cmds
            if not protocol:
                acl_dict = self.aclCreateDict['default']

            for c in acl_dict:
                cmds.append(c.format(protocol, cidr,
                                     from_port, to_port))
            return in_cmds, out_cmds

    def _delete_acl_from_eos(self, name, server):
        """deletes an ACL from Arista HW Device.

        :param name: Name for the ACL
        :param server: Server endpoint on the Arista switch to be configured
        """
        cmds = []

        for c in self.aclCreateDict['delete_acl']:
            cmds.append(c.format(name))

        self._run_openstack_sg_cmds(cmds, server)

    def _delete_acl_rule_from_eos(self, name,
                                  protocol, cidr,
                                  from_port, to_port,
                                  direction, server):
        """deletes an ACL from Arista HW Device.

        :param name: Name for the ACL
        :param server: Server endpoint on the Arista switch to be configured
        """
        cmds = []

        if protocol == 'icmp':
            # ICMP rules require special processing
            if not from_port and not to_port:
                rule = 'icmp_custom0'
            elif from_port and not to_port:
                rule = 'icmp_custom1'
            elif from_port and to_port:
                rule = 'icmp_custom2'
            else:
                msg = _('Invalid ICMP rule specified')
                LOG.exception(msg)
                raise arista_exc.AristaSecurityGroupError(msg=msg)
            rule_type = 'del_in'
            if direction == 'egress':
                rule_type = 'del_out'
            final_rule = rule_type + '_' + rule
            acl_dict = self.aclCreateDict[final_rule]

            # None port is probematic - should be replaced with 0
            if not from_port:
                from_port = 0
            if not to_port:
                to_port = 0

            for c in acl_dict:
                if rule == 'icmp_custom0':
                    cmds.append(c.format(cidr))
                elif rule == 'icmp_custom1':
                    cmds.append(c.format(cidr, from_port))
                else:
                    cmds.append(c.format(cidr, from_port, to_port))
        else:
            acl_dict = self.aclCreateDict['del_in_acl_rule']
            if direction == 'egress':
                acl_dict = self.aclCreateDict['del_out_acl_rule']

            for c in acl_dict:
                cmds.append(c.format(name, protocol, cidr,
                                     from_port, to_port))

        self._run_openstack_sg_cmds(cmds, server)

    def _apply_acl_on_eos(self, port_id, name, direction, server):
        """Creates an ACL on Arista HW Device.

        :param port_id: The port where the ACL needs to be applied
        :param name: Name for the ACL
        :param direction: must contain "ingress" or "egress"
        :param server: Server endpoint on the Arista switch to be configured
        """
        cmds = []
        port_id = self._get_port_for_acl(port_id, server)
        for c in self.aclApplyDict[direction]:
            cmds.append(c.format(port_id, name))

        self._run_openstack_sg_cmds(cmds, server)

    def _remove_acl_from_eos(self, port_id, name, direction, server):
        """Remove an ACL from a port on Arista HW Device.

        :param port_id: The port where the ACL needs to be applied
        :param name: Name for the ACL
        :param direction: must contain "ingress" or "egress"
        :param server: Server endpoint on the Arista switch to be configured
        """
        cmds = []

        port_id = self._get_port_for_acl(port_id, server)
        acl_cmd = self.aclApplyDict['rm_ingress']
        if direction == 'egress':
            acl_cmd = self.aclApplyDict['rm_egress']
        for c in acl_cmd:
            cmds.append(c.format(port_id, name))

        self._run_openstack_sg_cmds(cmds, server)

    def _create_acl_rule(self, in_cmds, out_cmds, sgr):
        """Creates an ACL on Arista Switch.

        For a given Security Group (ACL), it adds additional rule
        Deals with multiple configurations - such as multiple switches
        """
        # Only deal with valid protocols - skip the rest
        if not sgr or sgr['protocol'] not in SUPPORTED_SG_PROTOCOLS:
            return in_cmds, out_cmds

        remote_ip = sgr['remote_ip_prefix']
        if not remote_ip:
            remote_ip = 'any'
        min_port = sgr['port_range_min']
        if not min_port:
            min_port = 0
        max_port = sgr['port_range_max']
        if not max_port and sgr['protocol'] != 'icmp':
            max_port = 65535
        in_cmds, out_cmds = self._create_acl_on_eos(in_cmds, out_cmds,
                                                    sgr['protocol'],
                                                    remote_ip,
                                                    min_port,
                                                    max_port,
                                                    sgr['direction'])
        return in_cmds, out_cmds

    def create_acl_rule(self, sgr):
        """Creates an ACL on Arista Switch.

        For a given Security Group (ACL), it adds additional rule
        Deals with multiple configurations - such as multiple switches
        """
        # Do nothing if Security Groups are not enabled
        if not self.sg_enabled:
            return

        name = self._arista_acl_name(sgr['security_group_id'],
                                     sgr['direction'])
        cmds = []
        for c in self.aclCreateDict['create']:
            cmds.append(c.format(name))
        in_cmds, out_cmds = self._create_acl_rule(cmds, cmds, sgr)

        cmds = in_cmds
        if sgr['direction'] == 'egress':
            cmds = out_cmds

        cmds.append('exit')

        for s in self._servers:
            try:
                self._run_openstack_sg_cmds(cmds, s)
            except Exception:
                msg = (_('Failed to create ACL rule on EOS %s') % s)
                LOG.exception(msg)
                raise arista_exc.AristaSecurityGroupError(msg=msg)

    def delete_acl_rule(self, sgr):
        """Deletes an ACL rule on Arista Switch.

        For a given Security Group (ACL), it adds removes a rule
        Deals with multiple configurations - such as multiple switches
        """
        # Do nothing if Security Groups are not enabled
        if not self.sg_enabled:
            return

        # Only deal with valid protocols - skip the rest
        if not sgr or sgr['protocol'] not in SUPPORTED_SG_PROTOCOLS:
            return

        # Build seperate ACL for ingress and egress
        name = self._arista_acl_name(sgr['security_group_id'],
                                     sgr['direction'])
        remote_ip = sgr['remote_ip_prefix']
        if not remote_ip:
            remote_ip = 'any'
        min_port = sgr['port_range_min']
        if not min_port:
            min_port = 0
        max_port = sgr['port_range_max']
        if not max_port and sgr['protocol'] != 'icmp':
            max_port = 65535
        for s in self._servers:
            try:
                self._delete_acl_rule_from_eos(name,
                                               sgr['protocol'],
                                               remote_ip,
                                               min_port,
                                               max_port,
                                               sgr['direction'],
                                               s)
            except Exception:
                msg = (_('Failed to delete ACL on EOS %s') % s)
                LOG.exception(msg)
                raise arista_exc.AristaSecurityGroupError(msg=msg)

    def _create_acl_shell(self, sg_id):
        """Creates an ACL on Arista Switch.

        For a given Security Group (ACL), it adds additional rule
        Deals with multiple configurations - such as multiple switches
        """
        # Build seperate ACL for ingress and egress
        direction = ['ingress', 'egress']
        cmds = []
        for d in range(len(direction)):
            name = self._arista_acl_name(sg_id, direction[d])
            cmds.append([])
            for c in self.aclCreateDict['create']:
                cmds[d].append(c.format(name))
        return cmds[0], cmds[1]

    def create_acl(self, sg):
        """Creates an ACL on Arista Switch.

        Deals with multiple configurations - such as multiple switches
        """
        # Do nothing if Security Groups are not enabled
        if not self.sg_enabled:
            return

        if not sg:
            msg = _('Invalid or Empty Security Group Specified')
            raise arista_exc.AristaSecurityGroupError(msg=msg)

        in_cmds, out_cmds = self._create_acl_shell(sg['id'])
        for sgr in sg['security_group_rules']:
            in_cmds, out_cmds = self._create_acl_rule(in_cmds, out_cmds, sgr)
        in_cmds.append('exit')
        out_cmds.append('exit')

        for s in self._servers:
            try:
                self._run_openstack_sg_cmds(in_cmds, s)
                self._run_openstack_sg_cmds(out_cmds, s)

            except Exception:
                msg = (_('Failed to create ACL on EOS %s') % s)
                LOG.exception(msg)
                raise arista_exc.AristaSecurityGroupError(msg=msg)

    def delete_acl(self, sg):
        """Deletes an ACL from Arista Switch.

        Deals with multiple configurations - such as multiple switches
        """
        # Do nothing if Security Groups are not enabled
        if not self.sg_enabled:
            return

        if not sg:
            msg = _('Invalid or Empty Security Group Specified')
            raise arista_exc.AristaSecurityGroupError(msg=msg)

        direction = ['ingress', 'egress']
        for d in range(len(direction)):
            name = self._arista_acl_name(sg['id'], direction[d])

            for s in self._servers:
                try:
                    self._delete_acl_from_eos(name, s)
                except Exception:
                    msg = (_('Failed to create ACL on EOS %s') % s)
                    LOG.exception(msg)
                    raise arista_exc.AristaSecurityGroupError(msg=msg)

    def apply_acl(self, sgs, switch_id, port_id, switch_info):
        """Creates an ACL on Arista Switch.

        Applies ACLs to the baremetal ports only. The port/switch
        details is passed through the parameters.
        Deals with multiple configurations - such as multiple switches
        param sgs: List of Security Groups
        param switch_id: Switch ID of TOR where ACL needs to be applied
        param port_id: Port ID of port where ACL needs to be applied
        param switch_info: IP address of the TOR
        """
        # Do nothing if Security Groups are not enabled
        if not self.sg_enabled:
            return

        # We do not support more than one security group on a port
        if not sgs or len(sgs) > 1:
            msg = (_('Only one Security Group Supported on a port %s') % sgs)
            raise arista_exc.AristaSecurityGroupError(msg=msg)

        sg = self._ndb.get_security_group(sgs[0])

        # We already have ACLs on the TORs.
        # Here we need to find out which ACL is applicable - i.e.
        # Ingress ACL, egress ACL or both
        direction = ['ingress', 'egress']

        server = self._make_eapi_client(switch_info)

        for d in range(len(direction)):
            name = self._arista_acl_name(sg['id'], direction[d])
            try:
                self._apply_acl_on_eos(port_id, name, direction[d], server)
            except Exception:
                msg = (_('Failed to apply ACL on port %s') % port_id)
                LOG.exception(msg)
                raise arista_exc.AristaSecurityGroupError(msg=msg)

    def remove_acl(self, sgs, switch_id, port_id, switch_info):
        """Removes an ACL from Arista Switch.

        Removes ACLs from the baremetal ports only. The port/switch
        details is passed throuhg the parameters.
        param sgs: List of Security Groups
        param switch_id: Switch ID of TOR where ACL needs to be removed
        param port_id: Port ID of port where ACL needs to be removed
        param switch_info: IP address of the TOR
        """
        # Do nothing if Security Groups are not enabled
        if not self.sg_enabled:
            return

        # We do not support more than one security group on a port
        if not sgs or len(sgs) > 1:
            msg = (_('Only one Security Group Supported on a port %s') % sgs)
            raise arista_exc.AristaSecurityGroupError(msg=msg)

        sg = self._ndb.get_security_group(sgs[0])

        # We already have ACLs on the TORs.
        # Here we need to find out which ACL is applicable - i.e.
        # Ingress ACL, egress ACL or both
        direction = []
        for sgr in sg['security_group_rules']:
            # Only deal with valid protocols - skip the rest
            if not sgr or sgr['protocol'] not in SUPPORTED_SG_PROTOCOLS:
                continue

            if sgr['direction'] not in direction:
                direction.append(sgr['direction'])

        # THIS IS TOTAL HACK NOW - just for testing
        # Assumes the credential of all switches are same as specified
        # in the condig file
        server = self._make_eapi_client(switch_info)
        for d in range(len(direction)):
            name = self._arista_acl_name(sg['id'], direction[d])
            try:
                self._remove_acl_from_eos(port_id, name, direction[d], server)
            except Exception:
                msg = (_('Failed to remove ACL on port %s') % port_id)
                LOG.exception(msg)
                # No need to raise exception for ACL removal
                # raise arista_exc.AristaSecurityGroupError(msg=msg)

    def _run_openstack_sg_cmds(self, commands, server):
        """Execute/sends a CAPI (Command API) command to EOS.

        In this method, list of commands is appended with prefix and
        postfix commands - to make is understandble by EOS.

        :param commands : List of command to be executed on EOS.
        :param server: Server endpoint on the Arista switch to be configured
        """
        command_start = ['enable', 'configure']
        command_end = ['exit']
        full_command = command_start + commands + command_end
        return self._run_eos_cmds(full_command, server)

    def _run_eos_cmds(self, commands, server):
        """Execute/sends a CAPI (Command API) command to EOS.

        This method is useful for running show commands that require no
        prefix or postfix commands.

        :param commands : List of commands to be executed on EOS.
        :param server: Server endpoint on the Arista switch to be configured
        """
        LOG.info(_LI('Executing command on Arista EOS: %s'), commands)

        try:
            # this returns array of return values for every command in
            # commands list
            ret = server.execute(commands)
            LOG.info(_LI('Results of execution on Arista EOS: %s'), ret)
            return ret
        except Exception:
            msg = (_('Error occurred while trying to execute '
                     'commands %(cmd)s on EOS %(host)s') %
                   {'cmd': commands, 'host': server})
            LOG.exception(msg)
            raise arista_exc.AristaServicePluginRpcError(msg=msg)

    def _arista_acl_name(self, name, direction):
        """Generate an arista specific name for this ACL.

        Use a unique name so that OpenStack created ACLs
        can be distinguishged from the user created ACLs
        on Arista HW.
        """
        in_out = 'IN'
        if direction == 'egress':
            in_out = 'OUT'
        return 'SG' + '-' + in_out + '-' + name

    def perform_sync_of_sg(self):
        """Perform sync of the security groups between ML2 and EOS.

        This is unconditional sync to ensure that all security
        ACLs are pushed to all the switches, in case of switch
        or neutron reboot
        """
        # Do nothing if Security Groups are not enabled
        if not self.sg_enabled:
            return

        arista_ports = db_lib.get_ports()
        neutron_sgs = self._ndb.get_security_groups()
        sg_bindings = self._ndb.get_all_security_gp_to_port_bindings()
        sgs = []
        sgs_dict = {}
        arista_port_ids = arista_ports.keys()

        # Get the list of Security Groups of interest to us
        for s in sg_bindings:
            if s['port_id'] in arista_port_ids:
                if not s['security_group_id'] in sgs:
                    sgs_dict[s['port_id']] = (
                        {'security_group_id': s['security_group_id']})
                    sgs.append(s['security_group_id'])

        # Create the ACLs on Arista Switches
        for idx in range(len(sgs)):
            self.create_acl(neutron_sgs[sgs[idx]])

        # Get Baremetal port profiles, if any
        bm_port_profiles = db_lib.get_all_baremetal_ports()

        if bm_port_profiles:
            for bm in bm_port_profiles.values():
                if bm['port_id'] in sgs_dict:
                    sg = sgs_dict[bm['port_id']]['security_group_id']
                    profile = json.loads(bm['profile'])
                    link_info = profile['local_link_information']
                    for l in link_info:
                        if not l:
                            # skip all empty entries
                            continue
                        self.apply_acl([sg], l['switch_id'],
                                       l['port_id'], l['switch_info'])
