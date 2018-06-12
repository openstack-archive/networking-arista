# Copyright (c) 2016 OpenStack Foundation
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
from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib.plugins import directory
from neutron_lib.services import base as service_base
from oslo_log import helpers as log_helpers
from oslo_log import log as logging

from networking_arista.ml2.security_groups import security_group_sync
from networking_arista.ml2.security_groups import switch_helper


LOG = logging.getLogger(__name__)


class AristaSecurityGroupHandler(
        service_base.ServicePluginBase,
        switch_helper.AristaSecurityGroupCallbackHelper):
    """Security Group Handler for Arista networking hardware.

    Registers for the notification of security group updates.
    Once a notification is recieved, it takes appropriate actions by updating
    Arista hardware appropriately.
    """

    def __init__(self):
        super(AristaSecurityGroupHandler, self).__init__()
        self.initialize_switch_endpoints()
        self.subscribe()
        self.add_worker(security_group_sync.AristaSecurityGroupSyncWorker())

    def get_plugin_description(self):
        return "Arista baremetal security group service plugin"

    @classmethod
    def get_plugin_type(cls):
        return "arista_security_group"

    @log_helpers.log_method_call
    def create_security_group(self, resource, event, trigger, **kwargs):
        sg = kwargs.get('security_group')
        rules = sg['security_group_rules']
        sg_id = sg['id']
        cmds = self.get_create_security_group_commands(sg_id, rules)
        self.run_cmds_on_all_switches(cmds)

    @log_helpers.log_method_call
    def delete_security_group(self, resource, event, trigger, **kwargs):
        sg_id = kwargs.get('security_group_id')
        cmds = self.get_delete_security_group_commands(sg_id)
        self.run_cmds_on_all_switches(cmds)

    @log_helpers.log_method_call
    def create_security_group_rule(self, resource, event, trigger, **kwargs):
        sgr = kwargs.get('security_group_rule')
        sg_id = sgr['security_group_id']
        cmds = self.get_create_security_group_rule_commands(sg_id, sgr)
        self.run_cmds_on_all_switches(cmds)

    @log_helpers.log_method_call
    def delete_security_group_rule(self, resource, event, trigger, **kwargs):
        sgr_id = kwargs.get('security_group_rule_id')
        context = kwargs.get('context')
        plugin = directory.get_plugin()
        sgr = plugin.get_security_group_rule(context, sgr_id)
        sg_id = sgr['security_group_id']
        cmds = self.get_delete_security_group_rule_commands(sg_id, sgr)
        self.run_cmds_on_all_switches(cmds)

    @staticmethod
    def _valid_baremetal_port(port):
        """Check if port is a baremetal port with exactly one security group"""
        if port.get(portbindings.VNIC_TYPE) != portbindings.VNIC_BAREMETAL:
            return False
        sgs = port.get('security_groups', [])
        if len(sgs) == 0:
            # Nothing to do
            return False
        if len(port.get('security_groups', [])) > 1:
            LOG.warning('SG provisioning failed for %(port)s. Only one '
                        'SG may be applied per port.',
                        {'port': port['id']})
            return False
        return True

    @log_helpers.log_method_call
    def apply_security_group(self, resource, event, trigger, **kwargs):
        port = kwargs.get('port')
        if not self._valid_baremetal_port(port):
            return
        # _valid_baremetal_port guarantees we have exactly one SG
        sg_id = port.get('security_groups')[0]
        profile = port.get(portbindings.PROFILE, {})
        self._update_port_group_info(switches=self._get_switches(profile))
        switch_cmds = self.get_apply_security_group_commands(sg_id, profile)
        self.run_per_switch_cmds(switch_cmds)

    @log_helpers.log_method_call
    def remove_security_group(self, resource, event, trigger, **kwargs):
        port = kwargs.get('port')
        if not self._valid_baremetal_port(port):
            return
        # _valid_baremetal_port guarantees we have exactly one SG
        sg_id = port.get('security_groups')[0]
        profile = port.get(portbindings.PROFILE, {})
        self._update_port_group_info(switches=self._get_switches(profile))
        switch_cmds = self.get_remove_security_group_commands(sg_id, profile)
        self.run_per_switch_cmds(switch_cmds)

    def subscribe(self):
        # Subscribe to the events related to security groups and rules
        registry.subscribe(
            self.create_security_group, resources.SECURITY_GROUP,
            events.AFTER_CREATE)
        registry.subscribe(
            self.delete_security_group, resources.SECURITY_GROUP,
            events.AFTER_DELETE)
        registry.subscribe(
            self.create_security_group_rule, resources.SECURITY_GROUP_RULE,
            events.AFTER_CREATE)

        # We need to handle SG rules in before delete to be able to query
        # the db for the rule details
        registry.subscribe(
            self.delete_security_group_rule, resources.SECURITY_GROUP_RULE,
            events.BEFORE_DELETE)

        # Apply SG rules to intfs on AFTER_UPDATE, remove them on AFTER_DELETE
        registry.subscribe(
            self.apply_security_group, resources.PORT, events.AFTER_UPDATE)
        registry.subscribe(
            self.remove_security_group, resources.PORT, events.AFTER_DELETE)
