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

import json

from neutron_lib import worker
from oslo_config import cfg
from oslo_log import log as logging
from oslo_service import loopingcall

from networking_arista.common import db_lib
from networking_arista.ml2.security_groups import switch_helper

LOG = logging.getLogger(__name__)


class AristaSecurityGroupSyncWorker(
        worker.BaseWorker,
        switch_helper.AristaSecurityGroupSwitchHelper):
    """Worker that handles synchronizing Security Group ACLs on Arista switches

    The worker periodically queries the neutron db and sends all security
    groups, security group rules and security group port bindings to to
    registered switches.
    """

    def __init__(self):
        super(AristaSecurityGroupSyncWorker, self).__init__()
        self.initialize_switch_endpoints()
        self._loop = None

    def start(self):
        super(AristaSecurityGroupSyncWorker, self).start()
        if self._loop is None:
            self._loop = loopingcall.FixedIntervalLoopingCall(
                self.synchronize
            )
        self._loop.start(interval=cfg.CONF.ml2_arista.sync_interval)

    def stop(self):
        if self._loop is not None:
            self._loop.stop()

    def wait(self):
        if self._loop is not None:
            self._loop.wait()
        self._loop = None

    def reset(self):
        self.stop()
        self.wait()
        self.start()

    def update_switch_commands(self, full_switch_cmds, sg_id, profile):
        """Add port's SG bindings to existing per switch cmds

        This is an optimization to configure all interfaces on a switch
        with a single eAPI call, rather than one call per security group
        binding.
        """
        new_cmds = self.get_apply_security_group_commands(sg_id, profile)
        for switch_ip, cmds in new_cmds.items():
            if switch_ip not in full_switch_cmds:
                full_switch_cmds[switch_ip] = []
            full_switch_cmds[switch_ip].extend(cmds)
        return full_switch_cmds

    def synchronize(self):
        """Perform sync of the security groups between ML2 and EOS.

        This is unconditional sync to ensure that all security
        ACLs are pushed to all the switches, in case of switch
        or neutron reboot.

        There is a known limitation in that stale groups, rules
        and bindings are never cleaned up.
        """
        security_groups = db_lib.get_security_groups()
        sg_bindings = db_lib.get_baremetal_sg_bindings()

        # Ensure that all SGs have default deny for ingress and egress
        cmds = []
        for sg in security_groups:
            cmds.extend(self.get_create_security_group_commands(sg['id'],
                                                                sg['rules']))
        self.run_cmds_on_all_switches(cmds)

        self._update_port_group_info()

        # Apply appropriate ACLs to baremetal connected ports
        switch_cmds = {}
        for sg_binding, port_binding in sg_bindings:
            sg_id = sg_binding['security_group_id']
            try:
                binding_profile = json.loads(port_binding.profile)
            except ValueError:
                binding_profile = {}
            switch_cmds = self.update_switch_commands(switch_cmds, sg_id,
                                                      binding_profile)
        self.run_per_switch_cmds(switch_cmds)
