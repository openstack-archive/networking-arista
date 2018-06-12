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

from neutron_lib import worker
from oslo_config import cfg
from oslo_log import log as logging
from oslo_service import loopingcall

from networking_arista.ml2.security_groups import switch_helper

LOG = logging.getLogger(__name__)


class AristaSecurityGroupSyncWorker(
        worker.BaseWorker,
        switch_helper.AristaSecurityGroupSyncHelper):
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

    def synchronize_switch(self, switch_ip, expected_acls, expected_bindings):
        """Update ACL config on a switch to match expected config

        This is done as follows:
        1. Get switch ACL config using show commands
        2. Update expected bindings based on switch LAGs
        3. Get commands to synchronize switch ACLs
        4. Get commands to synchronize switch ACL bindings
        5. Run sync commands on switch
        """

        # Get ACL rules and interface mappings from the switch
        switch_acls, switch_bindings = self._get_dynamic_acl_info(switch_ip)

        # Adjust expected bindings for switch LAG config
        expected_bindings = self.adjust_bindings_for_lag(switch_ip,
                                                         expected_bindings)
        # Get synchronization commands
        switch_cmds = list()
        switch_cmds.extend(
            self.get_sync_acl_cmds(switch_acls, expected_acls))
        switch_cmds.extend(
            self.get_sync_binding_cmds(switch_bindings, expected_bindings))

        # Update switch config
        self.run_openstack_sg_cmds(switch_cmds, self._switches.get(switch_ip))

    def synchronize(self):
        """Perform sync of the security groups between ML2 and EOS."""

        # Get expected ACLs and rules
        expected_acls = self.get_expected_acls()

        # Get expected interface to ACL mappings
        all_expected_bindings = self.get_expected_bindings()

        # Check that config is correct on every registered switch
        for switch_ip in self._switches.keys():
            expected_bindings = all_expected_bindings.get(switch_ip, [])
            try:
                self.synchronize_switch(switch_ip, expected_acls,
                                        expected_bindings)
            except Exception:
                LOG.exception("Failed to sync SGs for %(switch)s",
                              {'switch': switch_ip})
