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

from oslo_log import helpers as log_helpers
from oslo_log import log as logging
from oslo_utils import excutils

from neutron.callbacks import events
from neutron.callbacks import registry
from neutron.callbacks import resources

from networking_arista._i18n import _LE

LOG = logging.getLogger(__name__)


class AristaSecurityGroupHandler(object):
    """Security Group Handler for Arista networking hardware.

    Registers for the notification of security group updates.
    Once a notification is recieved, it takes appropriate actions by updating
    Arista hardware appropriately.
    """
    def __init__(self, client):
        self.client = client
        self.subscribe()

    @log_helpers.log_method_call
    def create_security_group(self, resource, event, trigger, **kwargs):
        sg = kwargs.get('security_group')
        try:
            self.client.create_security_group(sg)
        except Exception as e:
            with excutils.save_and_reraise_exception():
                LOG.error(_LE("Failed to create a security group %(sg_id)s "
                              "in Arista Driver: %(err)s"),
                          {"sg_id": sg["id"], "err": e})
                try:
                    self.client.delete_security_group(sg)
                except Exception:
                    LOG.exception(_LE("Failed to delete security group %s"),
                                  sg['id'])

    @log_helpers.log_method_call
    def delete_security_group(self, resource, event, trigger, **kwargs):
        sg = kwargs.get('security_group')
        try:
            self.client.delete_security_group(sg)
        except Exception as e:
            LOG.error(_LE("Failed to delete security group %(sg_id)s "
                          "in Arista Driver: %(err)s"),
                      {"sg_id": sg["id"], "err": e})

    @log_helpers.log_method_call
    def update_security_group(self, resource, event, trigger, **kwargs):
        sg = kwargs.get('security_group')
        try:
            self.client.update_security_group(sg)
        except Exception as e:
            LOG.error(_LE("Failed to update security group %(sg_id)s "
                          "in Arista Driver: %(err)s"),
                      {"sg_id": sg["id"], "err": e})

    @log_helpers.log_method_call
    def create_security_group_rule(self, resource, event, trigger, **kwargs):
        sgr = kwargs.get('security_group_rule')
        try:
            self.client.create_security_group_rule(sgr)
        except Exception as e:
            with excutils.save_and_reraise_exception():
                LOG.error(_LE("Failed to create a security group %(sgr_id)s "
                              "rule in Arista Driver: %(err)s"),
                          {"sgr_id": sgr["id"], "err": e})
                try:
                    self.client.delete_security_group_rule(sgr)
                except Exception:
                    LOG.exception(_LE("Failed to delete security group "
                                      "rule %s"), sgr['id'])

    @log_helpers.log_method_call
    def delete_security_group_rule(self, resource, event, trigger, **kwargs):
        sgr_id = kwargs.get('security_group_rule_id')
        try:
            self.client.delete_security_group_rule(sgr_id)
        except Exception as e:
            LOG.error(_LE("Failed to delete security group %(sgr_id)s "
                          "rule in Arista Driver: %(err)s"),
                      {"sgr_id": sgr_id, "err": e})

    def subscribe(self):
        # Subscribe to the events related to security groups and rules
        registry.subscribe(
            self.create_security_group, resources.SECURITY_GROUP,
            events.AFTER_CREATE)
        registry.subscribe(
            self.update_security_group, resources.SECURITY_GROUP,
            events.AFTER_UPDATE)
        registry.subscribe(
            self.delete_security_group, resources.SECURITY_GROUP,
            events.BEFORE_DELETE)
        registry.subscribe(
            self.create_security_group_rule, resources.SECURITY_GROUP_RULE,
            events.AFTER_CREATE)
        registry.subscribe(
            self.delete_security_group_rule, resources.SECURITY_GROUP_RULE,
            events.BEFORE_DELETE)
