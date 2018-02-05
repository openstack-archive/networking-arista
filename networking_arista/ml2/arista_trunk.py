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

from oslo_config import cfg
from oslo_log import log

from neutron_lib.api.definitions import port as p_api
from neutron_lib.api.definitions import portbindings
from neutron_lib.api.definitions import trunk as t_api
from neutron_lib.api.definitions import trunk_details as td_api
from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib import constants as n_const
from neutron_lib import context
from neutron_lib.plugins import directory

from neutron.services.trunk import constants as t_const
from neutron.services.trunk.drivers import base

LOG = log.getLogger(__name__)

NAME = 'arista'
SUPPORTED_INTERFACES = (
    portbindings.VIF_TYPE_OTHER,
)
SUPPORTED_SEGMENTATION_TYPES = (
    t_const.VLAN,
)


class AristaTrunkDriver(base.DriverBase):

    @property
    def is_loaded(self):
        try:
            return NAME in cfg.CONF.ml2.mechanism_drivers
        except cfg.NoSuchOptError:
            return False

    @registry.receives(t_const.TRUNK_PLUGIN, [events.AFTER_INIT])
    def register(self, resource, event, trigger, **kwargs):
        """Called in trunk plugin's AFTER_INIT"""
        super(AristaTrunkDriver, self).register(resource, event,
                                                trigger, kwargs)
        registry.subscribe(self.subport_create,
                           t_const.SUBPORTS, events.AFTER_CREATE)
        registry.subscribe(self.subport_delete,
                           t_const.SUBPORTS, events.AFTER_DELETE)
        registry.subscribe(self.trunk_create,
                           t_const.TRUNK, events.AFTER_CREATE)
        registry.subscribe(self.trunk_update,
                           t_const.TRUNK, events.AFTER_UPDATE)
        registry.subscribe(self.trunk_delete,
                           t_const.TRUNK, events.AFTER_DELETE)
        self.core_plugin = directory.get_plugin()
        LOG.debug("Arista trunk driver initialized.")

    @classmethod
    def create(cls):
        return cls(NAME, SUPPORTED_INTERFACES, SUPPORTED_SEGMENTATION_TYPES,
                   can_trunk_bound_port=True)

    def bind_port(self, parent):
        ctx = context.get_admin_context()
        trunk = parent.get(td_api.TRUNK_DETAILS, {})
        subports = trunk.get(t_api.SUB_PORTS, [])
        subport_ids = [subport['port_id'] for subport in subports]
        self._bind_subports(ctx, subport_ids, parent)
        trunk_plugin = directory.get_plugin(t_api.ALIAS)
        trunk_plugin.update_trunk(ctx, trunk.get('trunk_id'),
                                  {t_api.TRUNK:
                                   {'status': t_const.ACTIVE_STATUS}})

    def _bind_subports(self, ctx, subport_ids, parent):
        host_id = parent.get(portbindings.HOST_ID)
        vnic_type = parent.get(portbindings.VNIC_TYPE)
        profile = parent.get(portbindings.PROFILE)
        device_id = parent.get('device_id')
        for subport_id in subport_ids:
            self.core_plugin.update_port(
                ctx, subport_id,
                {p_api.RESOURCE_NAME:
                 {portbindings.HOST_ID: host_id,
                  portbindings.VNIC_TYPE: vnic_type,
                  portbindings.PROFILE: profile,
                  'device_owner': t_const.TRUNK_SUBPORT_OWNER,
                  'device_id': device_id,
                  'status': n_const.PORT_STATUS_ACTIVE}})

    def _unbind_subports(self, ctx, subport_ids, parent):
        for subport_id in subport_ids:
            self.core_plugin.update_port(
                ctx, subport_id,
                {p_api.RESOURCE_NAME:
                 {portbindings.HOST_ID: None,
                  portbindings.VNIC_TYPE: None,
                  portbindings.PROFILE: None,
                  'device_owner': '',
                  'device_id': '',
                  'status': n_const.PORT_STATUS_DOWN}})

    def _delete_trunk(self, trunk):
        ctx = context.get_admin_context()
        parent_id = trunk.port_id
        parent = self.core_plugin.get_port(ctx, parent_id)
        if parent.get(portbindings.VNIC_TYPE) != portbindings.VNIC_BAREMETAL:
            return
        subport_ids = [subport.port_id
                       for subport in trunk.sub_ports]
        self._unbind_subports(ctx, subport_ids, parent)

    def trunk_create(self, resource, event, trunk_plugin, payload):
        ctx = context.get_admin_context()
        parent_id = payload.current_trunk.port_id
        parent = self.core_plugin.get_port(ctx, parent_id)
        if parent.get(portbindings.VNIC_TYPE) != portbindings.VNIC_BAREMETAL:
            return
        subport_ids = [subport.port_id
                       for subport in payload.current_trunk.sub_ports]
        self._bind_subports(ctx, subport_ids, parent)
        trunk_plugin.update_trunk(ctx, payload.trunk_id,
                                  {t_api.TRUNK:
                                   {'status': parent['status']}})

    def trunk_update(self, resource, event, trunk_plugin, payload):
        if payload.current_trunk.status != t_const.ACTIVE_STATUS:
            self._delete_trunk(payload.current_trunk)

    def trunk_delete(self, resource, event, trunk_plugin, payload):
        self._delete_trunk(payload.original_trunk)

    def subport_create(self, resource, event, trunk_plugin, payload):
        ctx = context.get_admin_context()
        parent_id = payload.current_trunk.port_id
        parent = self.core_plugin.get_port(ctx, parent_id)
        if parent.get(portbindings.VNIC_TYPE) != portbindings.VNIC_BAREMETAL:
            return
        subport_ids = [subport.port_id for subport in payload.subports]
        self._bind_subports(ctx, subport_ids, parent)
        trunk_plugin.update_trunk(ctx, payload.trunk_id,
                                  {t_api.TRUNK:
                                   {'status': parent['status']}})

    def subport_delete(self, resource, event, trunk_plugin, payload):
        ctx = context.get_admin_context()
        parent_id = payload.current_trunk.port_id
        parent = self.core_plugin.get_port(ctx, parent_id)
        if parent.get(portbindings.VNIC_TYPE) != portbindings.VNIC_BAREMETAL:
            return
        subport_ids = [subport.port_id for subport in payload.subports]
        self._unbind_subports(ctx, subport_ids, parent)
        trunk_plugin.update_trunk(ctx, payload.trunk_id,
                                  {t_api.TRUNK:
                                   {'status': parent['status']}})
