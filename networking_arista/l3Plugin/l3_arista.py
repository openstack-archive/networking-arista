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

import copy

from neutron_lib.agent import topics
from neutron_lib import constants as n_const
from neutron_lib import context as nctx
from neutron_lib.plugins import constants as plugin_constants
from neutron_lib.plugins import directory
from neutron_lib.services import base as service_base
from neutron_lib import worker
from oslo_config import cfg
from oslo_log import helpers as log_helpers
from oslo_log import log as logging
from oslo_service import loopingcall
from oslo_utils import excutils

from neutron.api.rpc.agentnotifiers import l3_rpc_agent_api
from neutron.api.rpc.handlers import l3_rpc
from neutron.common import rpc as n_rpc
from neutron.db import extraroute_db
from neutron.db import l3_agentschedulers_db
from neutron.db import l3_gwmode_db
from neutron.plugins.ml2.driver_context import NetworkContext  # noqa

from networking_arista._i18n import _LE, _LI
from networking_arista.l3Plugin import arista_l3_driver

LOG = logging.getLogger(__name__)


class AristaL3SyncWorker(worker.BaseWorker):
    def __init__(self, driver):
        self.driver = driver
        self._enable_cleanup = driver._enable_cleanup
        self._protected_vlans = driver._protected_vlans
        self._servers = driver._servers
        self._use_vrf = driver._use_vrf
        self._loop = None
        super(AristaL3SyncWorker, self).__init__(worker_process_count=0)

    def start(self):
        super(AristaL3SyncWorker, self).start()
        if self._loop is None:
            self._loop = loopingcall.FixedIntervalLoopingCall(
                self.synchronize
            )
        self._loop.start(interval=cfg.CONF.l3_arista.l3_sync_interval)

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

    def get_subnet_info(self, subnet_id):
        return self.get_subnet(subnet_id)

    def get_routers_and_interfaces(self):
        core = directory.get_plugin()
        ctx = nctx.get_admin_context()
        routers = directory.get_plugin(plugin_constants.L3).get_routers(ctx)
        router_interfaces = list()
        for r in routers:
            ports = core.get_ports(ctx,
                                   filters={'device_id': [r['id']]}) or []
            for p in ports:
                router_interface = r.copy()
                net_id = p['network_id']
                subnet_id = p['fixed_ips'][0]['subnet_id']
                subnet = core.get_subnet(ctx, subnet_id)
                ml2_db = NetworkContext(self, ctx, {'id': net_id})
                seg_id = ml2_db.network_segments[0]['segmentation_id']

                router_interface['seg_id'] = seg_id
                router_interface['cidr'] = subnet['cidr']
                router_interface['gip'] = subnet['gateway_ip']
                router_interface['ip_version'] = subnet['ip_version']
                router_interface['subnet_id'] = subnet_id
                router_interfaces.append(router_interface)
        return routers, router_interfaces

    def synchronize(self):
        """Synchronizes Router DB from Neturon DB with EOS.

        Walks through the Neturon Db and ensures that all the routers
        created in Netuton DB match with EOS. After creating appropriate
        routers, it ensures to add interfaces as well.
        Uses idempotent properties of EOS configuration, which means
        same commands can be repeated.
        """
        LOG.info(_LI('Syncing Neutron Router DB <-> EOS'))
        routers, router_interfaces = self.get_routers_and_interfaces()
        expected_vrfs = set()
        if self._use_vrf:
            expected_vrfs.update(self.driver._arista_router_name(
                r['id'], r['name']) for r in routers)
        expected_vlans = set(r['seg_id'] for r in router_interfaces)
        if self._enable_cleanup:
            self.do_cleanup(expected_vrfs, expected_vlans)
        self.create_routers(routers)
        self.create_router_interfaces(router_interfaces)

    def get_vrfs(self, server):
        ret = self.driver._run_eos_cmds(['show vrf'], server)
        if len(ret or []) != 1 or 'vrfs' not in ret[0].keys():
            return set()
        eos_vrfs = set(vrf for vrf in ret[0]['vrfs'].keys()
                       if vrf.startswith('__OpenStack__'))
        return eos_vrfs

    def get_svis(self, server):
        ret = self.driver._run_eos_cmds(['show interfaces vlan 1-$'], server)
        if len(ret or []) != 1 or 'interfaces' not in ret[0].keys():
            return set()
        eos_svis = set(int(vlan.strip('Vlan'))
                       for vlan in ret[0]['interfaces'].keys())
        return eos_svis

    def get_vlans(self, server):
        ret = self.driver._run_eos_cmds(['show vlan'], server)
        if len(ret or []) != 1 or 'vlans' not in ret[0].keys():
            return set()
        eos_vlans = set(int(vlan) for vlan, info in ret[0]['vlans'].items()
                        if not info['dynamic'])
        return eos_vlans

    def do_cleanup(self, expected_vrfs, expected_vlans):
        for server in self._servers:
            eos_svis = self.get_svis(server)
            eos_vlans = self.get_vlans(server)
            svis_to_delete = (eos_svis - self._protected_vlans
                              - expected_vlans)
            vlans_to_delete = (eos_vlans - self._protected_vlans
                               - expected_vlans)
            delete_cmds = []
            delete_cmds.extend('no interface vlan %s' % svi
                               for svi in svis_to_delete)
            delete_cmds.extend('no vlan %s' % vlan
                               for vlan in vlans_to_delete)
            if self._use_vrf:
                eos_vrfs = self.get_vrfs(server)
                vrfs_to_delete = eos_vrfs - expected_vrfs
                delete_cmds.extend(['no vrf definition %s' % vrf
                                    for vrf in vrfs_to_delete])
            if delete_cmds:
                self.driver._run_config_cmds(delete_cmds, server)

    def create_routers(self, routers):
        for r in routers:
            try:
                self.driver.create_router(self, r)
            except Exception:
                LOG.error(_LE("Error Adding router %(router_id)s "
                              "on Arista HW"), {'router_id': r})

    def create_router_interfaces(self, router_interfaces):
        for r in router_interfaces:
            try:
                self.driver.add_router_interface(self, r)
            except Exception:
                LOG.error(_LE("Error Adding interface %(subnet_id)s "
                              "to router %(router_id)s on Arista HW"),
                          {'subnet_id': r['subnet_id'], 'router_id': r['id']})


class AristaL3ServicePlugin(service_base.ServicePluginBase,
                            extraroute_db.ExtraRoute_db_mixin,
                            l3_gwmode_db.L3_NAT_db_mixin,
                            l3_agentschedulers_db.L3AgentSchedulerDbMixin):

    """Implements L3 Router service plugin for Arista hardware.

    Creates routers in Arista hardware, manages them, adds/deletes interfaces
    to the routes.
    """

    supported_extension_aliases = ["router", "ext-gw-mode",
                                   "extraroute"]

    def __init__(self, driver=None):
        super(AristaL3ServicePlugin, self).__init__()
        self.driver = driver or arista_l3_driver.AristaL3Driver()
        self.setup_rpc()
        self.add_worker(AristaL3SyncWorker(self.driver))

    def setup_rpc(self):
        # RPC support
        self.topic = topics.L3PLUGIN
        self.conn = n_rpc.Connection()
        self.agent_notifiers.update(
            {n_const.AGENT_TYPE_L3: l3_rpc_agent_api.L3AgentNotifyAPI()})
        self.endpoints = [l3_rpc.L3RpcCallback()]
        self.conn.create_consumer(self.topic, self.endpoints,
                                  fanout=False)
        self.conn.consume_in_threads()

    def get_plugin_type(self):
        return plugin_constants.L3

    def get_plugin_description(self):
        """Returns string description of the plugin."""
        return ("Arista L3 Router Service Plugin for Arista Hardware "
                "based routing")

    @log_helpers.log_method_call
    def create_router(self, context, router):
        """Create a new router entry in DB, and create it Arista HW."""

        # Add router to the DB
        new_router = super(AristaL3ServicePlugin, self).create_router(
            context,
            router)
        # create router on the Arista Hw
        try:
            self.driver.create_router(context, new_router)
            return new_router
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.error(_LE("Error creating router on Arista HW router=%s "),
                          new_router)
                super(AristaL3ServicePlugin, self).delete_router(
                    context,
                    new_router['id']
                )

    @log_helpers.log_method_call
    def update_router(self, context, router_id, router):
        """Update an existing router in DB, and update it in Arista HW."""

        # Read existing router record from DB
        original_router = self.get_router(context, router_id)
        # Update router DB
        new_router = super(AristaL3ServicePlugin, self).update_router(
            context, router_id, router)

        # Modify router on the Arista Hw
        try:
            self.driver.update_router(context, router_id,
                                      original_router, new_router)
            return new_router
        except Exception:
            LOG.error(_LE("Error updating router on Arista HW router=%s "),
                      new_router)

    @log_helpers.log_method_call
    def delete_router(self, context, router_id):
        """Delete an existing router from Arista HW as well as from the DB."""

        router = self.get_router(context, router_id)

        # Delete router on the Arista Hw
        try:
            self.driver.delete_router(context, router_id, router)
        except Exception as e:
            LOG.error(_LE("Error deleting router on Arista HW "
                          "router %(r)s exception=%(e)s"),
                      {'r': router, 'e': e})

        super(AristaL3ServicePlugin, self).delete_router(context, router_id)

    @log_helpers.log_method_call
    def add_router_interface(self, context, router_id, interface_info):
        """Add a subnet of a network to an existing router."""

        new_router = super(AristaL3ServicePlugin, self).add_router_interface(
            context, router_id, interface_info)

        core = directory.get_plugin()

        # Get network info for the subnet that is being added to the router.
        # Check if the interface information is by port-id or subnet-id
        add_by_port, add_by_sub = self._validate_interface_info(interface_info)
        if add_by_sub:
            subnet = core.get_subnet(context, interface_info['subnet_id'])
        elif add_by_port:
            port = core.get_port(context, interface_info['port_id'])
            subnet_id = port['fixed_ips'][0]['subnet_id']
            subnet = core.get_subnet(context, subnet_id)
        network_id = subnet['network_id']

        # To create SVI's in Arista HW, the segmentation Id is required
        # for this network.
        ml2_db = NetworkContext(self, context, {'id': network_id})
        seg_id = ml2_db.network_segments[0]['segmentation_id']

        # Package all the info needed for Hw programming
        router = self.get_router(context, router_id)
        router_info = copy.deepcopy(new_router)
        router_info['seg_id'] = seg_id
        router_info['name'] = router['name']
        router_info['cidr'] = subnet['cidr']
        router_info['gip'] = subnet['gateway_ip']
        router_info['ip_version'] = subnet['ip_version']

        try:
            self.driver.add_router_interface(context, router_info)
            return new_router
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.error(_LE("Error Adding subnet %(subnet)s to "
                              "router %(router_id)s on Arista HW"),
                          {'subnet': subnet, 'router_id': router_id})
                super(AristaL3ServicePlugin, self).remove_router_interface(
                    context,
                    router_id,
                    interface_info)

    @log_helpers.log_method_call
    def remove_router_interface(self, context, router_id, interface_info):
        """Remove a subnet of a network from an existing router."""

        router_to_del = (
            super(AristaL3ServicePlugin, self).remove_router_interface(
                context,
                router_id,
                interface_info)
            )

        # Get network information of the subnet that is being removed
        core = directory.get_plugin()
        subnet = core.get_subnet(context, router_to_del['subnet_id'])
        network_id = subnet['network_id']

        # For SVI removal from Arista HW, segmentation ID is needed
        ml2_db = NetworkContext(self, context, {'id': network_id})
        seg_id = ml2_db.network_segments[0]['segmentation_id']

        router = self.get_router(context, router_id)
        router_info = copy.deepcopy(router_to_del)
        router_info['seg_id'] = seg_id
        router_info['name'] = router['name']

        try:
            self.driver.remove_router_interface(context, router_info)
            return router_to_del
        except Exception as exc:
            LOG.error(_LE("Error removing interface %(interface)s from "
                          "router %(router_id)s on Arista HW"
                          "Exception =(exc)s"),
                      {'interface': interface_info, 'router_id': router_id,
                       'exc': exc})
