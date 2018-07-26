# Copyright (c) 2014 OpenStack Foundation
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

import threading
import time

from eventlet import event
from eventlet import greenthread
from six.moves.queue import Empty

from neutron_lib import worker
from oslo_config import cfg
from oslo_log import log as logging

from networking_arista.common import constants as a_const
from networking_arista.common import exceptions as arista_exc
from networking_arista.ml2 import arista_resources as resources
from networking_arista.ml2.rpc.arista_json import AristaRPCWrapperJSON

LOG = logging.getLogger(__name__)


class AristaSyncWorker(worker.BaseWorker):
    def __init__(self, provision_queue):
        super(AristaSyncWorker, self).__init__(worker_process_count=0)
        self._rpc = AristaRPCWrapperJSON()
        self.provision_queue = provision_queue
        self._thread = None
        self._running = False
        self.done = None
        self._sync_interval = cfg.CONF.ml2_arista.sync_interval

    def initialize(self):
        self._last_sync_time = 0
        self._cvx_uuid = None
        self._synchronizing_uuid = None

        self.tenants = resources.Tenants(self._rpc)
        self.networks = resources.Networks(self._rpc)
        self.segments = resources.Segments(self._rpc)
        self.dhcps = resources.Dhcps(self._rpc)
        self.routers = resources.Routers(self._rpc)
        self.vms = resources.Vms(self._rpc)
        self.baremetals = resources.Baremetals(self._rpc)
        self.dhcp_ports = resources.DhcpPorts(self._rpc)
        self.router_ports = resources.RouterPorts(self._rpc)
        self.vm_ports = resources.VmPorts(self._rpc)
        self.baremetal_ports = resources.BaremetalPorts(self._rpc)
        self.port_bindings = resources.PortBindings(self._rpc)

        # Sync order is important because of entity dependencies:
        # PortBinding -> Port -> Instance -> Tenant
        #             -> Segment -> Network -> Tenant
        self.sync_order = [self.tenants,
                           self.networks,
                           self.segments,
                           self.dhcps,
                           self.routers,
                           self.vms,
                           self.baremetals,
                           self.dhcp_ports,
                           self.router_ports,
                           self.vm_ports,
                           self.baremetal_ports,
                           self.port_bindings]

    def _on_done(self, gt, *args, **kwargs):
        self._thread = None
        self._running = False

    def start(self):
        if self._thread is not None:
            LOG.warning('Arista sync loop has already been started')
            return

        LOG.info("Arista sync worker started")
        super(AristaSyncWorker, self).start()
        self.initialize()
        self.done = event.Event()
        self._running = True
        LOG.info("Spawning Arista sync loop")
        self._thread = greenthread.spawn(self.sync_loop)
        self._thread.link(self._on_done)

    def stop(self, graceful=True):
        if graceful:
            self._running = False
        else:
            self._thread.kill()

    def wait(self):
        return self.done.wait()

    def reset(self):
        self.stop()
        self.wait()
        self.start()

    def get_resource_class(self, resource_type):
        class_map = {a_const.TENANT_RESOURCE: self.tenants,
                     a_const.NETWORK_RESOURCE: self.networks,
                     a_const.SEGMENT_RESOURCE: self.segments,
                     a_const.DHCP_RESOURCE: self.dhcps,
                     a_const.ROUTER_RESOURCE: self.routers,
                     a_const.VM_RESOURCE: self.vms,
                     a_const.BAREMETAL_RESOURCE: self.baremetals,
                     a_const.DHCP_PORT_RESOURCE: self.dhcp_ports,
                     a_const.ROUTER_PORT_RESOURCE: self.router_ports,
                     a_const.VM_PORT_RESOURCE: self.vm_ports,
                     a_const.BAREMETAL_PORT_RESOURCE: self.baremetal_ports,
                     a_const.PORT_BINDING_RESOURCE: self.port_bindings}
        return class_map[resource_type]

    def add_neutron_resource(self, resource):
        resource_class = self.get_resource_class(resource.resource_type)
        resource_class.add_neutron_resource(resource.id)

    def update_neutron_resource(self, resource):
        resource_class = self.get_resource_class(resource.resource_type)
        resource_class.update_neutron_resource(resource.id)

    def delete_neutron_resource(self, resource):
        resource_class = self.get_resource_class(resource.resource_type)
        resource_class.delete_neutron_resource(resource.id)

    def process_mech_update(self, resource):
        LOG.info("%(tid)s %(action)s %(rtype)s with id %(id)s",
                 {'action': resource.action,
                  'rtype': resource.resource_type,
                  'id': resource.id,
                  'tid': threading.current_thread().ident})
        if resource.action == a_const.CREATE:
            self.add_neutron_resource(resource)
        elif resource.action == a_const.DELETE:
            self.delete_neutron_resource(resource)
        else:
            raise arista_exc.UnknownActionException(resource.action)

    def force_full_sync(self):
        """Recompute resources to sync

        We need to compute resources to sync in reverse sync order
        in order to avoid missing dependencies on creation
        Eg. If we query in sync order
        1. Query Instances -> I1 isn't there
        2. Query Port table -> Port P1 is there, connected to I1
        3. We send P1 to CVX without sending I1 -> Error raised
        But if we query P1 first:
        1. Query Ports P1 -> P1 is not there
        2. Query Instances -> find I1
        3. We create I1, not P1 -> harmless, mech driver creates P1
        Missing dependencies on deletion will helpfully result in the
        dependent resource not being created:
        1. Query Ports -> P1 is found
        2. Query Instances -> I1 not found
        3. Creating P1 fails on CVX
        """
        for resource_type in reversed(self.sync_order):
            resource_type.clear_all_data()
            resource_type.get_neutron_resources()

    def check_if_out_of_sync(self):
        cvx_uuid = self._rpc.get_cvx_uuid()
        out_of_sync = False
        if self._cvx_uuid != cvx_uuid:
            LOG.info("Initiating full sync - local uuid %(l_uuid)s"
                     " - cvx uuid %(c_uuid)s",
                     {'l_uuid': self._cvx_uuid,
                      'c_uuid': cvx_uuid})
            self.force_full_sync()
            self._synchronizing_uuid = cvx_uuid
            out_of_sync = True
        self._last_sync_time = time.time()
        return out_of_sync

    def wait_for_mech_driver_update(self, timeout):
        try:
            resource = self.provision_queue.get(timeout=timeout)
            LOG.info("Processing %(res)s", {'res': resource})
            self.process_mech_update(resource)
            return True
        except Empty:
            return False

    def wait_for_sync_required(self):
        timeout = (self._sync_interval -
                   (time.time() - self._last_sync_time))
        LOG.info("Arista Sync time %(time)s last sync %(last_sync)s "
                 "timeout %(timeout)s", {'time': time.time(),
                                         'last_sync': self._last_sync_time,
                                         'timeout': timeout})
        if timeout < 0:
            return self.check_if_out_of_sync()
        else:
            return self.wait_for_mech_driver_update(timeout)

    def synchronize_resources(self):
        # Grab the sync lock
        if not self._rpc.sync_start():
            LOG.info("Failed to grab the sync lock")
            self._last_sync_time = 0
            greenthread.sleep(1)
            return

        # Sync any necessary resources.
        # We delete in reverse order and create in order to ensure that
        # dependent resources  are deleted before the resources they depend
        # on and created after them
        for resource_type in reversed(self.sync_order):
            resource_type.delete_cvx_resources()
        for resource_type in self.sync_order:
            resource_type.create_cvx_resources()

        # Release the sync lock
        self._rpc.sync_end()

        # Update local uuid if this was a full sync
        if self._synchronizing_uuid:
            LOG.info("Full sync for cvx uuid %(uuid)s complete",
                     {'uuid': self._synchronizing_uuid})
            self._cvx_uuid = self._synchronizing_uuid
            self._synchronizing_uuid = None

    def sync_loop(self):
        while self._running:
            try:
                sync_required = self.wait_for_sync_required()

                if sync_required:
                    self.synchronize_resources()
            except Exception:
                LOG.exception("Arista Sync failed")
                self._cvx_uuid = None
                self._synchronizing_uuid = None

            # Yield to avoid starvation
            greenthread.sleep(0)

        self.done.send(True)
