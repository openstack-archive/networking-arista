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

from neutron_lib import worker
from oslo_config import cfg
from oslo_log import log as logging
from oslo_service import loopingcall

from networking_arista._i18n import _LI
from networking_arista.common import constants
from networking_arista.common import exceptions as arista_exc
from networking_arista.ml2 import arista_resources as resources

LOG = logging.getLogger(__name__)


class AristaSyncWorker(worker.BaseWorker):
    def __init__(self, rpc, ndb, manage_fabric, managed_physnets):
        super(AristaSyncWorker, self).__init__(worker_process_count=0)
        self.ndb = ndb
        self.rpc = rpc
        self.sync_service = SyncService(rpc, ndb, manage_fabric,
                                        managed_physnets)
        rpc.sync_service = self.sync_service
        self._loop = None

    def start(self):
        super(AristaSyncWorker, self).start()

        self._sync_running = True
        self._sync_event = threading.Event()

        # Registering with EOS updates self.rpc.region_updated_time. Clear it
        # to force an initial sync
        self.rpc.clear_region_updated_time()

        if self._loop is None:
            self._loop = loopingcall.FixedIntervalLoopingCall(
                self.sync_service.do_synchronize
            )
        self._loop.start(interval=cfg.CONF.ml2_arista.sync_interval)

    def stop(self, graceful=False):
        if self._loop is not None:
            self._loop.stop()

    def wait(self):
        if self._loop is not None:
            self._loop.wait()

    def reset(self):
        self.stop()
        self.wait()
        self.start()


class SyncService(object):
    """Synchronization of information between Neutron and EOS

    Periodically (through configuration option), this service
    ensures that Networks and VMs configured on EOS/Arista HW
    are always in sync with Neutron DB.
    """
    def __init__(self, rpc_wrapper, neutron_db, manage_fabric=True,
                 managed_physnets=None):
        self._rpc = rpc_wrapper
        self._ndb = neutron_db
        self._force_sync = True
        self._region_updated_time = None
        self._manage_fabric = manage_fabric
        self._managed_physnets = managed_physnets

        # Sync order is important because of entity dependencies:
        # PortBinding -> Port -> Instance -> Tenant
        #             -> Segment -> Network -> Tenant
        self.sync_order = [resources.Tenants(self._rpc),
                           resources.Networks(self._rpc),
                           resources.Segments(self._rpc),
                           resources.Dhcps(self._rpc),
                           resources.Routers(self._rpc),
                           resources.Vms(self._rpc),
                           resources.Baremetals(self._rpc),
                           resources.DhcpPorts(self._rpc),
                           resources.RouterPorts(self._rpc),
                           resources.VmPorts(self._rpc),
                           resources.BaremetalPorts(self._rpc),
                           resources.PortBindings(self._rpc)]

    def force_sync(self):
        """Sets the force_sync flag."""
        self._force_sync = True

    def do_synchronize(self):
        """Periodically check whether EOS is in sync with ML2 driver.

           If ML2 database is not in sync with EOS, then compute the diff and
           send it down to EOS.
        """
        # Perform sync of Security Groups unconditionally
        # TODO(mitchell): Move security group sync to a separate worker
        try:
            self._rpc.perform_sync_of_sg()
        except Exception as e:
            LOG.warning(e)

        # Check whether CVX is available before starting the sync.
        if not self._rpc.check_cvx_availability():
            LOG.warning("Not syncing as CVX is unreachable")
            self.force_sync()
            return

        if not self._sync_required():
            return

        LOG.info('Attempting to sync')
        # Send 'sync start' marker.
        if not self._rpc.sync_start():
            LOG.info(_LI('Not starting sync, setting force'))
            self.force_sync()
            return

        # Perform the actual synchronization.
        self.synchronize()

        # Send 'sync end' marker.
        if not self._rpc.sync_end():
            LOG.info(_LI('Sync end failed, setting force'))
            self.force_sync()
            return

        self._set_region_updated_time()

    def synchronize(self):
        """Sends data to EOS which differs from neutron DB.

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

        LOG.info(_LI('Syncing Neutron <-> EOS'))

        # Compute resources to sync
        for resource_type in reversed(self.sync_order):
            # Clear all resources for now, once resource passing from
            # mech driver is implemented, we'll be more selective
            # and do so only when a full sync is required
            resource_type.clear_all_data()
            resource_type.get_cvx_ids()
            resource_type.get_neutron_resources()

        # Sync any necessary resources
        for resource_type in self.sync_order:
            resource_type.delete_cvx_resources()
            resource_type.create_cvx_resources()

    def _region_in_sync(self):
        """Checks if the region is in sync with EOS.

           Checks whether the timestamp stored in EOS is the same as the
           timestamp stored locally.
        """
        eos_region_updated_times = self._rpc.get_region_updated_time()
        if eos_region_updated_times:
            return (self._region_updated_time and
                    (self._region_updated_time['regionTimestamp'] ==
                     eos_region_updated_times['regionTimestamp']))
        else:
            return False

    def _sync_required(self):
        """"Check whether the sync is required."""
        try:
            # Get the time at which entities in the region were updated.
            # If the times match, then ML2 is in sync with EOS. Otherwise
            # perform a complete sync.
            if not self._force_sync and self._region_in_sync():
                LOG.info(_LI('OpenStack and EOS are in sync!'))
                return False
        except arista_exc.AristaRpcError:
            LOG.warning(constants.EOS_UNREACHABLE_MSG)
            # Force an update incase of an error.
            self._force_sync = True
        return True

    def _set_region_updated_time(self):
        """Get the region updated time from EOS and store it locally."""
        try:
            self._region_updated_time = self._rpc.get_region_updated_time()
        except arista_exc.AristaRpcError:
            # Force an update incase of an error.
            self._force_sync = True
