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
from networking_arista.common import db_lib
from networking_arista.common import exceptions as arista_exc

LOG = logging.getLogger(__name__)


class AristaSyncWorker(worker.BaseWorker):
    def __init__(self, rpc, ndb):
        super(AristaSyncWorker, self).__init__(worker_process_count=0)
        self.ndb = ndb
        self.rpc = rpc
        self.sync_service = SyncService(rpc, ndb)
        rpc.sync_service = self.sync_service
        self._loop = None

    def start(self):
        super(AristaSyncWorker, self).start()

        self._sync_running = True
        self._sync_event = threading.Event()

        self._cleanup_db()
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

    def _cleanup_db(self):
        """Clean up any unnecessary entries in our DB."""

        LOG.info('Arista Sync: DB Cleanup')
        neutron_nets = self.ndb.get_all_networks()
        arista_db_nets = db_lib.get_networks(tenant_id='any')
        neutron_net_ids = set()
        for net in neutron_nets:
            neutron_net_ids.add(net['id'])

        # Remove networks from the Arista DB if the network does not exist in
        # Neutron DB
        for net_id in set(arista_db_nets.keys()).difference(neutron_net_ids):
            tenant_network = arista_db_nets[net_id]
            db_lib.forget_network_segment(tenant_network['tenantId'], net_id)
            db_lib.forget_all_ports_for_network(net_id)


class SyncService(object):
    """Synchronization of information between Neutron and EOS

    Periodically (through configuration option), this service
    ensures that Networks and VMs configured on EOS/Arista HW
    are always in sync with Neutron DB.
    """
    def __init__(self, rpc_wrapper, neutron_db):
        self._rpc = rpc_wrapper
        self._ndb = neutron_db
        self._force_sync = True
        self._region_updated_time = None

    def force_sync(self):
        """Sets the force_sync flag."""
        self._force_sync = True

    def do_synchronize(self):
        """Periodically check whether EOS is in sync with ML2 driver.

           If ML2 database is not in sync with EOS, then compute the diff and
           send it down to EOS.
        """
        # Perform sync of Security Groups unconditionally
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
            self._force_sync = True
            return

        # Perform the actual synchronization.
        self.synchronize()

        # Send 'sync end' marker.
        if not self._rpc.sync_end():
            LOG.info(_LI('Sync end failed, setting force'))
            self._force_sync = True
            return

        self._set_region_updated_time()

    def synchronize(self):
        """Sends data to EOS which differs from neutron DB."""

        LOG.info(_LI('Syncing Neutron <-> EOS'))
        try:
            # Register with EOS to ensure that it has correct credentials
            self._rpc.register_with_eos(sync=True)
            self._rpc.check_supported_features()
            eos_tenants = self._rpc.get_tenants()
        except arista_exc.AristaRpcError:
            LOG.warning(constants.EOS_UNREACHABLE_MSG)
            self._force_sync = True
            return

        db_tenants = db_lib.get_tenants()

        # Delete tenants that are in EOS, but not in the database
        tenants_to_delete = frozenset(eos_tenants.keys()).difference(
            db_tenants.keys())

        if tenants_to_delete:
            try:
                self._rpc.delete_tenant_bulk(tenants_to_delete, sync=True)
            except arista_exc.AristaRpcError:
                LOG.warning(constants.EOS_UNREACHABLE_MSG)
                self._force_sync = True
                return

        # None of the commands have failed till now. But if subsequent
        # operations fail, then force_sync is set to true
        self._force_sync = False

        # Create a dict of networks keyed by id.
        neutron_nets = dict(
            (network['id'], network) for network in
            self._ndb.get_all_networks()
        )

        # Get Baremetal port switch_bindings, if any
        port_profiles = db_lib.get_all_portbindings()
        # To support shared networks, split the sync loop in two parts:
        # In first loop, delete unwanted VM and networks and update networks
        # In second loop, update VMs. This is done to ensure that networks for
        # all tenats are updated before VMs are updated
        instances_to_update = {}
        for tenant in db_tenants.keys():
            db_nets = db_lib.get_networks(tenant)
            db_instances = db_lib.get_vms(tenant)

            eos_nets = self._get_eos_networks(eos_tenants, tenant)
            eos_vms, eos_bms, eos_routers, eos_dhcps = self._get_eos_vms(
                eos_tenants, tenant)

            db_nets_key_set = frozenset(db_nets.keys())
            db_instances_key_set = frozenset(db_instances.keys())
            eos_nets_key_set = frozenset(eos_nets.keys())
            eos_vms_key_set = frozenset(eos_vms.keys())
            eos_routers_key_set = frozenset(eos_routers.keys())
            eos_bms_key_set = frozenset(eos_bms.keys())
            eos_dhcps_key_set = frozenset(eos_dhcps.keys())

            # Create a candidate list by incorporating all instances
            eos_instances_key_set = (eos_vms_key_set | eos_routers_key_set |
                                     eos_bms_key_set | eos_dhcps_key_set)

            # Find the networks that are present on EOS, but not in Neutron DB
            nets_to_delete = eos_nets_key_set.difference(db_nets_key_set)

            # Find the VMs that are present on EOS, but not in Neutron DB
            instances_to_delete = eos_instances_key_set.difference(
                db_instances_key_set)

            dhcps_to_delete = [dhcp for dhcp in eos_dhcps_key_set
                               if dhcp in instances_to_delete]
            vms_to_delete = [
                vm for vm in eos_vms_key_set if vm in instances_to_delete]
            routers_to_delete = [
                r for r in eos_routers_key_set if r in instances_to_delete]
            bms_to_delete = [
                b for b in eos_bms_key_set if b in instances_to_delete]

            # Find the Networks that are present in Neutron DB, but not on EOS
            nets_to_update = db_nets_key_set.difference(eos_nets_key_set)

            # Find the VMs that are present in Neutron DB, but not on EOS
            instances_to_update[tenant] = db_instances_key_set.difference(
                eos_instances_key_set)

            try:
                if vms_to_delete:
                    self._rpc.delete_vm_bulk(tenant, vms_to_delete, sync=True)
                if dhcps_to_delete:
                    self._rpc.delete_dhcp_bulk(tenant, dhcps_to_delete,
                                               sync=True)
                if routers_to_delete:
                    if self._rpc.bm_and_dvr_supported():
                        self._rpc.delete_instance_bulk(
                            tenant,
                            routers_to_delete,
                            constants.InstanceType.ROUTER,
                            sync=True)
                    else:
                        LOG.info(constants.ERR_DVR_NOT_SUPPORTED)

                if bms_to_delete:
                    if self._rpc.bm_and_dvr_supported():
                        self._rpc.delete_instance_bulk(
                            tenant,
                            bms_to_delete,
                            constants.InstanceType.BAREMETAL,
                            sync=True)
                    else:
                        LOG.info(constants.BAREMETAL_NOT_SUPPORTED)

                if nets_to_delete:
                    self._rpc.delete_network_bulk(tenant, nets_to_delete,
                                                  sync=True)
                if nets_to_update:
                    networks = [{
                        'network_id': net_id,
                        'network_name':
                            neutron_nets.get(net_id, {'name': ''})['name'],
                        'shared':
                            neutron_nets.get(net_id,
                                             {'shared': False})['shared'],
                        'segments': self._ndb.get_all_network_segments(net_id),
                        }
                        for net_id in nets_to_update
                    ]
                    self._rpc.create_network_bulk(tenant, networks, sync=True)
            except arista_exc.AristaRpcError:
                LOG.warning(constants.EOS_UNREACHABLE_MSG)
                self._force_sync = True

        ports_of_interest = {}
        for port in self._ndb.get_all_ports():
            ports_of_interest.update(
                self._port_dict_representation(port))

        # Now update the VMs
        for tenant in instances_to_update:
            if not instances_to_update[tenant]:
                continue
            try:
                db_vms = db_lib.get_vms(tenant)
                if db_vms:
                    self._rpc.create_instance_bulk(tenant,
                                                   ports_of_interest,
                                                   db_vms,
                                                   port_profiles,
                                                   sync=True)
            except arista_exc.AristaRpcError:
                LOG.warning(constants.EOS_UNREACHABLE_MSG)
                self._force_sync = True

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

    def _get_eos_networks(self, eos_tenants, tenant):
        networks = {}
        if eos_tenants and tenant in eos_tenants:
            networks = eos_tenants[tenant]['tenantNetworks']
        return networks

    def _get_eos_vms(self, eos_tenants, tenant):
        vms = {}
        bms = {}
        routers = {}
        dhcps = {}
        all_vms = {}
        if eos_tenants and tenant in eos_tenants:
            all_vms = eos_tenants[tenant]['tenantVmInstances']
            dhcps = (dict((vmid, all_vms[vmid]) for vmid in all_vms
                          if vmid.startswith('dhcp')))
            vms = dict((vm, all_vms[vm]) for vm in set(all_vms) - set(dhcps))
            if 'tenantBaremetalInstances' in eos_tenants[tenant]:
                # Check if baremetal service is supported
                bms = eos_tenants[tenant]['tenantBaremetalInstances']
            if 'tenantRouterInstances' in eos_tenants[tenant]:
                routers = eos_tenants[tenant]['tenantRouterInstances']
        return vms, bms, routers, dhcps

    def _port_dict_representation(self, port):
        return {port['id']: {'device_owner': port['device_owner'],
                             'device_id': port['device_id'],
                             'name': port['name'],
                             'id': port['id'],
                             'tenant_id': port['tenant_id'],
                             'network_id': port['network_id']}}
