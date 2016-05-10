# Copyright (c) 2013 OpenStack Foundation
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

from oslo_config import cfg
from oslo_log import log as logging

from neutron.common import constants as n_const
from neutron.i18n import _LI
from neutron.plugins.common import constants as p_const
from neutron.plugins.ml2.common import exceptions as ml2_exc
from neutron.plugins.ml2 import driver_api

from networking_arista.common import config  # noqa
from networking_arista.common import db
from networking_arista.common import db_lib
from networking_arista.common import exceptions as arista_exc
from networking_arista.ml2 import arista_ml2

LOG = logging.getLogger(__name__)

# Messages
EOS_UNREACHABLE_MSG = _('Unable to reach EOS')
UNABLE_TO_DELETE_PORT_MSG = _('Unable to delete port from EOS')
UNABLE_TO_DELETE_DEVICE_MSG = _('Unable to delete device')

# Constants
INTERNAL_TENANT_ID = 'INTERNAL-TENANT-ID'
PORT_BINDING_HOST = 'binding:host_id'


def pretty_log(tag, obj):
    import json
    log_data = json.dumps(obj, sort_keys=True, indent=4)
    LOG.debug(tag)
    LOG.debug(log_data)


class AristaDriver(driver_api.MechanismDriver):
    """Ml2 Mechanism driver for Arista networking hardware.

    Remembers all networks and VMs that are provisioned on Arista Hardware.
    Does not send network provisioning request if the network has already been
    provisioned before for the given port.
    """
    def __init__(self, rpc=None):

        self.rpc = rpc or arista_ml2.AristaRPCWrapper()
        self.db_nets = db.AristaProvisionedNets()
        self.db_vms = db.AristaProvisionedVms()
        self.db_tenants = db.AristaProvisionedTenants()
        self.ndb = db_lib.NeutronNets()

        confg = cfg.CONF.ml2_arista
        self.segmentation_type = db_lib.VLAN_SEGMENTATION
        self.timer = None
        self.eos = arista_ml2.SyncService(self.rpc, self.ndb)
        self.sync_timeout = confg['sync_interval']
        self.eos_sync_lock = threading.Lock()

    def initialize(self):
        self.rpc.register_with_eos()
        self._cleanup_db()
        self.rpc.check_cli_commands()
        # Registering with EOS updates self.rpc.region_updated_time. Clear it
        # to force an initial sync
        self.rpc.clear_region_updated_time()
        self._synchronization_thread()

    def create_network_precommit(self, context):
        """Remember the tenant, and network information."""

        network = context.current
        segments = context.network_segments
        if segments[0][driver_api.NETWORK_TYPE] != p_const.TYPE_VLAN:
            # If network type is not VLAN, do nothing
            return
        network_id = network['id']
        tenant_id = network['tenant_id'] or INTERNAL_TENANT_ID
        segmentation_id = segments[0]['segmentation_id']
        with self.eos_sync_lock:
            db_lib.remember_tenant(tenant_id)
            db_lib.remember_network(tenant_id,
                                    network_id,
                                    segmentation_id)

    def create_network_postcommit(self, context):
        """Provision the network on the Arista Hardware."""

        network = context.current
        network_id = network['id']
        network_name = network['name']
        tenant_id = network['tenant_id'] or INTERNAL_TENANT_ID
        segments = context.network_segments
        vlan_id = segments[0]['segmentation_id']
        shared_net = network['shared']
        with self.eos_sync_lock:
            if db_lib.is_network_provisioned(tenant_id, network_id):
                try:
                    network_dict = {
                        'network_id': network_id,
                        'segmentation_id': vlan_id,
                        'network_name': network_name,
                        'shared': shared_net}
                    self.rpc.create_network(tenant_id, network_dict)
                except arista_exc.AristaRpcError:
                    LOG.info(EOS_UNREACHABLE_MSG)
                    raise ml2_exc.MechanismDriverError()
            else:
                LOG.info(_LI('Network %s is not created as it is not found in '
                             'Arista DB'), network_id)

    def update_network_precommit(self, context):
        """At the moment we only support network name change

        Any other change in network is not supported at this time.
        We do not store the network names, therefore, no DB store
        action is performed here.
        """
        new_network = context.current
        orig_network = context.original
        if new_network['name'] != orig_network['name']:
            LOG.info(_LI('Network name changed to %s'), new_network['name'])

    def update_network_postcommit(self, context):
        """At the moment we only support network name change

        If network name is changed, a new network create request is
        sent to the Arista Hardware.
        """
        new_network = context.current
        orig_network = context.original
        if ((new_network['name'] != orig_network['name']) or
           (new_network['shared'] != orig_network['shared'])):
            network_id = new_network['id']
            network_name = new_network['name']
            tenant_id = new_network['tenant_id'] or INTERNAL_TENANT_ID
            vlan_id = new_network['provider:segmentation_id']
            shared_net = new_network['shared']
            with self.eos_sync_lock:
                if db_lib.is_network_provisioned(tenant_id, network_id):
                    try:
                        network_dict = {
                            'network_id': network_id,
                            'segmentation_id': vlan_id,
                            'network_name': network_name,
                            'shared': shared_net}
                        self.rpc.create_network(tenant_id, network_dict)
                    except arista_exc.AristaRpcError:
                        LOG.info(EOS_UNREACHABLE_MSG)
                        raise ml2_exc.MechanismDriverError()
                else:
                    LOG.info(_LI('Network %s is not updated as it is not found'
                                 ' in Arista DB'), network_id)

    def delete_network_precommit(self, context):
        """Delete the network information from the DB."""
        network = context.current
        network_id = network['id']
        tenant_id = network['tenant_id'] or INTERNAL_TENANT_ID
        with self.eos_sync_lock:
            if db_lib.is_network_provisioned(tenant_id, network_id):
                if db_lib.are_ports_attached_to_network(network_id):
                    LOG.info(_LI('Network %s can not be deleted as it '
                                 'has ports attached to it'), network_id)
                    raise ml2_exc.MechanismDriverError()
                else:
                    db_lib.forget_network(tenant_id, network_id)

    def delete_network_postcommit(self, context):
        """Send network delete request to Arista HW."""
        network = context.current
        segments = context.network_segments
        if segments[0][driver_api.NETWORK_TYPE] != p_const.TYPE_VLAN:
            # If networtk type is not VLAN, do nothing
            return
        network_id = network['id']
        tenant_id = network['tenant_id'] or INTERNAL_TENANT_ID
        with self.eos_sync_lock:

            # Succeed deleting network in case EOS is not accessible.
            # EOS state will be updated by sync thread once EOS gets
            # alive.
            try:
                self.rpc.delete_network(tenant_id, network_id)
                # if necessary, delete tenant as well.
                self.delete_tenant(tenant_id)
            except arista_exc.AristaRpcError:
                LOG.info(EOS_UNREACHABLE_MSG)
                raise ml2_exc.MechanismDriverError()

    def create_port_precommit(self, context):
        """Remember the information about a VM and its ports

        A VM information, along with the physical host information
        is saved.
        """
        port = context.current
        device_id = port['device_id']
        device_owner = port['device_owner']
        host = context.host

        pretty_log("create_port_precommit:", port)

        # device_id and device_owner are set on VM boot
        is_vm_boot = device_id and device_owner
        if host and is_vm_boot:
            port_id = port['id']
            network_id = port['network_id']
            tenant_id = port['tenant_id'] or INTERNAL_TENANT_ID
            with self.eos_sync_lock:
                # If network does not exist under this tenant,
                # it may be a shared network. Get shared network owner Id
                if not self._network_provisioned(tenant_id, network_id):
                    # Ignore this request if network is not provisioned
                    return
                db_lib.remember_tenant(tenant_id)
                db_lib.remember_vm(device_id, host, port_id,
                                   network_id, tenant_id)

    def create_port_postcommit(self, context):
        """Plug a physical host into a network.

        Send provisioning request to Arista Hardware to plug a host
        into appropriate network.
        """
        port = context.current
        device_id = port['device_id']
        device_owner = port['device_owner']
        host = context.host

        pretty_log("create_port_postcommit:", port)

        # device_id and device_owner are set on VM boot
        is_vm_boot = device_id and device_owner
        if host and is_vm_boot:
            port_id = port['id']
            port_name = port['name']
            network_id = port['network_id']
            tenant_id = port['tenant_id'] or INTERNAL_TENANT_ID
            with self.eos_sync_lock:
                hostname = self._host_name(host)
                port_provisioned = db_lib.is_port_provisioned(port_id)
                # If network does not exist under this tenant,
                # it may be a shared network. Get shared network owner Id
                if port_provisioned and self._network_provisioned(tenant_id,
                                                                  network_id):
                    try:
                        self.rpc.plug_port_into_network(device_id,
                                                        hostname,
                                                        port_id,
                                                        network_id,
                                                        tenant_id,
                                                        port_name,
                                                        device_owner)
                    except arista_exc.AristaRpcError:
                        LOG.info(EOS_UNREACHABLE_MSG)
                        raise ml2_exc.MechanismDriverError()
                else:
                    LOG.info(_LI('VM %s is not created as it is not found in '
                                 'Arista DB'), device_id)

    def update_port_precommit(self, context):
        """Update the name of a given port.

        At the moment we only support port name change.
        Any other change to port is not supported at this time.
        We do not store the port names, therefore, no DB store
        action is performed here.
        """
        new_port = context.current
        orig_port = context.original
        if new_port['name'] != orig_port['name']:
            LOG.info(_LI('Port name changed to %s'), new_port['name'])
        new_port = context.current
        device_id = new_port['device_id']
        host = context.host

        pretty_log("update_port_precommit: new", new_port)
        pretty_log("update_port_precommit: orig", orig_port)

        # device_id and device_owner are set on VM boot
        port_id = new_port['id']
        network_id = new_port['network_id']
        tenant_id = new_port['tenant_id'] or INTERNAL_TENANT_ID

        if not self._network_provisioned(tenant_id, network_id):
            # If the Arista driver does not know about the network, ignore the
            # port.
            LOG.info(_LI("Ignoring port connected to %s"), network_id)
            return

        with self.eos_sync_lock:
            port_down = False
            if(new_port['device_owner'] ==
               n_const.DEVICE_OWNER_DVR_INTERFACE):
                # We care about port status only for DVR ports because
                # for DVR, a single port exists on multiple hosts. If a port
                # is no longer needed on a host then the driver gets a
                # port_update notification for that <port, host> with the
                # port status as PORT_STATUS_DOWN.
                port_down = context.status == n_const.PORT_STATUS_DOWN

            if host and not port_down:
                port_host_filter = None
                if(new_port['device_owner'] ==
                   n_const.DEVICE_OWNER_DVR_INTERFACE):
                    # <port, host> uniquely identifies a DVR port. Other
                    # ports are identified by just the port id
                    port_host_filter = host

                port_provisioned = db_lib.is_port_provisioned(
                    port_id, port_host_filter)

                if not port_provisioned:
                    LOG.info("Remembering the port")
                    # Create a new port in the DB
                    db_lib.remember_tenant(tenant_id)
                    db_lib.remember_vm(device_id, host, port_id,
                                       network_id, tenant_id)
                else:
                    if(new_port['device_id'] != orig_port['device_id'] or
                       context.host != context.original_host or
                       new_port['network_id'] != orig_port['network_id'] or
                       new_port['tenant_id'] != orig_port['tenant_id']):
                        LOG.info("Updating the port")
                        # Port exists in the DB. Update it
                        db_lib.update_port(device_id, host, port_id,
                                           network_id, tenant_id)
            else:  # Unbound or down port does not concern us
                orig_host = context.original_host
                LOG.info("Forgetting the port on %s" % str(orig_host))
                db_lib.forget_port(port_id, orig_host)

    def _port_updated(self, context):
        """Returns true if any port parameters have changed."""
        new_port = context.current
        orig_port = context.original
        return (new_port['device_id'] != orig_port['device_id'] or
                context.host != context.original_host or
                new_port['network_id'] != orig_port['network_id'] or
                new_port['tenant_id'] != orig_port['tenant_id'])

    def update_port_postcommit(self, context):
        """Update the name of a given port in EOS.

        At the moment we only support port name change
        Any other change to port is not supported at this time.
        """
        port = context.current
        orig_port = context.original

        device_id = port['device_id']
        device_owner = port['device_owner']
        host = context.host
        is_vm_boot = device_id and device_owner

        port_id = port['id']
        port_name = port['name']
        network_id = port['network_id']
        tenant_id = port['tenant_id'] or INTERNAL_TENANT_ID

        pretty_log("update_port_postcommit: new", port)
        pretty_log("update_port_postcommit: orig", orig_port)

        with self.eos_sync_lock:
            hostname = self._host_name(host)
            segmentation_id = db_lib.get_segmentation_id(tenant_id,
                                                         network_id)
            port_host_filter = None
            if(port['device_owner'] ==
               n_const.DEVICE_OWNER_DVR_INTERFACE):
                # <port, host> uniquely identifies a DVR port. Other
                # ports are identified by just the port id
                port_host_filter = host

            port_provisioned = db_lib.is_port_provisioned(port_id,
                                                          port_host_filter)
            # If network does not exist under this tenant,
            # it may be a shared network. Get shared network owner Id
            net_provisioned = self._network_provisioned(tenant_id, network_id,
                                                        segmentation_id)
            try:
                orig_host = context.original_host
                port_down = False
                if(port['device_owner'] == n_const.DEVICE_OWNER_DVR_INTERFACE):
                    # We care about port status only for DVR ports
                    port_down = context.status == n_const.PORT_STATUS_DOWN

                if orig_host and (port_down or host != orig_host):
                    try:
                        LOG.info("Deleting the port %s" % str(orig_port))
                        # The port moved to a different host or the VM
                        # connected to the port was deleted or its in DOWN
                        # state. So delete the old port on the old host.
                        self._delete_port(orig_port, orig_host, tenant_id)
                    except ml2_exc.MechanismDriverError:
                        # If deleting a port fails, then not much can be done
                        # about it. Log a warning and move on.
                        LOG.warn(UNABLE_TO_DELETE_PORT_MSG)
                if(port_provisioned and net_provisioned and hostname and
                   is_vm_boot and not port_down):
                    LOG.info(_LI("Port plugged into network"))
                    # Plug port into the network only if it exists in the db
                    # and is bound to a host and the port is up.
                    self.rpc.plug_port_into_network(device_id,
                                                    hostname,
                                                    port_id,
                                                    network_id,
                                                    tenant_id,
                                                    port_name,
                                                    device_owner)
                else:
                    LOG.info(_LI("Port not plugged into network"))
            except arista_exc.AristaRpcError:
                LOG.info(EOS_UNREACHABLE_MSG)
                raise ml2_exc.MechanismDriverError()

    def delete_port_precommit(self, context):
        """Delete information about a VM and host from the DB."""
        port = context.current

        pretty_log("delete_port_precommit:", port)

        port_id = port['id']
        host_id = context.host
        with self.eos_sync_lock:
            if db_lib.is_port_provisioned(port_id):
                db_lib.forget_port(port_id, host_id)

    def delete_port_postcommit(self, context):
        """unPlug a physical host from a network.

        Send provisioning request to Arista Hardware to unplug a host
        from appropriate network.
        """
        port = context.current
        host = context.host
        tenant_id = port['tenant_id'] or INTERNAL_TENANT_ID

        pretty_log("delete_port_postcommit:", port)

        with self.eos_sync_lock:
            try:
                self._delete_port(port, host, tenant_id)
            except ml2_exc.MechanismDriverError:
                # Can't do much if deleting a port failed.
                # Log a warning and continue.
                LOG.warn(UNABLE_TO_DELETE_PORT_MSG)

    def _delete_port(self, port, host, tenant_id):
        """Deletes the port from EOS.

        param port: Port which is to be deleted
        param host: The host on which the port existed
        param tenant_id: The tenant to which the port belongs to. Some times
                         the tenant id in the port dict is not present (as in
                         the case of HA router).
        """
        device_id = port['device_id']
        port_id = port['id']
        network_id = port['network_id']
        device_owner = port['device_owner']

        if not device_id or not host:
            LOG.warn(UNABLE_TO_DELETE_DEVICE_MSG)
            return

        try:
            if not self._network_provisioned(tenant_id, network_id):
                # If we do not have network associated with this, ignore it
                return
            hostname = self._host_name(host)
            self.rpc.unplug_port_from_network(device_id, device_owner,
                                              hostname, port_id, network_id,
                                              tenant_id)

            # if necessary, delete tenant as well.
            self.delete_tenant(tenant_id)
        except arista_exc.AristaRpcError:
            LOG.info(EOS_UNREACHABLE_MSG)
            raise ml2_exc.MechanismDriverError()

    def delete_tenant(self, tenant_id):
        """delete a tenant from DB.

        A tenant is deleted only if there is no network or VM configured
        configured for this tenant.
        """
        objects_for_tenant = (db_lib.num_nets_provisioned(tenant_id) +
                              db_lib.num_vms_provisioned(tenant_id))
        if not objects_for_tenant:
            db_lib.forget_tenant(tenant_id)
            try:
                self.rpc.delete_tenant(tenant_id)
            except arista_exc.AristaRpcError:
                LOG.info(EOS_UNREACHABLE_MSG)
                raise ml2_exc.MechanismDriverError()

    def _host_name(self, hostname):
        fqdns_used = cfg.CONF.ml2_arista['use_fqdn']
        return hostname if fqdns_used else hostname.split('.')[0]

    def _synchronization_thread(self):
        with self.eos_sync_lock:
            self.eos.do_synchronize()

        self.timer = threading.Timer(self.sync_timeout,
                                     self._synchronization_thread)
        self.timer.start()

    def stop_synchronization_thread(self):
        if self.timer:
            self.timer.cancel()
            self.timer = None

    def _cleanup_db(self):
        """Clean up any uncessary entries in our DB."""
        neutron_nets = self.ndb.get_all_networks()
        arista_db_nets = db_lib.get_networks(tenant_id='any')
        neutron_net_ids = set()
        for net in neutron_nets:
            neutron_net_ids.add(net['id'])

        # Remove networks from the Arista DB if the network does not exist in
        # Neutron DB
        for net_id in set(arista_db_nets.keys()).difference(neutron_net_ids):
            tenant_network = arista_db_nets[net_id]
            db_lib.forget_network(tenant_network['tenantId'], net_id)
            db_lib.forget_all_ports_for_network(net_id)

    def _network_provisioned(self, tenant_id, network_id,
                             segmentation_id=None):
        # If network does not exist under this tenant,
        # it may be a shared network.

        return (
            db_lib.is_network_provisioned(tenant_id, network_id,
                                          segmentation_id) or
            self.ndb.get_shared_network_owner_id(network_id)
        )
