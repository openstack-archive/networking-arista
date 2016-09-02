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

from neutron_lib import constants as const
from oslo_config import cfg
from oslo_log import log as logging

from neutron._i18n import _LI
from neutron.common import constants as n_const
from neutron.extensions import portbindings
from neutron.plugins.common import constants as p_const
from neutron.plugins.ml2.common import exceptions as ml2_exc
from neutron.plugins.ml2 import driver_api

from networking_arista.common import config  # noqa
from networking_arista.common import db
from networking_arista.common import db_lib
from networking_arista.common import exceptions as arista_exc
from networking_arista.ml2 import arista_ml2
from networking_arista.ml2 import sec_group_callback

LOG = logging.getLogger(__name__)

# Messages
EOS_UNREACHABLE_MSG = _('Unable to reach EOS')
UNABLE_TO_DELETE_PORT_MSG = _('Unable to delete port from EOS')
UNABLE_TO_DELETE_DEVICE_MSG = _('Unable to delete device')

# Constants
INTERNAL_TENANT_ID = 'INTERNAL-TENANT-ID'
PORT_BINDING_HOST = 'binding:host_id'
MECHANISM_DRV_NAME = 'arista'


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

        self.ndb = db_lib.NeutronNets()
        self.rpc = rpc or arista_ml2.AristaRPCWrapper(self.ndb)
        self.db_nets = db.AristaProvisionedNets()
        self.db_vms = db.AristaProvisionedVms()
        self.db_tenants = db.AristaProvisionedTenants()

        confg = cfg.CONF.ml2_arista
        self.segmentation_type = db_lib.VLAN_SEGMENTATION
        self.timer = None
        self.eos = arista_ml2.SyncService(self.rpc, self.ndb)
        self.sync_timeout = confg['sync_interval']
        self.managed_physnets = confg['managed_physnets']
        self.eos_sync_lock = threading.Lock()

    def initialize(self):
        self.rpc.register_with_eos()
        self._cleanup_db()
        self.rpc.check_cli_commands()
        # Registering with EOS updates self.rpc.region_updated_time. Clear it
        # to force an initial sync
        self.rpc.clear_region_updated_time()
        self._synchronization_thread()
        self.sg_handler = sec_group_callback.AristaSecurityGroupHandler(self)

    def create_network_precommit(self, context):
        """Remember the tenant, and network information."""

        network = context.current
        segments = context.network_segments
        network_id = network['id']
        tenant_id = network['tenant_id'] or INTERNAL_TENANT_ID
        segmentation_id = segments[0]['segmentation_id']
        segment_id = segments[0]['id']
        with self.eos_sync_lock:
            db_lib.remember_tenant(tenant_id)
            db_lib.remember_network(tenant_id,
                                    network_id,
                                    segmentation_id,
                                    segment_id)

    def create_network_postcommit(self, context):
        """Provision the network on the Arista Hardware."""

        network = context.current
        network_id = network['id']
        network_name = network['name']
        tenant_id = network['tenant_id'] or INTERNAL_TENANT_ID
        segments = context.network_segments
        shared_net = network['shared']
        with self.eos_sync_lock:
            if db_lib.is_network_provisioned(tenant_id, network_id):
                try:
                    network_dict = {
                        'network_id': network_id,
                        'segments': segments,
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
            shared_net = new_network['shared']
            with self.eos_sync_lock:
                if db_lib.is_network_provisioned(tenant_id, network_id):
                    try:
                        network_dict = {
                            'network_id': network_id,
                            'segments': context.network_segments,
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
        """
        Returning from here, since the update_port_precommit is performing
        same operation, and also need of port binding information to decide
        whether to react to a port create event which is not available when
        this method is called.
        """
        # return
        port = context.current
        device_id = port['device_id']
        device_owner = port['device_owner']
        host = context.host

        pretty_log("create_port_precommit:", port)

        if device_owner == 'compute:probe':
            return

        # device_id and device_owner are set on VM boot
        is_vm_boot = device_id and device_owner
        if host and is_vm_boot:
            port_id = port['id']
            network_id = port['network_id']
            tenant_id = port['tenant_id'] or INTERNAL_TENANT_ID
            # Ensure that we use tenant Id for the network owner
            tenant_id = self._network_owner_tenant(context,
                                                   network_id,
                                                   tenant_id)
            with self.eos_sync_lock:
                # If network does not exist under this tenant,
                # it may be a shared network. Get shared network owner Id
                if not self._network_provisioned(tenant_id, network_id):
                    # Ignore this request if network is not provisioned
                    return
                db_lib.remember_tenant(tenant_id)
                db_lib.remember_vm(device_id, host, port_id,
                                   network_id, tenant_id)

    def _bind_port_to_baremetal(self, context, segment, switch_id):

        port = context.current
        vnic_type = port.get('binding:vnic_type')
        if vnic_type != portbindings.VNIC_BAREMETAL:
            # We are only interested in binding baremetal ports.
            return False

        binding_profile = port.get(portbindings.PROFILE)
        if not binding_profile:
            return False

        link_info = binding_profile.get('local_link_information')
        if not link_info:
            return False

        if switch_id != link_info.get('switch_id'):
            LOG.debug("Port %(port)s with %(link)s is not managed"
                      " by Arist mechanism driver ", {'port': port,
                                                      'link': link_info})
            return False

        vif_type = portbindings.VIF_TYPE_OTHER
        vif_details = {portbindings.VIF_DETAILS_VLAN: True}
        vif_details[portbindings.VIF_DETAILS_VLAN] = (
            str(segment[driver_api.SEGMENTATION_ID]))
        context.set_binding(segment[driver_api.ID],
                            vif_type,
                            vif_details,
                            p_const.ACTIVE)
        LOG.debug("AristaDriver: bound port info- port ID %(id)s "
                  "on network %(network)s",
                  {'id': port['id'],
                   'network': context.network.current['id']})
        return True

    def bind_port(self, context):
        """Bind baremetal port to a network.

        Provisioning request to Arista Hardware to plug a host
        into appropriate network is done when the port is created
        this simply tells the ML2 Plugin that we are binding the port
        """
        host_id = context.host
        if host_id:
            physnet_info = self.rpc.get_physical_network(host_id)
            physnet = physnet_info.get('physnet')
            switch_id = physnet_info.get('switch_id')
            if not physnet or not switch_id:
                LOG.debug("The host %(host)s not connected to arista switches"
                          ". Physical Network info = %(pi)s",
                          {'host': host_id, 'pi': physnet_info})
                return

        LOG.debug("bind_port: physical_network=%(physnet)s,"
                  "switch_id=%(swid)s", {'physnet': physnet,
                                         'swid': switch_id})
        for segment in context.segments_to_bind:
            if segment[driver_api.NETWORK_TYPE] != p_const.TYPE_VLAN:
                # The physical network is connected to arista switches,
                # allocate dynamic segmentation id to bind the port to
                # the network that the port belongs to.
                next_segment = context.allocate_dynamic_segment(
                    {'id': context.network.current,
                     'network_type': p_const.TYPE_VLAN,
                     'physical_network': physnet})
                LOG.debug("bind_port: current=%(current_seg)s, "
                          "next=%(next_seg)s", ({'current_seg': segment,
                                                 'next_seg': next_segment}))
                # If a baremetal is connected to arista switch, complete
                # the binding. Otherwise, continue binding and let other
                # driver complete the binding.
                if not self._bind_port_to_baremetal(context, next_segment,
                                                    switch_id):
                    # Binding is not completed, therefore continue binding.
                    context.continue_binding(segment['id'], [next_segment])
            else:
                # The network_type is vlan, try binding process for baremetal.
                self._bind_port_to_baremetal(context, segment, switch_id)

    def create_port_postcommit(self, context):
        """Plug a physical host into a network.

        Send provisioning request to Arista Hardware to plug a host
        into appropriate network.
        """
        """
        Returning from here, since the update_port_postcommit is performing
        same operation, and also need of port binding information to decide
        whether to react to a port create event which is not available when
        this method is called.
        """
        # return
        port = context.current
        device_id = port['device_id']
        device_owner = port['device_owner']
        host = context.host

        profile = []
        vnic_type = port['binding:vnic_type']
        binding_profile = port['binding:profile']
        if binding_profile:
            profile = binding_profile['local_link_information']

        pretty_log("create_port_postcommit:", port)

        sg = port['security_groups']

        # device_id and device_owner are set on VM boot
        is_vm_boot = device_id and device_owner
        if host and is_vm_boot:
            port_id = port['id']
            port_name = port['name']
            network_id = port['network_id']
            tenant_id = port['tenant_id'] or INTERNAL_TENANT_ID
            # Ensure that we use tenant Id for the network owner
            tenant_id = self._network_owner_tenant(context,
                                                   network_id,
                                                   tenant_id)
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
                                                        device_owner,
                                                        sg, [],
                                                        vnic_type,
                                                        profile=profile)
                    except arista_exc.AristaRpcError:
                        LOG.info(EOS_UNREACHABLE_MSG)
                        raise ml2_exc.MechanismDriverError()
                else:
                    LOG.info(_LI('VM %s is not created as it is not found in '
                                 'Arista DB'), device_id)

    def _network_owner_tenant(self, context, network_id, tenant_id):
        tid = tenant_id
        if network_id and tenant_id:
            context = context._plugin_context
            network_owner = self.ndb.get_network_from_net_id(network_id,
                                                             context=context)
            if network_owner and network_owner[0]['tenant_id'] != tenant_id:
                tid = network_owner[0]['tenant_id'] or tenant_id
        return tid

    def _should_port_be_managed(self, context):
        """Check if a given port is managed by the mechanism driver.

        It returns bound segment dictionary, if physical network in the bound
        segment is included in the managed physical network list.
        """
        if len(self.managed_physnets) == 0:
            return (context.bottom_bound_segment
                    if context.binding_levels else None)

        if context.binding_levels:
            for binding_level in context.binding_levels:
                bound_segment = binding_level.get(driver_api.BOUND_SEGMENT)
                if (bound_segment and
                    bound_segment.get(driver_api.PHYSICAL_NETWORK) in
                        self.managed_physnets):
                    return bound_segment

    def _handle_port_migration_precommit(self, context):
        """Handles port migration in precommit

        It updates the port's new host in the DB
        """
        orig_port = context.original
        orig_host = context.original_host
        orig_status = context.original_status
        new_status = context.status
        new_host = context.host
        port_id = orig_port['id']

        if (new_host != orig_host and
            orig_status == const.PORT_STATUS_ACTIVE and
                new_status == const.PORT_STATUS_DOWN):
            LOG.debug("Handling port migration for: %s " % orig_port)
            network_id = orig_port['network_id']
            tenant_id = orig_port['tenant_id'] or INTERNAL_TENANT_ID
            # Ensure that we use tenant Id for the network owner
            tenant_id = self._network_owner_tenant(context, network_id,
                                                   tenant_id)
            device_id = orig_port['device_id']
            with self.eos_sync_lock:
                port_provisioned = db_lib.is_port_provisioned(port_id,
                                                              orig_host)
                if port_provisioned:
                    db_lib.update_port(device_id, new_host, port_id,
                                       network_id, tenant_id)

            return True

    def _handle_port_migration_postcommit(self, context):
        """Handles port migration in postcommit

        In case of port migration, it removes the port from the original host
        and also it release the segment id if no port is attached to the same
        segment id that the port is attached to.
        """
        orig_port = context.original
        orig_host = context.original_host
        orig_status = context.original_status
        new_status = context.status
        new_host = context.host

        if (new_host != orig_host and
            orig_status == const.PORT_STATUS_ACTIVE and
                new_status == const.PORT_STATUS_DOWN):

            self._try_to_release_dynamic_segment(context, migration=True)

            # Handling migration case.
            # 1. The port should be unplugged from network
            # 2. If segment_id is provisioned and it not bound to any port it
            # should be removed from EOS.
            network_id = orig_port['network_id']
            tenant_id = orig_port['tenant_id'] or INTERNAL_TENANT_ID
            # Ensure that we use tenant Id for the network owner
            tenant_id = self._network_owner_tenant(context, network_id,
                                                   tenant_id)
            for binding_level in context._original_binding_levels:
                if self._network_provisioned(
                    tenant_id, network_id,
                    segment_id=binding_level.segment_id):
                    with self.eos_sync_lock:
                        # Removing the port form original host
                        self._delete_port(orig_port, orig_host, tenant_id)

                        # If segment id is not bound to any port, then
                        # remove it from EOS
                        segment = self.ndb.get_segment_by_id(
                            context._plugin_context.session,
                            binding_level.segment_id)
                        if not segment:
                            try:
                                segment_info = {
                                    'id': binding_level.segment_id,
                                    'network_id': network_id,
                                }
                                LOG.debug("migration_postcommit:"
                                          "deleting segment %s", segment_info)
                                self.rpc.delete_network_segment(tenant_id,
                                                                segment_info)
                                # Remove the segment from the provisioned
                                # network DB.
                                db_lib.forget_network(tenant_id, network_id,
                                                      binding_level.segment_id)
                            except arista_exc.AristaRpcError:
                                LOG.info(EOS_UNREACHABLE_MSG)

            return True

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
        device_id = new_port['device_id']
        host = context.host

        pretty_log("update_port_precommit: new", new_port)
        pretty_log("update_port_precommit: orig", orig_port)

        if new_port['device_owner'] == 'compute:probe':
            return

        # Check if it is port migration case
        if self._handle_port_migration_precommit(context):
            return

        # Check if the port is part of managed physical network
        seg_info = self._should_port_be_managed(context)
        if not seg_info:
            # Ignoring the update as the port is not managed by
            # arista mechanism driver.
            return

        # device_id and device_owner are set on VM boot
        port_id = new_port['id']
        network_id = new_port['network_id']
        tenant_id = new_port['tenant_id'] or INTERNAL_TENANT_ID
        # Ensure that we use tenant Id for the network owner
        tenant_id = self._network_owner_tenant(context, network_id, tenant_id)

        if not self._network_provisioned(tenant_id, network_id,
                                         seg_info[driver_api.SEGMENTATION_ID],
                                         seg_info[driver_api.ID]):
            LOG.info(
                _LI("Adding network %s to provisioned database"), network_id)
            with self.eos_sync_lock:
                db_lib.remember_tenant(tenant_id)
                db_lib.remember_network(tenant_id,
                                        network_id,
                                        seg_info[driver_api.SEGMENTATION_ID],
                                        seg_info[driver_api.ID])
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

        vnic_type = port['binding:vnic_type']
        binding_profile = port['binding:profile']
        profile = []
        if binding_profile:
            profile = binding_profile['local_link_information']

        port_id = port['id']
        port_name = port['name']
        network_id = port['network_id']
        tenant_id = port['tenant_id'] or INTERNAL_TENANT_ID
        # Ensure that we use tenant Id for the network owner
        tenant_id = self._network_owner_tenant(context, network_id, tenant_id)
        sg = port['security_groups']
        orig_sg = orig_port['security_groups']

        pretty_log("update_port_postcommit: new", port)
        pretty_log("update_port_postcommit: orig", orig_port)

        # Check if it is port migration case
        if self._handle_port_migration_postcommit(context):
            # Return from here as port migration is already handled.
            return

        seg_info = self._should_port_be_managed(context)
        if not seg_info:
            LOG.debug("Ignoring the update as the port is not managed by"
                      "Arista switches.")
            return

        with self.eos_sync_lock:
            hostname = self._host_name(host)
            segmentation_id = seg_info[driver_api.SEGMENTATION_ID]
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
            net_provisioned = self._network_provisioned(
                tenant_id, network_id, segmentation_id=segmentation_id)
            segments = []
            if net_provisioned:
                for binding_level in context.binding_levels:
                    bound_segment = binding_level.get(
                        driver_api.BOUND_SEGMENT)
                    if bound_segment:
                        segments.append(bound_segment)
                all_segments = self.ndb.get_all_network_segments(
                    network_id, session=context._plugin_context.session)
                LOG.debug("segments = %s" % all_segments)
                try:
                    self.rpc.create_network_segments(
                        tenant_id, network_id, context.network.current['name'],
                        all_segments)
                except arista_exc.AristaRpcError:
                    LOG.error(_LI("Failed to create network segments"))
                    raise ml2_exc.MechanismDriverError()

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
                                                    device_owner,
                                                    sg, orig_sg,
                                                    vnic_type,
                                                    segments=segments,
                                                    profile=profile)
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
        """Unplug a physical host from a network.

        Send provisioning request to Arista Hardware to unplug a host
        from appropriate network.
        """
        port = context.current
        host = context.host
        network_id = port['network_id']

        tenant_id = port['tenant_id'] or INTERNAL_TENANT_ID
        # Ensure that we use tenant Id for the network owner
        tenant_id = self._network_owner_tenant(context, network_id, tenant_id)

        pretty_log("delete_port_postcommit:", port)

        # If this port is the last one using dynamic segmentation id,
        # and the segmentaion id was alloated by this driver, it needs
        # to be releaed.
        self._try_to_release_dynamic_segment(context)

        with self.eos_sync_lock:
            try:
                self._delete_port(port, host, tenant_id)
                self._delete_segment(context, tenant_id)
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
        vnic_type = port['binding:vnic_type']
        binding_profile = port['binding:profile']
        profile = []
        if binding_profile:
            profile = binding_profile['local_link_information']
        sg = port['security_groups']

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
                                              tenant_id, sg, vnic_type,
                                              profile=profile)

            # if necessary, delete tenant as well.
            self.delete_tenant(tenant_id)
        except arista_exc.AristaRpcError:
            LOG.info(EOS_UNREACHABLE_MSG)

    def _delete_segment(self, context, tenant_id):
        """Deletes a dynamic network segment from EOS.

        param context: The port context
        param tenant_id: The tenant which the port belongs to
        """
        port = context.current
        network_id = port.get('network_id')

        if not context._binding_levels:
            return
        for binding_level in context._binding_levels:
            LOG.debug("deleting segment %s", binding_level.segment_id)
            if self._network_provisioned(tenant_id, network_id,
                                         segment_id=binding_level.segment_id):
                segment = self.ndb.get_segment_by_id(
                    context._plugin_context.session, binding_level.segment_id)
                if not segment:
                    # The segment is already released. Delete it from EOS
                    LOG.debug("Deleting segment %s", binding_level.segment_id)
                    try:
                        segment_info = {
                            'id': binding_level.segment_id,
                            'network_id': network_id,
                        }
                        self.rpc.delete_network_segment(tenant_id,
                                                        segment_info)
                        # Remove the segment from the provisioned network DB.
                        db_lib.forget_network(tenant_id, network_id,
                                              binding_level.segment_id)
                    except arista_exc.AristaRpcError:
                        LOG.info(EOS_UNREACHABLE_MSG)
                else:
                    LOG.debug("Cannot delete segment_id %(segid)s "
                              "segment is %(seg)s",
                              {'segid': binding_level.segment_id,
                               'seg': segment})

    def _try_to_release_dynamic_segment(self, context, migration=False):
        """Release dynamic segment allocated by the driver

        If this port is the last port using the segmentation id allocated
        by the driver, it should be released
        """
        host = context.original_host if migration else context.host

        physnet_info = self.rpc.get_physical_network(host)
        physnet = physnet_info.get('physnet')
        if not physnet:
            return

        binding_levels = context.binding_levels
        LOG.debug("_try_release_dynamic_segment: "
                  "binding_levels=%(bl)s", {'bl': binding_levels})
        if not binding_levels:
            return

        segment_id = None
        bound_drivers = []
        for binding_level in binding_levels:
            bound_segment = binding_level.get(driver_api.BOUND_SEGMENT)
            driver = binding_level.get(driver_api.BOUND_DRIVER)
            bound_drivers.append(driver)
            if (bound_segment and
                bound_segment.get('physical_network') == physnet and
                    bound_segment.get('network_type') == p_const.TYPE_VLAN):
                segment_id = bound_segment.get('id')
                break

        session = context._plugin_context.session
        result = None
        # If the segment id is found and it is bound by this driver, and also
        # the segment id is not bound to any other port, release the segment
        if (segment_id and bound_drivers[-2:-1] == [MECHANISM_DRV_NAME]):
            filters = {'segment_id': segment_id}
            result = db_lib.get_port_binding_level_for_filters(session,
                                                               filters)
            LOG.debug("Looking for entry with filters=%(filters)s "
                      "result=%(result)s ", {'filters': filters,
                                             'result': result})
            if not result:
                # The requested segment_id does not exist in the port binding
                # database. Release the dynamic segment.
                context.release_dynamic_segment(segment_id)
                LOG.debug("Released dynamic segment %(seg)s allocated "
                          "by %(drv)s", ({'seg': segment_id,
                                          'drv': bound_drivers[-2]}))

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
        """Clean up any unnecessary entries in our DB."""
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
                             segmentation_id=None, segment_id=None):
        # If network does not exist under this tenant,
        # it may be a shared network.

        return (
            db_lib.is_network_provisioned(tenant_id, network_id,
                                          segmentation_id, segment_id) or
            self.ndb.get_shared_network_owner_id(network_id)
        )

    def create_security_group(self, sg):
        try:
            self.rpc.create_acl(sg)
        except Exception:
            msg = (_('Failed to create ACL on EOS %s') % sg)
            LOG.exception(msg)
            raise arista_exc.AristaSecurityGroupError(msg=msg)

    def delete_security_group(self, sg):
        try:
            self.rpc.delete_acl(sg)
        except Exception:
            msg = (_('Failed to create ACL on EOS %s') % sg)
            LOG.exception(msg)
            raise arista_exc.AristaSecurityGroupError(msg=msg)

    def update_security_group(self, sg):
        try:
            self.rpc.create_acl(sg)
        except Exception:
            msg = (_('Failed to create ACL on EOS %s') % sg)
            LOG.exception(msg)
            raise arista_exc.AristaSecurityGroupError(msg=msg)

    def create_security_group_rule(self, sgr):
        try:
            self.rpc.create_acl_rule(sgr)
        except Exception:
            msg = (_('Failed to create ACL rule on EOS %s') % sgr)
            LOG.exception(msg)
            raise arista_exc.AristaSecurityGroupError(msg=msg)

    def delete_security_group_rule(self, sgr_id):
        if sgr_id:
            sgr = self.ndb.get_security_group_rule(sgr_id)
            if sgr:
                try:
                    self.rpc.delete_acl_rule(sgr)
                except Exception:
                    msg = (_('Failed to delete ACL rule on EOS %s') % sgr)
                    LOG.exception(msg)
                    raise arista_exc.AristaSecurityGroupError(msg=msg)
