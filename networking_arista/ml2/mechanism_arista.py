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

import json
import threading

from neutron_lib.api.definitions import portbindings
from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib import constants as n_const
from neutron_lib.plugins.ml2 import api as driver_api
from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import excutils

from neutron.services.trunk import constants as trunk_consts

from networking_arista._i18n import _, _LI, _LE
from networking_arista.common import constants
from networking_arista.common import db_lib
from networking_arista.common import exceptions as arista_exc
from networking_arista.common import utils
from networking_arista.ml2 import arista_sync
from networking_arista.ml2.rpc.arista_eapi import AristaRPCWrapperEapi
from networking_arista.ml2.rpc.arista_json import AristaRPCWrapperJSON
from networking_arista.ml2 import sec_group_callback


LOG = logging.getLogger(__name__)
cfg.CONF.import_group('ml2_arista', 'networking_arista.common.config')


def pretty_log(tag, obj):
    log_data = json.dumps(obj, sort_keys=True, indent=4)
    LOG.debug(tag)
    LOG.debug(log_data)


class AristaDriver(driver_api.MechanismDriver):
    """Ml2 Mechanism driver for Arista networking hardware.

    Remembers all networks and VMs that are provisioned on Arista Hardware.
    Does not send network provisioning request if the network has already been
    provisioned before for the given port.
    """
    def __init__(self):

        self.ndb = db_lib.NeutronNets()

        confg = cfg.CONF.ml2_arista
        self.managed_physnets = confg['managed_physnets']
        self.manage_fabric = confg['manage_fabric']
        self.eos_sync_lock = threading.Lock()
        self.eapi = AristaRPCWrapperEapi()
        self.rpc = AristaRPCWrapperJSON(self.ndb)
        self.mlag_pairs = dict()

    def initialize(self):
        if self.rpc.check_cvx_availability():
            self.rpc.register_with_eos()

        self.mlag_pairs = db_lib.get_mlag_physnets()
        self.sg_handler = sec_group_callback.AristaSecurityGroupHandler(self)
        registry.subscribe(self.set_subport,
                           trunk_consts.SUBPORTS, events.AFTER_CREATE)
        registry.subscribe(self.unset_subport,
                           trunk_consts.SUBPORTS, events.AFTER_DELETE)

    def get_workers(self):
        return [arista_sync.AristaSyncWorker(self.rpc, self.ndb,
                                             self.manage_fabric,
                                             self.managed_physnets)]

    def create_network_postcommit(self, context):
        """Provision the network on the Arista Hardware."""

        network = context.current
        network_id = network['id']
        network_name = network['name']
        tenant_id = network['tenant_id'] or constants.INTERNAL_TENANT_ID
        segments = context.network_segments
        shared_net = network['shared']
        with self.eos_sync_lock:
            try:
                network_dict = {
                    'network_id': network_id,
                    'segments': segments,
                    'network_name': network_name,
                    'shared': shared_net}
                self.rpc.create_network(tenant_id, network_dict)
            except arista_exc.AristaRpcError as err:
                LOG.error(_LE("create_network_postcommit: Did not create "
                              "network %(name)s. Reason: %(err)s"),
                          {'name': network_name, 'err': err})

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
            tenant_id = (new_network['tenant_id'] or
                         constants.INTERNAL_TENANT_ID)
            shared_net = new_network['shared']
            with self.eos_sync_lock:
                try:
                    network_dict = {
                        'network_id': network_id,
                        'segments': context.network_segments,
                        'network_name': network_name,
                        'shared': shared_net}
                    self.rpc.create_network(tenant_id, network_dict)
                except arista_exc.AristaRpcError as err:
                    LOG.error(_LE('update_network_postcommit: Did not '
                                  'update network %(name)s. '
                                  'Reason: %(err)s'),
                              {'name': network_name, 'err': err})

    def delete_network_postcommit(self, context):
        """Send network delete request to Arista HW."""
        network = context.current
        segments = context.network_segments
        network_id = network['id']
        tenant_id = network['tenant_id'] or constants.INTERNAL_TENANT_ID
        with self.eos_sync_lock:
            # Succeed deleting network in case EOS is not accessible.
            # EOS state will be updated by sync thread once EOS gets
            # alive.
            try:
                self.rpc.delete_network(tenant_id, network_id, segments)
                # if necessary, delete tenant as well.
                self.delete_tenant(tenant_id)
            except arista_exc.AristaRpcError as err:
                LOG.error(_LE('delete_network_postcommit: Did not delete '
                              'network %(network_id)s. Reason: %(err)s'),
                          {'network_id': network_id, 'err': err})

    def _bind_baremetal_port(self, context, segment):
        """Bind the baremetal port to the segment"""
        port = context.current
        vif_details = {
            portbindings.VIF_DETAILS_VLAN: str(
                segment[driver_api.SEGMENTATION_ID])
        }
        context.set_binding(segment[driver_api.ID],
                            portbindings.VIF_TYPE_OTHER,
                            vif_details,
                            n_const.ACTIVE)
        LOG.debug("AristaDriver: bound port info- port ID %(id)s "
                  "on network %(network)s",
                  {'id': port['id'],
                   'network': context.network.current['id']})
        if port.get('trunk_details'):
            self.trunk_driver.bind_port(port)
        return True

    def _get_physnet(self, context):
        """Find the appropriate physnet for the host

        - Baremetal ports' physnet is determined by looking at the
          local_link_information contained in the binding profile
        - Other ports' physnet is determined by looking for the host in the
          topology
        """
        port = context.current
        physnet = None
        if (port.get(portbindings.VNIC_TYPE) == portbindings.VNIC_BAREMETAL):
            physnet = self.eapi.get_baremetal_physnet(context)
        else:
            physnet = self.eapi.get_host_physnet(context)
        # If the switch is part of an mlag pair, the physnet is called
        # peer1_peer2
        if physnet in self.mlag_pairs:
            physnet = self.mlag_pairs[physnet]
        return physnet

    def _bind_fabric(self, context, segment):
        """Allocate dynamic segments for the port

        Segment physnets are based on the switch to which the host is
        connected.
        """
        port_id = context.current['id']
        physnet = self._get_physnet(context)
        if not physnet:
            LOG.debug("bind_port for port %(port)s: no physical_network "
                      "found", {'port': port_id})
            return False

        next_segment = context.allocate_dynamic_segment(
            {'network_id': context.network.current['id'],
             'network_type': n_const.TYPE_VLAN,
             'physical_network': physnet})
        LOG.debug("bind_port for port %(port)s: "
                  "current_segment=%(current_seg)s, "
                  "next_segment=%(next_seg)s",
                  {'port': port_id, 'current_seg': segment,
                   'next_seg': next_segment})
        context.continue_binding(segment['id'], [next_segment])
        return True

    def bind_port(self, context):
        """Bind port to a network segment.

        Provisioning request to Arista Hardware to plug a host
        into appropriate network is done when the port is created
        this simply tells the ML2 Plugin that we are binding the port
        """
        port = context.current
        for segment in context.segments_to_bind:
            physnet = segment.get(driver_api.PHYSICAL_NETWORK)
            segment_type = segment[driver_api.NETWORK_TYPE]
            if not physnet:
                if (segment_type == n_const.TYPE_VXLAN and self.manage_fabric):
                    if self._bind_fabric(context, segment):
                        continue
            elif (port.get(portbindings.VNIC_TYPE)
                    == portbindings.VNIC_BAREMETAL):
                if (not self.managed_physnets or
                        physnet in self.managed_physnets):
                    if self._bind_baremetal_port(context, segment):
                        continue
            LOG.debug("Arista mech driver unable to bind port %(port)s to "
                      "%(seg_type)s segment on physical_network %(physnet)s",
                      {'port': port.get('id'), 'seg_type': segment_type,
                       'physnet': physnet})

    def _network_owner_tenant(self, context, network_id, tenant_id):
        tid = tenant_id
        if network_id and tenant_id:
            context = context._plugin_context
            network_owner = self.ndb.get_network_from_net_id(network_id,
                                                             context=context)
            if network_owner and network_owner[0]['tenant_id'] != tenant_id:
                tid = network_owner[0]['tenant_id'] or tenant_id
        return tid

    def _is_in_managed_physnets(self, physnet):
        # Check if this is a fabric segment
        if not physnet:
            return self.manage_fabric
        # If managed physnet is empty, accept all.
        if not self.managed_physnets:
            return True
        # managed physnet is not empty, find for matching physnet
        return any(pn == physnet for pn in self.managed_physnets)

    def _bound_segments(self, context):
        """Check if a given port is managed by the mechanism driver.

        It returns bound segment dictionary, if physical network in the bound
        segment is included in the managed physical network list.
        """
        if not self.managed_physnets:
            return [
                binding_level.get(driver_api.BOUND_SEGMENT)
                for binding_level in (context.binding_levels or [])
            ]

        bound_segments = []
        for binding_level in (context.binding_levels or []):
            bound_segment = binding_level.get(driver_api.BOUND_SEGMENT)
            if (bound_segment and
                self._is_in_managed_physnets(
                    bound_segment.get(driver_api.PHYSICAL_NETWORK))):
                bound_segments.append(bound_segment)
        return bound_segments

    def _handle_port_migration_postcommit(self, context):
        """Handles port migration in postcommit

        In case of port migration, it removes the port from the original host
        and also it release the segment id if no port is attached to the same
        segment id that the port is attached to.
        """
        orig_port = context.original
        orig_host = context.original_host
        new_host = context.host

        if new_host and orig_host and new_host != orig_host:
            self._try_to_release_dynamic_segment(context, migration=True)

            # Handling migration case.
            # 1. The port should be unplugged from network
            # 2. If segment_id is provisioned and it not bound to any port it
            # should be removed from EOS.
            network_id = orig_port['network_id']
            tenant_id = orig_port['tenant_id'] or constants.INTERNAL_TENANT_ID
            # Ensure that we use tenant Id for the network owner
            tenant_id = self._network_owner_tenant(context, network_id,
                                                   tenant_id)
            for binding_level in context._original_binding_levels or []:
                with self.eos_sync_lock:
                    # Removing the port form original host
                    self._delete_port(orig_port, orig_host, tenant_id)
                    # If segment id is not bound to any port, then
                    # remove it from EOS
                    segment = self.ndb.get_segment_by_id(
                        context._plugin_context,
                        binding_level.segment_id)
                    if not segment:
                        try:
                            segment_info = [{
                                'id': binding_level.segment_id,
                                'network_id': network_id,
                            }]
                            LOG.debug("migration_postcommit:"
                                      "deleting segment %s", segment_info)
                            self.rpc.delete_network_segments(tenant_id,
                                                             segment_info)
                        except arista_exc.AristaRpcError:
                            LOG.info(constants.EOS_UNREACHABLE_MSG)

            return True

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

        # When delete a vm, the trunk port context has no device_owner
        # Keep device_owner as in original port
        if not device_owner and orig_port.get('trunk_details'):
            device_owner = orig_port['device_owner']

        if not utils.supported_device_owner(device_owner):
            return

        vnic_type = port['binding:vnic_type']
        binding_profile = port['binding:profile']
        bindings = []
        if binding_profile:
            bindings = binding_profile.get('local_link_information', [])

        port_id = port['id']
        port_name = port['name']
        network_id = port['network_id']
        tenant_id = port['tenant_id'] or constants.INTERNAL_TENANT_ID
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

        # Check if it is trunk_port deletion case
        seg_info = []
        if not port.get('trunk_details') or host:
            seg_info = self._bound_segments(context)
            if not seg_info:
                LOG.debug("Ignoring the update as the port is not managed by "
                          "Arista switches.")
                return

        with self.eos_sync_lock:
            hostname = self._host_name(host)
            try:
                orig_host = context.original_host
                port_down = False
                if(port['device_owner'] == n_const.DEVICE_OWNER_DVR_INTERFACE
                   or port.get('trunk_details')):
                    # We care about port status only for DVR ports and
                    # trunk ports
                    port_down = context.status == n_const.PORT_STATUS_DOWN

                if orig_host and (port_down or host != orig_host or
                   device_id == n_const.DEVICE_ID_RESERVED_DHCP_PORT):
                    LOG.info("Deleting the port %s" % str(orig_port))
                    # The port moved to a different host or the VM
                    # connected to the port was deleted or its in DOWN
                    # state. So delete the old port on the old host.
                    self._delete_port(orig_port, orig_host, tenant_id)
                if(hostname and is_vm_boot and not port_down and
                   device_id != n_const.DEVICE_ID_RESERVED_DHCP_PORT):
                    segments = seg_info
                    all_segments = self.ndb.get_all_network_segments(
                        network_id, context=context._plugin_context)
                    try:
                        self.rpc.create_network_segments(
                            tenant_id, network_id,
                            context.network.current['name'], all_segments)
                    except arista_exc.AristaRpcError:
                        with excutils.save_and_reraise_exception():
                            LOG.error(_LE("Failed to create network segments"))
                    LOG.info(_LI("Port plugged into network"))
                    # Plug port into the network only if it exists in the db
                    # and is bound to a host and the port is up.
                    trunk_details = port.get('trunk_details')
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
                                                    switch_bindings=bindings,
                                                    trunk_details=trunk_details
                                                    )
                else:
                    LOG.info(_LI("Port not plugged into network"))
            except arista_exc.AristaRpcError as err:
                LOG.error(_LE('update_port_postcommit: Did not update '
                              'port %(port_id)s. Reason: %(err)s'),
                          {'port_id': port_id, 'err': err})

    def delete_port_postcommit(self, context):
        """Unplug a physical host from a network.

        Send provisioning request to Arista Hardware to unplug a host
        from appropriate network.
        """
        port = context.current
        host = context.host
        network_id = port['network_id']

        tenant_id = port['tenant_id'] or constants.INTERNAL_TENANT_ID
        # Ensure that we use tenant Id for the network owner
        tenant_id = self._network_owner_tenant(context, network_id, tenant_id)

        pretty_log("delete_port_postcommit:", port)

        # If this port is the last one using dynamic segmentation id,
        # and the segmentation id was allocated by this driver, it needs
        # to be released.
        self._try_to_release_dynamic_segment(context)

        with self.eos_sync_lock:
            try:
                self._delete_port(port, host, tenant_id)
                self._delete_segment(context, tenant_id)
            except arista_exc.AristaRpcError:
                # Can't do much if deleting a port failed.
                # Log a warning and continue.
                LOG.warning(constants.UNABLE_TO_DELETE_PORT_MSG)

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

        if not utils.supported_device_owner(device_owner):
            return

        vnic_type = port['binding:vnic_type']
        binding_profile = port['binding:profile']
        switch_bindings = []
        if binding_profile:
            switch_bindings = binding_profile.get('local_link_information', [])
        sg = port['security_groups']

        if not device_id or not host:
            LOG.warning(constants.UNABLE_TO_DELETE_DEVICE_MSG)
            return

        try:
            hostname = self._host_name(host)
            trunk_details = port.get('trunk_details')
            self.rpc.unplug_port_from_network(device_id, device_owner,
                                              hostname, port_id, network_id,
                                              tenant_id, sg, vnic_type,
                                              switch_bindings=switch_bindings,
                                              trunk_details=trunk_details)
            self.rpc.remove_security_group(sg, switch_bindings)

            # if necessary, delete tenant as well.
            self.delete_tenant(tenant_id)
        except arista_exc.AristaRpcError:
            LOG.info(constants.EOS_UNREACHABLE_MSG)

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
            segment = self.ndb.get_segment_by_id(
                context._plugin_context, binding_level.segment_id)
            if not segment:
                # The segment is already released. Delete it from EOS
                LOG.debug("Deleting segment %s", binding_level.segment_id)
                try:
                    segment_info = {
                        'id': binding_level.segment_id,
                        'network_id': network_id,
                    }
                    self.rpc.delete_network_segments(tenant_id,
                                                     [segment_info])
                except arista_exc.AristaRpcError:
                    LOG.info(constants.EOS_UNREACHABLE_MSG)

    def _try_to_release_dynamic_segment(self, context, migration=False):
        """Release dynamic segment if necessary

        If this port was the last port using a segment and the segment was
        allocated by this driver, it should be released
        """
        binding_levels = context.binding_levels
        LOG.debug("_try_release_dynamic_segment: "
                  "binding_levels=%(bl)s", {'bl': binding_levels})
        if not binding_levels:
            return

        for prior_level, binding in enumerate(binding_levels[1:]):
            allocating_driver = binding_levels[prior_level].get(
                driver_api.BOUND_DRIVER)
            if allocating_driver != constants.MECHANISM_DRV_NAME:
                continue
            bound_segment = binding.get(driver_api.BOUND_SEGMENT, {})
            segment_id = bound_segment['id']
            if not db_lib.segment_is_dynamic(segment_id):
                continue
            if not db_lib.segment_bound(segment_id):
                context.release_dynamic_segment(segment_id)
                LOG.debug("Released dynamic segment %(seg)s allocated "
                          "by %(drv)s", {'seg': segment_id,
                                         'drv': allocating_driver})

    def delete_tenant(self, tenant_id):
        """delete a tenant from DB.

        A tenant is deleted only if there is no networks or ports configured
        configured for this tenant.
        """
        if not db_lib.tenant_provisioned(tenant_id):
            try:
                self.rpc.delete_tenant(tenant_id)
            except arista_exc.AristaRpcError:
                with excutils.save_and_reraise_exception():
                    LOG.info(constants.EOS_UNREACHABLE_MSG)

    def _host_name(self, hostname):
        fqdns_used = cfg.CONF.ml2_arista['use_fqdn']
        return hostname if fqdns_used else hostname.split('.')[0]

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

    def unset_subport(self, resource, event, trigger, **kwargs):
        payload = kwargs['payload']
        trunk_id = payload.trunk_id
        subports = payload.subports

        trunk_port = db_lib.get_trunk_port_by_trunk_id(trunk_id)
        if trunk_port:
            device_id = trunk_port.device_id
            tenant_id = trunk_port.tenant_id
            host = trunk_port.port_binding.host
            vnic_type = trunk_port.port_binding.vnic_type
            profile = trunk_port.port_binding.profile
            if profile:
                profile = json.loads(profile)

            for subport in subports:
                subport_id = subport.port_id
                subport_current = self.ndb.get_port(subport_id)
                subport_current['device_id'] = device_id
                subport_current['binding:vnic_type'] = vnic_type
                subport_current['binding:profile'] = profile
                subport_current['device_owner'] = 'trunk:subport'

                self._delete_port(subport_current, host, tenant_id)
        else:
            LOG.warning('Unable to unset the subport, no trunk port found')

    def set_subport(self, resource, event, trigger, **kwargs):
        payload = kwargs['payload']
        trunk_id = payload.trunk_id
        subports = payload.subports

        device_owner = 'trunk:subport'
        trunk_port = db_lib.get_trunk_port_by_trunk_id(trunk_id)
        if not trunk_port:
            return
        device_id = trunk_port.device_id
        tenant_id = trunk_port.tenant_id
        host = trunk_port.port_binding.host
        if not host:
            return
        hostname = self._host_name(host)
        vnic_type = trunk_port.port_binding.vnic_type

        profile = trunk_port.port_binding.profile
        bindings = []
        if profile:
            profile = json.loads(profile)
            bindings = profile.get('local_link_information', [])

        for subport in subports:
            subport_id = subport.port_id
            subport_current = self.ndb.get_port(subport_id)
            network_id = self.ndb.get_network_id_from_port_id(subport_id)
            port_name = subport_current.get('name')
            sg = subport_current.get('security_groups')
            orig_sg = None
            segments = db_lib.get_network_segments_by_port_id(subport_id)

            self.rpc.plug_port_into_network(device_id,
                                            hostname,
                                            subport_id,
                                            network_id,
                                            tenant_id,
                                            port_name,
                                            device_owner,
                                            sg, orig_sg,
                                            vnic_type,
                                            segments=segments,
                                            switch_bindings=bindings)
