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
from multiprocessing import Queue

from neutron_lib.api.definitions import portbindings
from neutron_lib import constants as n_const
from neutron_lib.plugins.ml2 import api as driver_api
from oslo_config import cfg
from oslo_log import log as logging

from neutron.services.trunk import constants as trunk_consts

from networking_arista._i18n import _LE
from networking_arista.common import constants as a_const
from networking_arista.common import db_lib
from networking_arista.common import exceptions as arista_exc
from networking_arista.ml2 import arista_sync
from networking_arista.ml2 import arista_trunk
from networking_arista.ml2.rpc.arista_eapi import AristaRPCWrapperEapi
from networking_arista.ml2 import sec_group_callback

LOG = logging.getLogger(__name__)
cfg.CONF.import_group('ml2_arista', 'networking_arista.common.config')


def pretty_log(tag, obj):
    log_data = json.dumps(obj, sort_keys=True, indent=4)
    LOG.debug(tag)
    LOG.debug(log_data)


class MechResource(object):
    """Container class for passing data to sync worker"""

    def __init__(self, id, resource_type, action):
        self.id = id
        self.resource_type = resource_type
        self.action = action

    def __str__(self):
        return "%s %s ID: %s" % (self.action, self.resource_type, self.id)


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
        self.eapi = AristaRPCWrapperEapi()
        self.provision_queue = Queue()
        self.trunk_driver = None

    def initialize(self):
        self.sg_handler = sec_group_callback.AristaSecurityGroupHandler(self)
        self.trunk_driver = arista_trunk.AristaTrunkDriver.create()

    def get_workers(self):
        return [arista_sync.AristaSyncWorker(self.provision_queue)]

    def create_tenant(self, tenant_id):
        """Enqueue tenant create"""
        t_res = MechResource(tenant_id, a_const.TENANT_RESOURCE,
                             a_const.CREATE)
        self.provision_queue.put(t_res)

    def delete_tenant_if_removed(self, tenant_id):
        """Enqueue tenant delete if it's no longer in the db"""
        if not db_lib.tenant_provisioned(tenant_id):
            t_res = MechResource(tenant_id, a_const.TENANT_RESOURCE,
                                 a_const.DELETE)
            self.provision_queue.put(t_res)

    def create_network(self, network):
        """Enqueue network create"""
        n_res = MechResource(network['id'], a_const.NETWORK_RESOURCE,
                             a_const.CREATE)
        self.provision_queue.put(n_res)

    def update_network(self, network):
        """Enqueue network update"""
        n_res = MechResource(network['id'], a_const.NETWORK_RESOURCE,
                             a_const.UPDATE)
        self.provision_queue.put(n_res)

    def delete_network(self, network):
        """Enqueue network delete"""
        n_res = MechResource(network['id'], a_const.NETWORK_RESOURCE,
                             a_const.DELETE)
        self.provision_queue.put(n_res)

    def create_segments(self, segments):
        """Enqueue segment creates"""
        for segment in segments:
            s_res = MechResource(segment['id'], a_const.SEGMENT_RESOURCE,
                                 a_const.CREATE)
            self.provision_queue.put(s_res)

    def delete_segments(self, segments):
        """Enqueue segment deletes"""
        for segment in segments:
            s_res = MechResource(segment['id'], a_const.SEGMENT_RESOURCE,
                                 a_const.DELETE)
            self.provision_queue.put(s_res)

    def get_instance_type(self, port):
        """Determine the port type based on device owner and vnic type"""
        if port[portbindings.VNIC_TYPE] == portbindings.VNIC_BAREMETAL:
            return a_const.BAREMETAL_RESOURCE
        owner_to_type = {
            n_const.DEVICE_OWNER_DHCP: a_const.DHCP_RESOURCE,
            n_const.DEVICE_OWNER_DVR_INTERFACE: a_const.ROUTER_RESOURCE,
            trunk_consts.TRUNK_SUBPORT_OWNER: a_const.VM_RESOURCE}
        if port['device_owner'] in owner_to_type.keys():
            return owner_to_type[port['device_owner']]
        elif port['device_owner'].startswith(
                n_const.DEVICE_OWNER_COMPUTE_PREFIX):
            return a_const.VM_RESOURCE
        return None

    def create_instance(self, port):
        """Enqueue instance create"""
        instance_type = self.get_instance_type(port)
        if not instance_type:
            return
        i_res = MechResource(port['device_id'], instance_type, a_const.CREATE)
        self.provision_queue.put(i_res)

    def delete_instance_if_removed(self, port):
        """Enqueue instance delete if it's no longer in the db"""
        instance_type = self.get_instance_type(port)
        if not instance_type:
            return
        if not db_lib.instance_provisioned(port['device_id']):
            i_res = MechResource(port['device_id'], instance_type,
                                 a_const.DELETE)
            self.provision_queue.put(i_res)

    def create_port(self, port):
        """Enqueue port create"""
        instance_type = self.get_instance_type(port)
        if not instance_type:
            return
        port_type = instance_type + a_const.PORT_SUFFIX
        p_res = MechResource(port['id'], port_type, a_const.CREATE)
        self.provision_queue.put(p_res)

    def delete_port_if_removed(self, port):
        """Enqueue port delete"""
        instance_type = self.get_instance_type(port)
        if not instance_type:
            return
        port_type = instance_type + a_const.PORT_SUFFIX
        if not db_lib.port_provisioned(port['id']):
            p_res = MechResource(port['id'], port_type, a_const.DELETE)
            self.provision_queue.put(p_res)

    def _get_binding_keys(self, port, host):
        """Get binding keys from the port binding"""
        binding_keys = list()
        switch_binding = port[portbindings.PROFILE].get(
            'local_link_information', None)
        if switch_binding:
            for binding in switch_binding:
                switch_id = binding.get('switch_id')
                port_id = binding.get('port_id')
                binding_keys.append((port['id'], (switch_id, port_id)))
        else:
            binding_keys.append((port['id'], host))
        return binding_keys

    def create_port_binding(self, port, host):
        """Enqueue port binding create"""
        for pb_key in self._get_binding_keys(port, host):
            pb_res = MechResource(pb_key, a_const.PORT_BINDING_RESOURCE,
                                  a_const.CREATE)
            self.provision_queue.put(pb_res)

    def delete_port_binding(self, port, host):
        """Enqueue port binding delete"""
        for pb_key in self._get_binding_keys(port, host):
            pb_res = MechResource(pb_key, a_const.PORT_BINDING_RESOURCE,
                                  a_const.DELETE)
            self.provision_queue.put(pb_res)

    def create_network_postcommit(self, context):
        """Provision the network on CVX"""
        network = context.current
        segments = context.network_segments
        tenant_id = network['project_id']
        self.create_tenant(tenant_id)
        self.create_network(network)
        self.create_segments(segments)

    def update_network_postcommit(self, context):
        """Send network updates to CVX:

        - Update the network name
        - Add new segments
        - Delete stale segments
        """
        network = context.current
        orig_network = context.original
        segments = context.network_segments

        # Check for name change
        if network['name'] != orig_network['name']:
            self.update_network(network)

        # New segments may have been added
        self.create_segments(segments)

    def delete_network_postcommit(self, context):
        """Delete the network from CVX"""
        network = context.current
        segments = context.network_segments
        tenant_id = network['project_id']
        self.delete_segments(segments)
        self.delete_network(network)
        self.delete_tenant_if_removed(tenant_id)

    def _delete_port_resources(self, port, host):
        tenant_id = port['project_id']

        self.delete_port_binding(port, host)
        self.delete_port_if_removed(port)
        self.delete_instance_if_removed(port)
        self.delete_tenant_if_removed(tenant_id)

    def update_port_postcommit(self, context):
        """Send port updates to CVX

        This method is also responsible for the initial creation of ports
        as we wait until after a port is bound to send the port data to CVX
        """
        port = context.current
        orig_port = context.original
        tenant_id = port['project_id']

        # Device id can change without a port going DOWN, but the new device
        # id may not be supported
        if orig_port and port['device_id'] != orig_port['device_id']:
            self._delete_port_resources(orig_port, context.original_host)

        if context.status == n_const.PORT_STATUS_DOWN:
            if context.original_host:
                self._delete_port_resources(orig_port, context.original_host)
                self._try_to_release_dynamic_segment(context, migration=True)
        else:
            self.create_tenant(tenant_id)
            if context.binding_levels:
                segments = [
                    level['bound_segment'] for level in context.binding_levels]
                self.create_segments(segments)
            self.create_instance(port)
            self.create_port(port)
            self.create_port_binding(port, context.host)

    def delete_port_postcommit(self, context):
        """Delete the port from CVX"""
        port = context.current
        self._delete_port_resources(port, context.host)
        self._try_to_release_dynamic_segment(context)

    def _get_physnet_from_link_info(self, port, physnet_info):

        binding_profile = port.get(portbindings.PROFILE)
        if not binding_profile:
            return

        link_info = binding_profile.get('local_link_information')
        if not link_info:
            return

        mac_to_hostname = physnet_info.get('mac_to_hostname', {})
        for link in link_info:
            if link.get('switch_id') in mac_to_hostname:
                physnet = mac_to_hostname.get(link.get('switch_id'))
                return self.rpc.mlag_pairs.get(physnet, physnet)

    def _bind_port_to_baremetal(self, context, segment):

        port = context.current
        vnic_type = port.get('binding:vnic_type')
        if vnic_type != portbindings.VNIC_BAREMETAL:
            # We are only interested in binding baremetal ports.
            return

        binding_profile = port.get(portbindings.PROFILE)
        if not binding_profile:
            return

        link_info = binding_profile.get('local_link_information')
        if not link_info:
            return

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

    def _is_in_managed_physnets(self, physnet):
        # Check if this is a fabric segment
        if not physnet:
            return self.manage_fabric
        # If managed physnet is empty, accept all.
        if not self.managed_physnets:
            return True
        # managed physnet is not empty, find for matching physnet
        return any(pn == physnet for pn in self.managed_physnets)

    def bind_port(self, context):
        """Bind port to a network segment.

        Provisioning request to Arista Hardware to plug a host
        into appropriate network is done when the port is created
        this simply tells the ML2 Plugin that we are binding the port
        """
        host_id = context.host
        port = context.current
        physnet_info = {}
        for segment in context.segments_to_bind:
            physnet = segment.get(driver_api.PHYSICAL_NETWORK)
            if not self._is_in_managed_physnets(physnet):
                LOG.debug("bind_port for port %(port)s: physical_network "
                          "%(physnet)s is not managed by Arista "
                          "mechanism driver", {'port': port.get('id'),
                                               'physnet': physnet})
                continue
            # If physnet is not set, we need to look it up using hostname
            # and topology info
            if not physnet:
                if not physnet_info:
                    # We only need to get physnet_info once
                    physnet_info = self.eapi.get_physical_network(host_id)
                if (port.get('binding:vnic_type') ==
                        portbindings.VNIC_BAREMETAL):
                    # Find physnet using link_information in baremetal case
                    physnet = self._get_physnet_from_link_info(port,
                                                               physnet_info)
                else:
                    physnet = physnet_info.get('physnet')
            # If physnet was not found, we cannot bind this port
            if not physnet:
                LOG.debug("bind_port for port %(port)s: no physical_network "
                          "found", {'port': port.get('id')})
                continue
            if segment[driver_api.NETWORK_TYPE] == n_const.TYPE_VXLAN:
                # The physical network is connected to arista switches,
                # allocate dynamic segmentation id to bind the port to
                # the network that the port belongs to.
                try:
                    next_segment = context.allocate_dynamic_segment(
                        {'id': context.network.current['id'],
                         'network_type': n_const.TYPE_VLAN,
                         'physical_network': physnet})
                except Exception as exc:
                    LOG.error(_LE("bind_port for port %(port)s: Failed to "
                                  "allocate dynamic segment for physnet "
                                  "%(physnet)s. %(exc)s"),
                              {'port': port.get('id'), 'physnet': physnet,
                               'exc': exc})
                    return

                LOG.debug("bind_port for port %(port)s: "
                          "current_segment=%(current_seg)s, "
                          "next_segment=%(next_seg)s",
                          {'port': port.get('id'), 'current_seg': segment,
                           'next_seg': next_segment})
                context.continue_binding(segment['id'], [next_segment])
            elif port.get('binding:vnic_type') == portbindings.VNIC_BAREMETAL:
                # The network_type is vlan, try binding process for baremetal.
                self._bind_port_to_baremetal(context, segment)

    def _try_to_release_dynamic_segment(self, context, migration=False):
        """Release dynamic segment allocated by the driver

        If this port is the last port using the segmentation id allocated
        by the driver, it should be released
        """
        host = context.original_host if migration else context.host

        physnet_info = self.eapi.get_physical_network(host)
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
                    bound_segment.get('network_type') == n_const.TYPE_VLAN):
                segment_id = bound_segment.get('id')
                break

        # If the segment id is found and it is bound by this driver, and also
        # the segment id is not bound to any other port, release the segment.
        # When Arista driver participate in port binding by allocating dynamic
        # segment and then calling continue_binding, the driver should the
        # second last driver in the bound drivers list.
        if (segment_id and bound_drivers[-2:-1] ==
                [a_const.MECHANISM_DRV_NAME]):
            filters = {'segment_id': segment_id}
            result = db_lib.get_port_binding_level(filters)
            LOG.debug("Looking for entry with filters=%(filters)s "
                      "result=%(result)s ", {'filters': filters,
                                             'result': result})
            if not result:
                # The requested segment_id does not exist in the port binding
                # database. Release the dynamic segment.
                context.release_dynamic_segment(segment_id)
                LOG.debug("Released dynamic segment %(seg)s allocated "
                          "by %(drv)s", {'seg': segment_id,
                                         'drv': bound_drivers[-2]})

    def create_security_group(self, sg):
        try:
            self.eapi.create_acl(sg)
        except Exception:
            msg = (_('Failed to create ACL on EOS %s') % sg)
            LOG.exception(msg)
            raise arista_exc.AristaSecurityGroupError(msg=msg)

    def delete_security_group(self, sg):
        try:
            self.eapi.delete_acl(sg)
        except Exception:
            msg = (_('Failed to create ACL on EOS %s') % sg)
            LOG.exception(msg)
            raise arista_exc.AristaSecurityGroupError(msg=msg)

    def update_security_group(self, sg):
        try:
            self.eapi.create_acl(sg)
        except Exception:
            msg = (_('Failed to create ACL on EOS %s') % sg)
            LOG.exception(msg)
            raise arista_exc.AristaSecurityGroupError(msg=msg)

    def create_security_group_rule(self, sgr):
        try:
            self.eapi.create_acl_rule(sgr)
        except Exception:
            msg = (_('Failed to create ACL rule on EOS %s') % sgr)
            LOG.exception(msg)
            raise arista_exc.AristaSecurityGroupError(msg=msg)

    def delete_security_group_rule(self, sgr_id):
        if sgr_id:
            sgr = self.ndb.get_security_group_rule(sgr_id)
            if sgr:
                try:
                    self.eapi.delete_acl_rule(sgr)
                except Exception:
                    msg = (_('Failed to delete ACL rule on EOS %s') % sgr)
                    LOG.exception(msg)
                    raise arista_exc.AristaSecurityGroupError(msg=msg)
