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

import abc
import base64
import os

from neutron_lib.db import api as db_api
from oslo_config import cfg
from oslo_log import log as logging
import six

from neutron.db.models.plugins.ml2 import vlanallocation

from networking_arista._i18n import _, _LW
from networking_arista.common import exceptions as arista_exc
from networking_arista.ml2 import arista_sec_gp

LOG = logging.getLogger(__name__)


@six.add_metaclass(abc.ABCMeta)
class AristaRPCWrapperBase(object):
    """Wraps Arista JSON RPC.

    All communications between Neutron and EOS are over JSON RPC.
    EOS - operating system used on Arista hardware
    Command API - JSON RPC API provided by Arista EOS
    """
    def __init__(self, neutron_db):
        self._ndb = neutron_db
        self._validate_config()
        self._server_ip = None
        self.region = cfg.CONF.ml2_arista.region_name
        self.sync_interval = cfg.CONF.ml2_arista.sync_interval
        self.conn_timeout = cfg.CONF.ml2_arista.conn_timeout
        self.eapi_hosts = cfg.CONF.ml2_arista.eapi_host.split(',')
        self.security_group_driver = arista_sec_gp.AristaSecGroupSwitchDriver(
            self._ndb)

        # We denote mlag_pair physnets as peer1_peer2 in the physnet name, the
        # following builds a mapping of peer name to physnet name for use
        # during port binding
        self.mlag_pairs = {}
        session = db_api.get_reader_session()
        with session.begin():
            physnets = session.query(
                vlanallocation.VlanAllocation.physical_network
            ).distinct().all()
        for (physnet,) in physnets:
            if '_' in physnet:
                peers = physnet.split('_')
                self.mlag_pairs[peers[0]] = physnet
                self.mlag_pairs[peers[1]] = physnet

        # Indication of CVX availabililty in the driver.
        self._cvx_available = True

        # Reference to SyncService object which is set in AristaDriver
        self.sync_service = None

    def _validate_config(self):
        if cfg.CONF.ml2_arista.get('eapi_host') == '':
            msg = _('Required option eapi_host is not set')
            LOG.error(msg)
            raise arista_exc.AristaConfigError(msg=msg)
        if cfg.CONF.ml2_arista.get('eapi_username') == '':
            msg = _('Required option eapi_username is not set')
            LOG.error(msg)
            raise arista_exc.AristaConfigError(msg=msg)

    def _api_username(self):
        return cfg.CONF.ml2_arista.eapi_username

    def _api_password(self):
        return cfg.CONF.ml2_arista.eapi_password

    def _get_random_name(self, length=10):
        """Returns a base64 encoded name."""
        result = base64.b64encode(os.urandom(10)).translate(None, b'=+/')

        return result if six.PY2 else result.decode('utf-8')

    def _get_cvx_hosts(self):
        cvx = []
        if self._server_ip:
            # If we know the master's IP, let's start with that
            cvx.append(self._server_ip)

        for h in self.eapi_hosts:
            if h.strip() not in cvx:
                cvx.append(h.strip())

        return cvx

    def set_cvx_unavailable(self):
        self._cvx_available = False
        if self.sync_service:
            self.sync_service.force_sync()

    def set_cvx_available(self):
        self._cvx_available = True

    def cvx_available(self):
        return self._cvx_available

    def check_cvx_availability(self):
        try:
            if self._get_eos_master():
                self.set_cvx_available()
                return True
        except Exception as exc:
            LOG.warning(_LW('%s when getting CVX master'), exc)

        self.set_cvx_unavailable()
        return False

    def delete_tenant(self, tenant_id):
        """Deletes a given tenant and all its networks and VMs from EOS.

        :param tenant_id: globally unique neutron tenant identifier
        """
        self.delete_tenant_bulk([tenant_id])

    def clear_region_updated_time(self):
        # TODO(shashank): Remove this once the call is removed from the ML2
        # driver.
        pass

    def create_network(self, tenant_id, network):
        """Creates a single network on Arista hardware

        :param tenant_id: globally unique neutron tenant identifier
        :param network: dict containing network_id, network_name and
                        segmentation_id
        """
        self.create_network_bulk(tenant_id, [network])

    def delete_network(self, tenant_id, network_id, network_segments):
        """Deletes a specified network for a given tenant

        :param tenant_id: globally unique neutron tenant identifier
        :param network_id: globally unique neutron network identifier
        :param network_segments: segments associated with the network
        """
        segments_info = []
        segments_info.extend({'id': segment['id'], 'network_id': network_id}
                             for segment in network_segments)
        self.delete_network_segments(tenant_id, segments_info)
        self.delete_network_bulk(tenant_id, [network_id])

    def delete_vm(self, tenant_id, vm_id):
        """Deletes a VM from EOS for a given tenant

        :param tenant_id : globally unique neutron tenant identifier
        :param vm_id : id of a VM that needs to be deleted.
        """
        self.delete_vm_bulk(tenant_id, [vm_id])

    @abc.abstractmethod
    def plug_port_into_network(self, device_id, host_id, port_id,
                               net_id, tenant_id, port_name, device_owner,
                               sg, orig_sg, vnic_type, segments=None,
                               switch_bindings=None, trunk_details=None):
        """Generic routine plug a port of a VM instace into network.

        :param device_id: globally unique identifier for the device
        :param host: ID of the host where the port is placed
        :param port_id: globally unique port ID that connects port to network
        :param network_id: globally unique neutron network identifier
        :param tenant_id: globally unique neutron tenant identifier
        :param port_name: Name of the port - for display purposes
        :param device_owner: Device owner - e.g. compute or network:dhcp
        :param sg: current security group for the port
        :param orig_sg: original security group for the port
        :param vnic_type: VNIC type for the port
        :param segments: list of network segments the port is bound to
        :param switch_bindings: List of switch_bindings
        :param trunk_details: List of subports of a trunk port
        """

    @abc.abstractmethod
    def unplug_port_from_network(self, device_id, device_owner, hostname,
                                 port_id, network_id, tenant_id, sg, vnic_type,
                                 switch_bindings=None, trunk_details=None):
        """Removes a port from the device

        :param device_id: globally unique identifier for the device
        :param host: ID of the host where the device is placed
        :param port_id: globally unique port ID that connects device to network
        :param network_id: globally unique neutron network identifier
        :param tenant_id: globally unique neutron tenant identifier
        :param trunk_details: List of subports of a trunk port
        """

    def _clean_acls(self, sg, failed_switch, switches_to_clean):
        """This is a helper function to clean up ACLs on switches.

        This called from within an exception - when apply_acl fails.
        Therefore, ensure that exception is raised after the cleanup
        is done.
        :param sg: Security Group to be removed
        :param failed_switch: IP of the switch where ACL failed
        :param switches_to_clean: List of switches containing link info
        """
        if not switches_to_clean:
            # This means the no switch needs cleaning - so, simply raise the
            # the exception and bail out
            msg = (_("Failed to apply ACL %(sg)s on switch %(switch)s") %
                   {'sg': sg, 'switch': failed_switch})
            LOG.error(msg)

        for s in switches_to_clean:
            try:
                # Port is being updated to remove security groups
                self.security_group_driver.remove_acl(sg,
                                                      s['switch_id'],
                                                      s['port_id'],
                                                      s['switch_info'])
            except Exception:
                msg = (_("Failed to remove ACL %(sg)s on switch %(switch)%") %
                       {'sg': sg, 'switch': s['switch_info']})
                LOG.warning(msg)
        raise arista_exc.AristaSecurityGroupError(msg=msg)

    def create_acl(self, sg):
        """Creates an ACL on Arista Switch.

        Deals with multiple configurations - such as multiple switches
        """
        self.security_group_driver.create_acl(sg)

    def delete_acl(self, sg):
        """Deletes an ACL from Arista Switch.

        Deals with multiple configurations - such as multiple switches
        """
        self.security_group_driver.delete_acl(sg)

    def create_acl_rule(self, sgr):
        """Creates an ACL on Arista Switch.

        For a given Security Group (ACL), it adds additional rule
        Deals with multiple configurations - such as multiple switches
        """
        self.security_group_driver.create_acl_rule(sgr)

    def delete_acl_rule(self, sgr):
        """Deletes an ACL rule on Arista Switch.

        For a given Security Group (ACL), it removes a rule
        Deals with multiple configurations - such as multiple switches
        """
        self.security_group_driver.delete_acl_rule(sgr)

    def perform_sync_of_sg(self):
        """Perform sync of the security groups between ML2 and EOS.

        This is unconditional sync to ensure that all security
        ACLs are pushed to all the switches, in case of switch
        or neutron reboot
        """
        self.security_group_driver.perform_sync_of_sg()

    @abc.abstractmethod
    def sync_supported(self):
        """Whether the EOS version supports sync.

        Returns True if sync is supported, false otherwise.
        """

    @abc.abstractmethod
    def bm_and_dvr_supported(self):
        """Whether EOS supports Ironic and DVR.

        Returns True if supported, false otherwise.
        """

    @abc.abstractmethod
    def register_with_eos(self, sync=False):
        """This is the registration request with EOS.

        This the initial handshake between Neutron and EOS.
        critical end-point information is registered with EOS.

        :param sync: This flags indicates that the region is being synced.
        """

    @abc.abstractmethod
    def check_supported_features(self):
        """Checks whether the CLI commands are valid.

           This method tries to execute the commands on EOS and if it succeedes
           the command is stored.
        """

    @abc.abstractmethod
    def get_region_updated_time(self):
        """Return the timestamp of the last update.

           This method returns the time at which any entities in the region
           were updated.
        """

    @abc.abstractmethod
    def delete_this_region(self):
        """Deleted the region data from EOS."""

    @abc.abstractmethod
    def sync_start(self):
        """Let EOS know that a sync in being initiated."""

    @abc.abstractmethod
    def sync_end(self):
        """Let EOS know that sync is complete."""

    @abc.abstractmethod
    def get_tenants(self):
        """Returns dict of all tenants known by EOS.

        :returns: dictionary containing the networks per tenant
                  and VMs allocated per tenant
        """

    @abc.abstractmethod
    def delete_tenant_bulk(self, tenant_list, sync=False):
        """Sends a bulk request to delete the tenants.

        :param tenant_list: list of globaly unique neutron tenant ids which
                            need to be deleted.
        :param sync: This flags indicates that the region is being synced.
        """

    @abc.abstractmethod
    def create_network_bulk(self, tenant_id, network_list, sync=False):
        """Creates a network on Arista Hardware

        :param tenant_id: globally unique neutron tenant identifier
        :param network_list: list of dicts containing network_id, network_name
                             and segmentation_id
        :param sync: This flags indicates that the region is being synced.
        """

    @abc.abstractmethod
    def create_network_segments(self, tenant_id, network_id,
                                network_name, segments):
        """Creates a network on Arista Hardware

        Note: This method is not used at the moment. create_network()
        is used instead. This will be used once the support for
        multiple segments is added in Neutron.

        :param tenant_id: globally unique neutron tenant identifier
        :param network_id: globally unique neutron network identifier
        :param network_name: Network name - for display purposes
        :param segments: List of segments in a given network
        """

    @abc.abstractmethod
    def delete_network_bulk(self, tenant_id, network_id_list, sync=False):
        """Deletes the network ids specified for a tenant

        :param tenant_id: globally unique neutron tenant identifier
        :param network_id_list: list of globally unique neutron network
                                identifiers
        :param sync: This flags indicates that the region is being synced.
        """

    @abc.abstractmethod
    def delete_network_segments(self, tenant_id, network_segments):
        """Deletes the network segments

        :param network_segments: List of network segments to be delted.
        """

    @abc.abstractmethod
    def create_instance_bulk(self, tenant_id, neutron_ports, vms,
                             port_profiles, sync=False):
        """Sends a bulk request to create ports.

        :param tenant_id: globaly unique neutron tenant identifier
        :param neutron_ports: list of ports that need to be created.
        :param vms: list of vms to which the ports will be attached to.
        :param sync: This flags indicates that the region is being synced.
        """

    @abc.abstractmethod
    def delete_instance_bulk(self, tenant_id, instance_id_list, instance_type,
                             sync=False):
        """Deletes instances from EOS for a given tenant

        :param tenant_id : globally unique neutron tenant identifier
        :param instance_id_list : ids of instances that needs to be deleted.
        :param instance_type: The type of the instance which is being deleted.
        :param sync: This flags indicates that the region is being synced.
        """

    @abc.abstractmethod
    def delete_vm_bulk(self, tenant_id, vm_id_list, sync=False):
        """Deletes VMs from EOS for a given tenant

        :param tenant_id : globally unique neutron tenant identifier
        :param vm_id_list : ids of VMs that needs to be deleted.
        :param sync: This flags indicates that the region is being synced.
        """

    @abc.abstractmethod
    def delete_dhcp_bulk(self, tenant_id, dhcp_id_list, sync=False):
        """Deletes instances from EOS for a given tenant

        :param tenant_id : globally unique neutron tenant identifier
        :param dhcp_id_list : ids of dhcp instances that needs to be deleted.
        :param sync: This flags indicates that the region is being synced.
        """

    @abc.abstractmethod
    def hpb_supported(self):
        """Whether hierarchical port binding (HPB) is supported by CVX.

        Returns True if HPB is supported, False otherwise.
        """

    def apply_security_group(self, security_group, switch_bindings):
        """Applies ACLs on switch interface.

        Translates neutron security group to switch ACL and applies the ACLs
        on all the switch interfaces defined in the switch_bindings.

        :param security_group: Neutron security group
        :param switch_bindings: Switch link information
        """
        switches_with_acl = []
        for binding in switch_bindings:
            try:
                self.security_group_driver.apply_acl(security_group,
                                                     binding['switch_id'],
                                                     binding['port_id'],
                                                     binding['switch_info'])
                switches_with_acl.append(binding)
            except Exception:
                message = _LW('Unable to apply security group on %s') % (
                    binding['switch_id'])
                LOG.warning(message)
                self._clean_acls(security_group, binding['switch_id'],
                                 switches_with_acl)

    def remove_security_group(self, security_group, switch_bindings):
        """Removes ACLs from switch interface

        Translates neutron security group to switch ACL and removes the ACLs
        from all the switch interfaces defined in the switch_bindings.

        :param security_group: Neutron security group
        :param switch_bindings: Switch link information
        """
        for binding in switch_bindings:
            try:
                self.security_group_driver.remove_acl(security_group,
                                                      binding['switch_id'],
                                                      binding['port_id'],
                                                      binding['switch_info'])
            except Exception:
                message = _LW('Unable to remove security group from %s') % (
                    binding['switch_id'])
                LOG.warning(message)
