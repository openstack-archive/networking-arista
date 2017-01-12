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
import json
import os
import socket

from neutron_lib import constants as n_const
from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import excutils
import requests
from six import add_metaclass

from neutron.extensions import portbindings

from networking_arista._i18n import _, _LI, _LW, _LE
from networking_arista.common import db_lib
from networking_arista.common import exceptions as arista_exc
from networking_arista.ml2 import arista_sec_gp

LOG = logging.getLogger(__name__)

EOS_UNREACHABLE_MSG = _('Unable to reach EOS')
DEFAULT_VLAN = 1

# Insert a heartbeat command every 100 commands
HEARTBEAT_INTERVAL = 100

# Commands dict keys
CMD_SYNC_HEARTBEAT = 'SYNC_HEARTBEAT'
CMD_REGION_SYNC = 'REGION_SYNC'
CMD_INSTANCE = 'INSTANCE'

# EAPI error messages of interest
ERR_CVX_NOT_LEADER = 'only available on cluster leader'
ERR_DVR_NOT_SUPPORTED = 'EOS version on CVX does not support DVR'
BAREMETAL_NOT_SUPPORTED = 'EOS version on CVX does not support Baremetal'

# Flat network constant
NETWORK_TYPE_FLAT = 'flat'


class InstanceType:
    BAREMETAL = 'baremetal'
    DHCP = 'dhcp'
    ROUTER = 'router'
    VM = 'vm'

    VIRTUAL_INSTANCE_TYPES = [DHCP, ROUTER, VM]
    BAREMETAL_INSTANCE_TYPES = [BAREMETAL]


@add_metaclass(abc.ABCMeta)
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
        self.keystone_conf = cfg.CONF.keystone_authtoken
        self.region = cfg.CONF.ml2_arista.region_name
        self.sync_interval = cfg.CONF.ml2_arista.sync_interval
        self.conn_timeout = cfg.CONF.ml2_arista.conn_timeout
        self.eapi_hosts = cfg.CONF.ml2_arista.eapi_host.split(',')
        self.security_group_driver = arista_sec_gp.AristaSecGroupSwitchDriver(
            self._ndb)

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

    def _keystone_url(self):
        if self.keystone_conf.auth_uri:
            auth_uri = self.keystone_conf.auth_uri.rstrip('/')
        else:
            auth_uri = (
                '%(protocol)s://%(host)s:%(port)s' %
                {'protocol': self.keystone_conf.auth_protocol,
                 'host': self.keystone_conf.auth_host,
                 'port': self.keystone_conf.auth_port})
        return '%s/v2.0/' % auth_uri

    def _api_username(self):
        return cfg.CONF.ml2_arista.eapi_username

    def _api_password(self):
        return cfg.CONF.ml2_arista.eapi_password

    def _get_random_name(self, length=10):
        """Returns a base64 encoded name."""
        return base64.b64encode(os.urandom(10)).translate(None, '=+/')

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
                               switch_bindings=None):
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
        """

    @abc.abstractmethod
    def unplug_port_from_network(self, device_id, device_owner, hostname,
                                 port_id, network_id, tenant_id, sg, vnic_type,
                                 switch_bindings=None):
        """Removes a port from the device

        :param device_id: globally unique identifier for the device
        :param host: ID of the host where the device is placed
        :param port_id: globally unique port ID that connects device to network
        :param network_id: globally unique neutron network identifier
        :param tenant_id: globally unique neutron tenant identifier
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
                             bm_port_profiles, sync=False):
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


class AristaRPCWrapperJSON(AristaRPCWrapperBase):
    def __init__(self, ndb):
        super(AristaRPCWrapperJSON, self).__init__(ndb)
        self.current_sync_name = None

    def _get_url(self, host="", user="", password=""):
        return ('https://%s:%s@%s/openstack/api/' %
                (user, password, host))

    def _api_host_url(self, host=""):
        return self._get_url(host, self._api_username(), self._api_password())

    def _send_request(self, host, path, method, data=None,
                      sanitized_data=None):
        request_headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'X-Sync-ID': self.current_sync_name
        }
        url = self._api_host_url(host=host) + path
        # Don't log the password
        log_url = self._get_url(host=host, user=self._api_username(),
                                password="*****") + path

        resp = None
        data = json.dumps(data)
        try:
            msg = (_('JSON request type: %(type)s url %(url)s data: '
                     '%(data)s sync_id: %(sync)s') %
                   {'type': method, 'url': log_url,
                    'data': sanitized_data or data,
                    'sync': self.current_sync_name})
            LOG.info(msg)
            func_lookup = {
                'GET': requests.get,
                'POST': requests.post,
                'PUT': requests.put,
                'PATCH': requests.patch,
                'DELETE': requests.delete
            }
            func = func_lookup.get(method)
            if not func:
                LOG.warning(_LI('Unrecognized HTTP method %s'), method)
                return None

            resp = func(url, timeout=self.conn_timeout, verify=False,
                        data=data, headers=request_headers)
            LOG.info(_LI('JSON response contains: %s'), resp.json())
            return resp.json()
        except requests.exceptions.ConnectionError:
            msg = (_('Error connecting to %(url)s') % {'url': url})
            LOG.warning(msg)
        except requests.exceptions.ConnectTimeout:
            msg = (_('Timed out connecting to API request to %(url)s') %
                   {'url': url})
            LOG.warning(msg)
        except requests.exceptions.Timeout:
            msg = (_('Timed out during API request to %(url)s') %
                   {'url': url})
            LOG.warning(msg)
        except requests.exceptions.InvalidURL:
            msg = (_('Ignore attempt to connect to invalid URL %(url)s') %
                   {'url': self._server_ip})
            LOG.warning(msg)
        except ValueError:
            LOG.warning(_LW("Ignoring invalid JSON response: %s"), resp.text)
        except Exception as error:
            msg = unicode(error)
            LOG.warning(msg)
            # reraise the exception
            with excutils.save_and_reraise_exception() as ctxt:
                ctxt.reraise = True

    def _check_if_cvx_leader(self, host):
        url = 'agent/'
        data = self._send_request(host, url, 'GET')
        return False if not data else data.get('isLeader', False)

    def _get_eos_master(self):
        cvx = self._get_cvx_hosts()
        for self._server_ip in cvx:
            if self._check_if_cvx_leader(self._server_ip):
                return self._server_ip
        return None

    def _send_api_request(self, path, method, data=None, sanitized_data=None):
        host = self._get_eos_master()
        if not host:
            msg = unicode("Could not find CVX leader")
            LOG.info(msg)
            self.set_cvx_unavailable()
            raise arista_exc.AristaRpcError(msg=msg)
        self.set_cvx_available()
        return self._send_request(host, path, method, data, sanitized_data)

    def _create_keystone_endpoint(self):
        path = 'region/%s/service-end-point' % self.region
        data = {
            'name': 'keystone',
            'authUrl': self._keystone_url(),
            'user': self.keystone_conf.admin_user or "",
            'password': self.keystone_conf.admin_password or "",
            'tenant': self.keystone_conf.admin_tenant_name or ""
        }
        # Hide the password
        sanitized_data = data.copy()
        sanitized_data['password'] = "*****"
        self._send_api_request(path, 'POST', [data], [sanitized_data])

    def _set_region_update_interval(self):
        path = 'region/%s' % self.region
        data = {
            'name': self.region,
            'syncInterval': self.sync_interval
        }
        self._send_api_request(path, 'PUT', [data])

    def register_with_eos(self, sync=False):
        self.create_region(self.region)
        self._create_keystone_endpoint()
        self._set_region_update_interval()

    def check_supported_features(self):
        # We don't use this function as we know the features
        # that are available once using this API.
        pass

    def bm_and_dvr_supported(self):
        return True

    def get_region_updated_time(self):
        path = 'agent/'
        data = self._send_api_request(path, 'GET')
        return {'regionTimestamp': data['uuid']}

    def create_region(self, region):
        path = 'region/'
        data = {'name': region}
        return self._send_api_request(path, 'POST', [data])

    def delete_region(self, region):
        path = 'region/'
        data = {'name': region}
        return self._send_api_request(path, 'DELETE', [data])

    def delete_this_region(self):
        return self.delete_region(self.region)

    def get_region(self, name):
        path = 'region/'
        regions = self._send_api_request(path, 'GET')
        for region in regions:
            if region['name'] == name:
                return region
        return None

    def sync_supported(self):
        return True

    def hpb_supported(self):
        return True

    def sync_start(self):
        try:
            region = self.get_region(self.region)
            if region and region['syncStatus'] == 'syncInProgress':
                LOG.info('Sync in progress, not syncing')
                return False

            req_id = self._get_random_name()
            data = {
                'requester': socket.gethostname().split('.')[0],
                'requestId': req_id
            }
            path = 'region/' + self.region + '/sync'
            self._send_api_request(path, 'POST', data)
            self.current_sync_name = req_id
            return True
        except (KeyError, arista_exc.AristaRpcError):
            LOG.info('Not syncing due to RPC error')
            return False
        LOG.info('Not syncing due to server syncStatus')
        return False

    def sync_end(self):
        LOG.info('Attempting to end sync')
        try:
            path = 'region/' + self.region + '/sync'
            self._send_api_request(path, 'DELETE')
            self.current_sync_name = None
            return True
        except arista_exc.AristaRpcError:
            LOG.info('Not ending sync due to RPC error')
            return False

    def get_vms_for_tenant(self, tenant):
        path = 'region/' + self.region + '/vm?tenantId=' + tenant
        return self._send_api_request(path, 'GET')

    def get_dhcps_for_tenant(self, tenant):
        path = 'region/' + self.region + '/dhcp?tenantId=' + tenant
        return self._send_api_request(path, 'GET')

    def get_baremetals_for_tenant(self, tenant):
        path = 'region/' + self.region + '/baremetal?tenantId=' + tenant
        return self._send_api_request(path, 'GET')

    def get_routers_for_tenant(self, tenant):
        path = 'region/' + self.region + '/router?tenantId=' + tenant
        return self._send_api_request(path, 'GET')

    def get_ports_for_tenant(self, tenant, pType):
        path = 'region/%s/port?tenantId=%s&type=%s' % (self.region,
                                                       tenant, pType)
        return self._send_api_request(path, 'GET')

    def get_tenants(self):
        path = 'region/' + self.region + '/tenant'
        tenants = self._send_api_request(path, 'GET')
        d = {}
        for ten in tenants:
            ten['tenantId'] = ten.pop('id')

            nets = self.get_networks(ten['tenantId'])
            netDict = {}
            try:
                for net in nets:
                    net['networkId'] = net.pop('id')
                    net['networkName'] = net.pop('name')
                    netDict[net['networkId']] = net
            except Exception as exc:
                LOG.error(_LE('Failed to get tenant network %(net)s. '
                              'Reason: %(exc)s'), {'net': net, 'exc': exc})

            ten['tenantNetworks'] = netDict

            vms = self.get_vms_for_tenant(ten['tenantId'])
            vmDict = dict((v['id'], v) for v in vms)
            ten['tenantVmInstances'] = vmDict

            routers = self.get_routers_for_tenant(ten['tenantId'])
            routerDict = dict((r['id'], r) for r in routers)
            ten['tenantRouterInstances'] = routerDict

            bms = self.get_baremetals_for_tenant(ten['tenantId'])
            bmDict = dict((b['id'], b) for b in bms)
            ten['tenantBaremetalInstances'] = bmDict

            d[ten['tenantId']] = ten
        return d

    def delete_tenant_bulk(self, tenant_list, sync=False):
        path = 'region/' + self.region + '/tenant'
        data = [{'id': t} for t in tenant_list]
        return self._send_api_request(path, 'DELETE', data)

    def get_networks(self, tenant):
        path = 'region/' + self.region + '/network?tenantId=' + tenant
        return self._send_api_request(path, 'GET')

    def create_network_bulk(self, tenant_id, network_list, sync=False):
        self._create_tenant_if_needed(tenant_id)
        networks = []
        segments = []
        for net in network_list:
            n = {
                'id': net['network_id'],
                'tenantId': tenant_id,
                'shared': net['shared'],
            }

            if net.get('network_name'):
                n['name'] = net['network_name']
            if net.get('segmentation_id'):
                n['segId'] = net['segmentation_id']

            for segment in net['segments']:
                if segment['network_type'] == NETWORK_TYPE_FLAT:
                    continue
                segmentType = 'static'
                if segment.get('is_dynamic', False):
                    segmentType = 'dynamic'

                segments.append({
                    'id': segment['id'],
                    'networkId': net['network_id'],
                    'type': segment['network_type'],
                    'segmentationId': segment['segmentation_id'],
                    'segmentType': segmentType,
                })

            networks.append(n)

        if networks:
            path = 'region/' + self.region + '/network'
            self._send_api_request(path, 'POST', networks)

        if segments:
            path = 'region/' + self.region + '/segment'
            self._send_api_request(path, 'POST', segments)

    def create_network_segments(self, tenant_id, network_id,
                                network_name, segments):
        segment_data = []
        for segment in segments:
            segmentType = 'static'
            if segment.get('is_dynamic', False):
                segmentType = 'dynamic'

            segment_data.append({
                'id': segment['id'],
                'networkId': network_id,
                'type': segment['network_type'],
                'segmentationId': segment['segmentation_id'],
                'segmentType': segmentType,
            })

        path = 'region/' + self.region + '/segment'
        self._send_api_request(path, 'POST', segment_data)

    def delete_network_segments(self, tenant_id, segments):
        segment_data = []
        for segment in segments:
            segment_data.append({
                'id': segment['id'],
            })
        path = 'region/' + self.region + '/segment'
        self._send_api_request(path, 'DELETE', segment_data)

    def delete_network_bulk(self, tenant_id, network_id_list, sync=False):
        path = 'region/' + self.region + '/network'
        data = [{'id': n, 'tenantId': tenant_id} for n in network_id_list]
        return self._send_api_request(path, 'DELETE', data)

    def _create_instance_data(self, vm_id, host_id):
        return {
            'id': vm_id,
            'hostId': host_id
        }

    def _create_port_data(self, port_id, tenant_id, network_id, instance_id,
                          name, instance_type, hosts):

        vlan_type = 'allowed'
        if instance_type in InstanceType.BAREMETAL_INSTANCE_TYPES:
            vlan_type = 'native'

        return {
            'id': port_id,
            'tenantId': tenant_id,
            'networkId': network_id,
            'instanceId': instance_id,
            'name': name,
            'instanceType': instance_type,
            'vlanType': vlan_type,
            'hosts': hosts or []
        }

    def _create_tenant_if_needed(self, tenant_id):
        tenResponse = self.get_tenant(tenant_id)
        if tenResponse is None:
            self.create_tenant_bulk([tenant_id])

    def get_tenant(self, tenant_id):
        path = 'region/' + self.region + '/tenant?tenantId=' + tenant_id
        tenants = self._send_api_request(path, 'GET')
        if tenants:
            try:
                return tenants[0]
            except KeyError:
                return None
        return None

    def create_tenant_bulk(self, tenant_ids):
        path = 'region/' + self.region + '/tenant'
        data = [{'id': tid} for tid in tenant_ids]
        return self._send_api_request(path, 'POST', data)

    def create_instance_bulk(self, tenant_id, neutron_ports, vms,
                             bm_port_profiles, sync=False):
        self._create_tenant_if_needed(tenant_id)

        vmInst = {}
        dhcpInst = {}
        baremetalInst = {}
        routerInst = {}
        portInst = []
        networkSegments = {}
        portBindings = {}

        for vm in vms.values():
            for v_port in vm['ports']:
                port_id = v_port['portId']
                if (port_id in neutron_ports and
                    neutron_ports[port_id]['device_owner'].startswith(
                        'baremetal')):
                    vm['baremetal_instance'] = True

            # Filter out all virtual ports, if instance type is baremetal
            index = 0
            for index, v_port in enumerate(vm['ports']):
                port_id = v_port['portId']
                if port_id in neutron_ports:
                    device_owner = neutron_ports[port_id]['device_owner']
                    if(device_owner.startswith('compute') and
                       vm['baremetal_instance']):
                        del vm['ports'][index]

            # Now we are left with the ports that we are interested that
            # require provisioning
            for v_port in vm['ports']:
                port_id = v_port['portId']
                if not v_port['hosts']:
                    # Skip all the ports that have no host associsted with them
                    continue

                if port_id not in neutron_ports.keys():
                    continue
                neutron_port = neutron_ports[port_id]

                inst_id = vm['vmId']
                inst_host = vm['ports'][0]['hosts'][0]
                instance = self._create_instance_data(inst_id, inst_host)

                device_owner = neutron_port['device_owner']
                if device_owner == n_const.DEVICE_OWNER_DHCP:
                    instance_type = InstanceType.DHCP
                    if inst_id not in dhcpInst:
                        dhcpInst[inst_id] = instance
                elif device_owner.startswith('compute'):
                    instance_type = InstanceType.VM
                    if inst_id not in vmInst:
                        vmInst[inst_id] = instance
                elif device_owner.startswith('baremetal'):
                    instance_type = InstanceType.BAREMETAL
                    if inst_id not in baremetalInst:
                        baremetalInst[inst_id] = instance
                elif device_owner == n_const.DEVICE_OWNER_DVR_INTERFACE:
                    instance_type = InstanceType.ROUTER
                    if inst_id not in routerInst:
                        routerInst[inst_id] = instance
                else:
                    LOG.warning(_LW("Unknown device owner: %s"),
                                neutron_port['device_owner'])
                    continue

                network_id = neutron_port['network_id']
                if network_id not in networkSegments:
                    networkSegments[
                        network_id] = self._ndb.get_all_network_segments(
                            network_id)

                port = self._create_port_data(port_id, tenant_id,
                                              network_id, inst_id,
                                              neutron_port.get('name'),
                                              instance_type, v_port['hosts'])
                portInst.append(port)

                if instance_type in InstanceType.VIRTUAL_INSTANCE_TYPES:
                    portBinding = self._get_host_bindings(
                        port_id, inst_host, network_id,
                        networkSegments[network_id])
                elif instance_type in InstanceType.BAREMETAL_INSTANCE_TYPES:
                    switch_profile = json.loads(bm_port_profiles[
                                                port_id]['profile'])
                    portBinding = self._get_switch_bindings(
                        port_id, inst_host, network_id,
                        switch_profile['local_link_information'],
                        networkSegments[network_id])
                if port_id not in portBindings:
                    portBindings[port_id] = portBinding
                else:
                    portBindings[port_id] += portBinding

        # create instances first
        if vmInst:
            path = 'region/' + self.region + '/vm?tenantId=' + tenant_id
            self._send_api_request(path, 'POST', vmInst.values())
        if dhcpInst:
            path = 'region/' + self.region + '/dhcp?tenantId=' + tenant_id
            self._send_api_request(path, 'POST', dhcpInst.values())
        if baremetalInst:
            path = 'region/' + self.region + '/baremetal?tenantId=' + tenant_id
            self._send_api_request(path, 'POST', baremetalInst.values())
        if routerInst:
            path = 'region/' + self.region + '/router?tenantId=' + tenant_id
            self._send_api_request(path, 'POST', routerInst.values())

        # now create ports for the instances
        path = 'region/' + self.region + '/port'
        self._send_api_request(path, 'POST', portInst)

        # TODO(shashank): Optimize this
        for port_id, bindings in portBindings.items():
            url = 'region/' + self.region + '/port/' + port_id + '/binding'
            self._send_api_request(url, 'POST', bindings)

    def delete_instance_bulk(self, tenant_id, instance_id_list, instance_type,
                             sync=False):
        path = 'region/%(region)s/%(type)s' % {
               'region': self.region,
               'type': instance_type}

        data = [{'id': i} for i in instance_id_list]
        return self._send_api_request(path, 'DELETE', data)

    def delete_vm_bulk(self, tenant_id, vm_id_list, sync=False):
        self.delete_instance_bulk(tenant_id, vm_id_list, InstanceType.VM)

    def delete_dhcp_bulk(self, tenant_id, dhcp_id_list):
        self.delete_instance_bulk(tenant_id, dhcp_id_list, InstanceType.DHCP)

    def delete_port(self, port_id, instance_id, instance_type):
        path = ('region/%s/port?portId=%s&id=%s&type=%s' %
                (self.region, port_id, instance_id, instance_type))
        port = self._create_port_data(port_id, None, None, instance_id,
                                      None, instance_type, None)
        return self._send_api_request(path, 'DELETE', [port])

    def get_instance_ports(self, instance_id, instance_type):
        path = ('region/%s/port?id=%s&type=%s' %
                (self.region, instance_id, instance_type))
        return self._send_api_request(path, 'GET')

    def plug_port_into_network(self, device_id, host_id, port_id,
                               net_id, tenant_id, port_name, device_owner,
                               sg, orig_sg, vnic_type, segments,
                               switch_bindings=None):
        device_type = ''
        if device_owner == n_const.DEVICE_OWNER_DHCP:
            device_type = InstanceType.DHCP
        elif device_owner.startswith('compute'):
            device_type = InstanceType.VM
        elif device_owner.startswith('baremetal'):
            device_type = InstanceType.BAREMETAL
        elif device_owner == n_const.DEVICE_OWNER_DVR_INTERFACE:
            device_type = InstanceType.ROUTER
        else:
            LOG.info(_LI('Unsupported device owner: %s'), device_owner)
            return

        self._create_tenant_if_needed(tenant_id)
        instance = self._create_instance_data(device_id, host_id)
        port = self._create_port_data(port_id, tenant_id, net_id, device_id,
                                      port_name, device_type, [host_id])
        url = 'region/%(region)s/%(device_type)s?tenantId=%(tenant_id)s' % {
              'region': self.region,
              'device_type': device_type,
              'tenant_id': tenant_id,
        }
        self._send_api_request(url, 'POST', [instance])
        self._send_api_request('region/' + self.region + '/port', 'POST',
                               [port])
        if device_type in InstanceType.VIRTUAL_INSTANCE_TYPES:
            self.bind_port_to_host(port_id, host_id, net_id, segments)
        elif device_type in InstanceType.BAREMETAL_INSTANCE_TYPES:
            self.bind_port_to_switch_interface(port_id, host_id, net_id,
                                               switch_bindings, segments)
            if sg:
                self.apply_security_group(sg, switch_bindings)
            else:
                # Security group was removed. Clean up the existing security
                # groups.
                if orig_sg:
                    self.remove_security_group(orig_sg, switch_bindings)

    def unplug_port_from_network(self, device_id, device_owner, hostname,
                                 port_id, network_id, tenant_id, sg, vnic_type,
                                 switch_bindings=None):
        device_type = ''
        if device_owner == n_const.DEVICE_OWNER_DHCP:
            device_type = InstanceType.DHCP
        elif device_owner.startswith('compute'):
            device_type = InstanceType.VM
        elif device_owner.startswith('baremetal'):
            device_type = InstanceType.BAREMETAL
        elif device_owner == n_const.DEVICE_OWNER_DVR_INTERFACE:
            device_type = InstanceType.ROUTER
        else:
            LOG.info(_LI('Unsupported device owner: %s'), device_owner)
            return

        if device_type in InstanceType.VIRTUAL_INSTANCE_TYPES:
            self.unbind_port_from_host(port_id, hostname)
        elif device_type in InstanceType.BAREMETAL_INSTANCE_TYPES:
            self.unbind_port_from_switch_interface(port_id, hostname,
                                                   switch_bindings)
        self.delete_port(port_id, device_id, device_type)
        port = self.get_instance_ports(device_id, device_type)
        if not port:
            # If the last port attached to an instance is deleted, cleanup the
            # instance.
            instances = [device_id]
            self.delete_instance_bulk(tenant_id, instances, device_type)

    def _get_segment_list(self, network_id, segments):
        if not network_id or not segments:
            return []

        return [{'id': s['id'],
                 'type': s['network_type'],
                 'segmentationId': s['segmentation_id'],
                 'networkId': network_id,
                 'segment_type': 'dynamic' if s.get('is_dynamic', False) else
                                 'static',
                 } for s in segments]

    def _get_host_bindings(self, port_id, host, network_id, segments):
        return [{'portId': port_id,
                'hostBinding': [{
                    'host': host,
                    'segment': self._get_segment_list(network_id,
                                                      segments),
                }]
            }]

    def bind_port_to_host(self, port_id, host, network_id, segments):

        url = 'region/' + self.region + '/port/' + port_id + '/binding'
        bindings = self._get_host_bindings(port_id, host, network_id,
                                           segments)
        self._send_api_request(url, 'POST', bindings)

    def unbind_port_from_host(self, port_id, host):
        url = 'region/' + self.region + '/port/' + port_id + '/binding'
        binding = {'portId': port_id,
                   'hostBinding': [{
                       'host': host,
                   }]}
        self._send_api_request(url, 'DELETE', [binding])

    def _get_switch_bindings(self, port_id, host, network_id,
                             switch_bindings, segments):
        bindings = []
        for binding in switch_bindings:
            if not binding:
                continue

            switch = binding['switch_id']
            interface = binding['port_id']

            bindings.append({'portId': port_id,
                             'switchBinding': [{
                                 'host': host,
                                 'switch': switch,
                                 'interface': interface,
                                 'segment': self._get_segment_list(
                                     network_id, segments),
                             }]})
        return bindings

    def bind_port_to_switch_interface(self, port_id, host, network_id,
                                      switch_bindings, segments):

        if not switch_bindings:
            return

        url = 'region/' + self.region + '/port/' + port_id + '/binding'
        bindings = self._get_switch_bindings(port_id, host, network_id,
                                             switch_bindings, segments)
        self._send_api_request(url, 'POST', bindings)

    def unbind_port_from_switch_interface(self, port_id, host,
                                          switch_bindings):
        url = 'region/' + self.region + '/port/' + port_id + '/binding'
        bindings = self._get_switch_bindings(port_id, host, None,
                                             switch_bindings, None)
        self._send_api_request(url, 'DELETE', bindings)


class AristaRPCWrapperEapi(AristaRPCWrapperBase):
    def __init__(self, ndb):
        super(AristaRPCWrapperEapi, self).__init__(ndb)
        # The cli_commands dict stores the mapping between the CLI command key
        # and the actual CLI command.
        self.cli_commands = {
            'timestamp': [
                'show openstack config region %s timestamp' % self.region],
            CMD_REGION_SYNC: 'region %s sync' % self.region,
            CMD_INSTANCE: None,
            CMD_SYNC_HEARTBEAT: 'sync heartbeat',
            'resource-pool': [],
            'features': {},
        }

    def _send_eapi_req(self, cmds, commands_to_log=None):
        # This method handles all EAPI requests (using the requests library)
        # and returns either None or response.json()['result'] from the EAPI
        # request.
        #
        # Exceptions related to failures in connecting/ timeouts are caught
        # here and logged. Other unexpected exceptions are logged and raised

        request_headers = {}
        request_headers['Content-Type'] = 'application/json'
        request_headers['Accept'] = 'application/json'
        url = self._api_host_url(host=self._server_ip)

        params = {}
        params['timestamps'] = "false"
        params['format'] = "json"
        params['version'] = 1
        params['cmds'] = cmds

        data = {}
        data['id'] = "Arista ML2 driver"
        data['method'] = "runCmds"
        data['jsonrpc'] = "2.0"
        data['params'] = params

        response = None

        try:
            # NOTE(pbourke): shallow copy data and params to remove sensitive
            # information before logging
            log_data = dict(data)
            log_data['params'] = dict(params)
            log_data['params']['cmds'] = commands_to_log or cmds
            msg = (_('EAPI request to %(ip)s contains %(cmd)s') %
                   {'ip': self._server_ip, 'cmd': json.dumps(log_data)})
            LOG.info(msg)
            response = requests.post(url, timeout=self.conn_timeout,
                                     verify=False, data=json.dumps(data))
            LOG.info(_LI('EAPI response contains: %s'), response.json())
            try:
                return response.json()['result']
            except KeyError:
                if response.json()['error']['code'] == 1002:
                    for data in response.json()['error']['data']:
                        if type(data) == dict and 'errors' in data:
                            if ERR_CVX_NOT_LEADER in data['errors'][0]:
                                msg = unicode("%s is not the master" % (
                                              self._server_ip))
                                LOG.info(msg)
                                return None

                msg = "Unexpected EAPI error"
                LOG.info(msg)
                raise arista_exc.AristaRpcError(msg=msg)
        except requests.exceptions.ConnectionError:
            msg = (_('Error while trying to connect to %(ip)s') %
                   {'ip': self._server_ip})
            LOG.warning(msg)
            return None
        except requests.exceptions.ConnectTimeout:
            msg = (_('Timed out while trying to connect to %(ip)s') %
                   {'ip': self._server_ip})
            LOG.warning(msg)
            return None
        except requests.exceptions.Timeout:
            msg = (_('Timed out during an EAPI request to %(ip)s') %
                   {'ip': self._server_ip})
            LOG.warning(msg)
            return None
        except requests.exceptions.InvalidURL:
            msg = (_('Ignore attempt to connect to invalid URL %(ip)s') %
                   {'ip': self._server_ip})
            LOG.warning(msg)
            return None
        except ValueError:
            LOG.info("Ignoring invalid JSON response")
            return None
        except Exception as error:
            msg = unicode(error)
            LOG.warning(msg)
            raise

    def check_supported_features(self):
        cmd = ['show openstack instances']
        try:
            self._run_eos_cmds(cmd)
            self.cli_commands[CMD_INSTANCE] = 'instance'
        except (arista_exc.AristaRpcError, Exception) as err:
            self.cli_commands[CMD_INSTANCE] = None
            LOG.warning(_LW("'instance' command is not available on EOS "
                            "because of %s"), err)

        # Get list of supported openstack features by CVX
        cmd = ['show openstack features']
        try:
            resp = self._run_eos_cmds(cmd)
            self.cli_commands['features'] = resp[0].get('features', {})
        except (Exception, arista_exc.AristaRpcError):
            self.cli_commands['features'] = {}

    def check_vlan_type_driver_commands(self):
        """Checks the validity of CLI commands for Arista's VLAN type driver.

           This method tries to execute the commands used exclusively by the
           arista_vlan type driver and stores the commands if they succeed.
        """
        cmd = ['show openstack resource-pool vlan region %s uuid'
               % self.region]
        try:
            self._run_eos_cmds(cmd)
            self.cli_commands['resource-pool'] = cmd
        except arista_exc.AristaRpcError:
            self.cli_commands['resource-pool'] = []
            LOG.warning(
                _LW("'resource-pool' command '%s' is not available on EOS"),
                cmd)

    def _heartbeat_required(self, sync, counter=0):
        return (sync and self.cli_commands[CMD_SYNC_HEARTBEAT] and
                (counter % HEARTBEAT_INTERVAL) == 0)

    def get_vlan_assignment_uuid(self):
        """Returns the UUID for the region's vlan assignment on CVX

        :returns: string containing the region's vlan assignment UUID
        """
        vlan_uuid_cmd = self.cli_commands['resource-pool']
        if vlan_uuid_cmd:
            return self._run_eos_cmds(commands=vlan_uuid_cmd)[0]
        return None

    def get_vlan_allocation(self):
        """Returns the status of the region's VLAN pool in CVX

        :returns: dictionary containg the assigned, allocated and available
                  VLANs for the region
        """
        if not self.cli_commands['resource-pool']:
            LOG.warning(_('The version of CVX you are using does not support'
                          'arista VLAN type driver.'))
            return None
        cmd = ['show openstack resource-pools region %s' % self.region]
        command_output = self._run_eos_cmds(cmd)
        if command_output:
            phys_nets = command_output[0]['physicalNetwork']
            if self.region in phys_nets.keys():
                return phys_nets[self.region]['vlanPool']['default']
        return None

    def get_tenants(self):
        cmds = ['show openstack config region %s' % self.region]
        command_output = self._run_eos_cmds(cmds)
        tenants = command_output[0]['tenants']

        return tenants

    def bm_and_dvr_supported(self):
        return (self.cli_commands[CMD_INSTANCE] == 'instance')

    def _baremetal_support_check(self, vnic_type):
        # Basic error checking for baremental deployments
        if (vnic_type == portbindings.VNIC_BAREMETAL and
           not self.bm_and_dvr_supported()):
            msg = _("Baremetal instances are not supported in this"
                    " release of EOS")
            LOG.error(msg)
            raise arista_exc.AristaConfigError(msg=msg)

    def plug_port_into_network(self, device_id, host_id, port_id,
                               net_id, tenant_id, port_name, device_owner,
                               sg, orig_sg, vnic_type, segments,
                               switch_bindings=None):
        if device_owner == n_const.DEVICE_OWNER_DHCP:
            self.plug_dhcp_port_into_network(device_id,
                                             host_id,
                                             port_id,
                                             net_id,
                                             tenant_id,
                                             segments,
                                             port_name)
        elif device_owner.startswith('compute'):
            self.plug_host_into_network(device_id,
                                        host_id,
                                        port_id,
                                        net_id,
                                        tenant_id,
                                        segments,
                                        port_name)
        elif device_owner.startswith('baremetal'):
            self.plug_baremetal_into_network(device_id,
                                             host_id,
                                             port_id,
                                             net_id,
                                             tenant_id,
                                             segments,
                                             port_name,
                                             sg, orig_sg,
                                             vnic_type,
                                             switch_bindings)
        elif device_owner == n_const.DEVICE_OWNER_DVR_INTERFACE:
            self.plug_distributed_router_port_into_network(device_id,
                                                           host_id,
                                                           port_id,
                                                           net_id,
                                                           tenant_id,
                                                           segments)

    def unplug_port_from_network(self, device_id, device_owner, hostname,
                                 port_id, network_id, tenant_id, sg, vnic_type,
                                 switch_bindings=None):
        if device_owner == n_const.DEVICE_OWNER_DHCP:
            self.unplug_dhcp_port_from_network(device_id,
                                               hostname,
                                               port_id,
                                               network_id,
                                               tenant_id)
        elif device_owner.startswith('compute'):
            self.unplug_host_from_network(device_id,
                                          hostname,
                                          port_id,
                                          network_id,
                                          tenant_id)
        elif device_owner.startswith('baremetal'):
            self.unplug_baremetal_from_network(device_id,
                                               hostname,
                                               port_id,
                                               network_id,
                                               tenant_id,
                                               sg,
                                               vnic_type,
                                               switch_bindings)
        elif device_owner == n_const.DEVICE_OWNER_DVR_INTERFACE:
            self.unplug_distributed_router_port_from_network(device_id,
                                                             port_id,
                                                             hostname,
                                                             tenant_id)

    def plug_host_into_network(self, vm_id, host, port_id,
                               network_id, tenant_id, segments, port_name):
        cmds = ['tenant %s' % tenant_id,
                'vm id %s hostid %s' % (vm_id, host)]
        if port_name:
            cmds.append('port id %s name "%s" network-id %s' %
                        (port_id, port_name, network_id))
        else:
            cmds.append('port id %s network-id %s' %
                        (port_id, network_id))
        cmds.extend(
            'segment level %d id %s' % (level, segment['id'])
            for level, segment in enumerate(segments))
        self._run_openstack_cmds(cmds)

    def plug_baremetal_into_network(self, vm_id, host, port_id,
                                    network_id, tenant_id, segments, port_name,
                                    sg=None, orig_sg=None,
                                    vnic_type=None, switch_bindings=None):
        # Basic error checking for baremental deployments
        # notice that the following method throws and exception
        # if an error condition exists
        self._baremetal_support_check(vnic_type)

        # For baremetal, add host to the topology
        if switch_bindings and vnic_type == portbindings.VNIC_BAREMETAL:
            cmds = ['tenant %s' % tenant_id]
            cmds.append('instance id %s hostid %s type baremetal' %
                        (vm_id, host))
            # This list keeps track of any ACLs that need to be rolled back
            # in case we hit a failure trying to apply ACLs, and we end
            # failing the transaction.
            for binding in switch_bindings:
                if not binding:
                    # skip all empty entries
                    continue
                # Ensure that binding contains switch and port ID info
                if binding['switch_id'] and binding['port_id']:
                    if port_name:
                        cmds.append('port id %s name "%s" network-id %s '
                                    'type native switch-id %s switchport %s' %
                                    (port_id, port_name, network_id,
                                     binding['switch_id'], binding['port_id']))
                    else:
                        cmds.append('port id %s network-id %s type native '
                                    'switch-id %s switchport %s' %
                                    (port_id, network_id, binding['switch_id'],
                                        binding['port_id']))
                    cmds.extend('segment level %d id %s' % (level,
                                segment['id'])
                                for level, segment in enumerate(segments))
                else:
                    msg = _('switch and port ID not specified for baremetal')
                    LOG.error(msg)
                    raise arista_exc.AristaConfigError(msg=msg)
            cmds.append('exit')
            self._run_openstack_cmds(cmds)

            if sg:
                self.apply_security_group(sg, switch_bindings)
            else:
                # Security group was removed. Clean up the existing security
                # groups.
                if orig_sg:
                    self.remove_security_group(orig_sg, switch_bindings)

    def plug_dhcp_port_into_network(self, dhcp_id, host, port_id,
                                    network_id, tenant_id, segments,
                                    port_name):
        cmds = ['tenant %s' % tenant_id,
                'network id %s' % network_id]
        if port_name:
            cmds.append('dhcp id %s hostid %s port-id %s name "%s"' %
                        (dhcp_id, host, port_id, port_name))
        else:
            cmds.append('dhcp id %s hostid %s port-id %s' %
                        (dhcp_id, host, port_id))
        cmds.extend('segment level %d id %s' % (level, segment['id'])
                    for level, segment in enumerate(segments))
        self._run_openstack_cmds(cmds)

    def plug_distributed_router_port_into_network(self, router_id, host,
                                                  port_id, net_id, tenant_id,
                                                  segments):
        if not self.bm_and_dvr_supported():
            LOG.info(ERR_DVR_NOT_SUPPORTED)
            return

        cmds = ['tenant %s' % tenant_id,
                'instance id %s type router' % router_id,
                'port id %s network-id %s hostid %s' % (port_id, net_id, host)]
        cmds.extend('segment level %d id %s' % (level, segment['id'])
                    for level, segment in enumerate(segments))
        self._run_openstack_cmds(cmds)

    def unplug_host_from_network(self, vm_id, host, port_id,
                                 network_id, tenant_id):
        cmds = ['tenant %s' % tenant_id,
                'vm id %s hostid %s' % (vm_id, host),
                'no port id %s' % port_id,
                ]
        self._run_openstack_cmds(cmds)

    def unplug_baremetal_from_network(self, vm_id, host, port_id,
                                      network_id, tenant_id, sg, vnic_type,
                                      switch_bindings=None):
        # Basic error checking for baremental deployments
        # notice that the following method throws and exception
        # if an error condition exists
        self._baremetal_support_check(vnic_type)

        # Following is a temporary code for native VLANs - should be removed
        cmds = ['tenant %s' % tenant_id]
        cmds.append('instance id %s hostid %s type baremetal' % (vm_id, host))
        cmds.append('no port id %s' % port_id)
        self._run_openstack_cmds(cmds)

        # SG -  Remove security group rules from the port
        # after deleting the instance
        for binding in switch_bindings:
            if not binding:
                continue
            self.security_group_driver.remove_acl(sg, binding['switch_id'],
                                                  binding['port_id'],
                                                  binding['switch_info'])

    def unplug_dhcp_port_from_network(self, dhcp_id, host, port_id,
                                      network_id, tenant_id):
        cmds = ['tenant %s' % tenant_id,
                'network id %s' % network_id,
                'no dhcp id %s port-id %s' % (dhcp_id, port_id),
                ]
        self._run_openstack_cmds(cmds)

    def unplug_distributed_router_port_from_network(self, router_id,
                                                    port_id, host, tenant_id):
        if not self.bm_and_dvr_supported():
            LOG.info(ERR_DVR_NOT_SUPPORTED)
            return

        # When the last router port is removed, the router is deleted from EOS.
        cmds = ['tenant %s' % tenant_id,
                'instance id %s type router' % router_id,
                'no port id %s hostid %s' % (port_id, host)]
        self._run_openstack_cmds(cmds)

    def create_network_bulk(self, tenant_id, network_list, sync=False):
        cmds = ['tenant %s' % tenant_id]
        # Create a reference to function to avoid name lookups in the loop
        append_cmd = cmds.append
        for counter, network in enumerate(network_list, 1):
            try:
                append_cmd('network id %s name "%s"' %
                           (network['network_id'], network['network_name']))
            except KeyError:
                append_cmd('network id %s' % network['network_id'])

            cmds.extend(
                'segment %s type %s id %d %s' % (
                    seg['id'] if self.hpb_supported() else 1,
                    seg['network_type'], seg['segmentation_id'],
                    ('dynamic' if seg.get('is_dynamic', False) else 'static'
                     if self.hpb_supported() else ''))
                for seg in network['segments']
                if seg['network_type'] != NETWORK_TYPE_FLAT
            )
            shared_cmd = 'shared' if network['shared'] else 'no shared'
            append_cmd(shared_cmd)
            if self._heartbeat_required(sync, counter):
                append_cmd(self.cli_commands[CMD_SYNC_HEARTBEAT])

        if self._heartbeat_required(sync):
            append_cmd(self.cli_commands[CMD_SYNC_HEARTBEAT])

        self._run_openstack_cmds(cmds, sync=sync)

    def create_network_segments(self, tenant_id, network_id,
                                network_name, segments):
        if segments:
            cmds = ['tenant %s' % tenant_id,
                    'network id %s name "%s"' % (network_id, network_name)]
            cmds.extend(
                'segment %s type %s id %d %s' % (
                    seg['id'], seg['network_type'], seg['segmentation_id'],
                    ('dynamic' if seg.get('is_dynamic', False) else 'static'
                     if self.hpb_supported() else ''))
                for seg in segments)
            self._run_openstack_cmds(cmds)

    def delete_network_segments(self, tenant_id, segments):
        cmds = ['tenant %s' % tenant_id]
        for segment in segments:
            cmds.append('network id %s' % segment['network_id'])
            cmds.append('no segment %s' % segment['id'])

        self._run_openstack_cmds(cmds)

    def delete_network_bulk(self, tenant_id, network_id_list, sync=False):
        cmds = ['tenant %s' % tenant_id]
        for counter, network_id in enumerate(network_id_list, 1):
            cmds.append('no network id %s' % network_id)
            if self._heartbeat_required(sync, counter):
                cmds.append(self.cli_commands[CMD_SYNC_HEARTBEAT])

        if self._heartbeat_required(sync):
            cmds.append(self.cli_commands[CMD_SYNC_HEARTBEAT])
        self._run_openstack_cmds(cmds, sync=sync)

    def delete_vm_bulk(self, tenant_id, vm_id_list, sync=False):
        cmds = ['tenant %s' % tenant_id]
        counter = 0
        for vm_id in vm_id_list:
            counter += 1
            cmds.append('no vm id %s' % vm_id)
            if self._heartbeat_required(sync, counter):
                cmds.append(self.cli_commands[CMD_SYNC_HEARTBEAT])

        if self._heartbeat_required(sync):
            cmds.append(self.cli_commands[CMD_SYNC_HEARTBEAT])
        self._run_openstack_cmds(cmds, sync=sync)

    def delete_instance_bulk(self, tenant_id, instance_id_list, instance_type,
                             sync=False):
        cmds = ['tenant %s' % tenant_id]
        counter = 0
        for instance in instance_id_list:
            counter += 1
            cmds.append('no instance id %s' % instance)
            if self._heartbeat_required(sync, counter):
                cmds.append(self.cli_commands[CMD_SYNC_HEARTBEAT])

        if self._heartbeat_required(sync):
            cmds.append(self.cli_commands[CMD_SYNC_HEARTBEAT])
        self._run_openstack_cmds(cmds, sync=sync)

    def create_instance_bulk(self, tenant_id, neutron_ports, vms,
                             bm_port_profiles, sync=False):
        cmds = ['tenant %s' % tenant_id]
        # Create a reference to function to avoid name lookups in the loop
        append_cmd = cmds.append
        counter = 0
        for vm in vms.values():
            counter += 1

            # Mark an instance as baremetal if any of the ports is baremetal
            for v_port in vm['ports']:
                port_id = v_port['portId']
                if (port_id in neutron_ports and
                    neutron_ports[port_id]['device_owner'].startswith(
                        'baremetal')):
                    vm['baremetal_instance'] = True

            # Filter out all virtual ports, if instance type is baremetal
            index = 0
            for v_port in vm['ports']:
                port_id = v_port['portId']
                if port_id in neutron_ports:
                    device_owner = neutron_ports[port_id]['device_owner']
                    if(device_owner.startswith('compute') and
                       vm['baremetal_instance']):
                        del vm['ports'][index]
                index += 1

            # Now we are left with the ports that we are interested that
            # require provisioning
            for v_port in vm['ports']:
                port_id = v_port['portId']
                if not v_port['hosts']:
                    # Skip all the ports that have no host associsted with them
                    continue

                if port_id not in neutron_ports.keys():
                    continue
                neutron_port = neutron_ports[port_id]

                port_name = ''
                if 'name' in neutron_port:
                    port_name = 'name "%s"' % neutron_port['name']

                device_owner = neutron_port['device_owner']
                network_id = neutron_port['network_id']
                segments = []
                if self.hpb_supported():
                    segments = self._ndb.get_all_network_segments(network_id)
                if device_owner == n_const.DEVICE_OWNER_DHCP:
                    append_cmd('network id %s' % neutron_port['network_id'])
                    append_cmd('dhcp id %s hostid %s port-id %s %s' %
                               (vm['vmId'], v_port['hosts'][0],
                                neutron_port['id'], port_name))
                    cmds.extend(
                        'segment level %d id %s' % (level, segment['id'])
                        for level, segment in enumerate(segments))
                elif device_owner.startswith('baremetal'):
                    append_cmd('instance id %s hostid %s type baremetal' %
                               (vm['vmId'], v_port['hosts'][0]))
                    profile = bm_port_profiles[neutron_port['id']]
                    profile = json.loads(profile['profile'])
                    for binding in profile['local_link_information']:
                        if not binding or not isinstance(binding, dict):
                            # skip all empty entries
                            continue
                        # Ensure that profile contains switch and port ID info
                        if binding['switch_id'] and binding['port_id']:
                            if port_name:
                                cmds.append('port id %s name "%s" '
                                            'network-id %s type native '
                                            'switch-id %s switchport %s' %
                                            (port_id, port_name, network_id,
                                             binding['switch_id'],
                                             binding['port_id']))
                            else:
                                cmds.append('port id %s network-id %s '
                                            'type native '
                                            'switch-id %s switchport %s' %
                                            (port_id, network_id,
                                             binding['switch_id'],
                                             binding['port_id']))
                            cmds.extend('segment level %d id %s' % (
                                level, segment['id'])
                                for level, segment in enumerate(segments))

                elif device_owner.startswith('compute'):
                    append_cmd('vm id %s hostid %s' % (vm['vmId'],
                                                       v_port['hosts'][0]))
                    append_cmd('port id %s %s network-id %s' %
                               (neutron_port['id'], port_name,
                                neutron_port['network_id']))
                    cmds.extend('segment level %d id %s' % (level,
                                segment['id'])
                                for level, segment in enumerate(segments))
                elif device_owner == n_const.DEVICE_OWNER_DVR_INTERFACE:
                    if not self.bm_and_dvr_supported():
                        LOG.info(ERR_DVR_NOT_SUPPORTED)
                        continue
                    append_cmd('instance id %s type router' % (
                               neutron_port['device_id']))
                    for host in v_port['hosts']:
                        append_cmd('port id %s network-id %s hostid %s' % (
                                   neutron_port['id'],
                                   neutron_port['network_id'], host))
                        cmds.extend('segment level %d id %s' % (level,
                                    segment['id'])
                                    for level, segment in enumerate(segments))
                else:
                    LOG.warning(_LW("Unknown device owner: %s"),
                                neutron_port['device_owner'])

                if self._heartbeat_required(sync, counter):
                    append_cmd(self.cli_commands[CMD_SYNC_HEARTBEAT])

        if self._heartbeat_required(sync):
            append_cmd(self.cli_commands[CMD_SYNC_HEARTBEAT])

        self._run_openstack_cmds(cmds, sync=sync)

    def delete_tenant_bulk(self, tenant_list, sync=False):
        cmds = []
        for tenant in tenant_list:
            cmds.append('no tenant %s' % tenant)
        if self._heartbeat_required(sync):
            cmds.append(self.cli_commands[CMD_SYNC_HEARTBEAT])
        self._run_openstack_cmds(cmds, sync=sync)

    def delete_this_region(self):
        cmds = ['enable',
                'configure',
                'cvx',
                'service openstack',
                'no region %s' % self.region,
                ]
        self._run_eos_cmds(cmds)

    def register_with_eos(self, sync=False):
        cmds = ['auth url %s user %s password %s tenant %s' % (
                self._keystone_url(),
                self.keystone_conf.admin_user,
                self.keystone_conf.admin_password,
                self.keystone_conf.admin_tenant_name)]

        log_cmds = ['auth url %s user %s password %s tenant %s' % (
                    self._keystone_url(),
                    self.keystone_conf.admin_user,
                    '******',
                    self.keystone_conf.admin_tenant_name)]

        sync_interval_cmd = 'sync interval %d' % self.sync_interval
        cmds.append(sync_interval_cmd)
        log_cmds.append(sync_interval_cmd)

        self._run_openstack_cmds(cmds, commands_to_log=log_cmds, sync=sync)

    def get_region_updated_time(self):
        timestamp_cmd = self.cli_commands['timestamp']
        if timestamp_cmd:
            try:
                return self._run_eos_cmds(commands=timestamp_cmd)[0]
            except IndexError:
                # EAPI request failed and so return none
                msg = "Failed to get last sync timestamp; trigger full sync"
                LOG.info(msg)
                return None

    def _check_sync_lock(self, client):
        """Check if the lock is owned by this client.

        :param client: Returns true only if the lock owner matches the expected
                       client.
        """
        cmds = ['show sync lock']
        ret = self._run_openstack_cmds(cmds, sync=True)
        for r in ret:
            if 'owner' in r:
                lock_owner = r['owner']
                LOG.info(_LI('Lock requested by: %s'), client)
                LOG.info(_LI('Lock owner: %s'), lock_owner)
                return lock_owner == client
        return False

    def sync_supported(self):
        return self.cli_commands[CMD_REGION_SYNC]

    def hpb_supported(self):
        return 'hierarchical-port-binding' in self.cli_commands['features']

    def sync_start(self):
        try:
            cmds = []
            if self.sync_supported():
                # Locking the region during sync is supported.
                client_id = socket.gethostname().split('.')[0]
                request_id = self._get_random_name()
                cmds = ['sync lock %s %s' % (client_id, request_id)]
                self._run_openstack_cmds(cmds)
                # Check whether the lock was acquired.
                return self._check_sync_lock(client_id)
            else:
                cmds = ['sync start']
                self._run_openstack_cmds(cmds)
            return True
        except arista_exc.AristaRpcError:
            return False

    def sync_end(self):
        try:
            # 'sync end' can be sent only when the region has been entered in
            # the sync mode
            self._run_openstack_cmds(['sync end'], sync=True)
            return True
        except arista_exc.AristaRpcError:
            return False

    def _run_eos_cmds(self, commands, commands_to_log=None):
        """Execute/sends a CAPI (Command API) command to EOS.

        In this method, list of commands is appended with prefix and
        postfix commands - to make is understandble by EOS.

        :param commands : List of command to be executed on EOS.
        :param commands_to_log : This should be set to the command that is
                                 logged. If it is None, then the commands
                                 param is logged.
        """

        # Always figure out who is master (starting with the last known val)
        try:
            if self._get_eos_master() is None:
                msg = "Failed to identify CVX master"
                self.set_cvx_unavailable()
                raise arista_exc.AristaRpcError(msg=msg)
        except Exception:
            self.set_cvx_unavailable()
            raise

        self.set_cvx_available()
        log_cmds = commands
        if commands_to_log:
            log_cmds = commands_to_log

        LOG.info(_LI('Executing command on Arista EOS: %s'), log_cmds)
        # this returns array of return values for every command in
        # full_command list
        try:
            response = self._send_eapi_req(cmds=commands,
                                           commands_to_log=log_cmds)
            if response is None:
                # Reset the server as we failed communicating with it
                self._server_ip = None
                self.set_cvx_unavailable()
                msg = "Failed to communicate with CVX master"
                raise arista_exc.AristaRpcError(msg=msg)
            return response
        except arista_exc.AristaRpcError:
            raise

    def _build_command(self, cmds, sync=False):
        """Build full EOS's openstack CLI command.

        Helper method to add commands to enter and exit from openstack
        CLI modes.

        :param cmds: The openstack CLI commands that need to be executed
                     in the openstack config mode.
        :param sync: This flags indicates that the region is being synced.
        """

        region_cmd = 'region %s' % self.region
        if sync and self.sync_supported():
            region_cmd = self.cli_commands[CMD_REGION_SYNC]

        full_command = [
            'enable',
            'configure',
            'cvx',
            'service openstack',
            region_cmd,
        ]
        full_command.extend(cmds)
        return full_command

    def _run_openstack_cmds(self, commands, commands_to_log=None, sync=False):
        """Execute/sends a CAPI (Command API) command to EOS.

        In this method, list of commands is appended with prefix and
        postfix commands - to make is understandble by EOS.

        :param commands : List of command to be executed on EOS.
        :param commands_to_logs : This should be set to the command that is
                                  logged. If it is None, then the commands
                                  param is logged.
        :param sync: This flags indicates that the region is being synced.
        """

        full_command = self._build_command(commands, sync=sync)
        if commands_to_log:
            full_log_command = self._build_command(commands_to_log, sync=sync)
        else:
            full_log_command = None
        return self._run_eos_cmds(full_command, full_log_command)

    def _get_eos_master(self):
        # Use guarded command to figure out if this is the master
        cmd = ['show openstack agent uuid']

        cvx = self._get_cvx_hosts()
        # Identify which EOS instance is currently the master
        for self._server_ip in cvx:
            try:
                response = self._send_eapi_req(cmds=cmd, commands_to_log=cmd)
                if response is not None:
                    return self._server_ip
                else:
                    continue  # Try another EOS instance
            except Exception:
                raise

        # Couldn't find an instance that is the leader and returning none
        self._server_ip = None
        msg = "Failed to reach the CVX master"
        LOG.error(msg)
        return None

    def _api_host_url(self, host=""):
        return ('https://%s:%s@%s/command-api' %
                (self._api_username(),
                 self._api_password(),
                 host))

    def get_physical_network(self, host_id):
        """Returns dirctionary which contains physical topology information

        for a given host_id
        """
        fqdns_used = cfg.CONF.ml2_arista['use_fqdn']
        hostname = None
        physnet = None
        switch_id = None
        mac_to_hostname = {}
        cmds = ['show network physical-topology neighbors',
                'show network physical-topology hosts']
        try:
            response = self._run_eos_cmds(cmds)
            # Get response for 'show network physical-topology neighbors'
            # command
            neighbors = response[0]['neighbors']
            for neighbor in neighbors:
                if host_id in neighbor:
                    hostname = neighbors[neighbor]['toPort'][0]['hostname']
                    physnet = hostname if fqdns_used else (
                        hostname.split('.')[0])
                    break
            # Get response for 'show network physical-topology hosts' command
            if hostname:
                switch_id = response[1]['hosts'][hostname]['name']

            for k in response[1]['hosts']:
                mac_to_hostname[response[1]['hosts'][k]['name']] = k

            res = {'physnet': physnet,
                   'switch_id': switch_id,
                   'mac_to_hostname': mac_to_hostname}
            LOG.debug("get_physical_network: Physical Network info for "
                      "%(host)s is %(res)s", {'host': host_id,
                                              'res': res})
            return res
        except Exception as exc:
            LOG.error(_LE('command %(cmds)s failed with '
                      '%(exc)s'), {'cmds': cmds, 'exc': exc})
            return {}


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
            LOG.warning(EOS_UNREACHABLE_MSG)
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
                LOG.warning(EOS_UNREACHABLE_MSG)
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
        bm_port_profiles = db_lib.get_all_baremetal_ports()
        # To support shared networks, split the sync loop in two parts:
        # In first loop, delete unwanted VM and networks and update networks
        # In second loop, update VMs. This is done to ensure that networks for
        # all tenats are updated before VMs are updated
        instances_to_update = {}
        for tenant in db_tenants.keys():
            db_nets = db_lib.get_networks(tenant)
            db_instances = db_lib.get_vms(tenant)

            eos_nets = self._get_eos_networks(eos_tenants, tenant)
            eos_vms, eos_bms, eos_routers = self._get_eos_vms(eos_tenants,
                                                              tenant)

            db_nets_key_set = frozenset(db_nets.keys())
            db_instances_key_set = frozenset(db_instances.keys())
            eos_nets_key_set = frozenset(eos_nets.keys())
            eos_vms_key_set = frozenset(eos_vms.keys())
            eos_routers_key_set = frozenset(eos_routers.keys())
            eos_bms_key_set = frozenset(eos_bms.keys())

            # Create a candidate list by incorporating all instances
            eos_instances_key_set = (eos_vms_key_set | eos_routers_key_set |
                                     eos_bms_key_set)

            # Find the networks that are present on EOS, but not in Neutron DB
            nets_to_delete = eos_nets_key_set.difference(db_nets_key_set)

            # Find the VMs that are present on EOS, but not in Neutron DB
            instances_to_delete = eos_instances_key_set.difference(
                db_instances_key_set)

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
                if routers_to_delete:
                    if self._rpc.bm_and_dvr_supported():
                        self._rpc.delete_instance_bulk(tenant,
                                                       routers_to_delete,
                                                       InstanceType.ROUTER,
                                                       sync=True)
                    else:
                        LOG.info(ERR_DVR_NOT_SUPPORTED)

                if bms_to_delete:
                    if self._rpc.bm_and_dvr_supported():
                        self._rpc.delete_instance_bulk(tenant,
                                                       bms_to_delete,
                                                       InstanceType.BAREMETAL,
                                                       sync=True)
                    else:
                        LOG.info(BAREMETAL_NOT_SUPPORTED)

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
                LOG.warning(EOS_UNREACHABLE_MSG)
                self._force_sync = True

        # Now update the VMs
        for tenant in instances_to_update:
            if not instances_to_update[tenant]:
                continue
            try:
                # Filter the ports to only the vms that we are interested
                # in.
                ports_of_interest = {}
                for port in self._ndb.get_all_ports_for_tenant(tenant):
                    ports_of_interest.update(
                        self._port_dict_representation(port))

                if ports_of_interest:
                    db_vms = db_lib.get_vms(tenant)
                    if db_vms:
                        self._rpc.create_instance_bulk(tenant,
                                                       ports_of_interest,
                                                       db_vms,
                                                       bm_port_profiles,
                                                       sync=True)
            except arista_exc.AristaRpcError:
                LOG.warning(EOS_UNREACHABLE_MSG)
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
            LOG.warning(EOS_UNREACHABLE_MSG)
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
        if eos_tenants and tenant in eos_tenants:
            vms = eos_tenants[tenant]['tenantVmInstances']
            if 'tenantBaremetalInstances' in eos_tenants[tenant]:
                # Check if baremetal service is supported
                bms = eos_tenants[tenant]['tenantBaremetalInstances']
            if 'tenantRouterInstances' in eos_tenants[tenant]:
                routers = eos_tenants[tenant]['tenantRouterInstances']
        return vms, bms, routers

    def _port_dict_representation(self, port):
        return {port['id']: {'device_owner': port['device_owner'],
                             'device_id': port['device_id'],
                             'name': port['name'],
                             'id': port['id'],
                             'tenant_id': port['tenant_id'],
                             'network_id': port['network_id']}}
