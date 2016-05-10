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

import base64
import json
import os

from oslo_config import cfg
from oslo_log import log as logging
import requests

from neutron.common import constants as n_const
from neutron.i18n import _LI
from neutron.i18n import _LW

from networking_arista.common import db_lib
from networking_arista.common import exceptions as arista_exc

import socket

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


class AristaRPCWrapper(object):
    """Wraps Arista JSON RPC.

    All communications between Neutron and EOS are over JSON RPC.
    EOS - operating system used on Arista hardware
    Command API - JSON RPC API provided by Arista EOS
    """
    def __init__(self):
        self._validate_config()
        self._server_ip = None
        self.keystone_conf = cfg.CONF.keystone_authtoken
        self.region = cfg.CONF.ml2_arista.region_name
        self.sync_interval = cfg.CONF.ml2_arista.sync_interval
        self.conn_timeout = cfg.CONF.ml2_arista.conn_timeout
        self.eapi_hosts = cfg.CONF.ml2_arista.eapi_host.split(',')

        # The cli_commands dict stores the mapping between the CLI command key
        # and the actual CLI command.
        self.cli_commands = {}
        self.initialize_cli_commands()

    def _send_eapi_req(self, cmds):
        # This method handles all EAPI requests (using the requests library)
        # and returns either None or response.json()['result'] from the EAPI
        # request.
        #
        # Exceptions related to failures in connecting/ timeouts are caught
        # here and logged. Other unexpected exceptions are logged and raised

        request_headers = {}
        request_headers['Content-Type'] = 'application/json'
        request_headers['Accept'] = 'application/json'
        url = self._eapi_host_url(host=self._server_ip)

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
            msg = (_('EAPI request to %(ip)s contains %(cmd)s') %
                   {'ip': self._server_ip, 'cmd': json.dumps(data)})
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
            LOG.warn(msg)
            return None
        except requests.exceptions.ConnectTimeout:
            msg = (_('Timed out while trying to connect to %(ip)s') %
                   {'ip': self._server_ip})
            LOG.warn(msg)
            return None
        except requests.exceptions.Timeout:
            msg = (_('Timed out during an EAPI request to %(ip)s') %
                   {'ip': self._server_ip})
            LOG.warn(msg)
            return None
        except requests.exceptions.InvalidURL:
            msg = (_('Ignore attempt to connect to invalid URL %(ip)s') %
                   {'ip': self._server_ip})
            LOG.warn(msg)
            return None
        except ValueError:
            LOG.info("Ignoring invalid JSON response")
            return None
        except Exception as error:
            msg = unicode(error)
            LOG.warn(msg)
            raise

    def _get_exit_mode_cmds(self, modes):
        """Returns a list of 'exit' commands for the modes.

        :param modes: a list of CLI modes to exit out of.
        """
        return ['exit'] * len(modes)

    def _get_random_name(self, length=10):
        """Returns a base64 encoded name."""
        return base64.b64encode(os.urandom(10)).translate(None, '=+/')

    def initialize_cli_commands(self):
        self.cli_commands['timestamp'] = []
        self.cli_commands[CMD_REGION_SYNC] = ''
        self.cli_commands[CMD_SYNC_HEARTBEAT] = ''
        self.cli_commands['resource-pool'] = []

    def check_cli_commands(self):
        """Checks whether the CLI commands are valid.

           This method tries to execute the commands on EOS and if it succeedes
           the command is stored.
        """
        cmd = ['show openstack config region %s timestamp' % self.region]
        try:
            self._run_eos_cmds(cmd)
            self.cli_commands['timestamp'] = cmd
        except arista_exc.AristaRpcError:
            self.cli_commands['timestamp'] = []
            LOG.warn(_LW("'timestamp' command '%s' is not available on EOS"),
                     cmd)

        # Test the CLI command against a random region to ensure that multiple
        # neutron servers trying to execute the same command do not interpret
        # the lock errors differently.
        test_region_name = self._get_random_name()
        sync_command = [
            'enable',
            'configure',
            'cvx',
            'service openstack',
            'region %s' % test_region_name,
            'sync lock clientid requestid',
            'exit',
            'region %s sync' % test_region_name,
            'sync end',
            'exit',
        ]
        try:
            self._run_eos_cmds(sync_command)
            self.cli_commands[CMD_REGION_SYNC] = 'region %s sync' % self.region
            self.cli_commands[CMD_SYNC_HEARTBEAT] = 'sync heartbeat'
        except arista_exc.AristaRpcError:
            self.cli_commands[CMD_REGION_SYNC] = ''
            LOG.warn(_LW("'region sync' command is not available on EOS"))
        finally:
            cmd = ['enable', 'configure', 'cvx', 'service openstack',
                   'no region %s' % test_region_name]
            self._run_eos_cmds(cmd)

        # Check if the instance command exists
        instance_command = [
            'enable',
            'configure',
            'cvx',
            'service openstack',
            'region %s' % test_region_name,
            'tenant t1',
            'instance id i1 type router',
        ]
        try:
            self._run_eos_cmds(instance_command)
            self.cli_commands[CMD_INSTANCE] = 'instance'
        except arista_exc.AristaRpcError:
            self.cli_commands[CMD_INSTANCE] = None
            LOG.warn(_LW("'instance' command is not available on EOS"))
        finally:
            cmd = ['enable', 'configure', 'cvx', 'service openstack',
                   'no region %s' % test_region_name]
            self._run_eos_cmds(cmd)

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
            LOG.warn(
                _LW("'resource-pool' command '%s' is not available on EOS"),
                cmd)

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
        """Returns dict of all tenants known by EOS.

        :returns: dictionary containing the networks per tenant
                  and VMs allocated per tenant
        """
        cmds = ['show openstack config region %s' % self.region]
        command_output = self._run_eos_cmds(cmds)
        tenants = command_output[0]['tenants']

        return tenants

    def plug_port_into_network(self, device_id, host_id, port_id,
                               net_id, tenant_id, port_name, device_owner):
        """Generic routine plug a port of a VM instace into network.

        :param device_id: globally unique identifier for the device
        :param host: ID of the host where the port is placed
        :param port_id: globally unique port ID that connects port to network
        :param network_id: globally unique neutron network identifier
        :param tenant_id: globally unique neutron tenant identifier
        :param port_name: Name of the port - for display purposes
        :param device_owner: Device owner - e.g. compute or network:dhcp
        """
        if device_owner == n_const.DEVICE_OWNER_DHCP:
            self.plug_dhcp_port_into_network(device_id,
                                             host_id,
                                             port_id,
                                             net_id,
                                             tenant_id,
                                             port_name)
        elif device_owner.startswith('compute'):
            self.plug_host_into_network(device_id,
                                        host_id,
                                        port_id,
                                        net_id,
                                        tenant_id,
                                        port_name)
        elif device_owner == n_const.DEVICE_OWNER_DVR_INTERFACE:
            self.plug_distributed_router_port_into_network(device_id,
                                                           host_id,
                                                           port_id,
                                                           net_id,
                                                           tenant_id)

    def plug_host_into_network(self, vm_id, host, port_id,
                               network_id, tenant_id, port_name):
        """Creates VLAN between TOR and compute host.

        :param vm_id: globally unique identifier for VM instance
        :param host: ID of the host where the VM is placed
        :param port_id: globally unique port ID that connects VM to network
        :param network_id: globally unique neutron network identifier
        :param tenant_id: globally unique neutron tenant identifier
        :param port_name: Name of the port - for display purposes
        """
        cmds = ['tenant %s' % tenant_id,
                'vm id %s hostid %s' % (vm_id, host)]
        if port_name:
            cmds.append('port id %s name "%s" network-id %s' %
                        (port_id, port_name, network_id))
        else:
            cmds.append('port id %s network-id %s' %
                        (port_id, network_id))
        self._run_openstack_cmds(cmds)

    def plug_dhcp_port_into_network(self, dhcp_id, host, port_id,
                                    network_id, tenant_id, port_name):
        """Creates VLAN between TOR and dhcp host.

        :param dhcp_id: globally unique identifier for dhcp
        :param host: ID of the host where the dhcp is hosted
        :param port_id: globally unique port ID that connects dhcp to network
        :param network_id: globally unique neutron network identifier
        :param tenant_id: globally unique neutron tenant identifier
        :param port_name: Name of the port - for display purposes
        """
        cmds = ['tenant %s' % tenant_id,
                'network id %s' % network_id]
        if port_name:
            cmds.append('dhcp id %s hostid %s port-id %s name "%s"' %
                        (dhcp_id, host, port_id, port_name))
        else:
            cmds.append('dhcp id %s hostid %s port-id %s' %
                        (dhcp_id, host, port_id))
        self._run_openstack_cmds(cmds)

    def plug_distributed_router_port_into_network(self, router_id, host,
                                                  port_id, net_id, tenant_id):
        """Creates a DVR port on EOS.

        :param router_id: globally unique identifier for router instance
        :param host: ID of the host where the DVR port is placed
        :param port_id: globally unique port ID that connects port to network
        :param network_id: globally unique neutron network identifier
        :param tenant_id: globally unique neutron tenant identifier
        """

        if not self.cli_commands[CMD_INSTANCE]:
            LOG.info(ERR_DVR_NOT_SUPPORTED)
            return

        cmds = ['tenant %s' % tenant_id,
                'instance id %s type router' % router_id,
                'port id %s network-id %s hostid %s' % (port_id, net_id, host)]
        self._run_openstack_cmds(cmds)

    def unplug_port_from_network(self, device_id, device_owner, hostname,
                                 port_id, network_id, tenant_id):
        """Removes a port from the device

        :param device_id: globally unique identifier for the device
        :param host: ID of the host where the device is placed
        :param port_id: globally unique port ID that connects device to network
        :param network_id: globally unique neutron network identifier
        :param tenant_id: globally unique neutron tenant identifier
        """
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
        elif device_owner == n_const.DEVICE_OWNER_DVR_INTERFACE:
            self.unplug_distributed_router_port_from_network(device_id,
                                                             port_id,
                                                             hostname,
                                                             tenant_id)

    def unplug_host_from_network(self, vm_id, host, port_id,
                                 network_id, tenant_id):
        """Removes previously configured VLAN between TOR and a host.

        :param vm_id: globally unique identifier for VM instance
        :param host: ID of the host where the VM is placed
        :param port_id: globally unique port ID that connects VM to network
        :param network_id: globally unique neutron network identifier
        :param tenant_id: globally unique neutron tenant identifier
        """
        cmds = ['tenant %s' % tenant_id,
                'vm id %s hostid %s' % (vm_id, host),
                'no port id %s' % port_id,
                ]
        self._run_openstack_cmds(cmds)

    def unplug_dhcp_port_from_network(self, dhcp_id, host, port_id,
                                      network_id, tenant_id):
        """Removes previously configured VLAN between TOR and a dhcp host.

        :param dhcp_id: globally unique identifier for dhcp
        :param host: ID of the host where the dhcp is hosted
        :param port_id: globally unique port ID that connects dhcp to network
        :param network_id: globally unique neutron network identifier
        :param tenant_id: globally unique neutron tenant identifier
        """
        cmds = ['tenant %s' % tenant_id,
                'network id %s' % network_id,
                'no dhcp id %s port-id %s' % (dhcp_id, port_id),
                ]
        self._run_openstack_cmds(cmds)

    def unplug_distributed_router_port_from_network(self, router_id,
                                                    port_id, host, tenant_id):
        """Removes a DVR port from EOS.

        :param router_id: globally unique identifier for router instance
        :param port_id: globally unique port ID that connects port to network
        :param host: ID of the host where the dhcp is hosted
        :param tenant_id: globally unique neutron tenant identifier
        """

        if not self.cli_commands[CMD_INSTANCE]:
            LOG.info(ERR_DVR_NOT_SUPPORTED)
            return

        # When the last router port is removed, the router is deleted from EOS.
        cmds = ['tenant %s' % tenant_id,
                'instance id %s type router' % router_id,
                'no port id %s hostid %s' % (port_id, host)]
        self._run_openstack_cmds(cmds)

    def create_network(self, tenant_id, network):
        """Creates a single network on Arista hardware

        :param tenant_id: globally unique neutron tenant identifier
        :param network: dict containing network_id, network_name and
                        segmentation_id
        """
        self.create_network_bulk(tenant_id, [network])

    def create_network_bulk(self, tenant_id, network_list, sync=False):
        """Creates a network on Arista Hardware

        :param tenant_id: globally unique neutron tenant identifier
        :param network_list: list of dicts containing network_id, network_name
                             and segmentation_id
        :param sync: This flags indicates that the region is being synced.
        """
        cmds = ['tenant %s' % tenant_id]
        # Create a reference to function to avoid name lookups in the loop
        append_cmd = cmds.append
        counter = 0
        for network in network_list:
            counter += 1
            try:
                append_cmd('network id %s name "%s"' %
                           (network['network_id'], network['network_name']))
            except KeyError:
                append_cmd('network id %s' % network['network_id'])
            # Enter segment mode without exiting out of network mode
            if not network['segmentation_id']:
                network['segmentation_id'] = DEFAULT_VLAN
            append_cmd('segment 1 type vlan id %d' %
                       network['segmentation_id'])
            shared_cmd = 'shared' if network['shared'] else 'no shared'
            append_cmd(shared_cmd)
            if self._heartbeat_required(sync, counter):
                append_cmd(self.cli_commands[CMD_SYNC_HEARTBEAT])

        if self._heartbeat_required(sync):
            append_cmd(self.cli_commands[CMD_SYNC_HEARTBEAT])

        self._run_openstack_cmds(cmds, sync=sync)

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
        if segments:
            cmds = ['tenant %s' % tenant_id,
                    'network id %s name "%s"' % (network_id, network_name)]
            seg_num = 1
            for seg in segments:
                cmds.append('segment %d type %s id %d' % (seg_num,
                            seg['network_type'], seg['segmentation_id']))
                seg_num += 1

            self._run_openstack_cmds(cmds)

    def delete_network(self, tenant_id, network_id):
        """Deletes a specified network for a given tenant

        :param tenant_id: globally unique neutron tenant identifier
        :param network_id: globally unique neutron network identifier
        """
        self.delete_network_bulk(tenant_id, [network_id])

    def delete_network_bulk(self, tenant_id, network_id_list, sync=False):
        """Deletes the network ids specified for a tenant

        :param tenant_id: globally unique neutron tenant identifier
        :param network_id_list: list of globally unique neutron network
                                identifiers
        :param sync: This flags indicates that the region is being synced.
        """
        cmds = ['tenant %s' % tenant_id]
        counter = 0
        for network_id in network_id_list:
            counter += 1
            cmds.append('no network id %s' % network_id)
            if self._heartbeat_required(sync, counter):
                cmds.append(self.cli_commands[CMD_SYNC_HEARTBEAT])

        if self._heartbeat_required(sync):
            cmds.append(self.cli_commands[CMD_SYNC_HEARTBEAT])
        self._run_openstack_cmds(cmds, sync=sync)

    def delete_vm(self, tenant_id, vm_id):
        """Deletes a VM from EOS for a given tenant

        :param tenant_id : globally unique neutron tenant identifier
        :param vm_id : id of a VM that needs to be deleted.
        """
        self.delete_vm_bulk(tenant_id, [vm_id])

    def delete_vm_bulk(self, tenant_id, vm_id_list, sync=False):
        """Deletes VMs from EOS for a given tenant

        :param tenant_id : globally unique neutron tenant identifier
        :param vm_id_list : ids of VMs that needs to be deleted.
        :param sync: This flags indicates that the region is being synced.
        """
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

    def delete_instance_bulk(self, tenant_id, instance_id_list, sync=False):
        """Deletes instances from EOS for a given tenant

        :param tenant_id : globally unique neutron tenant identifier
        :param instance_id_list : ids of instances that needs to be deleted.
        :param sync: This flags indicates that the region is being synced.
        """
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

    def create_port_bulk(self, tenant_id, neutron_ports, arista_ports,
                         sync=False):
        """Sends a bulk request to create ports.

        :param tenant_id: globaly unique neutron tenant identifier
        :param neutron_ports: list of neutron ports that need to be created.
        :param arista_ports: list of ports in the arista db.
        :param sync: This flags indicates that the region is being synced.
        """
        cmds = ['tenant %s' % tenant_id]
        # Create a reference to function to avoid name lookups in the loop
        append_cmd = cmds.append
        counter = 0
        for neutron_port in neutron_ports:
            counter += 1
            try:
                port = arista_ports[neutron_port['id']]
            except KeyError:
                LOG.warn(_LW(
                         "Device id %(device)s not found for port %(port)s"),
                         {'device': neutron_port['device_id'],
                          'port': neutron_port['id']})
                continue

            port_name = '' if 'name' not in neutron_port else 'name "%s"' % (
                neutron_port['name']
            )

            device_owner = neutron_port['device_owner']
            if device_owner == n_const.DEVICE_OWNER_DHCP:
                append_cmd('network id %s' % neutron_port['network_id'])
                append_cmd('dhcp id %s hostid %s port-id %s %s' %
                           (port['deviceId'], port['hosts'][0],
                            neutron_port['id'], port_name))
            elif device_owner.startswith('compute'):
                append_cmd('vm id %s hostid %s' % (port['deviceId'],
                                                   port['hosts'][0]))
                append_cmd('port id %s %s network-id %s' %
                           (neutron_port['id'], port_name,
                            neutron_port['network_id']))
            elif device_owner == n_const.DEVICE_OWNER_DVR_INTERFACE:
                if not self.cli_commands[CMD_INSTANCE]:
                    LOG.info(ERR_DVR_NOT_SUPPORTED)
                    continue
                append_cmd('instance id %s type router' % port['deviceId'])
                for host in port['hosts']:
                    append_cmd('port id %s network-id %s hostid %s' % (
                               neutron_port['id'], neutron_port['network_id'],
                               host))
            else:
                LOG.warn(_LW("Unknown device owner: %s"), device_owner)
                continue
            if self._heartbeat_required(sync, counter):
                append_cmd(self.cli_commands[CMD_SYNC_HEARTBEAT])

        if self._heartbeat_required(sync):
            append_cmd(self.cli_commands[CMD_SYNC_HEARTBEAT])

        self._run_openstack_cmds(cmds, sync=sync)

    def delete_tenant(self, tenant_id):
        """Deletes a given tenant and all its networks and VMs from EOS.

        :param tenant_id: globally unique neutron tenant identifier
        """
        self.delete_tenant_bulk([tenant_id])

    def delete_tenant_bulk(self, tenant_list, sync=False):
        """Sends a bulk request to delete the tenants.

        :param tenant_list: list of globaly unique neutron tenant ids which
                            need to be deleted.
        :param sync: This flags indicates that the region is being synced.
        """

        cmds = []
        for tenant in tenant_list:
            cmds.append('no tenant %s' % tenant)
        if self._heartbeat_required(sync):
            cmds.append(self.cli_commands[CMD_SYNC_HEARTBEAT])
        self._run_openstack_cmds(cmds, sync=sync)

    def delete_this_region(self):
        """Deleted the region data from EOS."""
        cmds = ['enable',
                'configure',
                'cvx',
                'service openstack',
                'no region %s' % self.region,
                ]
        self._run_eos_cmds(cmds)

    def register_with_eos(self, sync=False):
        """This is the registration request with EOS.

        This the initial handshake between Neutron and EOS.
        critical end-point information is registered with EOS.

        :param sync: This flags indicates that the region is being synced.
        """

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

    def clear_region_updated_time(self):
        # TODO(shashank): Remove this once the call is removed from the ML2
        # driver.
        pass

    def get_region_updated_time(self):
        """Return the timestamp of the last update.

           This method returns the time at which any entities in the region
           were updated.
        """
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

    def sync_start(self):
        """Let EOS know that a sync in being initiated."""
        try:
            cmds = []
            if self.cli_commands[CMD_REGION_SYNC]:
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
        """Let EOS know that sync is complete."""
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
                msg = "Failed to identify EOS master"
                raise arista_exc.AristaRpcError(msg=msg)
        except Exception:
            raise

        log_cmds = commands
        if commands_to_log:
            log_cmds = commands_to_log

        LOG.info(_LI('Executing command on Arista EOS: %s'), log_cmds)
        # this returns array of return values for every command in
        # full_command list
        try:
            response = self._send_eapi_req(cmds=commands)
            if response is None:
                # Reset the server as we failed communicating with it
                self._server_ip = None
                msg = "Failed to communicate with EOS master"
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
        if sync and self.cli_commands[CMD_REGION_SYNC]:
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

        cvx = []
        if self._server_ip:
            # If we know the master's IP, let's start with that
            cvx.append(self._server_ip)

        for h in self.eapi_hosts:
            if h.strip() not in cvx:
                cvx.append(h.strip())

        # Identify which EOS instance is currently the master
        for self._server_ip in cvx:
            try:
                if self._send_eapi_req(cmds=cmd) is not None:
                    return self._server_ip
                else:
                    continue  # Try another EOS instance
            except Exception:
                raise

        # Couldn't find an instance that is the leader and returning none
        self._server_ip = None
        msg = "Failed to reach the EOS master"
        LOG.error(msg)
        return None

    def _eapi_host_url(self, host=""):
        user = cfg.CONF.ml2_arista.eapi_username
        pwd = cfg.CONF.ml2_arista.eapi_password

        eapi_server_url = ('https://%s:%s@%s/command-api' %
                           (user, pwd, host))
        return eapi_server_url

    def _validate_config(self):
        if cfg.CONF.ml2_arista.get('eapi_host') == '':
            msg = _('Required option eapi_host is not set')
            LOG.error(msg)
            raise arista_exc.AristaConfigError(msg=msg)
        if cfg.CONF.ml2_arista.get('eapi_username') == '':
            msg = _('Required option eapi_username is not set')
            LOG.error(msg)
            raise arista_exc.AristaConfigError(msg=msg)


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
        if not self._sync_required():
            return

        # Send 'sync start' marker.
        if not self._rpc.sync_start():
            self._force_sync = True
            return

        # Perform the actual synchronization.
        self.synchronize()

        # Send 'sync end' marker.
        if not self._rpc.sync_end():
            self._force_sync = True
            return

        self._set_region_updated_time()

    def synchronize(self):
        """Sends data to EOS which differs from neutron DB."""

        LOG.info(_LI('Syncing Neutron <-> EOS'))
        try:
            # Register with EOS to ensure that it has correct credentials
            self._rpc.register_with_eos(sync=True)
            # Recheck whether the commands are still available
            self._rpc.check_cli_commands()
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

        # To support shared networks, split the sync loop in two parts:
        # In first loop, delete unwanted VM and networks and update networks
        # In second loop, update VMs. This is done to ensure that networks for
        # all tenats are updated before VMs are updated
        instances_to_update = {}
        for tenant in db_tenants.keys():
            db_nets = db_lib.get_networks(tenant)
            db_instances = db_lib.get_vms(tenant)

            eos_nets = self._get_eos_networks(eos_tenants, tenant)
            eos_vms = self._get_eos_vms(eos_tenants, tenant)
            eos_routers = self._get_eos_routers(eos_tenants, tenant)

            db_nets_key_set = frozenset(db_nets.keys())
            db_instances_key_set = frozenset(db_instances.keys())
            eos_nets_key_set = frozenset(eos_nets.keys())
            eos_vms_key_set = frozenset(eos_vms.keys())
            eos_routers_key_set = frozenset(eos_routers.keys())

            eos_instances_key_set = (eos_vms_key_set | eos_routers_key_set)

            # Find the networks that are present on EOS, but not in Neutron DB
            nets_to_delete = eos_nets_key_set.difference(db_nets_key_set)

            # Find the VMs that are present on EOS, but not in Neutron DB
            instances_to_delete = eos_instances_key_set.difference(
                db_instances_key_set)

            vms_to_delete = [
                vm for vm in eos_vms_key_set if vm in instances_to_delete]
            routers_to_delete = [
                r for r in eos_routers_key_set if r in instances_to_delete]

            # Find the Networks that are present in Neutron DB, but not on EOS
            nets_to_update = db_nets_key_set.difference(eos_nets_key_set)

            # Find the VMs that are present in Neutron DB, but not on EOS
            instances_to_update[tenant] = db_instances_key_set.difference(
                eos_instances_key_set)

            try:
                if vms_to_delete:
                    self._rpc.delete_vm_bulk(tenant, vms_to_delete, sync=True)
                if routers_to_delete:
                    if self._rpc.cli_commands[CMD_INSTANCE]:
                        self._rpc.delete_instance_bulk(tenant,
                                                       routers_to_delete,
                                                       sync=True)
                    else:
                        LOG.info(ERR_DVR_NOT_SUPPORTED)

                if nets_to_delete:
                    self._rpc.delete_network_bulk(tenant, nets_to_delete,
                                                  sync=True)
                if nets_to_update:
                    networks = [{
                        'network_id': net_id,
                        'segmentation_id':
                            db_nets[net_id]['segmentationTypeId'],
                        'network_name':
                            neutron_nets.get(net_id, {'name': ''})['name'],
                        'shared':
                            neutron_nets.get(net_id,
                                             {'shared': False})['shared'],
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
                relevant_ports = []
                for port in self._ndb.get_all_ports_for_tenant(tenant):
                    if port['device_id'] in instances_to_update[tenant]:
                        relevant_ports.append(port)

                if relevant_ports:
                    db_ports = db_lib.get_ports(tenant)
                    self._rpc.create_port_bulk(tenant, relevant_ports,
                                               db_ports, sync=True)
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
                if not self._rpc.cli_commands[CMD_REGION_SYNC]:
                    self._rpc.sync_end()
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
        if eos_tenants and tenant in eos_tenants:
            vms = eos_tenants[tenant]['tenantVmInstances']
        return vms

    def _get_eos_routers(self, eos_tenants, tenant):
        if eos_tenants and tenant in eos_tenants:
            if 'tenantRouterInstances' in eos_tenants[tenant]:
                return eos_tenants[tenant]['tenantRouterInstances']
        return {}
