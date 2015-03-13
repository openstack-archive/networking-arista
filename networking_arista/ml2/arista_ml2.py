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

import itertools

import jsonrpclib
from oslo.config import cfg
from oslo_log import log as logging

from neutron.common import constants as n_const
from neutron.i18n import _LI
from neutron.i18n import _LW
from neutron.plugins.ml2.drivers.arista import exceptions as arista_exc

from networking_arista.common import db_lib

LOG = logging.getLogger(__name__)

EOS_UNREACHABLE_MSG = _('Unable to reach EOS')
DEFAULT_VLAN = 1


class AristaRPCWrapper(object):
    """Wraps Arista JSON RPC.

    All communications between Neutron and EOS are over JSON RPC.
    EOS - operating system used on Arista hardware
    Command API - JSON RPC API provided by Arista EOS
    """
    def __init__(self):
        self._server = jsonrpclib.Server(self._eapi_host_url())
        self.keystone_conf = cfg.CONF.keystone_authtoken
        self.region = cfg.CONF.ml2_arista.region_name
        self.sync_interval = cfg.CONF.ml2_arista.sync_interval
        # The cli_commands dict stores the mapping between the CLI command key
        # and the actual CLI command.
        self.cli_commands = {}
        self.initialize_cli_commands()

    def _get_exit_mode_cmds(self, modes):
        """Returns a list of 'exit' commands for the modes.

        :param modes: a list of CLI modes to exit out of.
        """
        return ['exit'] * len(modes)

    def initialize_cli_commands(self):
        self.cli_commands['timestamp'] = []

    def check_cli_commands(self):
        """Checks whether the CLI commands are vaild.

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

    def _keystone_url(self):
        keystone_auth_url = ('%s://%s:%s/v2.0/' %
                             (self.keystone_conf.auth_protocol,
                              self.keystone_conf.auth_host,
                              self.keystone_conf.auth_port))
        return keystone_auth_url

    def get_tenants(self):
        """Returns dict of all tenants known by EOS.

        :returns: dictionary containing the networks per tenant
                  and VMs allocated per tenant
        """
        cmds = ['show openstack config region %s' % self.region]
        command_output = self._run_eos_cmds(cmds)
        tenants = command_output[0]['tenants']

        return tenants

    def plug_port_into_network(self, vm_id, host_id, port_id,
                               net_id, tenant_id, port_name, device_owner):
        """Genric routine plug a port of a VM instace into network.

        :param vm_id: globally unique identifier for VM instance
        :param host: ID of the host where the VM is placed
        :param port_id: globally unique port ID that connects VM to network
        :param network_id: globally unique neutron network identifier
        :param tenant_id: globally unique neutron tenant identifier
        :param port_name: Name of the port - for display purposes
        :param device_owner: Device owner - e.g. compute or network:dhcp
        """
        if device_owner == n_const.DEVICE_OWNER_DHCP:
            self.plug_dhcp_port_into_network(vm_id,
                                             host_id,
                                             port_id,
                                             net_id,
                                             tenant_id,
                                             port_name)
        elif device_owner.startswith('compute'):
            self.plug_host_into_network(vm_id,
                                        host_id,
                                        port_id,
                                        net_id,
                                        tenant_id,
                                        port_name)

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
        cmds.append('exit')
        cmds.append('exit')
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
        cmds.append('exit')
        self._run_openstack_cmds(cmds)

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
                'exit',
                'exit']
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
                'exit']
        self._run_openstack_cmds(cmds)

    def create_network(self, tenant_id, network):
        """Creates a single network on Arista hardware

        :param tenant_id: globally unique neutron tenant identifier
        :param network: dict containing network_id, network_name and
                        segmentation_id
        """
        self.create_network_bulk(tenant_id, [network])

    def create_network_bulk(self, tenant_id, network_list):
        """Creates a network on Arista Hardware

        :param tenant_id: globally unique neutron tenant identifier
        :param network_list: list of dicts containing network_id, network_name
                             and segmentation_id
        """
        cmds = ['tenant %s' % tenant_id]
        # Create a reference to function to avoid name lookups in the loop
        append_cmd = cmds.append
        for network in network_list:
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
        cmds.extend(self._get_exit_mode_cmds(['segment', 'network', 'tenant']))
        self._run_openstack_cmds(cmds)

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
            cmds.append('exit')  # exit for segment mode
            cmds.append('exit')  # exit for network mode
            cmds.append('exit')  # exit for tenant mode

            self._run_openstack_cmds(cmds)

    def delete_network(self, tenant_id, network_id):
        """Deletes a specified network for a given tenant

        :param tenant_id: globally unique neutron tenant identifier
        :param network_id: globally unique neutron network identifier
        """
        self.delete_network_bulk(tenant_id, [network_id])

    def delete_network_bulk(self, tenant_id, network_id_list):
        """Deletes the network ids specified for a tenant

        :param tenant_id: globally unique neutron tenant identifier
        :param network_id_list: list of globally unique neutron network
                                identifiers
        """
        cmds = ['tenant %s' % tenant_id]
        for network_id in network_id_list:
            cmds.append('no network id %s' % network_id)
        cmds.extend(self._get_exit_mode_cmds(['network', 'tenant']))
        self._run_openstack_cmds(cmds)

    def delete_vm(self, tenant_id, vm_id):
        """Deletes a VM from EOS for a given tenant

        :param tenant_id : globally unique neutron tenant identifier
        :param vm_id : id of a VM that needs to be deleted.
        """
        self.delete_vm_bulk(tenant_id, [vm_id])

    def delete_vm_bulk(self, tenant_id, vm_id_list):
        """Deletes VMs from EOS for a given tenant

        :param tenant_id : globally unique neutron tenant identifier
        :param vm_id_list : ids of VMs that needs to be deleted.
        """
        cmds = ['tenant %s' % tenant_id]
        for vm_id in vm_id_list:
            cmds.append('no vm id %s' % vm_id)
        cmds.extend(self._get_exit_mode_cmds(['vm', 'tenant']))
        self._run_openstack_cmds(cmds)

    def create_vm_port_bulk(self, tenant_id, vm_port_list, vms):
        """Sends a bulk request to create ports.

        :param tenant_id: globaly unique neutron tenant identifier
        :param vm_port_list: list of ports that need to be created.
        :param vms: list of vms to which the ports will be attached to.
        """
        cmds = ['tenant %s' % tenant_id]
        # Create a reference to function to avoid name lookups in the loop
        append_cmd = cmds.append
        for port in vm_port_list:
            try:
                vm = vms[port['device_id']]
            except KeyError:
                LOG.warn(_LW("VM id %(vmid)s not found for port %(portid)s"),
                         {'vmid': port['device_id'], 'portid': port['id']})
                continue

            port_name = '' if 'name' not in port else 'name "%s"' % (
                port['name']
            )

            if port['device_owner'] == n_const.DEVICE_OWNER_DHCP:
                append_cmd('network id %s' % port['network_id'])
                append_cmd('dhcp id %s hostid %s port-id %s %s' %
                           (vm['vmId'], vm['host'], port['id'], port_name))
            elif port['device_owner'].startswith('compute'):
                append_cmd('vm id %s hostid %s' % (vm['vmId'], vm['host']))
                append_cmd('port id %s %s network-id %s' %
                           (port['id'], port_name, port['network_id']))
            else:
                LOG.warn(_LW("Unknown device owner: %s"), port['device_owner'])
                continue

        append_cmd('exit')
        self._run_openstack_cmds(cmds)

    def delete_tenant(self, tenant_id):
        """Deletes a given tenant and all its networks and VMs from EOS.

        :param tenant_id: globally unique neutron tenant identifier
        """
        self.delete_tenant_bulk([tenant_id])

    def delete_tenant_bulk(self, tenant_list):
        """Sends a bulk request to delete the tenants.

        :param tenant_list: list of globaly unique neutron tenant ids which
                            need to be deleted.
        """

        cmds = []
        for tenant in tenant_list:
            cmds.append('no tenant %s' % tenant)
        cmds.append('exit')
        self._run_openstack_cmds(cmds)

    def delete_this_region(self):
        """Deleted the region data from EOS."""
        cmds = ['enable',
                'configure',
                'cvx',
                'service openstack',
                'no region %s' % self.region,
                'exit',
                'exit',
                'exit']
        self._run_eos_cmds(cmds)

    def register_with_eos(self):
        """This is the registration request with EOS.

        This the initial handshake between Neutron and EOS.
        critical end-point information is registered with EOS.
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

        self._run_openstack_cmds(cmds, commands_to_log=log_cmds)

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
            return self._run_eos_cmds(commands=timestamp_cmd)[0]
        return None

    def _run_eos_cmds(self, commands, commands_to_log=None):
        """Execute/sends a CAPI (Command API) command to EOS.

        In this method, list of commands is appended with prefix and
        postfix commands - to make is understandble by EOS.

        :param commands : List of command to be executed on EOS.
        :param commands_to_log : This should be set to the command that is
                                 logged. If it is None, then the commands
                                 param is logged.
        """

        log_cmds = commands
        if commands_to_log:
            log_cmds = commands_to_log

        LOG.info(_LI('Executing command on Arista EOS: %s'), log_cmds)

        try:
            # this returns array of return values for every command in
            # full_command list
            ret = self._server.runCmds(version=1, cmds=commands)
        except Exception as error:
            host = cfg.CONF.ml2_arista.eapi_host
            error_msg_str = unicode(error)
            if commands_to_log:
                # The command might contain sensitive information. If the
                # command to log is different from the actual command, use
                # that in the error message.
                for cmd, log_cmd in itertools.izip(commands, log_cmds):
                    error_msg_str = error_msg_str.replace(cmd, log_cmd)
            msg = (_('Error %(err)s while trying to execute '
                     'commands %(cmd)s on EOS %(host)s') %
                   {'err': error_msg_str,
                    'cmd': commands_to_log,
                    'host': host})
            # Logging exception here can reveal passwords as the exception
            # contains the CLI command which contains the credentials.
            LOG.error(msg)
            raise arista_exc.AristaRpcError(msg=msg)

        return ret

    def _build_command(self, cmds):
        """Build full EOS's openstack CLI command.

        Helper method to add commands to enter and exit from openstack
        CLI modes.

        :param cmds: The openstack CLI commands that need to be executed
                     in the openstack config mode.
        """

        full_command = [
            'enable',
            'configure',
            'cvx',
            'service openstack',
            'region %s' % self.region,
        ]
        full_command.extend(cmds)
        full_command.extend(self._get_exit_mode_cmds(['region',
                                                      'openstack',
                                                      'cvx']))
        return full_command

    def _run_openstack_cmds(self, commands, commands_to_log=None):
        """Execute/sends a CAPI (Command API) command to EOS.

        In this method, list of commands is appended with prefix and
        postfix commands - to make is understandble by EOS.

        :param commands : List of command to be executed on EOS.
        :param commands_to_logs : This should be set to the command that is
                                  logged. If it is None, then the commands
                                  param is logged.
        """

        full_command = self._build_command(commands)
        if commands_to_log:
            full_log_command = self._build_command(commands_to_log)
        else:
            full_log_command = None
        self._run_eos_cmds(full_command, full_log_command)

    def _eapi_host_url(self):
        self._validate_config()

        user = cfg.CONF.ml2_arista.eapi_username
        pwd = cfg.CONF.ml2_arista.eapi_password
        host = cfg.CONF.ml2_arista.eapi_host

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
        if not self._sync_start():
            return

        # Perform the actual synchronization.
        self.synchronize()
        # Send 'sync end' marker.
        if not self._sync_end():
            return

        self._set_region_updated_time()

    def synchronize(self):
        """Sends data to EOS which differs from neutron DB."""

        LOG.info(_LI('Syncing Neutron <-> EOS'))
        try:
            # Register with EOS to ensure that it has correct credentials
            self._rpc.register_with_eos()
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
                self._rpc.delete_tenant_bulk(tenants_to_delete)
            except arista_exc.AristaRpcError:
                LOG.warning(EOS_UNREACHABLE_MSG)
                self._force_sync = True
                return

        # None of the commands have failed till now. But if subsequent
        # operations fail, then force_sync is set to true
        self._force_sync = False

        # To support shared networks, split the sync loop in two parts:
        # In first loop, delete unwanted VM and networks and update networks
        # In second loop, update VMs. This is done to ensure that networks for
        # all tenats are updated before VMs are updated
        vms_to_update = {}
        for tenant in db_tenants:
            db_nets = db_lib.get_networks(tenant)
            db_vms = db_lib.get_vms(tenant)
            eos_nets = self._get_eos_networks(eos_tenants, tenant)
            eos_vms = self._get_eos_vms(eos_tenants, tenant)

            db_nets_key_set = frozenset(db_nets.keys())
            db_vms_key_set = frozenset(db_vms.keys())
            eos_nets_key_set = frozenset(eos_nets.keys())
            eos_vms_key_set = frozenset(eos_vms.keys())

            # Find the networks that are present on EOS, but not in Neutron DB
            nets_to_delete = eos_nets_key_set.difference(db_nets_key_set)

            # Find the VMs that are present on EOS, but not in Neutron DB
            vms_to_delete = eos_vms_key_set.difference(db_vms_key_set)

            # Find the Networks that are present in Neutron DB, but not on EOS
            nets_to_update = db_nets_key_set.difference(eos_nets_key_set)

            # Find the VMs that are present in Neutron DB, but not on EOS
            vms_to_update[tenant] = db_vms_key_set.difference(eos_vms_key_set)

            try:
                if vms_to_delete:
                    self._rpc.delete_vm_bulk(tenant, vms_to_delete)
                if nets_to_delete:
                    self._rpc.delete_network_bulk(tenant, nets_to_delete)
                if nets_to_update:
                    # Create a dict of networks keyed by id.
                    neutron_nets = dict(
                        (network['id'], network) for network in
                        self._ndb.get_all_networks_for_tenant(tenant)
                    )

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
                    self._rpc.create_network_bulk(tenant, networks)
            except arista_exc.AristaRpcError:
                LOG.warning(EOS_UNREACHABLE_MSG)
                self._force_sync = True

        # Now update the VMs
        for tenant in vms_to_update:
            if not vms_to_update[tenant]:
                continue
            try:
                # Filter the ports to only the vms that we are interested
                # in.
                vm_ports = [
                    port for port in self._ndb.get_all_ports_for_tenant(
                        tenant) if port['device_id'] in vms_to_update[tenant]
                ]
                if vm_ports:
                    db_vms = db_lib.get_vms(tenant)
                    self._rpc.create_vm_port_bulk(tenant, vm_ports, db_vms)
            except arista_exc.AristaRpcError:
                LOG.warning(EOS_UNREACHABLE_MSG)
                self._force_sync = True

    def _sync_start(self):
        """Let EOS know that a sync in being initiated."""
        try:
            self._rpc._run_openstack_cmds(['sync start'])
            return True
        except arista_exc.AristaRpcError:
            self._force_sync = True
            return False

    def _sync_end(self):
        """Let EOS know that sync is complete."""
        try:
            self._rpc._run_openstack_cmds(['sync end'])
            return True
        except arista_exc.AristaRpcError:
            self._force_sync = True
            return False

    def _region_in_sync(self):
        """Checks if the region is in sync with EOS.

           Checks whether the timestamp stored in EOS is the same as the
           timestamp stored locally.
        """
        eos_region_updated_times = self._rpc.get_region_updated_time()
        return (self._region_updated_time and
                (self._region_updated_time['regionTimestamp'] ==
                 eos_region_updated_times['regionTimestamp']))

    def _sync_required(self):
        """"Check whether the sync is required."""
        try:
            # Get the time at which entities in the region were updated.
            # If the times match, then ML2 is in sync with EOS. Otherwise
            # perform a complete sync.
            if not self._force_sync and self._region_in_sync():
                LOG.info(_LI('OpenStack and EOS are in sync!'))
                self._sync_end()
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
