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

import json
import socket

from neutron_lib.api.definitions import portbindings
from neutron_lib import constants as n_const
from oslo_config import cfg
from oslo_log import log as logging
import requests
import six

from networking_arista._i18n import _, _LI, _LW, _LE
from networking_arista.common import constants as const
from networking_arista.common import db_lib
from networking_arista.common import exceptions as arista_exc
from networking_arista.ml2.rpc.base import AristaRPCWrapperBase

LOG = logging.getLogger(__name__)


class AristaRPCWrapperEapi(AristaRPCWrapperBase):
    def __init__(self, ndb):
        super(AristaRPCWrapperEapi, self).__init__(ndb)
        # The cli_commands dict stores the mapping between the CLI command key
        # and the actual CLI command.
        self.cli_commands = {
            'timestamp': [
                'show openstack config region %s timestamp' % self.region],
            const.CMD_REGION_SYNC: 'region %s sync' % self.region,
            const.CMD_INSTANCE: None,
            const.CMD_SYNC_HEARTBEAT: 'sync heartbeat',
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
                            if const.ERR_CVX_NOT_LEADER in data['errors'][0]:
                                msg = six.text_type("%s is not the master" % (
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
            msg = six.text_type(error)
            LOG.warning(msg)
            raise

    def check_supported_features(self):
        cmd = ['show openstack instances']
        try:
            self._run_eos_cmds(cmd)
            self.cli_commands[const.CMD_INSTANCE] = 'instance'
        except (arista_exc.AristaRpcError, Exception) as err:
            self.cli_commands[const.CMD_INSTANCE] = None
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
        return (sync and self.cli_commands[const.CMD_SYNC_HEARTBEAT] and
                (counter % const.HEARTBEAT_INTERVAL) == 0)

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
        else:
            cmd = ['show openstack resource-pools region %s' % self.region]
            command_output = self._run_eos_cmds(cmd)
            if command_output:
                regions = command_output[0]['physicalNetwork']
                if self.region in regions.keys():
                    return regions[self.region]['vlanPool']['default']
        return {'assignedVlans': '',
                'availableVlans': '',
                'allocatedVlans': ''}

    def get_tenants(self):
        cmds = ['show openstack config region %s' % self.region]
        command_output = self._run_eos_cmds(cmds)
        tenants = command_output[0]['tenants']

        return tenants

    def bm_and_dvr_supported(self):
        return (self.cli_commands[const.CMD_INSTANCE] == 'instance')

    def _baremetal_support_check(self, vnic_type):
        # Basic error checking for baremental deployments
        self.check_supported_features()
        if (vnic_type == portbindings.VNIC_BAREMETAL and
           not self.bm_and_dvr_supported()):
            msg = _("Baremetal instances are not supported in this"
                    " release of EOS")
            LOG.error(msg)
            raise arista_exc.AristaConfigError(msg=msg)

    def plug_port_into_network(self, device_id, host_id, port_id,
                               net_id, tenant_id, port_name, device_owner,
                               sg, orig_sg, vnic_type, segments,
                               switch_bindings=None, trunk_details=None):
        if device_owner == n_const.DEVICE_OWNER_DHCP:
            self.plug_dhcp_port_into_network(device_id,
                                             host_id,
                                             port_id,
                                             net_id,
                                             tenant_id,
                                             segments,
                                             port_name)
        elif (device_owner.startswith('compute') or
              device_owner.startswith('baremetal') or
              device_owner.startswith('trunk')):
            if vnic_type == 'baremetal':
                self.plug_baremetal_into_network(device_id,
                                                 host_id,
                                                 port_id,
                                                 net_id,
                                                 tenant_id,
                                                 segments,
                                                 port_name,
                                                 device_owner,
                                                 sg, orig_sg,
                                                 vnic_type,
                                                 switch_bindings,
                                                 trunk_details)
            else:
                self.plug_host_into_network(device_id,
                                            host_id,
                                            port_id,
                                            net_id,
                                            tenant_id,
                                            segments,
                                            port_name,
                                            trunk_details)
        elif device_owner == n_const.DEVICE_OWNER_DVR_INTERFACE:
            self.plug_distributed_router_port_into_network(device_id,
                                                           host_id,
                                                           port_id,
                                                           net_id,
                                                           tenant_id,
                                                           segments)

    def unplug_port_from_network(self, device_id, device_owner, hostname,
                                 port_id, network_id, tenant_id, sg, vnic_type,
                                 switch_bindings=None, trunk_details=None):
        if device_owner == n_const.DEVICE_OWNER_DHCP:
            self.unplug_dhcp_port_from_network(device_id,
                                               hostname,
                                               port_id,
                                               network_id,
                                               tenant_id)
        elif (device_owner.startswith('compute') or
              device_owner.startswith('baremetal') or
              device_owner.startswith('trunk')):
            if vnic_type == 'baremetal':
                self.unplug_baremetal_from_network(device_id,
                                                   hostname,
                                                   port_id,
                                                   network_id,
                                                   tenant_id,
                                                   sg,
                                                   vnic_type,
                                                   switch_bindings,
                                                   trunk_details)
            else:
                self.unplug_host_from_network(device_id,
                                              hostname,
                                              port_id,
                                              network_id,
                                              tenant_id,
                                              trunk_details)
        elif device_owner == n_const.DEVICE_OWNER_DVR_INTERFACE:
            self.unplug_distributed_router_port_from_network(device_id,
                                                             port_id,
                                                             hostname,
                                                             tenant_id)

    def plug_host_into_network(self, vm_id, host, port_id,
                               network_id, tenant_id, segments, port_name,
                               trunk_details=None):
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

        if trunk_details and trunk_details.get('sub_ports'):
            for subport in trunk_details['sub_ports']:
                port_id = subport['port_id']
                net_id = self._ndb.get_network_id_from_port_id(port_id)
                filters = {'port_id': port_id}
                segments = db_lib.get_port_binding_level(filters)

                cmds.append('port id %s network-id %s' %
                            (port_id, net_id))
                cmds.extend(
                    'segment level %d id %s' % (s.level, s.segment_id)
                    for s in segments
                )
        self._run_openstack_cmds(cmds)

    def plug_baremetal_into_network(self, vm_id, host, port_id,
                                    network_id, tenant_id, segments, port_name,
                                    device_owner,
                                    sg=None, orig_sg=None,
                                    vnic_type=None, switch_bindings=None,
                                    trunk_details=None):
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
                if device_owner.startswith('trunk'):
                    vlan_type = 'allowed'
                else:
                    vlan_type = 'native'
                # Ensure that binding contains switch and port ID info
                if binding['switch_id'] and binding['port_id']:
                    if port_name:
                        cmds.append('port id %s name "%s" network-id %s '
                                    'type %s switch-id %s switchport %s' %
                                    (port_id, port_name, network_id,
                                     vlan_type, binding['switch_id'],
                                     binding['port_id']))
                    else:
                        cmds.append('port id %s network-id %s type %s '
                                    'switch-id %s switchport %s' %
                                    (port_id, network_id, vlan_type,
                                     binding['switch_id'],
                                     binding['port_id']))
                    cmds.extend('segment level %d id %s' % (level,
                                segment['id'])
                                for level, segment in enumerate(segments))

                    if trunk_details and trunk_details.get('sub_ports'):
                        for subport in trunk_details['sub_ports']:
                            port_id = subport['port_id']
                            net_id = self._ndb.get_network_id_from_port_id(
                                port_id)
                            filters = {'port_id': port_id}
                            segments = db_lib.get_port_binding_level(filters)

                            cmds.append('port id %s network-id %s type allowed'
                                        ' switch-id %s switchport %s' %
                                        (port_id, net_id, binding['switch_id'],
                                            binding['port_id']))
                            cmds.extend(
                                'segment level %d id %s' %
                                (s.level, s.segment_id) for s in segments
                            )
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
            LOG.info(const.ERR_DVR_NOT_SUPPORTED)
            return

        cmds = ['tenant %s' % tenant_id,
                'instance id %s type router' % router_id,
                'port id %s network-id %s hostid %s' % (port_id, net_id, host)]
        cmds.extend('segment level %d id %s' % (level, segment['id'])
                    for level, segment in enumerate(segments))
        self._run_openstack_cmds(cmds)

    def unplug_host_from_network(self, vm_id, host, port_id,
                                 network_id, tenant_id, trunk_details=None):
        cmds = ['tenant %s' % tenant_id,
                'vm id %s hostid %s' % (vm_id, host),
                ]
        if trunk_details and trunk_details.get('sub_ports'):
            cmds.extend(
                'no port id %s' % subport['port_id']
                for subport in trunk_details['sub_ports']
            )
        cmds.append('no port id %s' % port_id)
        self._run_openstack_cmds(cmds)

    def unplug_baremetal_from_network(self, vm_id, host, port_id,
                                      network_id, tenant_id, sg, vnic_type,
                                      switch_bindings=None,
                                      trunk_details=None):
        # Basic error checking for baremental deployments
        # notice that the following method throws and exception
        # if an error condition exists
        self._baremetal_support_check(vnic_type)

        # Following is a temporary code for native VLANs - should be removed
        cmds = ['tenant %s' % tenant_id]
        cmds.append('instance id %s hostid %s type baremetal' % (vm_id, host))
        if trunk_details and trunk_details.get('sub_ports'):
            cmds.extend(
                'no port id %s' % subport['port_id']
                for subport in trunk_details['sub_ports']
            )
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
            LOG.info(const.ERR_DVR_NOT_SUPPORTED)
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
                if seg['network_type'] != const.NETWORK_TYPE_FLAT
            )
            shared_cmd = 'shared' if network['shared'] else 'no shared'
            append_cmd(shared_cmd)
            if self._heartbeat_required(sync, counter):
                append_cmd(self.cli_commands[const.CMD_SYNC_HEARTBEAT])

        if self._heartbeat_required(sync):
            append_cmd(self.cli_commands[const.CMD_SYNC_HEARTBEAT])

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
        if not segments:
            return
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
                cmds.append(self.cli_commands[const.CMD_SYNC_HEARTBEAT])

        if self._heartbeat_required(sync):
            cmds.append(self.cli_commands[const.CMD_SYNC_HEARTBEAT])
        self._run_openstack_cmds(cmds, sync=sync)

    def delete_dhcp_bulk(self, tenant_id, dhcp_id_list, sync=False):
        self.delete_vm_bulk(tenant_id, dhcp_id_list, sync)

    def delete_vm_bulk(self, tenant_id, vm_id_list, sync=False):
        cmds = ['tenant %s' % tenant_id]
        counter = 0
        for vm_id in vm_id_list:
            counter += 1
            cmds.append('no vm id %s' % vm_id)
            if self._heartbeat_required(sync, counter):
                cmds.append(self.cli_commands[const.CMD_SYNC_HEARTBEAT])

        if self._heartbeat_required(sync):
            cmds.append(self.cli_commands[const.CMD_SYNC_HEARTBEAT])
        self._run_openstack_cmds(cmds, sync=sync)

    def delete_instance_bulk(self, tenant_id, instance_id_list, instance_type,
                             sync=False):
        cmds = ['tenant %s' % tenant_id]
        counter = 0
        for instance in instance_id_list:
            counter += 1
            cmds.append('no instance id %s' % instance)
            if self._heartbeat_required(sync, counter):
                cmds.append(self.cli_commands[const.CMD_SYNC_HEARTBEAT])

        if self._heartbeat_required(sync):
            cmds.append(self.cli_commands[const.CMD_SYNC_HEARTBEAT])
        self._run_openstack_cmds(cmds, sync=sync)

    def create_instance_bulk(self, tenant_id, neutron_ports, vms,
                             port_profiles, sync=False):
        cmds = ['tenant %s' % tenant_id]
        # Create a reference to function to avoid name lookups in the loop
        append_cmd = cmds.append
        counter = 0
        for vm in vms.values():
            counter += 1

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

                if port_id not in port_profiles:
                    continue

                vnic_type = port_profiles[port_id]['vnic_type']
                network_id = neutron_port['network_id']
                segments = []
                if (self.hpb_supported() and
                        device_owner != n_const.DEVICE_OWNER_DVR_INTERFACE):
                    filters = {'port_id': port_id,
                               'host': v_port['hosts'][0]}
                    segments = db_lib.get_port_binding_level(filters)

                if device_owner == n_const.DEVICE_OWNER_DHCP:
                    if vm['vmId'] != n_const.DEVICE_ID_RESERVED_DHCP_PORT:
                        append_cmd('network id %s' %
                                   neutron_port['network_id'])
                        append_cmd('dhcp id %s hostid %s port-id %s %s' %
                                   (vm['vmId'], v_port['hosts'][0],
                                    neutron_port['id'], port_name))
                        cmds.extend('segment level %d id %s' % (
                            segment.level, segment.segment_id)
                            for segment in segments)
                    else:
                        LOG.info(_LI("Not syncing reserved DHCP port: %s"),
                                 neutron_port['id'])
                elif (device_owner.startswith('compute') or
                      device_owner.startswith('baremetal') or
                      device_owner.startswith('trunk')):
                    if vnic_type == 'baremetal':
                        append_cmd('instance id %s hostid %s type baremetal' %
                                   (vm['vmId'], v_port['hosts'][0]))
                        profile = port_profiles[neutron_port['id']]
                        profile = json.loads(profile['profile'])
                        for binding in profile['local_link_information']:
                            if not binding or not isinstance(binding, dict):
                                # skip all empty entries
                                continue
                            if device_owner.startswith('trunk'):
                                vlan_type = 'allowed'
                            else:
                                vlan_type = 'native'
                            # Ensure that profile contains local link info
                            if binding['switch_id'] and binding['port_id']:
                                if port_name:
                                    cmds.append('port id %s name "%s" '
                                                'network-id %s type %s '
                                                'switch-id %s switchport %s' %
                                                (port_id, port_name,
                                                 network_id, vlan_type,
                                                 binding['switch_id'],
                                                 binding['port_id']))
                                else:
                                    cmds.append('port id %s network-id %s '
                                                'type %s '
                                                'switch-id %s switchport %s' %
                                                (port_id, network_id,
                                                 vlan_type,
                                                 binding['switch_id'],
                                                 binding['port_id']))
                                cmds.extend('segment level %d id %s' % (
                                    segment.level, segment.segment_id)
                                    for segment in segments)

                    else:
                        append_cmd('vm id %s hostid %s' % (vm['vmId'],
                                                           v_port['hosts'][0]))
                        append_cmd('port id %s %s network-id %s' %
                                   (neutron_port['id'], port_name,
                                    neutron_port['network_id']))
                        cmds.extend('segment level %d id %s' % (
                            segment.level, segment.segment_id)
                            for segment in segments)
                elif device_owner == n_const.DEVICE_OWNER_DVR_INTERFACE:
                    if not self.bm_and_dvr_supported():
                        LOG.info(const.ERR_DVR_NOT_SUPPORTED)
                        continue
                    append_cmd('instance id %s type router' % (
                               neutron_port['device_id']))
                    for host in v_port['hosts']:
                        if self.hpb_supported():
                            filters = {'port_id': port_id,
                                       'host': host}
                            segments = db_lib.get_port_binding_level(filters)
                        append_cmd('port id %s network-id %s hostid %s' % (
                                   neutron_port['id'],
                                   neutron_port['network_id'], host))
                        cmds.extend('segment level %d id %s' % (
                            segment.level, segment.segment_id)
                            for segment in segments)
                else:
                    LOG.warning(_LW("Unknown device owner: %s"),
                                neutron_port['device_owner'])

                if self._heartbeat_required(sync, counter):
                    append_cmd(self.cli_commands[const.CMD_SYNC_HEARTBEAT])

        if self._heartbeat_required(sync):
            append_cmd(self.cli_commands[const.CMD_SYNC_HEARTBEAT])

        self._run_openstack_cmds(cmds, sync=sync)

    def delete_tenant_bulk(self, tenant_list, sync=False):
        cmds = []
        for tenant in tenant_list:
            cmds.append('no tenant %s' % tenant)
        if self._heartbeat_required(sync):
            cmds.append(self.cli_commands[const.CMD_SYNC_HEARTBEAT])
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
        self._run_openstack_cmds(['sync interval %d' % self.sync_interval],
                                 sync=sync)
        self._run_eos_cmds(commands=['enable', 'configure', 'cvx',
                                     'service openstack',
                                     'sync-timeout %d' % self.sync_interval])

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
        return self.cli_commands[const.CMD_REGION_SYNC]

    def hpb_supported(self):
        if len(self.cli_commands['features']) == 0:
            self.check_supported_features()
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
            region_cmd = self.cli_commands[const.CMD_REGION_SYNC]

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
                    switchname = neighbors[neighbor]['toPort'][0]['hostname']
                    physnet = switchname if fqdns_used else (
                        switchname.split('.')[0])
                    switch_id = neighbors[neighbor]['toPort'][0].get('hostid')
                    if not switch_id:
                        switch_id = response[1]['hosts'][switchname]['name']
                    break

            # Check if the switch is part of an MLAG pair, and lookup the
            # pair's physnet name if so
            physnet = self.mlag_pairs.get(physnet, physnet)

            for host in response[1]['hosts'].values():
                mac_to_hostname[host['name']] = host['hostname']

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
