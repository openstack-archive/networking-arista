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

from oslo_log import log as logging
import requests
import six

from neutron_lib.api.definitions import portbindings

from networking_arista._i18n import _, _LI, _LW, _LE
from networking_arista.common import constants as const
from networking_arista.common import exceptions as arista_exc
from networking_arista.common import utils
from networking_arista.ml2.rpc.base import AristaRPCWrapperBase

LOG = logging.getLogger(__name__)


class AristaRPCWrapperEapi(AristaRPCWrapperBase):
    def __init__(self):
        super(AristaRPCWrapperEapi, self).__init__()
        # The cli_commands dict stores the mapping between the CLI command key
        # and the actual CLI command.
        self.cli_commands = {
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
        if sync:
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

    def get_baremetal_physnet(self, context):
        """Returns dictionary which contains mac to hostname mapping"""
        port = context.current
        host_id = context.host
        cmd = ['show network physical-topology hosts']
        try:
            response = self._run_eos_cmds(cmd)
            binding_profile = port.get(portbindings.PROFILE, {})
            link_info = binding_profile.get('local_link_information', [])
            for link in link_info:
                switch_id = link.get('switch_id')
                for host in response[0]['hosts'].values():
                    if switch_id == host['name']:
                        physnet = host['hostname']
                        LOG.debug("get_physical_network: Physical Network for "
                                  "%(host)s is %(physnet)s",
                                  {'host': host_id, 'physnet': physnet})
                        return physnet
            LOG.debug("Physical network not found for %(host)s",
                      {'host': host_id})
        except Exception as exc:
            LOG.error(_LE('command %(cmd)s failed with '
                      '%(exc)s'), {'cmd': cmd, 'exc': exc})
        return None

    def get_host_physnet(self, context):
        """Returns dictionary which contains physical topology information

        for a given host_id
        """
        host_id = utils.hostname(context.host)
        cmd = ['show network physical-topology neighbors']
        try:
            response = self._run_eos_cmds(cmd)
            # Get response for 'show network physical-topology neighbors'
            # command
            neighbors = response[0]['neighbors']
            for neighbor in neighbors:
                if host_id in neighbor:
                    physnet = neighbors[neighbor]['toPort'][0]['hostname']
                    LOG.debug("get_physical_network: Physical Network for "
                              "%(host)s is %(physnet)s", {'host': host_id,
                                                          'physnet': physnet})
                    return physnet
            LOG.debug("Physical network not found for %(host)s",
                      {'host': host_id})
        except Exception as exc:
            LOG.error(_LE('command %(cmd)s failed with '
                      '%(exc)s'), {'cmd': cmd, 'exc': exc})
        return None
