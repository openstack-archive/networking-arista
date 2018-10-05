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

from neutron_lib import constants as n_const
from oslo_log import log as logging
from oslo_utils import excutils
import requests
import six

from networking_arista._i18n import _, _LI, _LW, _LE
from networking_arista.common import constants as const
from networking_arista.common import db_lib
from networking_arista.common import exceptions as arista_exc
from networking_arista.ml2.rpc.base import AristaRPCWrapperBase

LOG = logging.getLogger(__name__)


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
                LOG.warning(_LW('Unrecognized HTTP method %s'), method)
                return None

            resp = func(url, timeout=self.conn_timeout, verify=False,
                        data=data, headers=request_headers)
            msg = (_LI('JSON response contains: %(code)s %(resp)s') %
                   {'code': resp.status_code,
                   'resp': resp.json()})
            LOG.info(msg)
            if resp.ok:
                return resp.json()
            else:
                raise arista_exc.AristaRpcError(msg=resp.json().get('error'))
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
            msg = six.text_type(error)
            LOG.warning(msg)
            # reraise the exception
            with excutils.save_and_reraise_exception() as ctxt:
                ctxt.reraise = True
        return {} if method == 'GET' else None

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
            msg = six.text_type("Could not find CVX leader")
            LOG.info(msg)
            self.set_cvx_unavailable()
            raise arista_exc.AristaRpcError(msg=msg)
        self.set_cvx_available()
        return self._send_request(host, path, method, data, sanitized_data)

    def _set_region_update_interval(self):
        path = 'region/%s' % self.region
        data = {
            'name': self.region,
            'syncInterval': self.sync_interval
        }
        self._send_api_request(path, 'PUT', [data])

    def register_with_eos(self, sync=False):
        self.create_region(self.region)
        self._set_region_update_interval()

    def check_supported_features(self):
        # We don't use this function as we know the features
        # that are available once using this API.
        pass

    def bm_and_dvr_supported(self):
        return True

    def get_region_updated_time(self):
        path = 'agent/'
        try:
            data = self._send_api_request(path, 'GET')
            return {'regionTimestamp': data.get('uuid', '')}
        except arista_exc.AristaRpcError:
            return {'regionTimestamp': ''}

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
        path = 'region/%s' % name
        try:
            regions = self._send_api_request(path, 'GET')
            for region in regions:
                if region['name'] == name:
                    return region
        except arista_exc.AristaRpcError:
            pass
        return None

    def sync_supported(self):
        return True

    def hpb_supported(self):
        return True

    def sync_start(self):
        self.current_sync_name = None
        try:
            region = self.get_region(self.region)

            # If the region doesn't exist, we may need to create
            # it in order for POSTs to the sync endpoint to succeed
            if not region:
                self.register_with_eos()
                return False

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

            dhcps = self.get_dhcps_for_tenant(ten['tenantId'])
            dhcpsDict = dict((v['id'], v) for v in dhcps)
            ten['tenantVmInstances'].update(dhcpsDict)

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
                if segment['network_type'] == const.NETWORK_TYPE_FLAT:
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
                          name, instance_type, hosts, device_owner=None):

        vlan_type = 'allowed'
        if instance_type in const.InstanceType.BAREMETAL_INSTANCE_TYPES:
            vlan_type = 'native'
            if device_owner and device_owner.startswith('trunk'):
                vlan_type = 'allowed'

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
                             port_profiles, sync=False):
        self._create_tenant_if_needed(tenant_id)

        vmInst = {}
        dhcpInst = {}
        baremetalInst = {}
        routerInst = {}
        portInst = []
        networkSegments = {}
        portBindings = {}

        for vm in vms.values():
            if vm['vmId'] == n_const.DEVICE_ID_RESERVED_DHCP_PORT:
                continue
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

                if port_id not in port_profiles:
                    continue

                vnic_type = port_profiles[port_id]['vnic_type']
                if device_owner == n_const.DEVICE_OWNER_DHCP:
                    instance_type = const.InstanceType.DHCP
                    if inst_id not in dhcpInst:
                        dhcpInst[inst_id] = instance
                elif (device_owner.startswith('compute') or
                      device_owner.startswith('baremetal') or
                      device_owner.startswith('trunk')):
                    if vnic_type == 'baremetal':
                        instance_type = const.InstanceType.BAREMETAL
                        if inst_id not in baremetalInst:
                            baremetalInst[inst_id] = instance
                    else:
                        instance_type = const.InstanceType.VM
                        if inst_id not in vmInst:
                            vmInst[inst_id] = instance
                elif device_owner == n_const.DEVICE_OWNER_DVR_INTERFACE:
                    instance_type = const.InstanceType.ROUTER
                    if inst_id not in routerInst:
                        routerInst[inst_id] = instance
                else:
                    LOG.warning(_LW("Unknown device owner: %s"),
                                neutron_port['device_owner'])
                    continue

                network_id = neutron_port['network_id']
                if port_id not in networkSegments:
                    networkSegments[port_id] = (
                        db_lib.get_network_segments_by_port_id(port_id))

                port = self._create_port_data(port_id, tenant_id,
                                              network_id, inst_id,
                                              neutron_port.get('name'),
                                              instance_type, v_port['hosts'],
                                              device_owner)
                portInst.append(port)

                if instance_type in const.InstanceType.VIRTUAL_INSTANCE_TYPES:
                    portBinding = self._get_host_bindings(
                        port_id, inst_host, network_id,
                        networkSegments[port_id])
                elif (instance_type in
                      const.InstanceType.BAREMETAL_INSTANCE_TYPES):
                    switch_profile = json.loads(port_profiles[
                                                port_id]['profile'])
                    portBinding = self._get_switch_bindings(
                        port_id, inst_host, network_id,
                        switch_profile['local_link_information'],
                        networkSegments[port_id])
                if port_id not in portBindings:
                    portBindings[port_id] = portBinding
                else:
                    portBindings[port_id] += portBinding

        # create instances first
        if vmInst:
            path = 'region/' + self.region + '/vm?tenantId=' + tenant_id
            self._send_api_request(path, 'POST', list(vmInst.values()))
        if dhcpInst:
            path = 'region/' + self.region + '/dhcp?tenantId=' + tenant_id
            self._send_api_request(path, 'POST', list(dhcpInst.values()))
        if baremetalInst:
            path = 'region/' + self.region + '/baremetal?tenantId=' + tenant_id
            self._send_api_request(path, 'POST', list(baremetalInst.values()))
        if routerInst:
            path = 'region/' + self.region + '/router?tenantId=' + tenant_id
            self._send_api_request(path, 'POST', list(routerInst.values()))

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
        self.delete_instance_bulk(tenant_id, vm_id_list, const.InstanceType.VM)

    def delete_dhcp_bulk(self, tenant_id, dhcp_id_list, sync=False):
        self.delete_instance_bulk(tenant_id, dhcp_id_list,
                                  const.InstanceType.DHCP, sync)

    def delete_port(self, port_id, instance_id, instance_type,
                    device_owner=None):
        path = ('region/%s/port?portId=%s&id=%s&type=%s' %
                (self.region, port_id, instance_id, instance_type))
        port = self._create_port_data(port_id, None, None, instance_id,
                                      None, instance_type, None,
                                      device_owner)
        return self._send_api_request(path, 'DELETE', [port])

    def get_instance_ports(self, instance_id, instance_type):
        path = ('region/%s/port?id=%s&type=%s' %
                (self.region, instance_id, instance_type))
        return self._send_api_request(path, 'GET')

    def plug_port_into_network(self, device_id, host_id, port_id,
                               net_id, tenant_id, port_name, device_owner,
                               sg, orig_sg, vnic_type, segments,
                               switch_bindings=None, trunk_details=None):
        device_type = ''
        if device_owner == n_const.DEVICE_OWNER_DHCP:
            device_type = const.InstanceType.DHCP
        elif (device_owner.startswith('compute')
              or device_owner.startswith('baremetal')
              or device_owner.startswith('trunk')):
            if vnic_type == 'baremetal':
                device_type = const.InstanceType.BAREMETAL
            else:
                device_type = const.InstanceType.VM
        elif device_owner == n_const.DEVICE_OWNER_DVR_INTERFACE:
            device_type = const.InstanceType.ROUTER
        else:
            LOG.info(_LI('Unsupported device owner: %s'), device_owner)
            return

        self._create_tenant_if_needed(tenant_id)
        instance = self._create_instance_data(device_id, host_id)
        port = self._create_port_data(port_id, tenant_id, net_id, device_id,
                                      port_name, device_type, [host_id],
                                      device_owner)
        url = 'region/%(region)s/%(device_type)s?tenantId=%(tenant_id)s' % {
              'region': self.region,
              'device_type': device_type,
              'tenant_id': tenant_id,
        }
        self._send_api_request(url, 'POST', [instance])
        self._send_api_request('region/' + self.region + '/port', 'POST',
                               [port])
        if trunk_details and trunk_details.get('sub_ports'):
            for subport in trunk_details['sub_ports']:
                subport_id = subport['port_id']
                subport_net_id = self._ndb.get_network_id_from_port_id(
                    subport_id)
                subport_name = 'name_%s' % subport_id
                sub_device_owner = 'trunk:subport'
                port = self._create_port_data(subport_id, tenant_id,
                                              subport_net_id, device_id,
                                              subport_name, device_type,
                                              [host_id], sub_device_owner)

                self._send_api_request('region/' + self.region + '/port',
                                       'POST', [port])
        if device_type in const.InstanceType.VIRTUAL_INSTANCE_TYPES:
            self.bind_port_to_host(port_id, host_id, net_id, segments)
            if trunk_details and trunk_details.get('sub_ports'):
                for subport in trunk_details['sub_ports']:
                    subport_id = subport['port_id']
                    subport_net_id = self._ndb.get_network_id_from_port_id(
                        subport_id)
                    sub_segments = db_lib.get_network_segments_by_port_id(
                        subport_id)
                    self.bind_port_to_host(subport_id, host_id,
                                           subport_net_id, sub_segments)
        elif device_type in const.InstanceType.BAREMETAL_INSTANCE_TYPES:
            self.bind_port_to_switch_interface(port_id, host_id, net_id,
                                               switch_bindings, segments)
            if trunk_details and trunk_details.get('sub_ports'):
                for subport in trunk_details['sub_ports']:
                    subport_id = subport['port_id']
                    subport_net_id = self._ndb.get_network_id_from_port_id(
                        subport_id)
                    sub_segments = db_lib.get_network_segments_by_port_id(
                        subport_id)
                    self.bind_port_to_switch_interface(subport_id, host_id,
                                                       subport_net_id,
                                                       switch_bindings,
                                                       sub_segments)
            if sg:
                self.apply_security_group(sg, switch_bindings)
            else:
                # Security group was removed. Clean up the existing security
                # groups.
                if orig_sg:
                    self.remove_security_group(orig_sg, switch_bindings)

    def unplug_port_from_network(self, device_id, device_owner, hostname,
                                 port_id, network_id, tenant_id, sg, vnic_type,
                                 switch_bindings=None, trunk_details=None):
        device_type = ''
        if device_owner == n_const.DEVICE_OWNER_DHCP:
            device_type = const.InstanceType.DHCP
        elif (device_owner.startswith('compute') or
              device_owner.startswith('baremetal') or
              device_owner.startswith('trunk')):
            if vnic_type == 'baremetal':
                device_type = const.InstanceType.BAREMETAL
            else:
                device_type = const.InstanceType.VM
        elif device_owner == n_const.DEVICE_OWNER_DVR_INTERFACE:
            device_type = const.InstanceType.ROUTER
        else:
            LOG.info(_LI('Unsupported device owner: %s'), device_owner)
            return

        if device_type in const.InstanceType.VIRTUAL_INSTANCE_TYPES:
            if trunk_details and trunk_details.get('sub_ports'):
                for subport in trunk_details['sub_ports']:
                    subport_id = subport['port_id']
                    subport_device_owner = 'trunk:subport'
                    self.unbind_port_from_host(subport_id, hostname)
                    self.delete_port(subport_id, device_id, device_type,
                                     subport_device_owner)
            self.unbind_port_from_host(port_id, hostname)
        elif device_type in const.InstanceType.BAREMETAL_INSTANCE_TYPES:
            if trunk_details and trunk_details.get('sub_ports'):
                for subport in trunk_details['sub_ports']:
                    subport_id = subport['port_id']
                    subport_device_owner = 'trunk:subport'
                    self.unbind_port_from_switch_interface(subport_id,
                                                           hostname,
                                                           switch_bindings)
                    self.delete_port(subport_id, device_id, device_type,
                                     subport_device_owner)
            self.unbind_port_from_switch_interface(port_id, hostname,
                                                   switch_bindings)
        self.delete_port(port_id, device_id, device_type, device_owner)
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
