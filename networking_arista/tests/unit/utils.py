# Copyright (c) 2017 OpenStack Foundation
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
import re

from oslo_log import log as logging

from neutron_lib import constants as n_const
from neutron_lib.db import api as db_api

from neutron.db.models import segment as segment_models
from neutron.db import models_v2
from neutron.plugins.ml2 import models as ml2_models
from neutron.services.trunk import constants as t_const
from neutron.services.trunk import models as t_models

from networking_arista.common import config  # noqa
from networking_arista.ml2 import arista_resources as resources

LOG = logging.getLogger(__name__)


def setup_arista_wrapper_config(cfg, host='host', user='user'):
    cfg.CONF.set_override('eapi_host', host, "ml2_arista")
    cfg.CONF.set_override('eapi_username', user, "ml2_arista")
    cfg.CONF.set_override('sync_interval', 1, "ml2_arista")
    cfg.CONF.set_override('conn_timeout', 20, "ml2_arista")
    cfg.CONF.set_override('switch_info', ['switch1:user:pass'], "ml2_arista")
    cfg.CONF.set_override('sec_group_support', False, "ml2_arista")


class MockCvx(object):

    def __init__(self, region):
        whitelist = ['AristaResourcesBase',
                     'PortResourcesBase',
                     'AttributeFormatter']
        self.endpoint_data = {}
        self.endpoint_to_id = {}
        self.endpoint_to_class = {}
        self.region = region
        for cls in resources.__dict__.values():
            if (isinstance(cls, type) and
                    cls.__module__ == resources.__name__ and
                    cls.__name__ not in whitelist):
                region_endpoint = cls.endpoint % {'region': region}
                self.endpoint_data[region_endpoint] = {}
                self.endpoint_to_id[region_endpoint] = cls.id_key
                self.endpoint_to_class[region_endpoint] = cls

    def send_api_request(self, endpoint, request_type, data=None):
        if request_type != 'GET':
            LOG.debug("%(type)s %(endpoint)s %(data)s", {'type': request_type,
                                                         'endpoint': endpoint,
                                                         'data': data})
        if request_type == 'POST':
            for resource in data:
                endpoint_class = self.endpoint_to_class[endpoint]
                for key in endpoint_class.get_resource_ids(resource):
                    self.endpoint_data[endpoint][key] = resource
        elif request_type == 'GET':
            return self.endpoint_data[endpoint].values()
        elif request_type == 'DELETE':
            for resource in data:
                endpoint_class = self.endpoint_to_class[endpoint]
                for key in endpoint_class.get_resource_ids(resource):
                    try:
                        del self.endpoint_data[endpoint][key]
                    except KeyError:
                        pass

    def get_cvx_uuid(self):
        return None

    def sync_start(self):
        return True

    def sync_end(self):
        return True


class MockSwitch(object):

    def __init__(self):
        self._commands = []
        self._vrfs = dict()
        self._svis = dict()
        self._vlans = dict()
        self._acl_mode_re = re.compile('^(?P<delete>no )?ip access-list '
                                       '(?P<acl>\S+)(?P<dyn> dynamic)?$')
        self._interface_mode_re = re.compile(
            '^(?P<delete>no )?interface (?P<intf>.+)$')
        self._access_group_re = re.compile(
            '^(?P<delete>no )?ip access-group (?P<acl>\S+) (?P<dir>\S+)$')
        self._vrf_mode_re = re.compile(
            '^(?P<delete>no )?vrf definition (?P<name>\S+)$')
        self._vlan_re = re.compile('^(?P<delete>no )?vlan (?P<vlan>\d+)$')
        self._ip_address_re = re.compile(
            '^ip address (?P<ip>[\d.]+)/(?P<mask>\d+)$')
        self._vip_re = re.compile('^ip virtual-router address (?P<ip>[\d.]+)$')
        self._svi_vrf_re = re.compile('^vrf forwarding (?P<vrf>\S+)$')
        self._rd_re = re.compile('^rd (?P<rd>\S+)$')
        self._varp_mac_re = re.compile(
            '^ip virtual-router mac-address (?P<varp_mac>\S+)$')
        self._mode = None

    def execute(self, commands, commands_to_log=None):
        ret = []
        for command in commands:
            if command == 'show vlan':
                vlans = {'vlans': {}}
                for vlan, info in self._vlans.items():
                    vlans['vlans'][str(vlan)] = {'dynamic': info['dynamic']}
                ret.append(vlans)
            elif command == 'show interfaces vlan 1-$':
                svis = {'interfaces': {}}
                for intf, svi in self._svis.items():
                    svis['interfaces']['Vlan%s' % intf.strip('vlan ')] = {
                        'interfaceAddress': [
                            {'primaryIp': {'maskLen': svi['mask'],
                                           'address': svi['ip']}}]}
                ret.append(svis)
            elif command == 'show vrf':
                vrfs = {'vrfs': {}}
                for vrf_name, vrf in self._vrfs.items():
                    vrfs['vrfs'][vrf_name] = {'interfaces': vrf['svis'],
                                              'routeDistinguisher': vrf['rd']}
                ret.append(vrfs)
            elif command == 'enable':
                ret.append({})
            elif 'show' in command:
                pass
            elif 'interface' in command:
                intf_match = self._interface_mode_re.match(command)
                intf = intf_match.group('intf')
                if intf_match.group('delete'):
                    del self._svis[intf]
                else:
                    if 'vlan' in intf:
                        self._svis[intf] = {'ip': '',
                                            'mask': '',
                                            'vip': ''}
                    self._mode = ('interface', intf)
            elif 'vrf definition' in command:
                vrf_match = self._vrf_mode_re.match(command)
                delete = vrf_match.group('delete')
                vrf_name = vrf_match.group('name')
                if delete:
                    del self._vrfs[vrf_name]
                else:
                    self._vrfs[vrf_name] = {'svis': []}
                    self._mode = ('vrf', vrf_name)
            elif 'vlan' in command:
                self._parse_vlan(command)
            elif command == 'exit':
                self._mode = None
            else:
                if self._mode:
                    if self._mode[0] == 'interface':
                        self._parse_svi(command)
                    elif self._mode[0] == 'vrf':
                        self._parse_vrf(command)
            self._commands.append(command)
        return ret

    def _parse_svi(self, command):
        ip_addr_match = self._ip_address_re.match(command)
        if ip_addr_match:
            self._svis[self._mode[1]]['ip'] = ip_addr_match.group('ip')
            self._svis[self._mode[1]]['mask'] = ip_addr_match.group('mask')
        vip_match = self._vip_re.match(command)
        if vip_match:
            self._svis[self._mode[1]]['vip'] = vip_match.group('ip')
        vrf_match = self._svi_vrf_re.match(command)
        if vrf_match:
            self._vrfs[vrf_match.group('vrf')]['svis'].append(self._mode[1])

    def _parse_vrf(self, command):
        rd_match = self._rd_re.match(command)
        if rd_match:
            self._vrfs[self._mode[1]]['rd'] = rd_match.group('rd')
        varp_mac_match = self._varp_mac_re.match(command)
        if varp_mac_match:
            pass

    def _parse_vlan(self, command):
        vlan_match = self._vlan_re.match(command)
        delete = vlan_match.group('delete')
        vlan = vlan_match.group('vlan')
        if delete:
            del self._vlans[vlan]
        else:
            self._vlans[vlan] = {'dynamic': False}

    @property
    def received_commands(self):
        return self._commands

    def clear_received_commands(self):
        self._commands = []

    def reset_switch(self):
        self._commands = []
        self._vrfs = dict()
        self._svis = dict()
        self._vlans = dict()


# Network utils #


def create_networks(networks):
    session = db_api.get_writer_session()
    with session.begin():
        for network in networks:
            session.add(models_v2.Network(**network))


def delete_network(network_id):
    session = db_api.get_writer_session()
    with session.begin():
        network_model = models_v2.Network
        session.query(network_model).filter(
            network_model.id == network_id).delete()


def delete_networks_for_tenant(tenant_id):
    session = db_api.get_writer_session()
    with session.begin():
        network_model = models_v2.Network
        networks = session.query(network_model).filter(
            network_model.project_id == tenant_id).all()
        for network in networks:
            delete_ports_on_network(network.id)
            session.delete(network)


# Segment utils #


def create_segments(segments):
    session = db_api.get_writer_session()
    with session.begin():
        for segment in segments:
            session.add(segment_models.NetworkSegment(**segment))


def delete_segment(segment_id):
    session = db_api.get_writer_session()
    with session.begin():
        segment_model = segment_models.NetworkSegment
        session.query(segment_model).filter(
            segment_model.id == segment_id).delete()


def delete_segments_for_network(network_id):
    session = db_api.get_writer_session()
    with session.begin():
        segment_model = segment_models.NetworkSegment
        session.query(segment_model).filter(
            segment_model.network_id == network_id).delete()


def delete_segments_for_tenant(tenant_id):
    session = db_api.get_writer_session()
    network_model = models_v2.Network
    segment_model = segment_models.NetworkSegment
    with session.begin():
        networks = session.query(network_model).filter(
            network_model.project_id == tenant_id).all()
        for network in networks:
            session.query(segment_model).filter(
                segment_model.network_id == network.id).delete()


# Port utils #


def create_ports(ports):
    session = db_api.get_writer_session()
    with session.begin():
        for port in ports:
            binding_levels = port.pop('binding_levels', [])
            binding = port.pop('binding', {})
            session.add(models_v2.Port(**port))
            if binding:
                binding['port_id'] = port['id']
                if binding['vif_type'] == 'distributed':
                    distributed_binding = binding.copy()
                    distributed_binding['status'] = 'ACTIVE'
                    for host in binding['host']:
                        distributed_binding['host'] = host
                        session.add(
                            ml2_models.DistributedPortBinding(
                                **distributed_binding))
                else:
                    session.add(ml2_models.PortBinding(**binding))
            for binding_level in binding_levels:
                binding_level['port_id'] = port['id']
                session.add(ml2_models.PortBindingLevel(**binding_level))


def delete_port(port_id):
    session = db_api.get_writer_session()
    with session.begin():
        port_model = models_v2.Port
        session.query(port_model).filter(
            port_model.id == port_id).delete()


def delete_ports_on_network(network_id):
    session = db_api.get_writer_session()
    with session.begin():
        port_model = models_v2.Port
        session.query(port_model).filter(
            port_model.network_id == network_id).delete()


def delete_ports_for_instance(instance_id):
    session = db_api.get_writer_session()
    with session.begin():
        port_model = models_v2.Port
        session.query(port_model).filter(
            port_model.device_id == instance_id).delete()


def delete_ports_for_tenant(tenant_id):
    session = db_api.get_writer_session()
    with session.begin():
        port_model = models_v2.Port
        session.query(port_model).filter(
            port_model.project_id == tenant_id).delete()


# Port binding utils #


def delete_port_binding(port_id, host):
    session = db_api.get_writer_session()
    with session.begin():
        # We cannot do any bulk deletes here because every delete bumps the
        # revision number of the Port
        pbl_model = ml2_models.PortBindingLevel
        levels = (session.query(pbl_model)
                  .filter(pbl_model.port_id == port_id,
                          pbl_model.host == host))
        for level in levels:
            session.delete(level)
        pb_model = ml2_models.PortBinding
        bindings = (session.query(pb_model)
                    .filter(pb_model.port_id == port_id,
                            pb_model.host == host))
        for binding in bindings:
            session.delete(binding)
        dpb_model = ml2_models.DistributedPortBinding
        bindings = (session.query(dpb_model)
                    .filter(dpb_model.port_id == port_id,
                            dpb_model.host == host))
        for binding in bindings:
            session.delete(binding)


def remove_switch_binding(port_id, switch_id, intf_id):
    session = db_api.get_writer_session()
    with session.begin():
        pb_model = ml2_models.PortBinding
        binding = (session.query(pb_model)
                   .filter(pb_model.port_id == port_id).first())
        profile = json.loads(binding.profile)
        lli = profile['local_link_information']
        for idx, link in enumerate(lli):
            if link['switch_id'] == switch_id and link['port_id'] == intf_id:
                lli.pop(idx)
                break
        binding.profile = json.dumps(profile)
    if len(lli) == 0:
        delete_port_binding(port_id, binding.host)


# Trunk utils #


def create_trunks(trunks):
    session = db_api.get_writer_session()
    with session.begin():
        for trunk in trunks:
            session.add(t_models.Trunk(**trunk))


def create_subports(subports):
    session = db_api.get_writer_session()
    with session.begin():
        for subport in subports:
            session.add(t_models.SubPort(**subport))


def setup_scenario():
    # Create networks
    regular_network = {'id': 'n1',
                       'project_id': 't1',
                       'name': 'regular',
                       'admin_state_up': True,
                       'rbac_entries': []}
    hpb_network = {'id': 'n2',
                   'project_id': 't2',
                   'name': 'hpb',
                   'admin_state_up': True,
                   'rbac_entries': []}

    # Create segments
    flat_segment = {'id': 'sError',
                    'network_id': 'n1',
                    'is_dynamic': False,
                    'network_type': 'flat'}
    regular_segment = {'id': 's1',
                       'network_id': 'n1',
                       'is_dynamic': False,
                       'segmentation_id': 11,
                       'network_type': 'vlan',
                       'physical_network': 'default'}
    fabric_segment = {'id': 's2',
                      'network_id': 'n2',
                      'is_dynamic': False,
                      'segmentation_id': 20001,
                      'network_type': 'vxlan',
                      'physical_network': None}
    dynamic_segment1 = {'id': 's3',
                        'network_id': 'n2',
                        'is_dynamic': True,
                        'segmentation_id': 21,
                        'network_type': 'vlan',
                        'physical_network': 'switch1'}
    dynamic_segment2 = {'id': 's4',
                        'network_id': 'n2',
                        'is_dynamic': True,
                        'segmentation_id': 31,
                        'network_type': 'vlan',
                        'physical_network': 'switch2'}
    # Create ports
    port_ctr = 0
    ports = list()
    trunk_ctr = 0
    trunks = list()
    subports = list()
    instance_types = [(n_const.DEVICE_OWNER_DHCP, 'normal'),
                      (n_const.DEVICE_OWNER_DVR_INTERFACE, 'normal'),
                      (n_const.DEVICE_OWNER_COMPUTE_PREFIX, 'normal'),
                      (n_const.DEVICE_OWNER_COMPUTE_PREFIX, 'baremetal'),
                      (n_const.DEVICE_OWNER_BAREMETAL_PREFIX, 'baremetal')]
    for device_owner, vnic_type in instance_types:
        vif_type = 'ovs'
        regular_host = 'host1'
        regular_binding_levels = [
            {'host': 'host1',
             'segment_id': regular_segment['id'],
             'level': 0,
             'driver': 'arista'}]
        hpb_binding_levels = [
            {'host': 'host2',
             'segment_id': fabric_segment['id'],
             'level': 0,
             'driver': 'arista'},
            {'host': 'host2',
             'segment_id': dynamic_segment1['id'],
             'level': 1,
             'driver': 'arista'}]
        hpb_host = 'host2'
        binding_profile = ''
        if vnic_type == 'baremetal':
            binding_profile = ('{"local_link_information": ' +
                               '[{"switch_id": "00:11:22:33:44:55", ' +
                               '"port_id": "Ethernet1"}, ' +
                               '{"switch_id": "00:11:22:33:44:55", ' +
                               '"port_id": "Ethernet2"}, ' +
                               '{"switch_id": "55:44:33:22:11:00", ' +
                               '"port_id": "Ethernet1/1"}, ' +
                               '{"switch_id": "55:44:33:22:11:00", ' +
                               '"port_id": "Ethernet1/2"}]}')

        if device_owner == n_const.DEVICE_OWNER_DVR_INTERFACE:
            vif_type = 'distributed'
            regular_host = ['host1', 'host2']
            regular_binding_levels = [
                {'host': 'host1',
                 'segment_id': regular_segment['id'],
                 'level': 0,
                 'driver': 'arista'},
                {'host': 'host2',
                 'segment_id': regular_segment['id'],
                 'level': 0,
                 'driver': 'arista'}]
            hpb_binding_levels = [
                {'host': 'host1',
                 'segment_id': fabric_segment['id'],
                 'level': 0,
                 'driver': 'arista'},
                {'host': 'host1',
                 'segment_id': dynamic_segment1['id'],
                 'level': 1,
                 'driver': 'arista'},
                {'host': 'host2',
                 'segment_id': fabric_segment['id'],
                 'level': 0,
                 'driver': 'arista'},
                {'host': 'host2',
                 'segment_id': dynamic_segment2['id'],
                 'level': 1,
                 'driver': 'arista'}]
            hpb_host = ['host1', 'host2']

        port_ctr += 1
        regular_port = {'admin_state_up': True,
                        'status': 'ACTIVE',
                        'device_id': '%s%s1' % (device_owner, vnic_type),
                        'device_owner': device_owner,
                        'binding': {'host': regular_host,
                                    'vif_type': vif_type,
                                    'vnic_type': vnic_type,
                                    'profile': binding_profile},
                        'tenant_id': 't1',
                        'id': 'p%d' % port_ctr,
                        'network_id': regular_network['id'],
                        'mac_address': '00:00:00:00:00:%02x' % port_ctr,
                        'name': 'regular_port',
                        'binding_levels': regular_binding_levels}
        port_ctr += 1
        hpb_port = {'admin_state_up': True,
                    'status': 'ACTIVE',
                    'device_id': '%s%s2' % (device_owner, vnic_type),
                    'device_owner': device_owner,
                    'binding': {'host': hpb_host,
                                'vif_type': vif_type,
                                'vnic_type': vnic_type,
                                'profile': binding_profile},
                    'tenant_id': 't2',
                    'id': 'p%d' % port_ctr,
                    'network_id': hpb_network['id'],
                    'mac_address': '00:00:00:00:00:%02x' % port_ctr,
                    'name': 'hpb_port',
                    'binding_levels': hpb_binding_levels}
        ports.extend([regular_port, hpb_port])
        if device_owner == n_const.DEVICE_OWNER_COMPUTE_PREFIX:
            port_ctr += 1
            trunk_subport = {'admin_state_up': True,
                             'status': 'ACTIVE',
                             'device_id': '%s%s1' % (device_owner, vnic_type),
                             'device_owner': t_const.TRUNK_SUBPORT_OWNER,
                             'binding': {'host': regular_host,
                                         'vif_type': vif_type,
                                         'vnic_type': vnic_type,
                                         'profile': binding_profile},
                             'tenant_id': 't1',
                             'id': 'p%d' % port_ctr,
                             'network_id': regular_network['id'],
                             'mac_address': '10:00:00:00:00:%02x' % port_ctr,
                             'name': 'trunk_subport',
                             'binding_levels': regular_binding_levels}
            ports.extend([trunk_subport])
            trunk = {'id': 't%d' % trunk_ctr,
                     'port_id': regular_port['id']}
            subport = {'port_id': trunk_subport['id'],
                       'trunk_id': trunk['id'],
                       'segmentation_type': 'vlan',
                       'segmentation_id': 100}
            trunk_ctr += 1
            trunks.append(trunk)
            subports.append(subport)

    create_networks([regular_network, hpb_network])
    create_segments([regular_segment, fabric_segment, flat_segment,
                     dynamic_segment1, dynamic_segment2])
    create_ports(ports)
    create_trunks(trunks)
    create_subports(subports)
