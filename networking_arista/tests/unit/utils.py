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

from neutron_lib.api.definitions import portbindings
from neutron_lib.db import api as db_api
from neutron_lib.plugins.ml2 import api as driver_api

from networking_arista.common import db_lib


def setup_arista_wrapper_config(cfg, host='host', user='user'):
    cfg.CONF.set_override('eapi_host', host, "ml2_arista")
    cfg.CONF.set_override('eapi_username', user, "ml2_arista")
    cfg.CONF.set_override('sync_interval', 10, "ml2_arista")
    cfg.CONF.set_override('conn_timeout', 20, "ml2_arista")
    cfg.CONF.set_override('switch_info', ['switch1:user:pass'], "ml2_arista")
    cfg.CONF.set_override('sec_group_support', False, "ml2_arista")


def port_dict_representation(port):
    return {port['portId']: {'device_owner': port['device_owner'],
                             'device_id': port['device_id'],
                             'name': port['name'],
                             'id': port['portId'],
                             'tenant_id': port['tenant_id'],
                             'network_id': port['network_id']}}


def get_network_context(tenant_id, net_id, seg_id, shared=False,
                        session=None):
    network = {'id': net_id,
               'tenant_id': tenant_id,
               'name': net_id,
               'admin_state_up': True,
               'shared': shared}
    network_segments = [{'segmentation_id': seg_id,
                         'id': 'segment_%s' % net_id,
                         'network_type': 'vlan'}]
    return FakeNetworkContext(network, network_segments, network, session)


def get_port_context(tenant_id, net_id, device_id, network, port_id=101,
                     device_owner='compute', status='ACTIVE', session=None):
    port = {'admin_state_up': True,
            'device_id': device_id,
            'device_owner': device_owner,
            'binding:host_id': 'ubuntu1',
            'binding:vnic_type': 'normal',
            'binding:profile': [],
            'tenant_id': tenant_id,
            'id': port_id,
            'network_id': net_id,
            'name': '',
            'status': status,
            'fixed_ips': [],
            'security_groups': None}
    binding_levels = []
    for level, segment in enumerate(network.network_segments):
        binding_levels.append(FakePortBindingLevel(port['id'],
                                                   level,
                                                   'vendor-1',
                                                   segment['id']))
    return FakePortContext(port, dict(port), network, port['status'],
                           binding_levels, session)


def create_network(tenant_id, net_id, seg_id, shared=False):
    session = db_api.get_writer_session()
    ndb = db_lib.NeutronNets()
    net_ctx = get_network_context(tenant_id, net_id, seg_id,
                                  shared=shared, session=session)
    ndb.create_network(net_ctx, {'network': net_ctx.current})
    session.flush()
    return net_ctx


def delete_network(context, network_id):
    ndb = db_lib.NeutronNets()
    ndb.delete_network(context, network_id)
    context.session.flush()


def create_port(tenant_id, net_id, device_id, port_id, network_ctx):
    session = db_api.get_writer_session()
    ndb = db_lib.NeutronNets()
    ndb.set_ipam_backend()
    port_ctx = get_port_context(tenant_id, net_id, device_id,
                                network_ctx, session=session,
                                port_id=port_id)
    ndb.create_port(port_ctx, {'port': port_ctx.current})
    session.flush()
    return port_ctx


def delete_port(context, port_id):
    ndb = db_lib.NeutronNets()
    ndb.set_ipam_backend()
    ndb.delete_port(context, port_id)
    context.session.flush()


class FakeNetworkContext(driver_api.NetworkContext):
    """To generate network context for testing purposes only."""

    def __init__(self, network, segments=None, original_network=None,
                 session=None):
        self._network = network
        self._original_network = original_network
        self._segments = segments
        self.is_admin = False
        self.is_advsvc = False
        self.tenant_id = network['tenant_id']
        self.session = session or db_api.get_reader_session()

    @property
    def current(self):
        return self._network

    @property
    def original(self):
        return self._original_network

    @property
    def network_segments(self):
        return self._segments


class FakePortContext(object):
    """To generate port context for testing purposes only."""

    def __init__(self, port, original_port, network, status,
                 binding_levels, session=None):
        self._plugin_context = None
        self._port = port
        self._original_port = original_port
        self._network_context = network
        self._status = status
        self._binding_levels = binding_levels
        self.is_admin = False
        self.is_advsvc = False
        self.tenant_id = port['tenant_id']
        self.project_id = port['tenant_id']
        self.session = session or db_api.get_reader_session()

    @property
    def current(self):
        return self._port

    @property
    def original(self):
        return self._original_port

    @property
    def network(self):
        return self._network_context

    @property
    def host(self):
        return self._port.get(portbindings.HOST_ID)

    @property
    def original_host(self):
        return self._original_port.get(portbindings.HOST_ID)

    @property
    def status(self):
        return self._status

    @property
    def original_status(self):
        if self._original_port:
            return self._original_port['status']

    @property
    def binding_levels(self):
        if self._binding_levels:
            return [{
                driver_api.BOUND_DRIVER: level.driver,
                driver_api.BOUND_SEGMENT:
                    self._expand_segment(level.segment_id)
            } for level in self._binding_levels]

    @property
    def bottom_bound_segment(self):
        if self._binding_levels:
            return self._expand_segment(self._binding_levels[-1].segment_id)

    def _expand_segment(self, segment_id):
        for segment in self._network_context.network_segments:
            if segment[driver_api.ID] == segment_id:
                return segment


class FakePortBindingLevel(object):
    """Port binding object for testing purposes only."""

    def __init__(self, port_id, level, driver, segment_id):
        self.port_id = port_id
        self.level = level
        self.driver = driver
        self.segment_id = segment_id
