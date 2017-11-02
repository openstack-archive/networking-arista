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

from neutron_lib import constants as n_const
from neutron_lib import context as nctx
from neutron_lib.plugins.ml2 import api as driver_api

import neutron.db.api as db
from neutron.db import db_base_plugin_v2
from neutron.db.models import segment as segment_models
from neutron.db import models_v2
from neutron.db import securitygroups_db as sec_db
from neutron.db import segments_db
from neutron.plugins.ml2 import models as ml2_models
from neutron.services.trunk import models as trunk_models

from networking_arista.common import utils

VLAN_SEGMENTATION = 'vlan'


def get_instance_ports(tenant_id, manage_fabric=True, managed_physnets=None):
    """Returns all instance ports for a given tenant."""
    session = db.get_reader_session()
    with session.begin():
        # hack for pep8 E711: comparison to None should be
        # 'if cond is not None'
        none = None
        port_model = models_v2.Port
        binding_level_model = ml2_models.PortBindingLevel
        segment_model = segment_models.NetworkSegment
        all_ports = (session
                     .query(port_model, binding_level_model, segment_model)
                     .join(binding_level_model)
                     .join(segment_model)
                     .filter(port_model.tenant_id == tenant_id,
                             binding_level_model.host != none,
                             port_model.device_id != none,
                             port_model.network_id != none))
        if not manage_fabric:
            all_ports = all_ports.filter(
                segment_model.physical_network != none)
        if managed_physnets is not None:
            managed_physnets.append(None)
            all_ports = all_ports.filter(segment_model.physical_network.in_(
                managed_physnets))

        def eos_port_representation(port):
            return {u'portId': port.id,
                    u'deviceId': port.device_id,
                    u'hosts': set([bl.host for bl in port.binding_levels]),
                    u'networkId': port.network_id}

        ports = {}
        for port in all_ports:
            if not utils.supported_device_owner(port.Port.device_owner):
                continue
            ports[port.Port.id] = eos_port_representation(port.Port)

        vm_dict = dict()

        def eos_vm_representation(port):
            return {u'vmId': port['deviceId'],
                    u'baremetal_instance': False,
                    u'ports': {port['portId']: port}}

        for port in ports.values():
            deviceId = port['deviceId']
            if deviceId in vm_dict:
                vm_dict[deviceId]['ports'][port['portId']] = port
            else:
                vm_dict[deviceId] = eos_vm_representation(port)
        return vm_dict


def get_instances(tenant):
    """Returns set of all instance ids that may be relevant on CVX."""
    session = db.get_reader_session()
    with session.begin():
        port_model = models_v2.Port
        return set(device_id[0] for device_id in
                   session.query(port_model.device_id).
                   filter(port_model.tenant_id == tenant).distinct())


def tenant_provisioned(tid):
    """Returns true if any networks or ports exist for a tenant."""
    session = db.get_reader_session()
    with session.begin():
        network_model = models_v2.Network
        port_model = models_v2.Port
        res = bool(
            session.query(network_model).filter_by(tenant_id=tid).count() or
            session.query(port_model).filter_by(tenant_id=tid).count()
        )
    return res


def get_tenants():
    """Returns list of all project/tenant ids that may be relevant on CVX."""
    session = db.get_reader_session()
    project_ids = set()
    with session.begin():
        network_model = models_v2.Network
        project_ids |= set(pid[0] for pid in
                           session.query(network_model.project_id).distinct())
        port_model = models_v2.Port
        project_ids |= set(pid[0] for pid in
                           session.query(port_model.project_id).distinct())
    return project_ids


def _make_port_dict(record):
    """Make a dict from the BM profile DB record."""
    return {'port_id': record.port_id,
            'host_id': record.host,
            'vnic_type': record.vnic_type,
            'profile': record.profile}


def get_all_baremetal_ports():
    """Returns a list of all ports that belong to baremetal hosts."""
    session = db.get_reader_session()
    with session.begin():
        querry = session.query(ml2_models.PortBinding)
        bm_ports = querry.filter_by(vnic_type='baremetal').all()

        return {bm_port.port_id: _make_port_dict(bm_port)
                for bm_port in bm_ports}


def get_all_portbindings():
    """Returns a list of all ports bindings."""
    session = db.get_reader_session()
    with session.begin():
        query = session.query(ml2_models.PortBinding)
        ports = query.all()

        return {port.port_id: _make_port_dict(port)
                for port in ports}


def get_port_binding_level(filters):
    """Returns entries from PortBindingLevel based on the specified filters."""
    session = db.get_reader_session()
    with session.begin():
        return (session.query(ml2_models.PortBindingLevel).
                filter_by(**filters).
                order_by(ml2_models.PortBindingLevel.level).
                all())


def get_network_segments_by_port_id(port_id):
    session = db.get_reader_session()
    with session.begin():
        segments = (session.query(segment_models.NetworkSegment,
                                  ml2_models.PortBindingLevel).
                    join(ml2_models.PortBindingLevel).
                    filter_by(port_id=port_id).
                    order_by(ml2_models.PortBindingLevel.level).
                    all())
        return [segment[0] for segment in segments]


def get_trunk_port_by_subport_id(subport_id):
    """Returns trunk parent port based on sub port id."""
    session = db.get_reader_session()
    with session.begin():
        subport = (session.query(trunk_models.SubPort).
                   filter_by(port_id=subport_id).first())
        if subport:
            trunk_id = subport.trunk_id
            return get_trunk_port_by_trunk_id(trunk_id)


def get_trunk_port_by_trunk_id(trunk_id):
    session = db.get_reader_session()
    with session.begin():
        trunk_port = (session.query(trunk_models.Trunk).
                      filter_by(id=trunk_id).first())
        if trunk_port:
            return trunk_port.port


class NeutronNets(db_base_plugin_v2.NeutronDbPluginV2,
                  sec_db.SecurityGroupDbMixin):
    """Access to Neutron DB.

    Provides access to the Neutron Data bases for all provisioned
    networks as well ports. This data is used during the synchronization
    of DB between ML2 Mechanism Driver and Arista EOS
    Names of the networks and ports are not stroed in Arista repository
    They are pulled from Neutron DB.
    """

    def __init__(self):
        self.admin_ctx = nctx.get_admin_context()

    def get_all_networks_for_tenant(self, tenant_id):
        filters = {'tenant_id': [tenant_id]}
        return super(NeutronNets,
                     self).get_networks(self.admin_ctx, filters=filters) or []

    def get_all_networks(self):
        return super(NeutronNets, self).get_networks(self.admin_ctx) or []

    def get_all_ports_for_tenant(self, tenant_id):
        filters = {'tenant_id': [tenant_id]}
        return super(NeutronNets,
                     self).get_ports(self.admin_ctx, filters=filters) or []

    def get_shared_network_owner_id(self, network_id):
        filters = {'id': [network_id]}
        nets = self.get_networks(self.admin_ctx, filters=filters) or []
        segments = segments_db.get_network_segments(self.admin_ctx,
                                                    network_id)
        if not nets or not segments:
            return
        if (nets[0]['shared'] and
           segments[0][driver_api.NETWORK_TYPE] == n_const.TYPE_VLAN):
            return nets[0]['tenant_id']

    def get_network_segments(self, network_id, dynamic=False, context=None):
        context = context if context is not None else self.admin_ctx
        segments = segments_db.get_network_segments(context, network_id,
                                                    filter_dynamic=dynamic)
        if dynamic:
            for segment in segments:
                segment['is_dynamic'] = True
        return segments

    def get_all_network_segments(self, network_id, context=None):
        segments = self.get_network_segments(network_id, context=context)
        segments += self.get_network_segments(network_id, dynamic=True,
                                              context=context)
        return segments

    def get_segment_by_id(self, context, segment_id):
        return segments_db.get_segment_by_id(context,
                                             segment_id)

    def get_network_from_net_id(self, network_id, context=None):
        filters = {'id': [network_id]}
        ctxt = context if context else self.admin_ctx
        return super(NeutronNets,
                     self).get_networks(ctxt, filters=filters) or []

    def get_subnet_info(self, subnet_id):
        return self.get_subnet(subnet_id)

    def get_subnet_ip_version(self, subnet_id):
        subnet = self.get_subnet(subnet_id)
        return subnet['ip_version'] if 'ip_version' in subnet else None

    def get_subnet_gateway_ip(self, subnet_id):
        subnet = self.get_subnet(subnet_id)
        return subnet['gateway_ip'] if 'gateway_ip' in subnet else None

    def get_subnet_cidr(self, subnet_id):
        subnet = self.get_subnet(subnet_id)
        return subnet['cidr'] if 'cidr' in subnet else None

    def get_network_id(self, subnet_id):
        subnet = self.get_subnet(subnet_id)
        return subnet['network_id'] if 'network_id' in subnet else None

    def get_network_id_from_port_id(self, port_id):
        port = self.get_port(port_id)
        return port['network_id'] if 'network_id' in port else None

    def get_subnet(self, subnet_id):
        return super(NeutronNets,
                     self).get_subnet(self.admin_ctx, subnet_id) or {}

    def get_port(self, port_id):
        return super(NeutronNets,
                     self).get_port(self.admin_ctx, port_id) or {}

    def get_all_security_gp_to_port_bindings(self):
        return super(NeutronNets, self)._get_port_security_group_bindings(
            self.admin_ctx) or []

    def get_security_gp_to_port_bindings(self, sec_gp_id):
        filters = {'security_group_id': [sec_gp_id]}
        return super(NeutronNets, self)._get_port_security_group_bindings(
            self.admin_ctx, filters=filters) or []

    def get_security_group(self, sec_gp_id):
        return super(NeutronNets,
                     self).get_security_group(self.admin_ctx, sec_gp_id) or []

    def get_security_groups(self):
        sgs = super(NeutronNets,
                    self).get_security_groups(self.admin_ctx) or []
        sgs_all = {}
        if sgs:
            for s in sgs:
                sgs_all[s['id']] = s
        return sgs_all

    def get_security_group_rule(self, sec_gpr_id):
        return super(NeutronNets,
                     self).get_security_group_rule(self.admin_ctx,
                                                   sec_gpr_id) or []

    def validate_network_rbac_policy_change(self, resource, event, trigger,
                                            context, object_type, policy,
                                            **kwargs):
        return super(NeutronNets, self).validate_network_rbac_policy_change(
            resource, event, trigger, context, object_type, policy, kwargs)
