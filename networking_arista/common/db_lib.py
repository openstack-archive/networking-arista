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

import collections

from oslo_config import cfg
from oslo_log import log as logging
from sqlalchemy import and_, or_
from sqlalchemy import func
from sqlalchemy.orm import joinedload, Query, aliased

from neutron_lib.api.definitions import portbindings
from neutron_lib import constants as n_const

import neutron.db.api as db
from neutron.db.models.plugins.ml2 import vlanallocation
from neutron.db.models import securitygroup as sg_models
from neutron.db.models import segment as segment_models
from neutron.db import models_v2
from neutron.plugins.ml2 import models as ml2_models
from neutron.services.trunk import constants as t_const
from neutron.services.trunk import models as trunk_models

from networking_arista.common import utils

LOG = logging.getLogger(__name__)


def join_if_necessary(query, *args, **kwargs):
    table = args[0]
    if table in [t.entity for t in query._join_entities]:
        return query
    elif table in query._primary_entity.entities:
        return query
    return query.join(*args, **kwargs)


def outerjoin_if_necessary(query, *args, **kwargs):
    table = args[0]
    if table in [t.entity for t in query._join_entities]:
        return query
    elif table in query._primary_entity.entities:
        return query
    return query.outerjoin(*args, **kwargs)


def filter_network_type(query):
    """Filter unsupported segment types"""
    segment_model = segment_models.NetworkSegment
    query = (query
             .filter(
                 segment_model.network_type.in_(
                     utils.SUPPORTED_NETWORK_TYPES)))
    return query


def filter_unbound_ports(query):
    """Filter ports not bound to a host or network"""
    # hack for pep8 E711: comparison to None should be
    # 'if cond is not None'
    none = None
    port_model = models_v2.Port
    binding_level_model = ml2_models.PortBindingLevel
    query = (query
             .join_if_necessary(port_model)
             .join_if_necessary(binding_level_model)
             .filter(
                 binding_level_model.host != '',
                 port_model.device_id != none,
                 port_model.network_id != none))
    return query


def filter_by_device_owner(query, device_owners=None):
    """Filter ports by device_owner

    Either filter using specified device_owner or using the list of all
    device_owners supported and unsupported by the arista ML2 plugin
    """
    port_model = models_v2.Port
    if not device_owners:
        device_owners = utils.SUPPORTED_DEVICE_OWNERS
    supported_device_owner_filter = [
        port_model.device_owner.ilike('%s%%' % owner)
        for owner in device_owners]
    unsupported_device_owner_filter = [
        port_model.device_owner.notilike('%s%%' % owner)
        for owner in utils.UNSUPPORTED_DEVICE_OWNERS]
    query = (query
             .filter(
                 and_(*unsupported_device_owner_filter),
                 or_(*supported_device_owner_filter)))
    return query


def filter_by_device_id(query):
    """Filter ports attached to devices we don't care about

    Currently used to filter DHCP_RESERVED ports
    """
    port_model = models_v2.Port
    unsupported_device_id_filter = [
        port_model.device_id.notilike('%s%%' % id)
        for id in utils.UNSUPPORTED_DEVICE_IDS]
    query = (query
             .filter(and_(*unsupported_device_id_filter)))
    return query


def filter_by_vnic_type(query, vnic_type):
    """Filter ports by vnic_type (currently only used for baremetals)"""
    port_model = models_v2.Port
    binding_model = ml2_models.PortBinding
    dst_binding_model = ml2_models.DistributedPortBinding
    query = (query
             .outerjoin_if_necessary(
                 binding_model,
                 port_model.id == binding_model.port_id)
             .outerjoin_if_necessary(
                 dst_binding_model,
                 port_model.id == dst_binding_model.port_id)
             .filter(
                 (binding_model.vnic_type == vnic_type) |
                 (dst_binding_model.vnic_type == vnic_type)))
    return query


def filter_unmanaged_physnets(query):
    """Filter ports managed by other ML2 plugins """
    config = cfg.CONF.ml2_arista
    managed_physnets = config['managed_physnets']

    # Filter out ports bound to segments on physnets that we're not
    # managing
    segment_model = segment_models.NetworkSegment
    if managed_physnets:
        query = (query
                 .join_if_necessary(segment_model)
                 .filter(segment_model.physical_network.in_(
                     managed_physnets)))
    return query


def filter_inactive_ports(query):
    """Filter ports that aren't in active status """
    port_model = models_v2.Port
    query = (query
             .filter(port_model.status == n_const.PORT_STATUS_ACTIVE))
    return query


def filter_unnecessary_ports(query, device_owners=None, vnic_type=None,
                             active=True):
    """Filter out all ports are not needed on CVX """
    query = (query
             .filter_unbound_ports()
             .filter_by_device_owner(device_owners)
             .filter_by_device_id()
             .filter_unmanaged_physnets())
    if active:
        query = query.filter_inactive_ports()
    if vnic_type:
        query = query.filter_by_vnic_type(vnic_type)
    return query


Query.join_if_necessary = join_if_necessary
Query.outerjoin_if_necessary = outerjoin_if_necessary
Query.filter_network_type = filter_network_type
Query.filter_unbound_ports = filter_unbound_ports
Query.filter_by_device_owner = filter_by_device_owner
Query.filter_by_device_id = filter_by_device_id
Query.filter_by_vnic_type = filter_by_vnic_type
Query.filter_unmanaged_physnets = filter_unmanaged_physnets
Query.filter_inactive_ports = filter_inactive_ports
Query.filter_unnecessary_ports = filter_unnecessary_ports


def get_tenants(tenant_id=None):
    """Returns list of all project/tenant ids that may be relevant on CVX"""
    if tenant_id == '':
        return []
    session = db.get_reader_session()
    project_ids = set()
    with session.begin():
        for m in [models_v2.Network, models_v2.Port]:
            q = session.query(m.project_id).filter(m.project_id != '')
            if tenant_id:
                q = q.filter(m.project_id == tenant_id)
            project_ids.update(pid[0] for pid in q.distinct())
    return [{'project_id': project_id} for project_id in project_ids]


def get_networks(network_id=None):
    """Returns list of all networks that may be relevant on CVX"""
    session = db.get_reader_session()
    with session.begin():
        model = models_v2.Network
        networks = session.query(model)
        if network_id:
            networks = networks.filter(model.id == network_id)
    return networks.all()


def get_segments(segment_id=None):
    """Returns list of all network segments that may be relevant on CVX"""
    session = db.get_reader_session()
    with session.begin():
        model = segment_models.NetworkSegment
        segments = session.query(model).filter_network_type()
        if segment_id:
            segments = segments.filter(model.id == segment_id)
    return segments.all()


def get_instances(device_owners=None, vnic_type=None, instance_id=None):
    """Returns filtered list of all instances in the neutron db"""
    session = db.get_reader_session()
    with session.begin():
        port_model = models_v2.Port
        binding_model = ml2_models.PortBinding
        instances = (session
                     .query(port_model,
                            binding_model)
                     .outerjoin(
                         binding_model,
                         port_model.id == binding_model.port_id)
                     .distinct(port_model.device_id)
                     .group_by(port_model.device_id)
                     .filter_unnecessary_ports(device_owners, vnic_type))
        if instance_id:
            instances = instances.filter(port_model.device_id == instance_id)
    return instances.all()


def get_dhcp_instances(instance_id=None):
    """Returns filtered list of DHCP instances that may be relevant on CVX"""
    return get_instances(device_owners=[n_const.DEVICE_OWNER_DHCP],
                         instance_id=instance_id)


def get_router_instances(instance_id=None):
    """Returns filtered list of routers that may be relevant on CVX"""
    return get_instances(device_owners=[n_const.DEVICE_OWNER_DVR_INTERFACE],
                         instance_id=instance_id)


def get_vm_instances(instance_id=None):
    """Returns filtered list of vms that may be relevant on CVX"""
    return get_instances(device_owners=[n_const.DEVICE_OWNER_COMPUTE_PREFIX],
                         vnic_type=portbindings.VNIC_NORMAL,
                         instance_id=instance_id)


def get_baremetal_instances(instance_id=None):
    """Returns filtered list of baremetals that may be relevant on CVX"""
    return get_instances(vnic_type=portbindings.VNIC_BAREMETAL,
                         instance_id=instance_id)


def get_ports(device_owners=None, vnic_type=None, port_id=None, active=True):
    """Returns list of all ports in neutron the db"""
    session = db.get_reader_session()
    with session.begin():
        port_model = models_v2.Port
        ports = (session
                 .query(port_model)
                 .filter_unnecessary_ports(device_owners, vnic_type, active))
        if port_id:
            ports = ports.filter(port_model.id == port_id)
    return ports.all()


def get_dhcp_ports(port_id=None):
    """Returns filtered list of DHCP instances that may be relevant on CVX"""
    return get_ports(device_owners=[n_const.DEVICE_OWNER_DHCP],
                     port_id=port_id)


def get_router_ports(port_id=None):
    """Returns filtered list of routers that may be relevant on CVX"""
    return get_ports(device_owners=[n_const.DEVICE_OWNER_DVR_INTERFACE],
                     port_id=port_id)


def get_vm_ports(port_id=None):
    """Returns filtered list of vms that may be relevant on CVX"""
    return get_ports(device_owners=[n_const.DEVICE_OWNER_COMPUTE_PREFIX,
                                    t_const.TRUNK_SUBPORT_OWNER],
                     vnic_type=portbindings.VNIC_NORMAL, port_id=port_id)


def get_baremetal_ports(port_id=None):
    """Returns filtered list of baremetals that may be relevant on CVX"""
    return get_ports(vnic_type=portbindings.VNIC_BAREMETAL, port_id=port_id)


def get_port_bindings(binding_key=None):
    """Returns filtered list of port bindings that may be relevant on CVX

    This query is a little complex as we need all binding levels for any
    binding that has a single managed physnet, but we need to filter bindings
    that have no managed physnets. In order to achieve this, we join to the
    binding_level_model once to filter bindings with no managed levels,
    then a second time to get all levels for the remaining bindings.

    The loop at the end is a convenience to associate levels with bindings
    as a list. This would ideally be done through the use of an orm.relation,
    but due to some sqlalchemy limitations imposed to make OVO work, we can't
    add relations to existing models.
    """
    session = db.get_reader_session()
    with session.begin():
        binding_level_model = ml2_models.PortBindingLevel
        aliased_blm = aliased(ml2_models.PortBindingLevel)
        port_binding_model = ml2_models.PortBinding
        dist_binding_model = ml2_models.DistributedPortBinding
        bindings = (session.query(port_binding_model, aliased_blm)
                    .join(binding_level_model,
                          and_(
                              port_binding_model.port_id ==
                              binding_level_model.port_id,
                              port_binding_model.host ==
                              binding_level_model.host))
                    .filter_unnecessary_ports()
                    .join(aliased_blm,
                          and_(port_binding_model.port_id ==
                               aliased_blm.port_id,
                               port_binding_model.host ==
                               aliased_blm.host)))
        dist_bindings = (session.query(dist_binding_model, aliased_blm)
                         .join(
                             binding_level_model,
                             and_(dist_binding_model.port_id ==
                                  binding_level_model.port_id,
                                  dist_binding_model.host ==
                                  binding_level_model.host))
                         .filter_unnecessary_ports()
                         .filter(dist_binding_model.status ==
                                 n_const.PORT_STATUS_ACTIVE)
                         .join(aliased_blm,
                               and_(dist_binding_model.port_id ==
                                    aliased_blm.port_id,
                                    dist_binding_model.host ==
                                    aliased_blm.host)))
        if binding_key:
            port_id = binding_key[0]
            if type(binding_key[1]) == tuple:
                switch_id = binding_key[1][0]
                switch_port = binding_key[1][1]
                bindings = bindings.filter(and_(
                    port_binding_model.port_id == port_id,
                    port_binding_model.profile.ilike('%%%s%%' % switch_id),
                    port_binding_model.profile.ilike('%%%s%%' % switch_port)))
                dist_bindings = dist_bindings.filter(and_(
                    dist_binding_model.port_id == port_id,
                    dist_binding_model.profile.ilike('%%%s%%' % switch_id),
                    dist_binding_model.profile.ilike('%%%s%%' % switch_port)))
            else:
                host_id = binding_key[1]
                bindings = bindings.filter(and_(
                    port_binding_model.port_id == port_id,
                    port_binding_model.host == host_id))
                dist_bindings = dist_bindings.filter(and_(
                    dist_binding_model.port_id == port_id,
                    dist_binding_model.host == host_id))
    binding_levels = collections.defaultdict(list)
    for binding, level in bindings.all() + dist_bindings.all():
        binding_levels[binding].append(level)
    bindings_with_levels = list()
    for binding, levels in binding_levels.items():
        binding.levels = levels
        bindings_with_levels.append(binding)
    return bindings_with_levels


def get_mlag_physnets():
    mlag_pairs = dict()
    session = db.get_reader_session()
    with session.begin():
        physnets = session.query(
            vlanallocation.VlanAllocation.physical_network
        ).distinct().all()
        for (physnet,) in physnets:
            if '_' in physnet:
                peers = physnet.split('_')
                mlag_pairs[peers[0]] = physnet
                mlag_pairs[peers[1]] = physnet
    return mlag_pairs


def segment_is_dynamic(segment_id):
    session = db.get_reader_session()
    with session.begin():
        segment_model = segment_models.NetworkSegment
        res = bool(session
                   .query(segment_model)
                   .filter_by(id=segment_id)
                   .filter_by(is_dynamic=True).count())
    return res


def segment_bound(segment_id):
    session = db.get_reader_session()
    with session.begin():
        binding_level_model = ml2_models.PortBindingLevel
        res = bool(session
                   .query(binding_level_model)
                   .filter_by(segment_id=segment_id).count())
    return res


def tenant_provisioned(tenant_id):
    """Returns true if any networks or ports exist for a tenant."""
    session = db.get_reader_session()
    with session.begin():
        res = any(
            session.query(m).filter(m.tenant_id == tenant_id).count()
            for m in [models_v2.Network, models_v2.Port]
        )
    return res


def instance_provisioned(device_id):
    """Returns true if any ports exist for an instance."""
    session = db.get_reader_session()
    with session.begin():
        port_model = models_v2.Port
        res = bool(session.query(port_model)
                   .filter(port_model.device_id == device_id).count())
    return res


def port_provisioned(port_id):
    """Returns true if port still exists."""
    session = db.get_reader_session()
    with session.begin():
        port_model = models_v2.Port
        res = bool(session.query(port_model)
                   .filter(port_model.id == port_id).count())
    return res


def get_parent(port_id):
    """Get trunk subport's parent port"""
    session = db.get_reader_session()
    res = dict()
    with session.begin():
        subport_model = trunk_models.SubPort
        trunk_model = trunk_models.Trunk
        subport = (session.query(subport_model).
                   filter(subport_model.port_id == port_id).first())
        if subport:
            trunk = (session.query(trunk_model).
                     filter(trunk_model.id == subport.trunk_id).first())
            if trunk:
                trunk_port_id = trunk.port.id
                res = get_ports(port_id=trunk_port_id, active=False)[0]
    return res


def get_port_binding_level(filters):
    """Returns entries from PortBindingLevel based on the specified filters."""
    session = db.get_reader_session()
    with session.begin():
        return (session.query(ml2_models.PortBindingLevel).
                filter_by(**filters).
                order_by(ml2_models.PortBindingLevel.level).
                all())


def get_security_groups():
    session = db.get_reader_session()
    with session.begin():
        sg_model = sg_models.SecurityGroup
        # We do a joined load to prevent the need for the sync worker
        # to issue subqueries
        security_groups = (session.query(sg_model)
                           .options(joinedload(sg_model.rules)))
    return security_groups


def get_baremetal_sg_bindings():
    session = db.get_reader_session()
    with session.begin():
        sg_binding_model = sg_models.SecurityGroupPortBinding
        binding_model = ml2_models.PortBinding
        sg_bindings = (session
                       .query(sg_binding_model,
                              binding_model)
                       .outerjoin(
                           binding_model,
                           sg_binding_model.port_id == binding_model.port_id)
                       .filter_unnecessary_ports(
                           vnic_type=portbindings.VNIC_BAREMETAL)
                       .group_by(sg_binding_model.port_id)
                       .having(func.count(sg_binding_model.port_id) == 1))
    return sg_bindings
