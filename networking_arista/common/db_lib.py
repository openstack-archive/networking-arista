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

from neutron import context as nctx
import neutron.db.api as db
from neutron.db import db_base_plugin_v2
from neutron.plugins.common import constants as p_const
from neutron.plugins.ml2 import db as ml2_db
from neutron.plugins.ml2 import driver_api

from networking_arista.common import db as db_models

VLAN_SEGMENTATION = 'vlan'


def remember_tenant(tenant_id):
    """Stores a tenant information in repository.

    :param tenant_id: globally unique neutron tenant identifier
    """
    session = db.get_session()
    with session.begin():
        tenant = (session.query(db_models.AristaProvisionedTenants).
                  filter_by(tenant_id=tenant_id).first())
        if not tenant:
            tenant = db_models.AristaProvisionedTenants(tenant_id=tenant_id)
            session.add(tenant)


def forget_tenant(tenant_id):
    """Removes a tenant information from repository.

    :param tenant_id: globally unique neutron tenant identifier
    """
    session = db.get_session()
    with session.begin():
        (session.query(db_models.AristaProvisionedTenants).
         filter_by(tenant_id=tenant_id).
         delete())


def get_all_tenants():
    """Returns a list of all tenants stored in repository."""
    session = db.get_session()
    with session.begin():
        return session.query(db_models.AristaProvisionedTenants).all()


def num_provisioned_tenants():
    """Returns number of tenants stored in repository."""
    session = db.get_session()
    with session.begin():
        return session.query(db_models.AristaProvisionedTenants).count()


def remember_vm(vm_id, host_id, port_id, network_id, tenant_id):
    """Stores all relevant information about a VM in repository.

    :param vm_id: globally unique identifier for VM instance
    :param host_id: ID of the host where the VM is placed
    :param port_id: globally unique port ID that connects VM to network
    :param network_id: globally unique neutron network identifier
    :param tenant_id: globally unique neutron tenant identifier
    """
    session = db.get_session()
    with session.begin():
        vm = db_models.AristaProvisionedVms(
            vm_id=vm_id,
            host_id=host_id,
            port_id=port_id,
            network_id=network_id,
            tenant_id=tenant_id)
        session.add(vm)


def forget_all_ports_for_network(net_id):
    """Removes all ports for a given network fron repository.

    :param net_id: globally unique network ID
    """
    session = db.get_session()
    with session.begin():
        (session.query(db_models.AristaProvisionedVms).
         filter_by(network_id=net_id).delete())


def update_port(vm_id, host_id, port_id, network_id, tenant_id):
    """Updates the port details in the database.

    :param vm_id: globally unique identifier for VM instance
    :param host_id: ID of the new host where the VM is placed
    :param port_id: globally unique port ID that connects VM to network
    :param network_id: globally unique neutron network identifier
    :param tenant_id: globally unique neutron tenant identifier
    """
    session = db.get_session()
    with session.begin():
        port = session.query(db_models.AristaProvisionedVms).filter_by(
            port_id=port_id).first()
        if port:
            # Update the VM's host id
            port.host_id = host_id
            port.vm_id = vm_id
            port.network_id = network_id
            port.tenant_id = tenant_id


def forget_port(port_id, host_id):
    """Deletes the port from the database

    :param port_id: globally unique port ID that connects VM to network
    :param host_id: host to which the port is bound to
    """
    session = db.get_session()
    with session.begin():
        session.query(db_models.AristaProvisionedVms).filter_by(
            port_id=port_id,
            host_id=host_id).delete()


def remember_network(tenant_id, network_id, segmentation_id):
    """Stores all relevant information about a Network in repository.

    :param tenant_id: globally unique neutron tenant identifier
    :param network_id: globally unique neutron network identifier
    :param segmentation_id: VLAN ID that is assigned to the network
    """
    session = db.get_session()
    with session.begin():
        net = db_models.AristaProvisionedNets(
            tenant_id=tenant_id,
            network_id=network_id,
            segmentation_id=segmentation_id)
        session.add(net)


def forget_network(tenant_id, network_id):
    """Deletes all relevant information about a Network from repository.

    :param tenant_id: globally unique neutron tenant identifier
    :param network_id: globally unique neutron network identifier
    """
    session = db.get_session()
    with session.begin():
        (session.query(db_models.AristaProvisionedNets).
         filter_by(tenant_id=tenant_id, network_id=network_id).
         delete())


def get_segmentation_id(tenant_id, network_id):
    """Returns Segmentation ID (VLAN) associated with a network.

    :param tenant_id: globally unique neutron tenant identifier
    :param network_id: globally unique neutron network identifier
    """
    session = db.get_session()
    with session.begin():
        net = (session.query(db_models.AristaProvisionedNets).
               filter_by(tenant_id=tenant_id,
                         network_id=network_id).first())
        return net.segmentation_id if net else None


def is_vm_provisioned(vm_id, host_id, port_id,
                      network_id, tenant_id):
    """Checks if a VM is already known to EOS

    :returns: True, if yes; False otherwise.
    :param vm_id: globally unique identifier for VM instance
    :param host_id: ID of the host where the VM is placed
    :param port_id: globally unique port ID that connects VM to network
    :param network_id: globally unique neutron network identifier
    :param tenant_id: globally unique neutron tenant identifier
    """
    session = db.get_session()
    with session.begin():
        num_vm = (session.query(db_models.AristaProvisionedVms).
                  filter_by(tenant_id=tenant_id,
                            vm_id=vm_id,
                            port_id=port_id,
                            network_id=network_id,
                            host_id=host_id).count())
        return num_vm > 0


def is_port_provisioned(port_id, host_id=None):
    """Checks if a port is already known to EOS

    :returns: True, if yes; False otherwise.
    :param port_id: globally unique port ID that connects VM to network
    :param host_id: host to which the port is bound to
    """

    filters = {
        'port_id': port_id
    }
    if host_id:
        filters['host_id'] = host_id

    session = db.get_session()
    with session.begin():
        num_ports = (session.query(db_models.AristaProvisionedVms).
                     filter_by(**filters).count())
        return num_ports > 0


def is_network_provisioned(tenant_id, network_id, seg_id=None):
    """Checks if a networks is already known to EOS

    :returns: True, if yes; False otherwise.
    :param tenant_id: globally unique neutron tenant identifier
    :param network_id: globally unique neutron network identifier
    :param seg_id: Optionally matches the segmentation ID (VLAN)
    """
    session = db.get_session()
    with session.begin():
        if not seg_id:
            num_nets = (session.query(db_models.AristaProvisionedNets).
                        filter_by(tenant_id=tenant_id,
                                  network_id=network_id).count())
        else:
            num_nets = (session.query(db_models.AristaProvisionedNets).
                        filter_by(tenant_id=tenant_id,
                                  network_id=network_id,
                                  segmentation_id=seg_id).count())
        return num_nets > 0


def is_tenant_provisioned(tenant_id):
    """Checks if a tenant is already known to EOS

    :returns: True, if yes; False otherwise.
    :param tenant_id: globally unique neutron tenant identifier
    """
    session = db.get_session()
    with session.begin():
        num_tenants = (session.query(db_models.AristaProvisionedTenants).
                       filter_by(tenant_id=tenant_id).count())
    return num_tenants > 0


def num_nets_provisioned(tenant_id):
    """Returns number of networks for a given tennat.

    :param tenant_id: globally unique neutron tenant identifier
    """
    session = db.get_session()
    with session.begin():
        return (session.query(db_models.AristaProvisionedNets).
                filter_by(tenant_id=tenant_id).count())


def num_vms_provisioned(tenant_id):
    """Returns number of VMs for a given tennat.

    :param tenant_id: globally unique neutron tenant identifier
    """
    session = db.get_session()
    with session.begin():
        return (session.query(db_models.AristaProvisionedVms).
                filter_by(tenant_id=tenant_id).count())


def get_networks(tenant_id):
    """Returns all networks for a given tenant in EOS-compatible format.

    See AristaRPCWrapper.get_network_list() for return value format.
    :param tenant_id: globally unique neutron tenant identifier
    """
    session = db.get_session()
    with session.begin():
        model = db_models.AristaProvisionedNets
        # hack for pep8 E711: comparison to None should be
        # 'if cond is not None'
        none = None
        all_nets = []
        if tenant_id != 'any':
            all_nets = (session.query(model).
                        filter(model.tenant_id == tenant_id,
                               model.segmentation_id != none))
        else:
            all_nets = (session.query(model).
                        filter(model.segmentation_id != none))

        res = dict(
            (net.network_id, net.eos_network_representation(
                VLAN_SEGMENTATION))
            for net in all_nets
        )
        return res


def get_vms(tenant_id):
    """Returns all VMs for a given tenant in EOS-compatible format.

    :param tenant_id: globally unique neutron tenant identifier
    """
    session = db.get_session()
    with session.begin():
        model = db_models.AristaProvisionedVms
        # hack for pep8 E711: comparison to None should be
        # 'if cond is not None'
        none = None
        all_vms = (session.query(model).
                   filter(model.tenant_id == tenant_id,
                          model.host_id != none,
                          model.vm_id != none,
                          model.network_id != none,
                          model.port_id != none))
        res = dict(
            (vm.vm_id, vm.eos_vm_representation())
            for vm in all_vms
        )
        return res


def are_ports_attached_to_network(net_id):
    """Returns all records associated with network in EOS-compatible format.

    :param net_id: globally unique network ID
    """
    session = db.get_session()
    with session.begin():
        model = db_models.AristaProvisionedVms
        num_ports = (session.query(model).
                     filter(model.network_id == net_id).count())

        return num_ports > 0


def get_ports(tenant_id):
    """Returns all ports of VMs in EOS-compatible format.

    :param tenant_id: globally unique neutron tenant identifier
    """
    session = db.get_session()
    with session.begin():
        model = db_models.AristaProvisionedVms
        # hack for pep8 E711: comparison to None should be
        # 'if cond is not None'
        none = None
        all_ports = (session.query(model).
                     filter(model.tenant_id == tenant_id,
                            model.host_id != none,
                            model.vm_id != none,
                            model.network_id != none,
                            model.port_id != none))

    ports = {}
    for port in all_ports:
        if port.port_id not in ports:
            ports[port.port_id] = port.eos_port_representation()
        ports[port.port_id]['hosts'].append(port.host_id)

    return ports


def get_tenants():
    """Returns list of all tenants in EOS-compatible format."""
    session = db.get_session()
    with session.begin():
        model = db_models.AristaProvisionedTenants
        all_tenants = session.query(model)
        res = dict(
            (tenant.tenant_id, tenant.eos_tenant_representation())
            for tenant in all_tenants
        )
        return res


class NeutronNets(db_base_plugin_v2.NeutronDbPluginV2):
    """Access to Neutron DB.

    Provides access to the Neutron Data bases for all provisioned
    networks as well ports. This data is used during the synchronization
    of DB between ML2 Mechanism Driver and Arista EOS
    Names of the networks and ports are not stroed in Arista repository
    They are pulled from Neutron DB.
    """

    def __init__(self):
        self.admin_ctx = nctx.get_admin_context()

    def get_network_name(self, tenant_id, network_id):
        network = self._get_network(tenant_id, network_id)
        network_name = None
        if network:
            network_name = network[0]['name']
        return network_name

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
        segments = ml2_db.get_network_segments(self.admin_ctx.session,
                                               network_id)
        if not nets or not segments:
            return
        if (nets[0]['shared'] and
           segments[0][driver_api.NETWORK_TYPE] == p_const.TYPE_VLAN):
            return nets[0]['tenant_id']

    def _get_network(self, tenant_id, network_id):
        filters = {'tenant_id': [tenant_id],
                   'id': [network_id]}
        return super(NeutronNets,
                     self).get_networks(self.admin_ctx, filters=filters) or []

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
