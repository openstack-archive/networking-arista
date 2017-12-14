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

from networking_arista.common import db_lib
from networking_arista.common import utils
from neutron_lib import constants as n_const


class AttributeFormatter(object):
    """Formats a single attribute of the CVX model based on the neutron model

    There are 4 elements to an AttributeFormatter:
    1. neutron_key - name of the key in the neutron model
    2. cvx_key - name of the key in the cvx model
    3. format(optional) - function to alter the value to be CVX compatible
    4. submodel(optional) - If the get_db_resources function queries multiple
       models, the name of the model that contains the neutron_key must be
       specified
    """

    def __init__(self, neutron_key, cvx_key, format=None, submodel=None):
        self.neutron_key = neutron_key
        self.cvx_key = cvx_key
        self.format = format or (lambda arg: arg)
        self.submodel = submodel

    def transform(self, resource):
        if self.submodel:
            resource = getattr(resource, self.submodel)
        return {self.cvx_key: self.format(resource[self.neutron_key])}


class AristaResourcesBase(object):
    """Tracks state of resources of one resource type on neutron and CVX

    An AristaResources class is responsible for:
    - tracking resources that have been provisioned in neutron
    - tracking resources that have been provisioned on CVX
    - creating and deleting resources on CVX to bring it in line with neutron
    - formatting neutron resources to be compatible with CVX's API
    - tracking the correct endpoint for CVX API calls

    In order to facilitate this each resource type should define:
    1. formatter - a list of AttributeFormatters to convert neutron attributes
       to models compatible with CVX's API
    2. id_key - the key in the CVX model that uniquely identifies the resource
    3. endpoint - format string for region resource endpoint
    4. get_db_resources - function that queries the neutron db for all
       resources of the resource type in question
    """

    formatter = [AttributeFormatter('id', 'id')]
    id_key = 'id'
    endpoint = 'region/%(region)s'

    def __init__(self, rpc):
        self.region = rpc.region
        self.rpc = rpc
        self.cvx_ids = set()
        self.neutron_resources = dict()

    def clear_cvx_data(self):
        self.cvx_ids = set()

    def clear_neutron_data(self):
        self.neutron_resources = dict()

    def clear_all_data(self):
        self.clear_cvx_data()
        self.clear_neutron_data()

    def add_neutron_resource(self, resource):
        formatted_resource = self.format_for_create(resource)
        self.neutron_resources.update(formatted_resource)

    def delete_neutron_resource(self, id):
        del self.neutron_resources[id]

    def get_endpoint(self):
        return self.endpoint % {'region': self.region}

    @classmethod
    def get_resource_ids(cls, resource):
        return set([resource[cls.id_key]])

    def get_cvx_ids(self):
        if not self.cvx_ids:
            cvx_data = self.rpc.send_api_request(self.get_endpoint(), 'GET')
            for resource in cvx_data:
                self.cvx_ids |= self.get_resource_ids(resource)
        return self.cvx_ids

    @staticmethod
    def get_db_resources():
        raise NotImplementedError

    def get_neutron_ids(self):
        if not self.neutron_resources:
            self.get_neutron_resources()
        return set(self.neutron_resources.keys())

    def get_neutron_resources(self):
        if not self.neutron_resources:
            for resource in self.get_db_resources():
                self.add_neutron_resource(resource)
        return self.neutron_resources

    def resource_ids_to_delete(self):
        cvx_resource_ids = self.get_cvx_ids()
        neutron_resource_ids = self.get_neutron_ids()
        return (cvx_resource_ids - neutron_resource_ids)

    def resource_ids_to_create(self):
        cvx_resource_ids = self.get_cvx_ids()
        neutron_resource_ids = self.get_neutron_ids()
        return (neutron_resource_ids - cvx_resource_ids)

    @classmethod
    def format_for_create(cls, neutron_resource):
        cvx_resource = dict()
        for attr in cls.formatter:
            cvx_resource.update(attr.transform(neutron_resource))
        return {cvx_resource[cls.id_key]: cvx_resource}

    @classmethod
    def format_for_delete(cls, id):
        return {cls.id_key: id}

    def create_cvx_resources(self):
        resource_ids_to_create = self.resource_ids_to_create()
        neutron_resources = self.get_neutron_resources()
        resources_to_create = list(neutron_resources[resource_id] for
                                   resource_id in resource_ids_to_create)
        if resources_to_create:
            self.rpc.send_api_request(self.get_endpoint(), 'POST',
                                      resources_to_create)
        for id in resource_ids_to_create:
            self.cvx_ids.add(id)
        return resources_to_create

    def delete_cvx_resources(self):
        resource_ids_to_delete = self.resource_ids_to_delete()
        resources_to_delete = list(self.format_for_delete(id) for id in
                                   resource_ids_to_delete)
        if resources_to_delete:
            self.rpc.send_api_request(self.get_endpoint(), 'DELETE',
                                      resources_to_delete)
        for id in resource_ids_to_delete:
            self.cvx_ids.remove(id)
        return resources_to_delete


class Tenants(AristaResourcesBase):

    endpoint = 'region/%(region)s/tenant'
    formatter = [AttributeFormatter('project_id', 'id')]
    get_db_resources = db_lib.get_tenants


class Networks(AristaResourcesBase):

    def _is_shared(rbac_entries):
        for entry in rbac_entries:
            if (entry.action == 'access_as_shared' and
                    entry.target_tenant == '*'):
                return True
        return False

    formatter = [AttributeFormatter('id', 'id'),
                 AttributeFormatter('project_id', 'tenantId'),
                 AttributeFormatter('name', 'networkName'),
                 AttributeFormatter('rbac_entries', 'shared', _is_shared)]
    endpoint = 'region/%(region)s/network'
    get_db_resources = db_lib.get_networks


class Segments(AristaResourcesBase):

    formatter = [AttributeFormatter('id', 'id'),
                 AttributeFormatter('network_type', 'type'),
                 AttributeFormatter('segmentation_id', 'segmentationId'),
                 AttributeFormatter('network_id', 'networkId'),
                 AttributeFormatter('is_dynamic', 'segmentType',
                                    lambda x: 'dynamic' if x else 'static')]
    endpoint = 'region/%(region)s/segment'
    get_db_resources = db_lib.get_segments


class Dhcps(AristaResourcesBase):

    formatter = [AttributeFormatter('device_id', 'dhcpInstanceId',
                                    submodel='Port'),
                 AttributeFormatter('host', 'dhcpHostId',
                                    utils.hostname,
                                    submodel='PortBinding'),
                 AttributeFormatter('project_id', 'tenantId',
                                    submodel='Port')]
    id_key = 'dhcpInstanceId'
    endpoint = 'region/%(region)s/dhcp'
    get_db_resources = db_lib.get_dhcp_instances


class Routers(AristaResourcesBase):

    formatter = [AttributeFormatter('device_id', 'routerInstanceId',
                                    submodel='Port'),
                 AttributeFormatter('device_owner', 'routerHostId',
                                    lambda *args: 'distributed',
                                    submodel='Port'),
                 AttributeFormatter('project_id', 'tenantId',
                                    submodel='Port')]
    id_key = 'routerInstanceId'
    endpoint = 'region/%(region)s/router'
    get_db_resources = db_lib.get_router_instances


class Vms(AristaResourcesBase):

    formatter = [AttributeFormatter('device_id', 'vmInstanceId',
                                    submodel='Port'),
                 AttributeFormatter('host', 'vmHostId',
                                    utils.hostname,
                                    submodel='PortBinding'),
                 AttributeFormatter('project_id', 'tenantId',
                                    submodel='Port')]
    id_key = 'vmInstanceId'
    endpoint = 'region/%(region)s/vm'
    get_db_resources = db_lib.get_vm_instances


class Baremetals(AristaResourcesBase):

    formatter = [AttributeFormatter('device_id', 'baremetalInstanceId',
                                    submodel='Port'),
                 AttributeFormatter('host', 'baremetalHostId',
                                    submodel='PortBinding'),
                 AttributeFormatter('project_id', 'tenantId',
                                    submodel='Port')]
    id_key = 'baremetalInstanceId'
    endpoint = 'region/%(region)s/baremetal'
    get_db_resources = db_lib.get_baremetal_instances


class PortResourcesBase(AristaResourcesBase):
    id_key = 'id'


class DhcpPorts(PortResourcesBase):

    endpoint = 'region/%(region)s/port?type=dhcp'
    formatter = [AttributeFormatter('id', 'id'),
                 AttributeFormatter('name', 'portName'),
                 AttributeFormatter('device_owner', 'vlanType',
                                    lambda *args: 'allowed'),
                 AttributeFormatter('network_id', 'networkId'),
                 AttributeFormatter('device_id', 'instanceId'),
                 AttributeFormatter('device_owner', 'instanceType',
                                    lambda *args: 'dhcp'),
                 AttributeFormatter('project_id', 'tenantId')]
    get_db_resources = db_lib.get_dhcp_ports


class RouterPorts(PortResourcesBase):

    endpoint = 'region/%(region)s/port?type=router'
    formatter = [AttributeFormatter('id', 'id'),
                 AttributeFormatter('name', 'portName'),
                 AttributeFormatter('device_owner', 'vlanType',
                                    lambda *args: 'allowed'),
                 AttributeFormatter('network_id', 'networkId'),
                 AttributeFormatter('device_id', 'instanceId'),
                 AttributeFormatter('device_owner', 'instanceType',
                                    lambda *args: 'router'),
                 AttributeFormatter('project_id', 'tenantId')]
    get_db_resources = db_lib.get_router_ports


class VmPorts(PortResourcesBase):

    endpoint = 'region/%(region)s/port?type=vm'
    formatter = [AttributeFormatter('id', 'id'),
                 AttributeFormatter('name', 'portName'),
                 AttributeFormatter('device_owner', 'vlanType',
                                    lambda *args: 'allowed'),
                 AttributeFormatter('network_id', 'networkId'),
                 AttributeFormatter('device_id', 'instanceId'),
                 AttributeFormatter('device_owner', 'instanceType',
                                    lambda *args: 'vm'),
                 AttributeFormatter('project_id', 'tenantId')]
    get_db_resources = db_lib.get_vm_ports


class BaremetalPorts(PortResourcesBase):

    def _get_vlan_type(device_owner):
        if (device_owner.startswith(n_const.DEVICE_OWNER_BAREMETAL_PREFIX) or
                device_owner.startswith(n_const.DEVICE_OWNER_COMPUTE_PREFIX)):
            return 'native'
        else:
            return 'allowed'

    endpoint = 'region/%(region)s/port?type=baremetal'
    formatter = [AttributeFormatter('id', 'id'),
                 AttributeFormatter('name', 'portName'),
                 AttributeFormatter('device_owner', 'vlanType',
                                    _get_vlan_type),
                 AttributeFormatter('network_id', 'networkId'),
                 AttributeFormatter('device_id', 'instanceId'),
                 AttributeFormatter('device_owner', 'instanceType',
                                    lambda *args: 'baremetal'),
                 AttributeFormatter('project_id', 'tenantId')]
    get_db_resources = db_lib.get_baremetal_ports


class PortBindings(AristaResourcesBase):

    endpoint = 'region/%(region)s/portbinding'
    get_db_resources = db_lib.get_port_bindings

    @classmethod
    def get_resource_ids(cls, resource):
        resource_ids = set()
        port_id = resource['portId']
        for host_binding in resource.get('hostBinding', []):
            resource_ids.add((port_id, host_binding['host']))
        for switch_binding in resource.get('switchBinding', []):
            resource_ids.add((port_id, (switch_binding['switch'],
                                        switch_binding['interface'])))
        return resource_ids

    @classmethod
    def format_for_delete(cls, id):
        model = dict()
        port_id, binding = id
        model['portId'] = port_id
        if type(binding) == tuple:
            switch, interface = binding
            model['switchBinding'] = [{'switch': switch,
                                       'interface': interface}]
        else:
            host = binding
            model['hostBinding'] = [{'host': host}]
        return model

    @classmethod
    def format_for_create(cls, binding):
        cvx_resources = {}
        # First build the list of segments to which the port is bound
        # binding levels are in order from       0 -> highest
        #               which is typically   vxlan -> vlan
        # The Arista JSON API depends on this ordering being present in
        # the segments list
        segments = []
        for binding_level in (sorted(binding['levels'],
                                     key=lambda bl: bl.level)):
            segments.append({'id': binding_level.segment_id})

        # Determine if this is a switch or host bindings and populate
        # the appropriate model attribute accordingly
        host = utils.hostname(binding['host'])
        port_id = binding['port_id']
        # If the binding profile isn't valid json, this is a host binding
        try:
            profile = json.loads(binding.profile)
        except ValueError:
            profile = {}
        if profile.get('local_link_information'):
            for link in profile['local_link_information']:
                switch_binding = {'host': host,
                                  'switch': link['switch_id'],
                                  'interface': link['port_id'],
                                  'segment': segments}
                binding_key = (link['switch_id'], link['port_id'])
                cvx_resources[(port_id, binding_key)] = {
                    'portId': port_id,
                    'hostBinding': [],
                    'switchBinding': [switch_binding]}
        else:
            cvx_resources[(port_id, host)] = {
                'portId': port_id,
                'hostBinding': [{'host': host, 'segment': segments}],
                'switchBinding': []}
        return cvx_resources
