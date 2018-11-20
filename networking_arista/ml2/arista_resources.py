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
import os

from neutron.services.trunk import constants as t_const
from neutron_lib import constants as n_const
from oslo_log import log as logging

from networking_arista.common import db_lib
from networking_arista.common import exceptions as arista_exc
from networking_arista.common import utils


LOG = logging.getLogger(__name__)


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
        return (self.cvx_key, self.format(resource[self.neutron_key]))


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
        self.cvx_data_stale = True
        self.neutron_data_stale = True
        self.cvx_ids = set()
        self.neutron_resources = dict()

    def clear_cvx_data(self):
        self.cvx_data_stale = True
        self.cvx_ids = set()

    def clear_neutron_data(self):
        self.neutron_data_stale = True
        self.neutron_resources = dict()

    def clear_all_data(self):
        self.clear_cvx_data()
        self.clear_neutron_data()

    def update_neutron_resource(self, id, action):
        LOG.info("%(pid)s Requesting %(action)s %(class)s resource %(id)s",
                 {'action': action, 'class': self.__class__.__name__, 'id': id,
                  'pid': os.getpid()})
        resource = self.get_db_resources(id)
        assert(len(resource) <= 1)
        if resource:
            # Until we start using etcd, we need to unconditionally send the
            # create request because it might have been delete by another
            # worker.  We force this by removing the resource to our 'view' of
            # cvx resources
            self.force_resource_update(id)
            LOG.info("%(pid)s Resource %(class)s %(id)s found, creating",
                     {'class': self.__class__.__name__, 'id': id,
                      'pid': os.getpid()})
            self._add_neutron_resource(resource[0])
        else:
            LOG.info("%(pid)s Resource %(class)s %(id)s not found, deleting",
                     {'class': self.__class__.__name__, 'id': id,
                      'pid': os.getpid()})
            self._delete_neutron_resource(id)

    def _add_neutron_resource(self, resource):
        formatted_resource = self.format_for_create(resource)
        resource_id = list(formatted_resource.keys())[0]
        LOG.info("%(pid)s %(class)s resource %(id)s added locally",
                 {'class': self.__class__.__name__,
                  'id': resource_id,
                  'pid': os.getpid()})
        # If the resource has changed, force a POST to CVX
        old_resource = self.neutron_resources.get(resource_id)
        if old_resource and old_resource != formatted_resource:
            LOG.info("%(pid)s %(class)s resource %(id)s requires update",
                     {'class': self.__class__.__name__,
                      'id': resource_id,
                      'pid': os.getpid()})
            self.force_resource_update(resource_id)
        self.neutron_resources.update(formatted_resource)

    def force_resource_update(self, id):
        self.cvx_ids.discard(id)

    def _delete_neutron_resource(self, id):
        # Until we start using etcd, we need to unconditionally send the
        # delete request because it might have been created by another worker.
        # We force this by adding the resource to our 'view' of cvx resources
        self.cvx_ids.add(id)
        try:
            del self.neutron_resources[id]
            LOG.info("%(pid)s %(class)s resource %(id)s removed locally",
                     {'class': self.__class__.__name__, 'id': id,
                      'pid': os.getpid()})
        except KeyError:
            LOG.debug("Resource ID %(id)s already deleted locally", {'id': id})

    def get_endpoint(self):
        return self.endpoint % {'region': self.region}

    @classmethod
    def get_resource_ids(cls, resource):
        return set([resource[cls.id_key]])

    def get_cvx_ids(self):
        LOG.info("%(pid)s Getting %(class)s from CVX",
                 {'class': self.__class__.__name__,
                  'pid': os.getpid()})
        if self.cvx_data_stale:
            cvx_data = self.rpc.send_api_request(self.get_endpoint(), 'GET')
            for resource in cvx_data:
                self.cvx_ids |= self.get_resource_ids(resource)
            self.cvx_data_stale = False
        return self.cvx_ids

    @staticmethod
    def get_db_resources(key=None):
        raise NotImplementedError

    def get_neutron_ids(self):
        if self.neutron_data_stale:
            self.get_neutron_resources()
        return set(self.neutron_resources.keys())

    def get_neutron_resources(self):
        LOG.info("%(pid)s Getting %(class)s from neutron",
                 {'class': self.__class__.__name__,
                  'pid': os.getpid()})
        if self.neutron_data_stale:
            for resource in self.get_db_resources():
                self._add_neutron_resource(resource)
            self.neutron_data_stale = False
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
        cvx_resource = dict(
            attr.transform(neutron_resource) for attr in cls.formatter
        )
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
            LOG.info("%(pid)s Creating %(class)s resources with ids %(ids)s "
                     "on CVX",
                     {'class': self.__class__.__name__,
                      'ids': ', '.join(str(r) for r in resource_ids_to_create),
                      'pid': os.getpid()})
            self.rpc.send_api_request(self.get_endpoint(), 'POST',
                                      resources_to_create)
            self.cvx_ids.update(resource_ids_to_create)
            LOG.info("%(pid)s %(class)s resources with ids %(ids)s created "
                     "on CVX",
                     {'class': self.__class__.__name__,
                      'ids': ', '.join(str(r) for r in resource_ids_to_create),
                      'pid': os.getpid()})
        else:
            LOG.info("%(pid)s No %(class)s resources to create",
                     {'class': self.__class__.__name__,
                      'pid': os.getpid()})
        return resources_to_create

    def delete_cvx_resources(self):
        resource_ids_to_delete = self.resource_ids_to_delete()
        resources_to_delete = list(self.format_for_delete(id) for id in
                                   resource_ids_to_delete)
        if resources_to_delete:
            LOG.info("%(pid)s Deleting %(class)s resources with ids %(ids)s "
                     "from CVX",
                     {'class': self.__class__.__name__,
                      'ids': ', '.join(str(r) for r in resource_ids_to_delete),
                      'pid': os.getpid()})
            try:
                self.rpc.send_api_request(self.get_endpoint(), 'DELETE',
                                          resources_to_delete)
            except arista_exc.AristaRpcError as err:
                if not err.msg.startswith('Unknown port id'):
                    raise
            self.cvx_ids -= resource_ids_to_delete
            LOG.info("%(pid)s %(class)s resources with ids %(ids)s deleted "
                     "from CVX",
                     {'class': self.__class__.__name__,
                      'ids': ', '.join(str(r) for r in resource_ids_to_delete),
                      'pid': os.getpid()})
        else:
            LOG.info("%(pid)s No %(class)s resources to delete",
                     {'class': self.__class__.__name__,
                      'pid': os.getpid()})
        return resources_to_delete


class Tenants(AristaResourcesBase):

    endpoint = 'region/%(region)s/tenant'
    formatter = [AttributeFormatter('project_id', 'id')]
    get_db_resources = staticmethod(db_lib.get_tenants)


class Networks(AristaResourcesBase):

    def _is_shared(rbac_entries):
        for entry in rbac_entries:
            if (entry.action == 'access_as_shared' and
                    entry.target_tenant == '*'):
                return True
        return False

    formatter = [AttributeFormatter('id', 'id'),
                 AttributeFormatter('project_id', 'tenantId'),
                 AttributeFormatter('name', 'name'),
                 AttributeFormatter('rbac_entries', 'shared', _is_shared)]
    endpoint = 'region/%(region)s/network'
    get_db_resources = staticmethod(db_lib.get_networks)


class Segments(AristaResourcesBase):

    formatter = [AttributeFormatter('id', 'id'),
                 AttributeFormatter('network_type', 'type'),
                 AttributeFormatter('segmentation_id', 'segmentationId'),
                 AttributeFormatter('network_id', 'networkId'),
                 AttributeFormatter('is_dynamic', 'segmentType',
                                    lambda x: 'dynamic' if x else 'static')]
    endpoint = 'region/%(region)s/segment'
    get_db_resources = staticmethod(db_lib.get_segments)


class Dhcps(AristaResourcesBase):

    formatter = [AttributeFormatter('device_id', 'id',
                                    submodel='Port'),
                 AttributeFormatter('host', 'hostId',
                                    utils.hostname,
                                    submodel='PortBinding'),
                 AttributeFormatter('project_id', 'tenantId',
                                    submodel='Port')]
    endpoint = 'region/%(region)s/dhcp'
    get_db_resources = staticmethod(db_lib.get_dhcp_instances)


class Routers(AristaResourcesBase):

    formatter = [AttributeFormatter('device_id', 'id',
                                    submodel='Port'),
                 AttributeFormatter('device_owner', 'hostId',
                                    lambda *args: 'distributed',
                                    submodel='Port'),
                 AttributeFormatter('project_id', 'tenantId',
                                    submodel='Port')]
    endpoint = 'region/%(region)s/router'
    get_db_resources = staticmethod(db_lib.get_router_instances)


class Vms(AristaResourcesBase):

    formatter = [AttributeFormatter('device_id', 'id',
                                    submodel='Port'),
                 AttributeFormatter('host', 'hostId',
                                    utils.hostname,
                                    submodel='PortBinding'),
                 AttributeFormatter('project_id', 'tenantId',
                                    submodel='Port')]
    endpoint = 'region/%(region)s/vm'
    get_db_resources = staticmethod(db_lib.get_vm_instances)


class Baremetals(AristaResourcesBase):

    formatter = [AttributeFormatter('device_id', 'id',
                                    submodel='Port'),
                 AttributeFormatter('host', 'hostId',
                                    submodel='PortBinding'),
                 AttributeFormatter('project_id', 'tenantId',
                                    submodel='Port')]
    endpoint = 'region/%(region)s/baremetal'
    get_db_resources = staticmethod(db_lib.get_baremetal_instances)


class DhcpPorts(AristaResourcesBase):

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
    get_db_resources = staticmethod(db_lib.get_dhcp_ports)


class RouterPorts(AristaResourcesBase):

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
    get_db_resources = staticmethod(db_lib.get_router_ports)


class VmPorts(AristaResourcesBase):

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
    get_db_resources = staticmethod(db_lib.get_vm_ports)

    @classmethod
    def format_for_create(cls, port):
        # This is needed until we can update the upstream trunk port
        # handling to add device_id to subports
        if port['device_owner'] == t_const.TRUNK_SUBPORT_OWNER:
            parent_port = db_lib.get_parent(port['id'])
            port['device_id'] = parent_port.get('device_id')
        return super(VmPorts, cls).format_for_create(port)


class BaremetalPorts(AristaResourcesBase):

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
    get_db_resources = staticmethod(db_lib.get_baremetal_ports)


class PortBindings(AristaResourcesBase):

    endpoint = 'region/%(region)s/portbinding'
    get_db_resources = staticmethod(db_lib.get_port_bindings)

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
