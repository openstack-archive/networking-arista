# Copyright (c) 2018 OpenStack Foundation
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

from multiprocessing import Queue
import random

from neutron.agent import rpc as agent_rpc
from neutron_lib.agent import topics
from neutron_lib.api.definitions import portbindings
from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib import context

from networking_arista.ml2 import arista_sync
from networking_arista.ml2.mechanism_arista import AristaDriver


class AristaHASimulationDriver(AristaDriver):

    def __init__(self):
        super(AristaHASimulationDriver, self).__init__()
        self.provision_queue1 = Queue()
        self.provision_queue2 = Queue()
        self.provision_queue3 = Queue()
        self.provision_queues = [self.provision_queue1,
                                 self.provision_queue2,
                                 self.provision_queue3]

    def get_workers(self):
        return [arista_sync.AristaSyncWorker(self.provision_queue1),
                arista_sync.AristaSyncWorker(self.provision_queue2),
                arista_sync.AristaSyncWorker(self.provision_queue3)]

    def create_network_postcommit(self, context):
        self.provision_queue = random.choice(self.provision_queues)
        super(AristaHASimulationDriver, self).create_network_postcommit(
            context)

    def update_network_postcommit(self, context):
        self.provision_queue = random.choice(self.provision_queues)
        super(AristaHASimulationDriver, self).update_network_postcommit(
            context)

    def delete_network_postcommit(self, context):
        self.provision_queue = random.choice(self.provision_queues)
        super(AristaHASimulationDriver, self).delete_network_postcommit(
            context)

    def update_port_postcommit(self, context):
        self.provision_queue = random.choice(self.provision_queues)
        super(AristaHASimulationDriver, self).update_port_postcommit(context)

    def delete_port_postcommit(self, context):
        self.provision_queue = random.choice(self.provision_queues)
        super(AristaHASimulationDriver, self).delete_port_postcommit(context)


class AristaHAScaleSimulationDriver(AristaHASimulationDriver):

    def __init__(self):
        super(AristaHAScaleSimulationDriver, self).__init__()
        self.context = None
        self.plugin_rpc = None

    def initialize(self):
        super(AristaHAScaleSimulationDriver, self).initialize()
        self.context = context.get_admin_context_without_session()
        # Subscribe to port updates to force ports to active after binding
        # since a fake virt driver is being used, so OVS will never see
        # the libvirt interfaces come up, triggering the OVS provisioning
        self.plugin_rpc = agent_rpc.PluginApi(topics.PLUGIN)
        registry.subscribe(self._port_update_callback,
                           resources.PORT, events.AFTER_UPDATE)

    def _port_update_callback(self, resource, event, trigger, **kwargs):
        port = kwargs.get('port')
        host = port.get(portbindings.HOST_ID)
        vif_type = port.get(portbindings.VIF_TYPE)
        device_dict = {'device': port['id'],
                       'agent_id': 'ovs-agent-%s' % host,
                       'host': host}
        if vif_type == 'ovs':
            self.plugin_rpc.update_device_up(self.context, **device_dict)
        elif (port.get(portbindings.VNIC_TYPE) == 'normal'
              and vif_type == 'unbound'):
            self.plugin_rpc.update_device_down(self.context, **device_dict)
