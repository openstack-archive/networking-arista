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
