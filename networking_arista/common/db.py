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

from neutron.plugins.ml2 import models as ml2_models
from sqlalchemy.orm import relationship


class PortBindingWithLevels(ml2_models.PortBinding):
    levels = relationship(
        ml2_models.PortBindingLevel,
        primaryjoin="and_("
        "PortBindingWithLevels.port_id == PortBindingLevel.port_id,"
        "PortBindingWithLevels.host == PortBindingLevel.host)",
        foreign_keys='[PortBindingLevel.port_id, PortBindingLevel.host]',
        lazy='joined')

    __mapper_args__ = {
        'polymorphic_identity': 'PortBindingWithLevels'
    }


class DistributedPortBindingWithLevels(ml2_models.DistributedPortBinding):
    levels = relationship(
        ml2_models.PortBindingLevel,
        primaryjoin="and_("
        "DistributedPortBindingWithLevels.port_id == PortBindingLevel.port_id,"
        "DistributedPortBindingWithLevels.host == PortBindingLevel.host)",
        foreign_keys='[PortBindingLevel.port_id, PortBindingLevel.host]',
        lazy='joined')

    __mapper_args__ = {
        'polymorphic_identity': 'DistributedPortBindingWithLevels'
    }
