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

from neutron_lib.db import constants as db_const
from neutron_lib.db import model_base
import sqlalchemy as sa

UUID_LEN = 36
STR_LEN = 255


class HasTenant(object):
    """Tenant mixin, add to subclasses that have a tenant."""

    tenant_id = sa.Column(sa.String(db_const.PROJECT_ID_FIELD_SIZE),
                          index=True)


class AristaProvisionedNets(model_base.BASEV2, model_base.HasId,
                            HasTenant):
    """Stores networks provisioned on Arista EOS.

    Saves the segmentation ID for each network that is provisioned
    on EOS. This information is used during synchronization between
    Neutron and EOS.
    """
    __tablename__ = 'arista_provisioned_nets'

    network_id = sa.Column(sa.String(UUID_LEN))
    segmentation_id = sa.Column(sa.Integer)

    def eos_network_representation(self, segmentation_type):
        return {u'networkId': self.network_id,
                u'segmentationTypeId': self.segmentation_id,
                u'segmentationType': segmentation_type,
                u'tenantId': self.tenant_id,
                u'segmentId': self.id,
                }


class AristaProvisionedVms(model_base.BASEV2, model_base.HasId,
                           HasTenant):
    """Stores VMs provisioned on Arista EOS.

    All VMs launched on physical hosts connected to Arista
    Switches are remembered
    """
    __tablename__ = 'arista_provisioned_vms'

    vm_id = sa.Column(sa.String(STR_LEN))
    host_id = sa.Column(sa.String(STR_LEN))
    port_id = sa.Column(sa.String(UUID_LEN))
    network_id = sa.Column(sa.String(UUID_LEN))

    def eos_port_representation(self):
        return {u'portId': self.port_id,
                u'deviceId': self.vm_id,
                u'hosts': [self.host_id],
                u'networkId': self.network_id}


class AristaProvisionedTenants(model_base.BASEV2, model_base.HasId,
                               HasTenant):
    """Stores Tenants provisioned on Arista EOS.

    Tenants list is maintained for sync between Neutron and EOS.
    """
    __tablename__ = 'arista_provisioned_tenants'

    def eos_tenant_representation(self):
        return {u'tenantId': self.tenant_id}
