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

from networking_arista._i18n import _

EOS_UNREACHABLE_MSG = _('Unable to reach EOS')
UNABLE_TO_DELETE_PORT_MSG = _('Unable to delete port from EOS')
UNABLE_TO_DELETE_DEVICE_MSG = _('Unable to delete device')

# Constants
INTERNAL_TENANT_ID = 'INTERNAL-TENANT-ID'
MECHANISM_DRV_NAME = 'arista'

# EAPI error messages of interest
ERR_CVX_NOT_LEADER = 'only available on cluster leader'

# Flat network constant
NETWORK_TYPE_FLAT = 'flat'


class InstanceType(object):
    BAREMETAL = 'baremetal'
    DHCP = 'dhcp'
    ROUTER = 'router'
    VM = 'vm'

    VIRTUAL_INSTANCE_TYPES = [DHCP, ROUTER, VM]
    BAREMETAL_INSTANCE_TYPES = [BAREMETAL]
