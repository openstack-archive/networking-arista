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

MECHANISM_DRV_NAME = 'arista'

# Resource actions
CREATE = 'create'
UPDATE = 'update'
DELETE = 'delete'

# Resource types
TENANT_RESOURCE = 'tenant'
NETWORK_RESOURCE = 'network'
SEGMENT_RESOURCE = 'segment'
DHCP_RESOURCE = 'dhcp'
ROUTER_RESOURCE = 'router'
VM_RESOURCE = 'vm'
BAREMETAL_RESOURCE = 'baremetal'
PORT_SUFFIX = '_port'
DHCP_PORT_RESOURCE = DHCP_RESOURCE + PORT_SUFFIX
ROUTER_PORT_RESOURCE = ROUTER_RESOURCE + PORT_SUFFIX
VM_PORT_RESOURCE = VM_RESOURCE + PORT_SUFFIX
BAREMETAL_PORT_RESOURCE = BAREMETAL_RESOURCE + PORT_SUFFIX
PORT_BINDING_RESOURCE = 'port_binding'

ALL_RESOURCE_TYPES = [TENANT_RESOURCE,
                      NETWORK_RESOURCE,
                      SEGMENT_RESOURCE,
                      DHCP_RESOURCE,
                      ROUTER_RESOURCE,
                      VM_RESOURCE,
                      BAREMETAL_RESOURCE,
                      DHCP_PORT_RESOURCE,
                      VM_PORT_RESOURCE,
                      BAREMETAL_PORT_RESOURCE,
                      PORT_BINDING_RESOURCE]

# EAPI error messages of interest
EOS_UNREACHABLE_MSG = _('Unable to reach EOS')
UNABLE_TO_DELETE_PORT_MSG = _('Unable to delete port from EOS')
UNABLE_TO_DELETE_DEVICE_MSG = _('Unable to delete device')
ERR_CVX_NOT_LEADER = _('Only available on cluster leader')
