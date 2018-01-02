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

from neutron_lib import constants as n_const
from oslo_log import log as logging


LOG = logging.getLogger(__name__)


def supported_device_owner(device_owner):
    supported_device_owner = [n_const.DEVICE_OWNER_DHCP,
                              n_const.DEVICE_OWNER_DVR_INTERFACE]

    if any([device_owner in supported_device_owner,
            device_owner.startswith('compute') and
            device_owner != 'compute:probe',
            device_owner.startswith('baremetal'),
            device_owner.startswith('trunk')]):
        return True

    LOG.debug('Unsupported device owner: %s', device_owner)
    return False
