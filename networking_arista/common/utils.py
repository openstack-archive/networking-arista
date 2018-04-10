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

from neutron.services.trunk import constants as t_const
from neutron_lib import constants as n_const
from oslo_config import cfg
from oslo_log import log as logging

LOG = logging.getLogger(__name__)


SUPPORTED_NETWORK_TYPES = [
    n_const.TYPE_VLAN,
    n_const.TYPE_VXLAN]


SUPPORTED_DEVICE_OWNERS = [
    n_const.DEVICE_OWNER_COMPUTE_PREFIX,
    n_const.DEVICE_OWNER_BAREMETAL_PREFIX,
    n_const.DEVICE_OWNER_DHCP,
    n_const.DEVICE_OWNER_DVR_INTERFACE,
    t_const.TRUNK_SUBPORT_OWNER]


UNSUPPORTED_DEVICE_OWNERS = [
    n_const.DEVICE_OWNER_COMPUTE_PREFIX + 'probe']


UNSUPPORTED_DEVICE_IDS = [
    n_const.DEVICE_ID_RESERVED_DHCP_PORT]

SUPPORTED_SG_PROTOCOLS = [
    None,
    n_const.PROTO_NAME_TCP,
    n_const.PROTO_NAME_UDP,
    n_const.PROTO_NAME_ICMP]

LOG = logging.getLogger(__name__)


def supported_device_owner(device_owner):

    if (any([device_owner.startswith(supported_owner) for
             supported_owner in SUPPORTED_DEVICE_OWNERS]) and
        not any([device_owner.startswith(unsupported_owner) for
                 unsupported_owner in UNSUPPORTED_DEVICE_OWNERS])):
        return True

    LOG.debug('Unsupported device owner: %s', device_owner)
    return False


def hostname(hostname):
    fqdns_used = cfg.CONF.ml2_arista['use_fqdn']
    return hostname if fqdns_used else hostname.split('.')[0]
