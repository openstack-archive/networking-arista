# Copyright (c) 2016 OpenStack Foundation
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


def setup_arista_wrapper_config(cfg, host='host', user='user'):
    cfg.CONF.keystone_authtoken = fake_keystone_info_class()
    cfg.CONF.set_override('eapi_host', host, "ml2_arista")
    cfg.CONF.set_override('eapi_username', user, "ml2_arista")
    cfg.CONF.set_override('sync_interval', 10, "ml2_arista")
    cfg.CONF.set_override('conn_timeout', 20, "ml2_arista")
    cfg.CONF.set_override('switch_info', ['switch1:user:pass'], "ml2_arista")
    cfg.CONF.set_override('sec_group_support', False, "ml2_arista")


class fake_keystone_info_class(object):
    """To generate fake Keystone Authentication token information

    Arista Driver expects Keystone auth info. This fake information
    is for testing only
    """
    auth_uri = False
    auth_protocol = 'abc'
    auth_host = 'host'
    auth_port = 5000
    admin_user = 'neutron'
    admin_password = 'fun'
    admin_tenant_name = 'tenant_name'
