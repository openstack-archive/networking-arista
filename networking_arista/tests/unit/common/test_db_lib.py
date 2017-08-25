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

from neutron_lib.plugins import constants as plugin_constants
from neutron_lib.plugins import directory
from oslo_utils import importutils

from neutron.tests.unit import testlib_api

from networking_arista.common import db_lib
from networking_arista.tests.unit import utils


class DbLibTest(testlib_api.SqlTestCase):
    """Test cases for database helper functions."""

    def setUp(self):
        super(DbLibTest, self).setUp()
        plugin_klass = importutils.import_class(
            "neutron.db.db_base_plugin_v2.NeutronDbPluginV2")
        directory.add_plugin(plugin_constants.CORE, plugin_klass())

    def test_get_tenants_empty(self):
        tenants = db_lib.get_tenants()
        assert tenants == set()

    def test_get_tenants_from_networks(self):
        tenant_1_id = 't1'
        network_1_id = 'n1'
        seg_1_id = 11
        utils.create_network(tenant_1_id,
                             network_1_id,
                             seg_1_id)
        tenant_2_id = 't2'
        network_2_id = 'n2'
        seg_2_id = 21
        utils.create_network(tenant_2_id,
                             network_2_id,
                             seg_2_id)

        tenants = db_lib.get_tenants()
        assert tenants == set([tenant_1_id, tenant_2_id])

    def test_get_tenants_with_shared_network_ports(self):
        tenant_1_id = 't1'
        port_1_id = 'p1'
        device_1_id = 'v1'

        tenant_2_id = 't2'
        port_2_id = 'p2'
        device_2_id = 'v2'

        network_id = 'n1'
        seg_id = 11
        network_ctx = utils.create_network(tenant_1_id,
                                           network_id,
                                           seg_id,
                                           shared=True)

        utils.create_port(tenant_1_id, network_id, device_1_id,
                          port_1_id, network_ctx)
        utils.create_port(tenant_2_id, network_id, device_2_id,
                          port_2_id, network_ctx)

        tenants = db_lib.get_tenants()
        assert tenants == set([tenant_1_id, tenant_2_id])

    def test_get_tenants_uniqueness(self):
        tenant_1_id = 't1'
        network_1_id = 'n1'
        seg_1_id = 11
        network_1_ctx = utils.create_network(tenant_1_id,
                                             network_1_id,
                                             seg_1_id)
        tenant_2_id = 't2'
        network_2_id = 'n2'
        seg_2_id = 21
        network_2_ctx = utils.create_network(tenant_2_id,
                                             network_2_id,
                                             seg_2_id)
        device_1_id = 'v1'
        port_1_id = 'p1'
        device_2_id = 'v2'
        port_2_id = 'p2'
        utils.create_port(tenant_1_id, network_1_id, device_1_id,
                          port_1_id, network_1_ctx)
        utils.create_port(tenant_2_id, network_2_id, device_2_id,
                          port_2_id, network_2_ctx)

        tenants = db_lib.get_tenants()
        assert tenants == set([tenant_1_id, tenant_2_id])

    def test_get_tenants_port_network_union(self):
        tenant_1_id = 't1'
        network_1_id = 'n1'
        seg_1_id = 11
        network_1_ctx = utils.create_network(tenant_1_id,
                                             network_1_id,
                                             seg_1_id,
                                             shared=True)
        tenant_2_id = 't2'
        network_2_id = 'n2'
        seg_2_id = 21
        network_2_ctx = utils.create_network(tenant_2_id,
                                             network_2_id,
                                             seg_2_id,
                                             shared=True)
        tenant_3_id = 't3'
        port_1_id = 'p1'
        device_1_id = 'v1'
        utils.create_port(tenant_3_id, network_1_id, device_1_id, port_1_id,
                          network_1_ctx)
        tenant_4_id = 't4'
        port_2_id = 'p2'
        device_2_id = 'v2'
        utils.create_port(tenant_4_id, network_2_id, device_2_id, port_2_id,
                          network_2_ctx)

        tenants = db_lib.get_tenants()
        assert tenants == set([tenant_1_id, tenant_2_id,
                               tenant_3_id, tenant_4_id])
