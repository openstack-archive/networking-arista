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

import mock
from oslo_config import cfg

from neutron.tests import base
from neutron.tests.unit import testlib_api

from networking_arista.common import exceptions as arista_exc
from networking_arista.ml2.rpc import arista_eapi
from networking_arista.tests.unit import utils


def setup_valid_config():
    utils.setup_arista_wrapper_config(cfg)


class AristaRPCWrapperInvalidConfigTestCase(base.BaseTestCase):
    """Negative test cases to test the Arista Driver configuration."""

    def setUp(self):
        super(AristaRPCWrapperInvalidConfigTestCase, self).setUp()
        self.setup_invalid_config()  # Invalid config, required options not set

    def setup_invalid_config(self):
        utils.setup_arista_wrapper_config(cfg, host='', user='')

    def test_raises_exception_on_wrong_configuration(self):
        self.assertRaises(arista_exc.AristaConfigError,
                          arista_eapi.AristaRPCWrapperEapi)


class NegativeRPCWrapperTestCase(testlib_api.SqlTestCase):
    """Negative test cases to test the RPC between Arista Driver and EOS."""

    def setUp(self):
        super(NegativeRPCWrapperTestCase, self).setUp()
        setup_valid_config()

    def test_exception_is_raised_on_json_server_error(self):
        drv = arista_eapi.AristaRPCWrapperEapi()

        drv.api_request = mock.MagicMock(
            side_effect=Exception('server error')
        )
        with mock.patch.object(arista_eapi.LOG, 'error') as log_err:
            self.assertRaises(arista_exc.AristaRpcError,
                              drv._run_openstack_cmds, [])
            log_err.assert_called_once_with(mock.ANY)
