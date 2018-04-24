# Copyright (c) 2017 Arista Networks, Inc
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
import requests
from requests import exceptions as requests_exc
import testtools

from networking_arista.common import api


class TestEAPIClientInit(testtools.TestCase):
    def test_basic_init(self):
        host_ip = '10.20.30.40'
        client = api.EAPIClient(host_ip)
        self.assertEqual(client.host, host_ip)
        self.assertEqual(client.url, 'https://10.20.30.40/command-api')
        self.assertDictContainsSubset(
            {'Content-Type': 'application/json', 'Accept': 'application/json'},
            client.session.headers
        )

    def test_init_enable_verify(self):
        client = api.EAPIClient('10.0.0.1', verify=True)
        self.assertTrue(client.session.verify)

    def test_init_auth(self):
        client = api.EAPIClient('10.0.0.1', username='user', password='pass')
        self.assertEqual(client.session.auth, ('user', 'pass'))

    def test_init_timeout(self):
        client = api.EAPIClient('10.0.0.1', timeout=99)
        self.assertEqual(client.timeout, 99)

    def test_make_url(self):
        url = api.EAPIClient._make_url('1.2.3.4')
        self.assertEqual(url, 'https://1.2.3.4/command-api')

    def test_make_url_http(self):
        url = api.EAPIClient._make_url('5.6.7.8', 'http')
        self.assertEqual(url, 'http://5.6.7.8/command-api')


class TestEAPIClientExecute(testtools.TestCase):
    def setUp(self):
        super(TestEAPIClientExecute, self).setUp()

        mock.patch('requests.Session.post').start()
        self.mock_log = mock.patch.object(api, 'LOG').start()
        self.mock_json_dumps = mock.patch.object(api.json, 'dumps').start()

        self.addCleanup(mock.patch.stopall)

        self.client = api.EAPIClient('10.0.0.1', timeout=99)

    def _test_execute_helper(self, commands, commands_to_log=None):
        expected_data = {
            'id': 'Networking Arista Driver',
            'method': 'runCmds',
            'jsonrpc': '2.0',
            'params': {
                'timestamps': False,
                'format': 'json',
                'version': 1,
                'cmds': commands
            }
        }

        self.client.session.post.assert_called_once_with(
            'https://10.0.0.1/command-api',
            data=self.mock_json_dumps.return_value,
            timeout=99
        )

        self.mock_log.info.assert_has_calls(
            [
                mock.call(
                    mock.ANY,
                    {
                        'ip': '10.0.0.1',
                        'data': self.mock_json_dumps.return_value
                    }
                )
            ]
        )

        log_data = dict(expected_data)
        log_data['params'] = dict(expected_data['params'])
        log_data['params']['cmds'] = commands_to_log or commands

        self.mock_json_dumps.assert_has_calls(
            [
                mock.call(log_data),
                mock.call(expected_data)
            ]
        )

    def test_command_prep(self):
        commands = ['enable']
        self.client.execute(commands)
        self._test_execute_helper(commands)

    def test_commands_to_log(self):
        commands = ['config', 'secret']
        commands_to_log = ['config', '******']
        self.client.execute(commands, commands_to_log)
        self._test_execute_helper(commands, commands_to_log)

    def _test_execute_error_helper(self, raise_exception, expected_exception,
                                   warning_has_params=False):
        commands = ['config']

        self.client.session.post.side_effect = raise_exception

        self.assertRaises(
            expected_exception,
            self.client.execute,
            commands
        )

        self._test_execute_helper(commands)

        if warning_has_params:
            args = (mock.ANY, mock.ANY)
        else:
            args = (mock.ANY,)
        self.mock_log.warning.assert_called_once_with(*args)

    def test_request_connection_error(self):
        self._test_execute_error_helper(
            requests_exc.ConnectionError,
            api.arista_exc.AristaRpcError
        )

    def test_request_connect_timeout(self):
        self._test_execute_error_helper(
            requests_exc.ConnectTimeout,
            api.arista_exc.AristaRpcError
        )

    def test_request_timeout(self):
        self._test_execute_error_helper(
            requests_exc.Timeout,
            api.arista_exc.AristaRpcError
        )

    def test_request_connect_InvalidURL(self):
        self._test_execute_error_helper(
            requests_exc.InvalidURL,
            api.arista_exc.AristaRpcError
        )

    def test_request_other_exception(self):
        class OtherException(Exception):
            pass

        self._test_execute_error_helper(
            OtherException,
            OtherException,
            warning_has_params=True
        )

    def _test_response_helper(self, response_data):
        mock_response = mock.MagicMock(requests.Response)
        mock_response.status_code = requests.status_codes.codes.OK
        mock_response.json.return_value = response_data
        self.client.session.post.return_value = mock_response

    def test_response_success(self):
        mock_response = mock.MagicMock(requests.Response)
        mock_response.status_code = requests.status_codes.codes.OK
        mock_response.json.return_value = {'result': mock.sentinel}
        self.client.session.post.return_value = mock_response

        retval = self.client.execute(['enable'])
        self.assertEqual(retval, mock.sentinel)

    def test_response_json_error(self):
        mock_response = mock.MagicMock(requests.Response)
        mock_response.status_code = requests.status_codes.codes.OK
        mock_response.json.side_effect = ValueError
        self.client.session.post.return_value = mock_response

        retval = self.client.execute(['enable'])
        self.assertIsNone(retval)
        self.mock_log.info.assert_has_calls([mock.call(mock.ANY)])

    def _test_response_format_error_helper(self, bad_response):
        mock_response = mock.MagicMock(requests.Response)
        mock_response.status_code = requests.status_codes.codes.OK
        mock_response.json.return_value = bad_response
        self.client.session.post.return_value = mock_response

        self.assertRaises(
            api.arista_exc.AristaRpcError,
            self.client.execute,
            ['enable']
        )
        self.mock_log.info.assert_has_calls([mock.call(mock.ANY)])

    def test_response_format_error(self):
        self._test_response_format_error_helper({})

    def test_response_unknown_error_code(self):
        self._test_response_format_error_helper(
            {'error': {'code': 999}}
        )

    def test_response_known_error_code(self):
        self._test_response_format_error_helper(
            {'error': {'code': 1002, 'data': []}}
        )

    def test_response_known_error_code_data_is_not_dict(self):
        self._test_response_format_error_helper(
            {'error': {'code': 1002, 'data': ['some text']}}
        )

    def test_response_not_cvx_leader(self):
        mock_response = mock.MagicMock(requests.Response)
        mock_response.status_code = requests.status_codes.codes.OK
        mock_response.json.return_value = {
            'error': {
                'code': 1002,
                'data': [{'errors': [api.ERR_CVX_NOT_LEADER]}]
            }
        }
        self.client.session.post.return_value = mock_response

        retval = self.client.execute(['enable'])
        self.assertIsNone(retval)

    def test_response_other_exception(self):
        class OtherException(Exception):
            pass

        mock_response = mock.MagicMock(requests.Response)
        mock_response.status_code = requests.status_codes.codes.OK
        mock_response.json.return_value = 'text'
        self.client.session.post.return_value = mock_response

        self.assertRaises(
            TypeError,
            self.client.execute,
            ['enable']
        )
        self.mock_log.warning.assert_has_calls(
            [
                mock.call(mock.ANY, {'error': mock.ANY})
            ]
        )
