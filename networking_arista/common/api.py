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

import json

from oslo_log import log as logging
from oslo_utils import excutils
import requests
from requests import exceptions as requests_exc
from six.moves.urllib import parse

from networking_arista._i18n import _LI, _LW, _LC
from networking_arista.common import exceptions as arista_exc

LOG = logging.getLogger(__name__)

# EAPI error message
ERR_CVX_NOT_LEADER = 'only available on cluster leader'


class EAPIClient(object):
    def __init__(self, host, username=None, password=None, verify=False,
                 timeout=None):
        self.host = host
        self.timeout = timeout
        self.url = self._make_url(host)
        self.session = requests.Session()
        self.session.headers['Content-Type'] = 'application/json'
        self.session.headers['Accept'] = 'application/json'
        self.session.verify = verify
        self.session.auth = (username, password)

    @staticmethod
    def _make_url(host, scheme='https'):
        return parse.urlunsplit(
            (scheme, host, '/command-api', '', '')
        )

    def execute(self, commands, commands_to_log=None):
        params = {
            'timestamps': False,
            'format': 'json',
            'version': 1,
            'cmds': commands
        }

        data = {
            'id': 'Networking Arista Driver',
            'method': 'runCmds',
            'jsonrpc': '2.0',
            'params': params
        }

        if commands_to_log:
            log_data = dict(data)
            log_data['params'] = dict(params)
            log_data['params']['cmds'] = commands_to_log
        else:
            log_data = data

        LOG.info(
            _LI('EAPI request %(ip)s contains %(data)s'),
            {'ip': self.host, 'data': json.dumps(log_data)}
        )

        # request handling
        try:
            error = None
            response = self.session.post(
                self.url,
                data=json.dumps(data),
                timeout=self.timeout
            )
        except requests_exc.ConnectionError:
            error = _LW('Error while trying to connect to %(ip)s')
        except requests_exc.ConnectTimeout:
            error = _LW('Timed out while trying to connect to %(ip)s')
        except requests_exc.Timeout:
            error = _LW('Timed out during an EAPI request to %(ip)s')
        except requests_exc.InvalidURL:
            error = _LW('Ingoring attempt to connect to invalid URL at %(ip)s')
        except Exception as e:
            with excutils.save_and_reraise_exception():
                LOG.warning(
                    _LW('Error during processing the EAPI request %(error)s'),
                    {'error': e}
                )
        finally:
            if error:
                msg = error % {'ip': self.host}
                # stop processing since we've encountered request error
                LOG.warning(msg)
                raise arista_exc.AristaRpcError(msg=msg)

        if response.status_code != requests.status_codes.codes.OK:
            msg = _LC(
                'Error (%(code)s - %(reason)s) while executing the command')
            LOG.error(msg, {
                'code': response.status_code,
                'reason': response.text})

        # response handling
        try:
            resp_data = response.json()
            return resp_data['result']
        except ValueError as e:
            LOG.info(_LI('Ignoring invalid JSON response'))
        except KeyError:
            if 'error' in resp_data:
                for i, d in enumerate(resp_data['error']['data'], 1):
                    if not isinstance(d, dict):
                        continue
                    if 'messages' in d:
                        LOG.info(
                            _LI('Command %(cmd)s returned message %(msg)s'),
                            {'cmd': i, 'msg': d['messages']})
                    if 'errors' in d:
                        LOG.info(
                            _LI('Command %(cmd)s returned error %(err)s'),
                            {'cmd': i, 'err': d['errors']})
                        if ERR_CVX_NOT_LEADER in d['errors'][0]:
                            LOG.info(_LI('%(ip)s is not the CVX leader'),
                                     {'ip': self.host})
                            return
            msg = ('Unexpected EAPI error: %s' %
                   resp_data.get('error', {}).get('message', 'Unknown Error'))
            LOG.info(msg)
            raise arista_exc.AristaRpcError(msg=msg)
        except Exception as e:
            with excutils.save_and_reraise_exception():
                LOG.warning(
                    _LW('Error during processing the EAPI response %(error)s'),
                    {'error': e}
                )
