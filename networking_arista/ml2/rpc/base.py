# Copyright (c) 2014 OpenStack Foundation
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

import abc
import base64
import os

from oslo_config import cfg
from oslo_log import log as logging
import six

from networking_arista._i18n import _, _LW
from networking_arista.common import exceptions as arista_exc

LOG = logging.getLogger(__name__)


@six.add_metaclass(abc.ABCMeta)
class AristaRPCWrapperBase(object):
    """Wraps Arista JSON RPC.

    All communications between Neutron and EOS are over JSON RPC.
    EOS - operating system used on Arista hardware
    Command API - JSON RPC API provided by Arista EOS
    """
    def __init__(self):
        self._validate_config()
        self._server_ip = None
        self.region = cfg.CONF.ml2_arista.region_name
        self.sync_interval = cfg.CONF.ml2_arista.sync_interval
        self.conn_timeout = cfg.CONF.ml2_arista.conn_timeout
        self.eapi_hosts = cfg.CONF.ml2_arista.eapi_host.split(',')

        # Indication of CVX availabililty in the driver.
        self._cvx_available = True

        # Reference to SyncService object which is set in AristaDriver
        self.sync_service = None

    def _validate_config(self):
        if cfg.CONF.ml2_arista.get('eapi_host') == '':
            msg = _('Required option eapi_host is not set')
            LOG.error(msg)
            raise arista_exc.AristaConfigError(msg=msg)
        if cfg.CONF.ml2_arista.get('eapi_username') == '':
            msg = _('Required option eapi_username is not set')
            LOG.error(msg)
            raise arista_exc.AristaConfigError(msg=msg)

    def _api_username(self):
        return cfg.CONF.ml2_arista.eapi_username

    def _api_password(self):
        return cfg.CONF.ml2_arista.eapi_password

    def _get_random_name(self, length=10):
        """Returns a base64 encoded name."""
        result = base64.b64encode(os.urandom(10)).translate(None, b'=+/')

        return result if six.PY2 else result.decode('utf-8')

    def _get_cvx_hosts(self):
        cvx = []
        if self._server_ip:
            # If we know the master's IP, let's start with that
            cvx.append(self._server_ip)

        for h in self.eapi_hosts:
            if h.strip() not in cvx:
                cvx.append(h.strip())

        return cvx

    def set_cvx_unavailable(self):
        self._cvx_available = False
        if self.sync_service:
            self.sync_service.force_sync()

    def set_cvx_available(self):
        self._cvx_available = True

    def cvx_available(self):
        return self._cvx_available

    def check_cvx_availability(self):
        try:
            if self._get_eos_master():
                self.set_cvx_available()
                return True
        except Exception as exc:
            LOG.warning(_LW('%s when getting CVX master'), exc)
            LOG.warning("Failed to initialize connection with CVX. Please "
                        "ensure CVX is reachable and running EOS 4.18.1 "
                        "or greater.")

        self.set_cvx_unavailable()
        return False
