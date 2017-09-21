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

from neutron_lib.db import api as db_api
from oslo_config import cfg
from oslo_log import log as logging
import six

from neutron.db.models.plugins.ml2 import vlanallocation

from networking_arista._i18n import _, _LW
from networking_arista.common import exceptions as arista_exc
from networking_arista.ml2 import arista_sec_gp

LOG = logging.getLogger(__name__)


@six.add_metaclass(abc.ABCMeta)
class AristaRPCWrapperBase(object):
    """Wraps Arista JSON RPC.

    All communications between Neutron and EOS are over JSON RPC.
    EOS - operating system used on Arista hardware
    Command API - JSON RPC API provided by Arista EOS
    """
    def __init__(self, neutron_db):
        self._ndb = neutron_db
        self._validate_config()
        self._server_ip = None
        self.region = cfg.CONF.ml2_arista.region_name
        self.sync_interval = cfg.CONF.ml2_arista.sync_interval
        self.conn_timeout = cfg.CONF.ml2_arista.conn_timeout
        self.eapi_hosts = cfg.CONF.ml2_arista.eapi_host.split(',')
        self.security_group_driver = arista_sec_gp.AristaSecGroupSwitchDriver(
            self._ndb)

        # We denote mlag_pair physnets as peer1_peer2 in the physnet name, the
        # following builds a mapping of peer name to physnet name for use
        # during port binding
        self.mlag_pairs = {}
        session = db_api.get_reader_session()
        with session.begin():
            physnets = session.query(
                vlanallocation.VlanAllocation.physical_network
            ).distinct().all()
        for (physnet,) in physnets:
            if '_' in physnet:
                peers = physnet.split('_')
                self.mlag_pairs[peers[0]] = physnet
                self.mlag_pairs[peers[1]] = physnet

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

    def _clean_acls(self, sg, failed_switch, switches_to_clean):
        """This is a helper function to clean up ACLs on switches.

        This called from within an exception - when apply_acl fails.
        Therefore, ensure that exception is raised after the cleanup
        is done.
        :param sg: Security Group to be removed
        :param failed_switch: IP of the switch where ACL failed
        :param switches_to_clean: List of switches containing link info
        """
        if not switches_to_clean:
            # This means the no switch needs cleaning - so, simply raise the
            # the exception and bail out
            msg = (_("Failed to apply ACL %(sg)s on switch %(switch)s") %
                   {'sg': sg, 'switch': failed_switch})
            LOG.error(msg)

        for s in switches_to_clean:
            try:
                # Port is being updated to remove security groups
                self.security_group_driver.remove_acl(sg,
                                                      s['switch_id'],
                                                      s['port_id'],
                                                      s['switch_info'])
            except Exception:
                msg = (_("Failed to remove ACL %(sg)s on switch %(switch)%") %
                       {'sg': sg, 'switch': s['switch_info']})
                LOG.warning(msg)
        raise arista_exc.AristaSecurityGroupError(msg=msg)

    def create_acl(self, sg):
        """Creates an ACL on Arista Switch.

        Deals with multiple configurations - such as multiple switches
        """
        self.security_group_driver.create_acl(sg)

    def delete_acl(self, sg):
        """Deletes an ACL from Arista Switch.

        Deals with multiple configurations - such as multiple switches
        """
        self.security_group_driver.delete_acl(sg)

    def create_acl_rule(self, sgr):
        """Creates an ACL on Arista Switch.

        For a given Security Group (ACL), it adds additional rule
        Deals with multiple configurations - such as multiple switches
        """
        self.security_group_driver.create_acl_rule(sgr)

    def delete_acl_rule(self, sgr):
        """Deletes an ACL rule on Arista Switch.

        For a given Security Group (ACL), it removes a rule
        Deals with multiple configurations - such as multiple switches
        """
        self.security_group_driver.delete_acl_rule(sgr)

    def perform_sync_of_sg(self):
        """Perform sync of the security groups between ML2 and EOS.

        This is unconditional sync to ensure that all security
        ACLs are pushed to all the switches, in case of switch
        or neutron reboot
        """
        self.security_group_driver.perform_sync_of_sg()

    def apply_security_group(self, security_group, switch_bindings):
        """Applies ACLs on switch interface.

        Translates neutron security group to switch ACL and applies the ACLs
        on all the switch interfaces defined in the switch_bindings.

        :param security_group: Neutron security group
        :param switch_bindings: Switch link information
        """
        switches_with_acl = []
        for binding in switch_bindings:
            try:
                self.security_group_driver.apply_acl(security_group,
                                                     binding['switch_id'],
                                                     binding['port_id'],
                                                     binding['switch_info'])
                switches_with_acl.append(binding)
            except Exception:
                message = _LW('Unable to apply security group on %s') % (
                    binding['switch_id'])
                LOG.warning(message)
                self._clean_acls(security_group, binding['switch_id'],
                                 switches_with_acl)

    def remove_security_group(self, security_group, switch_bindings):
        """Removes ACLs from switch interface

        Translates neutron security group to switch ACL and removes the ACLs
        from all the switch interfaces defined in the switch_bindings.

        :param security_group: Neutron security group
        :param switch_bindings: Switch link information
        """
        for binding in switch_bindings:
            try:
                self.security_group_driver.remove_acl(security_group,
                                                      binding['switch_id'],
                                                      binding['port_id'],
                                                      binding['switch_info'])
            except Exception:
                message = _LW('Unable to remove security group from %s') % (
                    binding['switch_id'])
                LOG.warning(message)
