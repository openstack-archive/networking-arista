# Copyright 2015 OpenStack Foundation
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#

"""Initial db version

Revision ID: 296b4e0236e0
Create Date: 2015-10-23 14:37:49.594974

"""

from neutron.db.migration import cli

# revision identifiers, used by Alembic.
revision = '1c6993ce7db0'
down_revision = '296b4e0236e0'
branch_labels = (cli.EXPAND_BRANCH,)


def upgrade():
    pass
