# Copyright 2017 Arista Networks, Inc.
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

"""Drop AristaProvisionedVms

Revision ID: 941bad5630c1
Revises: 39c2eeb67116
Create Date: 2017-08-31 17:44:21.334780

"""

# revision identifiers, used by Alembic.
revision = '941bad5630c1'
down_revision = '39c2eeb67116'
branch_labels = None
depends_on = None

from alembic import op


def upgrade():
    op.drop_table('arista_provisioned_vms')
