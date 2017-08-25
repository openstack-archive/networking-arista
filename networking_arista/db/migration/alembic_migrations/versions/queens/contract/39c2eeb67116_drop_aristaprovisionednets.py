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

"""Drop AristaProvisionedNets

Revision ID: 39c2eeb67116
Revises: dc7bf9c1ab4d
Create Date: 2017-08-25 16:42:31.814580

"""

# revision identifiers, used by Alembic.
revision = '39c2eeb67116'
down_revision = 'dc7bf9c1ab4d'
branch_labels = None
depends_on = None

from alembic import op


def upgrade():
    op.drop_table('arista_provisioned_nets')
