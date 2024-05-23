#
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sqlalchemy import Column, MetaData, Table, Integer
from sqlalchemy import String, DateTime
import json

ENGINE = 'InnoDB'
CHARSET = 'utf8'


def upgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine

    # Seed SDN disabled capability in the i_system DB table
    systems = Table('i_system', meta, autoload=True)
    # only one system entry should be populated
    sys = list(systems.select().where(
        systems.c.uuid is not None).execute())
    if len(sys) > 0:
        json_dict = json.loads(sys[0].capabilities)
        json_dict['pod_to_pod_security_enabled'] = 'n'
        systems.update().where(  # pylint: disable=no-value-for-parameter
            systems.c.uuid == sys[0].uuid).values(
            {'capabilities': json.dumps(json_dict)}).execute()

    ipsec_pod_policy_table = Table(
        'ipsec_pod_policy',
        meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),
        Column('id', Integer, primary_key=True, nullable=False),
        Column('uuid', String(36), unique=True),
        Column('protocol', String(10)),
        Column('port', String(20)),
        Column('policy_status', String(20)),
        mysql_engine=ENGINE,
        mysql_charset=CHARSET,
    )
    ipsec_pod_policy_table.create()


def downgrade(migrate_engine):
    raise NotImplementedError('SysInv database downgrade is unsupported.')
