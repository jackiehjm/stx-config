#
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# vim: tabstop=4 shiftwidth=4 softtabstop=4
# coding=utf-8
#

from sysinv.db import api as db_api
from sysinv.objects import base
from sysinv.objects import utils


class IpsecPodPolicy(base.SysinvObject):
    VERSION = '1.0'

    dbapi = db_api.get_instance()

    fields = {
        'id': int,
        'uuid': utils.uuid_or_none,
        'protocol': utils.str_or_none,
        'port': utils.str_or_none,
        'policy_status': utils.str_or_none,
    }

    @base.remotable_classmethod
    def get_by_uuid(cls, context, uuid):
        return cls.dbapi.ipsec_pod_policy_get(uuid)
