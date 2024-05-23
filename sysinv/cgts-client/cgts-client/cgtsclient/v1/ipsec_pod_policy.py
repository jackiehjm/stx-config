#
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# -*- encoding: utf-8 -*-
#

from cgtsclient.common import base
from cgtsclient import exc

CREATION_ATTRIBUTES = ['protocol', 'port']


class ipsec_pod_policy(base.Resource):
    def __repr__(self):
        return "<ipsec_pod_policy %s>" % self._info


class ipsec_pod_policyManager(base.Manager):
    resource_class = ipsec_pod_policy

    def list(self):
        path = '/v1/ipsec_pod_policy/'
        ret = self._list(path, "ipsec_pod_policy")
        return ret

    def get(self, ipsec_pod_policy_uuid):
        path = '/v1/ipsec_pod_policy/%s' % ipsec_pod_policy_uuid
        try:
            return self._list(path)[0]
        except IndexError:
            return None

    def delete(self, ipsec_pod_policy_uuid):
        path = '/v1/ipsec_pod_policy/%s' % ipsec_pod_policy_uuid
        return self._delete(path)

    def create(self, **kwargs):
        path = '/v1/ipsec_pod_policy'
        new = {}
        for (key, value) in kwargs.items():
            if key in CREATION_ATTRIBUTES:
                new[key] = value
            else:
                raise exc.InvalidAttribute('%s' % key)
        return self._create(path, new)

    def update(self, policy_uuid, patch):
        path = '/v1/ipsec_pod_policy/%s' % policy_uuid
        return self._update(path, patch)
