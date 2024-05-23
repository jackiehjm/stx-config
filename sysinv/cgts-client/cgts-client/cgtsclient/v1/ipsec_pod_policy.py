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


class IpsecPodPolicy(base.Resource):
    def __repr__(self):
        return "<ipsec_pod_policy %s>" % self._info


class IpsecPodPolicyManager(base.Manager):
    resource_class = IpsecPodPolicy

    def list(self):
        """Show list of IPsec pod policies."""
        path = '/v1/ipsec_pod_policy/'
        ret = self._list(path, "ipsec_pod_policy")
        return ret

    def apply(self):
        """Apply IPsec pod policies."""
        path = '/v1/ipsec_pod_policy/apply'
        return self._update(path, None)

    def get(self, ipsec_pod_policy_uuid):
        """Show an IPsec pod policy."""
        path = '/v1/ipsec_pod_policy/%s' % ipsec_pod_policy_uuid
        try:
            return self._list(path)[0]
        except IndexError:
            return None

    def delete(self, ipsec_pod_policy_uuid):
        """Delete an IPsec pod policy by UUID."""
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
        """Update an IPsec pod policy's port or protocol"""
        path = '/v1/ipsec_pod_policy/%s' % policy_uuid
        return self._update(path, patch)
