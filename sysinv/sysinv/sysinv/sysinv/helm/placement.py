#
# Copyright (c) 2019 StarlingX.
#
# SPDX-License-Identifier: Apache-2.0
#

from sysinv.common import constants
from sysinv.common import exception
from sysinv.helm import common
from sysinv.helm import openstack


class PlacementHelm(openstack.OpenstackBaseHelm):
    """Class to encapsulate helm operations for the placement chart"""

    CHART = constants.HELM_CHART_PLACEMENT

    SERVICE_NAME = 'placement'
    AUTH_USERS = ['placement']

    def get_overrides(self, namespace=None):

        overrides = {
            common.HELM_NS_OPENSTACK: {
                'pod': {
                    'replicas': {
                        'api': self._num_controllers()
                    }
                },
                'endpoints': self._get_endpoints_overrides()
            }
        }

        if namespace in self.SUPPORTED_NAMESPACES:
            return overrides[namespace]
        elif namespace:
            raise exception.InvalidHelmNamespace(chart=self.CHART,
                                                 namespace=namespace)
        else:
            return overrides

    def _get_endpoints_overrides(self):
        overrides = {
            'identity': {
                'name': 'keystone',
                'auth': self._get_endpoints_identity_overrides(
                    self.SERVICE_NAME, self.AUTH_USERS),
            },
            'oslo_db': {
                'auth': self._get_endpoints_oslo_db_overrides(
                    self.SERVICE_NAME, [self.SERVICE_NAME])
            }
        }

        return overrides
