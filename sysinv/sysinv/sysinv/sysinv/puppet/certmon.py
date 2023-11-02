#
# Copyright (c) 2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sysinv.puppet import openstack
from sysinv.common import constants
from sysinv.common import utils


class CertMonPuppet(openstack.OpenstackBasePuppet):
    """Class to encapsulate puppet operations for sysinv configuration"""
    SYSINV_SERVICE_NAME = 'sysinv'
    DC_SERVICE_NAME = 'dcmanager'

    def get_secure_static_config(self):
        sysinv_kspass = self._get_service_password(self.SYSINV_SERVICE_NAME)
        dc_kspass = self._get_service_password(self.DC_SERVICE_NAME)
        return {
            'sysinv::certmon::local_keystone_password': sysinv_kspass,
            'sysinv::certmon::dc_keystone_password': dc_kspass,
        }

    def get_system_config(self):
        sysinv_user = self._get_service_user_name(self.SYSINV_SERVICE_NAME)

        host = (constants.CONTROLLER_FQDN
                if utils.is_fqdn_ready_to_use()
                else None)

        config = {}
        config.update({
            # The auth info for local authentication
            'sysinv::certmon::local_keystone_auth_uri': self._keystone_auth_uri(host),
            'sysinv::certmon::local_keystone_identity_uri': self._keystone_identity_uri(host),
            'sysinv::certmon::local_keystone_project_domain': self._get_service_project_domain_name(),
            'sysinv::certmon::local_keystone_tenant': self._get_service_project_name(),
            'sysinv::certmon::local_keystone_user': sysinv_user,
            'sysinv::certmon::local_keystone_user_domain': self._get_service_user_domain_name(),
            'sysinv::certmon::local_region_name': self._keystone_region_name(),
        })

        if self._distributed_cloud_role() == constants.DISTRIBUTED_CLOUD_ROLE_SYSTEMCONTROLLER:
            dc_user = self._get_service_user_name(self.DC_SERVICE_NAME),
            config.update({
                # The auth info for DC authentication
                'sysinv::certmon::dc_keystone_auth_uri': self._keystone_auth_uri(host),
                'sysinv::certmon::dc_keystone_identity_uri': self._keystone_identity_uri(host),
                'sysinv::certmon::dc_keystone_project_domain': self._get_service_project_domain_name(),
                'sysinv::certmon::dc_keystone_tenant': self._get_service_project_name(),
                'sysinv::certmon::dc_keystone_user': dc_user,
                'sysinv::certmon::dc_keystone_user_domain': self._get_service_user_domain_name(),
                'sysinv::certmon::dc_region_name': self._keystone_region_name(),
            })

        return config

    def get_public_url(self):
        # not an openstack service
        raise NotImplementedError()

    def get_internal_url(self):
        # not an openstack service
        raise NotImplementedError()

    def get_admin_url(self):
        # not an openstack service
        raise NotImplementedError()
