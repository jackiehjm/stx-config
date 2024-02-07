# vim: tabstop=4 shiftwidth=4 softtabstop=4

# All Rights Reserved.
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

# Server Specific Configurations
server = {
    'port': '6385',
    'host': '0.0.0.0'
}

# Pecan Application Configurations
app = {
    'root': 'sysinv.api.controllers.root.RootController',
    'modules': ['sysinv.api'],
    'static_root': '%(confdir)s/public',
    'debug': False,
    'enable_acl': True,
    'acl_public_routes': ['/', '/v1', '/v1/isystems/mgmtvlan',
                          '/v1/ihosts/wipe_osds',
                          '/v1/ihosts/.+/install_progress',
                          '/v1/ihosts/[a-z0-9\-]+/icpus/platform_cpu_list',
                          '/v1/ihosts/[a-z0-9\-]+/icpus/vswitch_cpu_list',
                          '/v1/upgrade/[a-zA-Z0-9\-]+/in_upgrade',
                          '/v1/upgrade/[a-zA-Z0-9\-]+/upgrade_in_progress',
                          '/v1/ihosts/[a-zA-Z0-9\:]+/mgmt_ip',
                          ]
}
