# vim: tabstop=4 shiftwidth=4 softtabstop=4
# coding=utf-8
# Copyright 2013 Hewlett-Packard Development Company, L.P.
# Copyright 2013 International Business Machines Corporation
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
#
# Copyright (c) 2013-2023 Wind River Systems, Inc.
#

"""Conduct all activity related system inventory.

A single instance of :py:class:`sysinv.conductor.manager.ConductorManager` is
created within the *sysinv-conductor* process, and is responsible for
performing all actions for hosts managed by system inventory.
Commands are received via RPC calls. The conductor service also performs
collection of inventory data for each host.

"""

import errno
import filecmp
import hashlib
import io
import math
import os
import re
import requests
import ruamel.yaml as yaml
from ruamel.yaml.compat import StringIO
import shutil
import six
import socket
import tempfile
import time
import traceback
import uuid
import xml.etree.ElementTree as ElementTree
from contextlib import contextmanager
from datetime import datetime
from distutils.util import strtobool
from distutils.version import LooseVersion
from copy import deepcopy

import tsconfig.tsconfig as tsc
from collections import namedtuple
from collections import OrderedDict
from cgcs_patch.patch_verify import verify_files
from controllerconfig.upgrades import management as upgrades_management
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from eventlet import greenthread
# Make subprocess module greenthread friendly
from eventlet.green import subprocess
from fm_api import constants as fm_constants
from fm_api import fm_api
from netaddr import IPAddress
from netaddr import IPNetwork
from oslo_config import cfg
from oslo_context import context as ctx
from oslo_log import log
from oslo_serialization import base64
from oslo_serialization import jsonutils
from oslo_service import periodic_task
from oslo_utils import encodeutils
from oslo_utils import excutils
from oslo_utils import timeutils
from oslo_utils import uuidutils
from platform_util.license import license
from sqlalchemy.orm import exc
from six.moves import http_client as httplib
from sysinv._i18n import _
from sysinv.agent import rpcapiproxy as agent_rpcapi
from sysinv.api.controllers.v1 import address_pool
from sysinv.api.controllers.v1 import cpu_utils
from sysinv.api.controllers.v1 import kube_app as kube_api
from sysinv.api.controllers.v1 import mtce_api
from sysinv.api.controllers.v1 import utils
from sysinv.api.controllers.v1 import vim_api
from sysinv.common import fpga_constants
from sysinv.common import constants
from sysinv.common import ceph as cceph
from sysinv.common import dc_api
from sysinv.common import device as dconstants
from sysinv.common import exception
from sysinv.common import fm
from sysinv.common import fernet
from sysinv.common import health
from sysinv.common import interface as cinterface
from sysinv.common import kubernetes
from sysinv.common import retrying
from sysinv.common import service
from sysinv.common import utils as cutils
from sysinv.common.retrying import retry
from sysinv.common.storage_backend_conf import StorageBackendConfig
from cephclient import wrapper as ceph
from sysinv.conductor import ceph as iceph
from sysinv.conductor import kube_app
from sysinv.conductor import openstack
from sysinv.conductor import docker_registry
from sysinv.conductor import keystone_listener
from sysinv.db import api as dbapi
from sysinv.loads.loads import LoadImport
from sysinv import objects
from sysinv.objects import base as objects_base
from sysinv.objects import kube_app as kubeapp_obj
from sysinv.openstack.common.rpc import service as rpc_service
from sysinv.puppet import common as puppet_common
from sysinv.puppet import puppet
from sysinv.puppet import interface as pinterface
from sysinv.helm import helm
from sysinv.helm.lifecycle_constants import LifecycleConstants
from sysinv.helm.lifecycle_hook import LifecycleHookInfo
from sysinv.zmq_rpc.zmq_rpc import ZmqRpcServer
from sysinv.zmq_rpc.zmq_rpc import is_rpc_hybrid_mode_active


MANAGER_TOPIC = 'sysinv.conductor_manager'

LOG = log.getLogger(__name__)

conductor_opts = [
       cfg.StrOpt('api_url',
                  default=None,
                  help=('Url of SysInv API service. If not set SysInv can '
                        'get current value from Keystone service catalog.')),
       cfg.IntOpt('osd_remove_retry_count',
                  default=11,
                  help=('Maximum number of retries in case Ceph OSD remove '
                        'requests fail because OSD is still up.')),
       cfg.IntOpt('osd_remove_retry_interval',
                  default=5,
                  help='Interval in seconds between retries to remove Ceph OSD.'),
       cfg.IntOpt('managed_app_auto_recovery_interval',
                  default=300,
                  help='Interval to run managed app auto recovery'),
       cfg.IntOpt('kube_upgrade_downgrade_retry_interval',
                  default=3600,
                  help='Interval in seconds between retries to upgrade/downgrade kubernetes components'),
       cfg.IntOpt('fw_update_large_timeout',
                  default=3600,
                  help='Timeout interval in seconds for a large device image'),
       cfg.IntOpt('fw_update_small_timeout',
                  default=300,
                  help='Timeout interval in seconds for a small device image'),
                  ]

audit_intervals_opts = [
       cfg.IntOpt('default', default=60),
       cfg.IntOpt('agent_update_request', default=60),
       cfg.IntOpt('kubernetes_local_secrets', default=86400),
       cfg.IntOpt('deferred_runtime_config', default=60),
       cfg.IntOpt('controller_config_active_apply', default=60),
       cfg.IntOpt('upgrade_status', default=180),
       cfg.IntOpt('install_states', default=60),
       cfg.IntOpt('kubernetes_labels', default=180),
       cfg.IntOpt('image_conversion', default=60),
       cfg.IntOpt('ihost_action', default=60),
       cfg.IntOpt('storage_backend_failure', default=400),
       cfg.IntOpt('k8s_application', default=60),
       cfg.IntOpt('device_image_update', default=300),
       cfg.IntOpt('kube_upgrade_states', default=1800),
                  ]

CONF = cfg.CONF
CONF.register_opts(conductor_opts, 'conductor')
CONF.register_opts(audit_intervals_opts, 'conductor_periodic_task_intervals')

# doesn't work otherwise for ceph-manager RPC calls; reply is lost
#
CONF.amqp_rpc_single_reply_queue = True

# configuration flags
CFS_DRBDADM_RECONFIGURED = os.path.join(
    tsc.PLATFORM_CONF_PATH, ".cfs_drbdadm_reconfigured")

# volatile flags
CONFIG_CONTROLLER_FINI_FLAG = os.path.join(tsc.VOLATILE_PATH,
                                           ".config_controller_fini")
CONFIG_FAIL_FLAG = os.path.join(tsc.VOLATILE_PATH, ".config_fail")

ACTIVE_CONFIG_REBOOT_REQUIRED = os.path.join(
    constants.SYSINV_VOLATILE_PATH, ".reboot_required")

# Types of runtime configuration applies
CONFIG_APPLY_RUNTIME_MANIFEST = 'config_apply_runtime_manifest'
CONFIG_UPDATE_FILE = 'config_update_file'

LOCK_NAME_UPDATE_CONFIG = 'update_config_'
LOCK_APP_AUTO_MANAGE = 'AppAutoManageLock'
LOCK_RUNTIME_CONFIG_CHECK = 'runtime_config_check'
LOCK_IMAGE_PULL = 'image_pull_'

MAX_UPTIME_TO_CLEAR_REBOOT_REQUIRED = 1200

# Keystone users whose passwords change are monitored by keystone listener, and
# the puppet classes to update the service after the passwords change.
# TODO(yuxing): there are still several keystone users are not covered by this
# dictionary, e.g. dcmanager, dcorch,dcdbsync, and smapi etc. Need to consider
# to create puppet class to reload the related service in case their passwords
# are changed in keystone and keyring.
KEYSTONE_USER_PASSWORD_UPDATE = {
    "sysinv": "openstack::keystone::sysinv::password::runtime",
    "admin": "openstack::keystone::password::runtime",
    "barbican": "openstack::keystone::barbican::password::runtime",
    "fm": "openstack::keystone::fm::password::runtime",
    "mtce": "platform::mtce::runtime",
    "patching": "openstack::keystone::patching::password::runtime",
    "vim": "openstack::keystone::nfv::password::runtime"
}

AppTarBall = namedtuple(
    'AppTarBall',
    "tarball_name app_name app_version manifest_name manifest_file metadata")


class ConductorManager(service.PeriodicService):
    """Sysinv Conductor service main class."""

    RPC_API_VERSION = '1.1'
    my_host_id = None

    def __init__(self, host, topic):
        self.host = host
        self.topic = topic
        serializer = objects_base.SysinvObjectSerializer()
        super(ConductorManager, self).__init__()
        self._rpc_service = None
        self._zmq_rpc_service = None

        # TODO(RPCHybridMode): Usage of RabbitMQ RPC is only required for
        #  21.12 -> 22.12 upgrades.
        #  Remove this in new releases, when it's no longer necessary do the
        #  migration work through RabbitMQ and ZeroMQ
        # NOTE: If more switches are necessary before RabbitMQ removal,
        # refactor this into an RPC layer
        if not CONF.rpc_backend_zeromq or is_rpc_hybrid_mode_active():
            self._rpc_service = rpc_service.Service(self.host, self.topic,
                                                    manager=self,
                                                    serializer=serializer)
        if CONF.rpc_backend_zeromq:
            self._zmq_rpc_service = ZmqRpcServer(
                self,
                CONF.rpc_zeromq_conductor_bind_ip,
                CONF.rpc_zeromq_conductor_bind_port)

        self.dbapi = None
        self.fm_api = None
        self.fm_log = None
        self.host_uuid = None
        self._app = None
        self._ceph = None
        self._ceph_api = ceph.CephWrapper(
            endpoint='http://localhost:{}'.format(constants.CEPH_MGR_PORT))
        self._kube = None
        self._fernet = None

        self._openstack = None
        self._api_token = None
        self._mtc_address = constants.LOCALHOST_HOSTNAME
        self._mtc_port = 2112

        # Timeouts for adding & removing operations
        self._pv_op_timeouts = {}
        self._stor_bck_op_timeouts = {}
        # struct {'host_uuid':[config_uuid_0,config_uuid_1]}
        # this will track the config w/ reboot request to apply
        self._host_reboot_config_uuid = {}

        # track upgrade activation manifests status
        self._upgrade_manifest_start_time = None

        # track deferred runtime config which need to be applied
        self._host_deferred_runtime_config = []

        # track whether runtime class apply may be in progress
        self._runtime_class_apply_in_progress = []

        # Guard for a function that should run only once per conductor start
        self._do_detect_swact = True

        # Guard for a function that should run only once per conductor start
        self._has_loaded_missing_apps_metadata = False

        self.apps_metadata = {constants.APP_METADATA_APPS: {},
                              constants.APP_METADATA_PLATFORM_MANAGED_APPS: {},
                              constants.APP_METADATA_DESIRED_STATES: {},
                              constants.APP_METADATA_ORDERED_APPS: []}

        self._backup_action_map = dict()
        for action in [constants.BACKUP_ACTION_SEMANTIC_CHECK,
                       constants.BACKUP_ACTION_PRE_BACKUP,
                       constants.BACKUP_ACTION_POST_BACKUP,
                       constants.BACKUP_ACTION_PRE_ETCD_BACKUP,
                       constants.BACKUP_ACTION_POST_ETCD_BACKUP,
                       constants.BACKUP_ACTION_PRE_RESTORE,
                       constants.BACKUP_ACTION_POST_RESTORE]:
            impl = getattr(self, '_do_' + action.replace('-', '_'))
            self._backup_action_map[action] = impl

        self._initialize_backup_actions_log()

    def start(self):
        self._start()
        # accept API calls and run periodic tasks after
        # initializing conductor manager service
        if self._rpc_service:
            self._rpc_service.start()

        if self._zmq_rpc_service:
            self._zmq_rpc_service.run()

        super(ConductorManager, self).start()

        # greenthreads must be called after super.start for it to work properly

        # Move PTP parameters from legacy configuration to multi-instance.
        greenthread.spawn(self._update_ptp_parameters)

        # Upgrade/Downgrade kubernetes components.
        greenthread.spawn(self._upgrade_downgrade_kube_components)

        # monitor keystone user update event to check whether admin password is
        # changed or not. If changed, then sync it to kubernetes's secret info,
        # and restart impacted services.
        callback_endpoints = self._get_keystone_callback_endpoints()
        greenthread.spawn(keystone_listener.start_keystone_listener,
                          callback_endpoints)

        # Monitor ceph to become responsive
        if StorageBackendConfig.has_backend_configured(
                        self.dbapi,
                        constants.SB_TYPE_CEPH):
            greenthread.spawn(self._init_ceph_cluster_info)

    def _start(self):
        self.dbapi = dbapi.get_instance()
        self.fm_api = fm_api.FaultAPIs()
        self.fm_log = fm.FmCustomerLog()
        self.host_uuid = self._get_active_controller_uuid()

        self._openstack = openstack.OpenStackOperator(self.dbapi)
        self._puppet = puppet.PuppetOperator(self.dbapi)

        # create /var/run/sysinv if required. On DOR, the manifests
        # may not run to create this volatile directory.
        cutils.check_lock_path()
        self._initialize_active_controller_reboot_config()

        system = self._create_default_system()

        # Besides OpenStack and Puppet operators, all other operators
        # should be initialized after the default system is in place.
        # For instance, CephOperator expects a system to exist to initialize
        # correctly. With Ansible bootstrap deployment, sysinv conductor is
        # brought up during bootstrap manifest apply and is not restarted
        # until host unlock and we need ceph-mon up in order to configure
        # ceph for the initial unlock.
        # kube_app operator will load app metadata from database
        self._helm = helm.HelmOperator(self.dbapi)
        self._app = kube_app.AppOperator(self.dbapi, self._helm, self.apps_metadata)
        self._docker = kube_app.DockerHelper(self.dbapi)
        self._kube = kubernetes.KubeOperator()
        self._kube_app_helper = kube_api.KubeAppHelper(self.dbapi)
        self._fernet = fernet.FernetOperator()

        # Upgrade start tasks
        self._clear_stuck_loads()
        self._upgrade_init_actions()
        self._kube_upgrade_init_actions()

        self._handle_restore_in_progress()

        self._sx_to_dx_post_migration_actions(system)

        LOG.info("sysinv-conductor start committed system=%s" %
                 system.as_dict())

        # Save our start time for time limited init actions
        self._start_time = timeutils.utcnow()

    def _get_active_controller_uuid(self):
        ahost = utils.HostHelper.get_active_controller(self.dbapi)
        if ahost:
            return ahost.uuid
        else:
            return None

    def _get_keystone_callback_endpoints(self):
        """ Get call back endpoints for keystone listener"""

        callback_endpoints = []
        context = ctx.RequestContext(user_id='admin', project_id='admin',
                                     is_admin=True)
        for username in KEYSTONE_USER_PASSWORD_UPDATE.keys():
            if username == 'admin':
                callback_endpoints.append(
                    {'function': self._app.audit_local_registry_secrets,
                     'context': context,
                     'user': username})
            if ((username == 'admin') or
                    (self.dbapi.isystem_get_one().distributed_cloud_role ==
                     constants.DISTRIBUTED_CLOUD_ROLE_SUBCLOUD)):
                callback_endpoints.append({'function': self._update_keystone_password,
                                           'context': context,
                                           'user': username})
        return callback_endpoints

    def _initialize_active_controller_reboot_config(self):
        # initialize host_reboot_config for active controller in case
        # process has been restarted
        if self.host_uuid and os.path.exists(ACTIVE_CONFIG_REBOOT_REQUIRED):
            ahost = self.dbapi.ihost_get(self.host_uuid)
            self._host_reboot_config_uuid[self.host_uuid] = \
                [ahost.config_target]

    def periodic_tasks(self, context, raise_on_error=False):
        """ Periodic tasks are run at pre-specified intervals. """
        return self.run_periodic_tasks(context, raise_on_error=raise_on_error)

    def stop(self):
        if self._rpc_service:
            self._rpc_service.stop()
        if self._zmq_rpc_service:
            self._zmq_rpc_service.stop()
        super(ConductorManager, self).stop()

    @contextmanager
    def session(self):
        session = dbapi.get_instance().get_session(autocommit=True)
        try:
            yield session
        finally:
            session.remove()

    def _create_default_system(self):
        """Populate the default system tables"""

        system = None
        try:
            system = self.dbapi.isystem_get_one()

            # fill in empty remotelogging system_id fields
            self.dbapi.remotelogging_fill_empty_system_id(system.id)
            # fill in empty ptp system_id fields
            self.dbapi.ptp_fill_empty_system_id(system.id)

            return system  # system already configured
        except exception.NotFound:
            pass  # create default system

        # Create the default system entry
        mode = None
        if tsc.system_mode is not None:
            mode = tsc.system_mode

        security_profile = None
        if tsc.security_profile is not None:
            security_profile = tsc.security_profile

        security_feature = constants.SYSTEM_SECURITY_FEATURE_SPECTRE_MELTDOWN_DEFAULT_OPTS
        if tsc.security_feature is not None:
            security_feature = tsc.security_feature

        system = self.dbapi.isystem_create({
            'name': uuidutils.generate_uuid(),
            'system_mode': mode,
            'software_version': cutils.get_sw_version(),
            'capabilities': {},
            'security_profile': security_profile,
            'security_feature': security_feature
        })

        # Populate the default system tables, referencing the newly created
        # table (additional attributes will be populated during
        # config_controller configuration population)
        values = {'forisystemid': system.id}

        self.dbapi.iuser_create(values)
        self.dbapi.idns_create(values)
        self.dbapi.intp_create(values)

        self.dbapi.drbdconfig_create({
            'forisystemid': system.id,
            'uuid': uuidutils.generate_uuid(),
            'link_util': constants.DRBD_LINK_UTIL_DEFAULT,
            'num_parallel': constants.DRBD_NUM_PARALLEL_DEFAULT,
            'rtt_ms': constants.DRBD_RTT_MS_DEFAULT
        })

        # remotelogging and ptp tables have attribute 'system_id' not 'forisystemid'
        system_id_attribute_value = {'system_id': system.id}
        self.dbapi.remotelogging_create(system_id_attribute_value)
        self.dbapi.ptp_create(system_id_attribute_value)

        # populate service table
        for optional_service in constants.ALL_OPTIONAL_SERVICES:
            self.dbapi.service_create({'name': optional_service,
                                       'enabled': False})

        self._create_default_service_parameter()
        return system

    def _update_pvc_migration_alarm(self, alarm_state=None):
        entity_instance_id = "%s=%s" % (fm_constants.FM_ENTITY_TYPE_K8S,
                                        "PV-migration-failed")
        reason_text = "Failed to patch Persistent Volumes backed by CEPH "\
                      "during AIO-SX to AIO-DX migration"

        if alarm_state == fm_constants.FM_ALARM_STATE_SET:
            fault = fm_api.Fault(
                alarm_id=fm_constants.FM_ALARM_ID_K8S_RESOURCE_PV,
                alarm_state=fm_constants.FM_ALARM_STATE_SET,
                entity_type_id=fm_constants.FM_ENTITY_TYPE_K8S,
                entity_instance_id=entity_instance_id,
                severity=fm_constants.FM_ALARM_SEVERITY_MAJOR,
                reason_text=reason_text,
                alarm_type=fm_constants.FM_ALARM_TYPE_3,
                probable_cause=fm_constants.ALARM_PROBABLE_CAUSE_6,
                proposed_repair_action=_("Manually execute /usr/bin/ceph_k8s_update_monitors.sh "
                                         "to confirm PVs are updated, then lock/unlock to clear "
                                         "alarms. If problem persists, contact next level of "
                                         "support."),
                service_affecting=False)

            self.fm_api.set_fault(fault)
        else:
            alarms = self.fm_api.get_faults(entity_instance_id)
            if alarms:
                self.fm_api.clear_all(entity_instance_id)

    def _pvc_monitor_migration(self):
        ceph_backend_enabled = StorageBackendConfig.get_backend(
            self.dbapi,
            constants.SB_TYPE_CEPH)

        if not ceph_backend_enabled:
            # if it does not have ceph backend enabled there is
            # nothing to migrate
            return True

        # get the controller-0 and floating management IP address
        controller_0_address = self.dbapi.address_get_by_name(
            constants.CONTROLLER_0_MGMT).address
        floating_address = self.dbapi.address_get_by_name(
            cutils.format_address_name(constants.CONTROLLER_HOSTNAME,
                                       constants.NETWORK_TYPE_MGMT)).address
        try:
            cmd = ["/usr/bin/ceph_k8s_update_monitors.sh",
                controller_0_address,
                floating_address]
            __, __ = cutils.execute(*cmd, run_as_root=True)

            LOG.info("Updated ceph-mon address from {} to {} on existing Persistent Volumes."
                .format(controller_0_address, floating_address))
            self._update_pvc_migration_alarm()
        except exception.ProcessExecutionError:
            error_msg = "Failed to patch Kubernetes Persistent Volume resources. "\
                "ceph-mon address changed from {} to {}".format(
                    controller_0_address, floating_address)
            LOG.error(error_msg)

            # raise alarm
            self._update_pvc_migration_alarm(fm_constants.FM_ALARM_STATE_SET)
            return False
        return True

    def _sx_to_dx_post_migration_actions(self, system):
        if not self.host_uuid:
            return

        try:
            host = self.dbapi.ihost_get(self.host_uuid)
        except exception.ServerNotFound:
            LOG.warn('No active controller available')
            return

        system_mode_options = [
                    constants.SYSTEM_MODE_DUPLEX,
                    constants.SYSTEM_MODE_DUPLEX_DIRECT,
                ]
        # Skip if the system mode is not set to duplex or duplex-direct
        # or it is not unlocked
        if (host.administrative != constants.ADMIN_UNLOCKED or
                system.system_mode not in system_mode_options):
            return

        system_dict = system.as_dict()
        if system.capabilities.get('simplex_to_duplex_migration'):
            del system_dict['capabilities']['simplex_to_duplex_migration']
            self.dbapi.isystem_update(system.uuid, system_dict)
            greenthread.spawn(self._pvc_monitor_migration)
        elif system.capabilities.get('simplex_to_duplex-direct_migration'):
            del system_dict['capabilities']['simplex_to_duplex-direct_migration']
            self.dbapi.isystem_update(system.uuid, system_dict)
            greenthread.spawn(self._pvc_monitor_migration)
        elif self.fm_api.get_faults_by_id(fm_constants.FM_ALARM_ID_K8S_RESOURCE_PV):
            greenthread.spawn(self._pvc_monitor_migration)

    def _upgrade_init_actions(self):
        """ Perform any upgrade related startup actions"""
        try:
            upgrade = self.dbapi.software_upgrade_get_one()
        except exception.NotFound:
            # Not upgrading. No need to update status
            return

        hostname = socket.gethostname()
        if hostname == constants.CONTROLLER_0_HOSTNAME:
            if os.path.isfile(tsc.UPGRADE_ROLLBACK_FLAG):
                self._set_state_for_rollback(upgrade)
            elif os.path.isfile(tsc.UPGRADE_ABORT_FLAG):
                self._set_state_for_abort(upgrade)
        elif hostname == constants.CONTROLLER_1_HOSTNAME:
            self._init_controller_for_upgrade(upgrade)
            if upgrade.state == constants.UPGRADE_UPGRADING_CONTROLLERS:
                # request report initial inventory as controller-1 has
                # not had a chance to report inventory to upgraded system
                context = ctx.RequestContext('admin', 'admin', is_admin=True)
                ihost = self.dbapi.ihost_get_by_hostname(hostname)
                rpcapi = agent_rpcapi.AgentAPI()
                rpcapi.report_initial_inventory(context, ihost.uuid)

        system_mode = self.dbapi.isystem_get_one().system_mode
        if system_mode == constants.SYSTEM_MODE_SIMPLEX:
            self._init_controller_for_upgrade(upgrade)

        if upgrade.state in [constants.UPGRADE_ACTIVATION_REQUESTED,
                             constants.UPGRADE_ACTIVATING]:
            # Reset to activation-failed if the conductor restarts. This could
            # be due to a swact or the process restarting. Either way we'll
            # need to rerun the activation.
            self.dbapi.software_upgrade_update(
                upgrade.uuid, {'state': constants.UPGRADE_ACTIVATION_FAILED})

        self._upgrade_default_service()
        self._upgrade_default_service_parameter()

    def _handle_restore_in_progress(self):
        if os.path.isfile(tsc.SKIP_CEPH_OSD_WIPING):
            LOG.info("Starting thread to fix storage nodes install uuid.")
            greenthread.spawn(self._fix_storage_install_uuid)

        if os.path.isfile(tsc.RESTORE_IN_PROGRESS_FLAG):
            if StorageBackendConfig.has_backend(
                    self.dbapi,
                    constants.CINDER_BACKEND_CEPH):
                StorageBackendConfig.update_backend_states(
                    self.dbapi,
                    constants.CINDER_BACKEND_CEPH,
                    task=constants.SB_TASK_RESTORE)

    def _clear_stuck_loads(self):
        load_stuck_states = [constants.IMPORTING_LOAD_STATE]

        loads = self.dbapi.load_get_list()
        stuck_loads = [load for load in loads
                              if load.state in load_stuck_states]
        if stuck_loads:
            # set stuck isos state to error
            for load in stuck_loads:
                LOG.error("Unexpected restart during import of load %s for "
                          "release %s, please delete the load and try again." %
                          (load.id, load.software_version))
                self.dbapi.load_update(load.id, {'state': constants.ERROR_LOAD_STATE})
            cutils.unmount_stuck_isos()

    def _set_state_for_abort(self, upgrade):
        """ Update the database to reflect the abort"""
        LOG.info("Upgrade Abort detected. Correcting database state.")

        # Update the upgrade state
        self.dbapi.software_upgrade_update(
            upgrade.uuid, {'state': constants.UPGRADE_ABORTING})

        try:
            os.remove(tsc.UPGRADE_ABORT_FLAG)
        except OSError:
            LOG.exception("Failed to remove upgrade rollback flag")

    def _set_state_for_rollback(self, upgrade):
        """ Update the database to reflect the rollback"""
        LOG.info("Upgrade Rollback detected. Correcting database state.")

        # Update the upgrade state
        self.dbapi.software_upgrade_update(
            upgrade.uuid, {'state': constants.UPGRADE_ABORTING_ROLLBACK})

        # At this point we are swacting to controller-0 which has just been
        # downgraded.
        # Before downgrading controller-0 all storage/worker nodes were locked
        # The database of the from_load is not aware of this, so we set the
        # state in the database to match the state of the system. This does not
        # actually lock the nodes.
        hosts = self.dbapi.ihost_get_list()
        for host in hosts:
            if host.personality not in [constants.WORKER, constants.STORAGE]:
                continue
            self.dbapi.ihost_update(host.uuid, {
                'administrative': constants.ADMIN_LOCKED})

        # Remove the rollback flag, we only want to modify the database once
        try:
            os.remove(tsc.UPGRADE_ROLLBACK_FLAG)
        except OSError:
            LOG.exception("Failed to remove upgrade rollback flag")

    def _init_controller_for_upgrade(self, upgrade):
        # Raise alarm to show an upgrade is in progress
        # After upgrading controller-1 and swacting to it, we must
        # re-raise the upgrades alarm, because alarms are not preserved
        # from the previous release.
        entity_instance_id = "%s=%s" % (fm_constants.FM_ENTITY_TYPE_HOST,
                                        constants.CONTROLLER_HOSTNAME)

        if not self.fm_api.get_fault(
                fm_constants.FM_ALARM_ID_UPGRADE_IN_PROGRESS,
                entity_instance_id):
            fault = fm_api.Fault(
                alarm_id=fm_constants.FM_ALARM_ID_UPGRADE_IN_PROGRESS,
                alarm_state=fm_constants.FM_ALARM_STATE_SET,
                entity_type_id=fm_constants.FM_ENTITY_TYPE_HOST,
                entity_instance_id=entity_instance_id,
                severity=fm_constants.FM_ALARM_SEVERITY_MINOR,
                reason_text="System Upgrade in progress.",
                # operational
                alarm_type=fm_constants.FM_ALARM_TYPE_7,
                # congestion
                probable_cause=fm_constants.ALARM_PROBABLE_CAUSE_8,
                proposed_repair_action="No action required.",
                service_affecting=False)
            self.fm_api.set_fault(fault)

            # Regenerate dnsmasq.hosts and dnsmasq.addn_hosts.
            # This is necessary to handle the case where a lease expires during
            # an upgrade, in order to allow hostnames to be resolved from
            # the dnsmasq.addn_hosts file before unlocking controller-0 forces
            # dnsmasq.addn_hosts to be regenerated.
            self._generate_dnsmasq_hosts_file()

    DEFAULT_PARAMETERS = [
        {'service': constants.SERVICE_TYPE_IDENTITY,
         'section': constants.SERVICE_PARAM_SECTION_IDENTITY_CONFIG,
         'name': constants.SERVICE_PARAM_IDENTITY_CONFIG_TOKEN_EXPIRATION,
         'value': constants.SERVICE_PARAM_IDENTITY_CONFIG_TOKEN_EXPIRATION_DEFAULT
         },
        {'service': constants.SERVICE_TYPE_IDENTITY,
         'section': constants.SERVICE_PARAM_SECTION_SECURITY_COMPLIANCE,
         'name': constants.SERVICE_PARAM_NAME_SECURITY_COMPLIANCE_LOCKOUT_DURATION,
         'value': constants.SERVICE_PARAM_NAME_SECURITY_COMPLIANCE_LOCKOUT_DURATION_DEFAULT,
         },
        {'service': constants.SERVICE_TYPE_IDENTITY,
         'section': constants.SERVICE_PARAM_SECTION_SECURITY_COMPLIANCE,
         'name': constants.SERVICE_PARAM_NAME_SECURITY_COMPLIANCE_LOCKOUT_FAILURE_ATTEMPTS,
         'value': constants.SERVICE_PARAM_NAME_SECURITY_COMPLIANCE_LOCKOUT_FAILURE_ATTEMPTS_DEFAULT,
         },
        {'service': constants.SERVICE_TYPE_PLATFORM,
         'section': constants.SERVICE_PARAM_SECTION_PLATFORM_MAINTENANCE,
         'name': constants.SERVICE_PARAM_PLAT_MTCE_WORKER_BOOT_TIMEOUT,
         'value': constants.SERVICE_PARAM_PLAT_MTCE_WORKER_BOOT_TIMEOUT_DEFAULT,
         },
        {'service': constants.SERVICE_TYPE_PLATFORM,
         'section': constants.SERVICE_PARAM_SECTION_PLATFORM_MAINTENANCE,
         'name': constants.SERVICE_PARAM_PLAT_MTCE_CONTROLLER_BOOT_TIMEOUT,
         'value': constants.SERVICE_PARAM_PLAT_MTCE_CONTROLLER_BOOT_TIMEOUT_DEFAULT,
         },
        {'service': constants.SERVICE_TYPE_PLATFORM,
         'section': constants.SERVICE_PARAM_SECTION_PLATFORM_MAINTENANCE,
         'name': constants.SERVICE_PARAM_PLAT_MTCE_HBS_PERIOD,
         'value': constants.SERVICE_PARAM_PLAT_MTCE_HBS_PERIOD_DEFAULT,
         },
        {'service': constants.SERVICE_TYPE_PLATFORM,
         'section': constants.SERVICE_PARAM_SECTION_PLATFORM_MAINTENANCE,
         'name': constants.SERVICE_PARAM_PLAT_MTCE_HBS_FAILURE_ACTION,
         'value': constants.SERVICE_PARAM_PLAT_MTCE_HBS_FAILURE_ACTION_DEFAULT,
         },
        {'service': constants.SERVICE_TYPE_PLATFORM,
         'section': constants.SERVICE_PARAM_SECTION_PLATFORM_MAINTENANCE,
         'name': constants.SERVICE_PARAM_PLAT_MTCE_HBS_FAILURE_THRESHOLD,
         'value': constants.SERVICE_PARAM_PLAT_MTCE_HBS_FAILURE_THRESHOLD_DEFAULT,
         },
        {'service': constants.SERVICE_TYPE_PLATFORM,
         'section': constants.SERVICE_PARAM_SECTION_PLATFORM_MAINTENANCE,
         'name': constants.SERVICE_PARAM_PLAT_MTCE_HBS_DEGRADE_THRESHOLD,
         'value': constants.SERVICE_PARAM_PLAT_MTCE_HBS_DEGRADE_THRESHOLD_DEFAULT,
         },
        {'service': constants.SERVICE_TYPE_PLATFORM,
         'section': constants.SERVICE_PARAM_SECTION_PLATFORM_MAINTENANCE,
         'name': constants.SERVICE_PARAM_PLAT_MTCE_MNFA_THRESHOLD,
         'value': constants.SERVICE_PARAM_PLAT_MTCE_MNFA_THRESHOLD_DEFAULT,
         },
        {'service': constants.SERVICE_TYPE_PLATFORM,
         'section': constants.SERVICE_PARAM_SECTION_PLATFORM_MAINTENANCE,
         'name': constants.SERVICE_PARAM_PLAT_MTCE_MNFA_TIMEOUT,
         'value': constants.SERVICE_PARAM_PLAT_MTCE_MNFA_TIMEOUT_DEFAULT,
         },
        {'service': constants.SERVICE_TYPE_PLATFORM,
         'section': constants.SERVICE_PARAM_SECTION_PLATFORM_KERNEL,
         'name': constants.SERVICE_PARAM_NAME_PLATFORM_AUDITD,
         'value': constants.SERVICE_PARAM_PLATFORM_AUDITD_DISABLED,
         },
        {'service': constants.SERVICE_TYPE_PLATFORM,
         'section': constants.SERVICE_PARAM_SECTION_PLATFORM_CONFIG,
         'name': constants.SERVICE_PARAM_NAME_PLAT_CONFIG_INTEL_NIC_DRIVER_VERSION,
         'value': constants.SERVICE_PARAM_PLAT_CONFIG_INTEL_CVL_VALUES[-1],
         },
        {'service': constants.SERVICE_TYPE_RADOSGW,
         'section': constants.SERVICE_PARAM_SECTION_RADOSGW_CONFIG,
         'name': constants.SERVICE_PARAM_NAME_RADOSGW_SERVICE_ENABLED,
         'value': False},
        {'service': constants.SERVICE_TYPE_RADOSGW,
         'section': constants.SERVICE_PARAM_SECTION_RADOSGW_CONFIG,
         'name': constants.SERVICE_PARAM_NAME_RADOSGW_FS_SIZE_MB,
         'value': constants.SERVICE_PARAM_RADOSGW_FS_SIZE_MB_DEFAULT},
        {'service': constants.SERVICE_TYPE_HTTP,
         'section': constants.SERVICE_PARAM_SECTION_HTTP_CONFIG,
         'name': constants.SERVICE_PARAM_HTTP_PORT_HTTP,
         'value': constants.SERVICE_PARAM_HTTP_PORT_HTTP_DEFAULT
         },
        {'service': constants.SERVICE_TYPE_HTTP,
         'section': constants.SERVICE_PARAM_SECTION_HTTP_CONFIG,
         'name': constants.SERVICE_PARAM_HTTP_PORT_HTTPS,
         'value': constants.SERVICE_PARAM_HTTP_PORT_HTTPS_DEFAULT
         },
        {'service': constants.SERVICE_TYPE_PLATFORM,
         'section': constants.SERVICE_PARAM_SECTION_PLATFORM_CONFIG,
         'name': constants.SERVICE_PARAM_NAME_PLATFORM_MAX_CPU_PERCENTAGE,
         'value': constants.SERVICE_PARAM_PLATFORM_MAX_CPU_PERCENTAGE_DEFAULT
         },
    ]

    def _create_default_service_parameter(self):
        """ Populate the default service parameters"""
        for p in ConductorManager.DEFAULT_PARAMETERS:
            self.dbapi.service_parameter_create(p)

    def _upgrade_default_service_parameter(self):
        """ Update the default service parameters when upgrade is done"""
        parms = self.dbapi.service_parameter_get_all()
        for p_new in ConductorManager.DEFAULT_PARAMETERS:
            found = False
            for p_db in parms:
                if (p_new['service'] == p_db.service and
                            p_new['section'] == p_db.section and
                            p_new['name'] == p_db.name):
                    found = True
                    break
            if not found:
                self.dbapi.service_parameter_create(p_new)

    def _get_service_parameter_sections(self, service):
        """ Given a service, returns all sections defined"""
        params = self.dbapi.service_parameter_get_all(service)
        return params

    def _upgrade_default_service(self):
        """ Update the default service when upgrade is done"""
        services = self.dbapi.service_get_all()
        for s_new in constants.ALL_OPTIONAL_SERVICES:
            found = False
            for s_db in services:
                if (s_new == s_db.name):
                    found = True
                    break
            if not found:
                self.dbapi.service_create({'name': s_new,
                                          'enabled': False})

    def _lookup_static_ip_address(self, name, networktype):
        """"Find a statically configured address based on name and network
        type."""
        try:
            # address names are refined by network type to ensure they are
            # unique across different address pools
            name = cutils.format_address_name(name, networktype)
            address = self.dbapi.address_get_by_name(name)
            return address.address
        except exception.AddressNotFoundByName:
            return None

    def _using_static_ip(self, ihost, personality=None, hostname=None):
        using_static = False
        if ihost:
            ipersonality = ihost['personality']
            ihostname = ihost['hostname'] or ""
        else:
            ipersonality = personality
            ihostname = hostname or ""

        if ipersonality and ipersonality == constants.CONTROLLER:
            using_static = True
        elif ipersonality and ipersonality == constants.STORAGE:
            # only storage-0 and storage-1 have static (later storage-2)
            if (ihostname[:len(constants.STORAGE_0_HOSTNAME)] in
               [constants.STORAGE_0_HOSTNAME, constants.STORAGE_1_HOSTNAME]):
                using_static = True

        return using_static

    def handle_dhcp_lease(self, context, tags, mac, ip_address, cid=None):
        """Synchronously, have a conductor handle a DHCP lease update.

        Handling depends on the interface:
        - management interface: do nothing
        - pxeboot interface: create i_host

        :param context: request context.
        :param tags: specifies the interface type (mgmt)
        :param mac: MAC for the lease
        :param ip_address: IP address for the lease
        """

        LOG.info("receiving dhcp_lease: %s %s %s %s %s" %
                 (context, tags, mac, ip_address, cid))
        # Get the first field from the tags
        first_tag = tags.split()[0]

        # Not allow adding a new host to simplex system
        if 'pxeboot' == first_tag and not cutils.is_aio_simplex_system(self.dbapi):
            mgmt_network = self.dbapi.network_get_by_type(
                constants.NETWORK_TYPE_MGMT)
            if not mgmt_network.dynamic:
                return

            # This is a DHCP lease for a node on the pxeboot network
            # Create the ihost (if necessary).
            ihost_dict = {'mgmt_mac': mac}
            self.create_ihost(context, ihost_dict, reason='dhcp pxeboot')

    def handle_dhcp_lease_from_clone(self, context, mac):
        """Handle dhcp request from a cloned controller-1.
           If MAC address in DB is still set to well known
           clone label, then this is the first boot of the
           other controller. Real MAC address from PXE request
           is updated in the DB."""
        controller_hosts =\
                self.dbapi.ihost_get_by_personality(constants.CONTROLLER)
        for host in controller_hosts:
            if (constants.CLONE_ISO_MAC in host.mgmt_mac and
                    host.personality == constants.CONTROLLER and
                    host.administrative == constants.ADMIN_LOCKED):
                LOG.info("create_ihost (clone): Host found: {}:{}:{}->{}"
                         .format(host.hostname, host.personality,
                                 host.mgmt_mac, mac))
                values = {'mgmt_mac': mac}
                self.dbapi.ihost_update(host.uuid, values)
                host.mgmt_mac = mac
                self._configure_controller_host(context, host)
                if host.personality and host.hostname:
                    ihost_mtc = host.as_dict()
                    ihost_mtc['operation'] = 'modify'
                    ihost_mtc = cutils.removekeys_nonmtce(ihost_mtc)
                    mtce_api.host_modify(
                             self._api_token, self._mtc_address,
                             self._mtc_port, ihost_mtc,
                             constants.MTC_DEFAULT_TIMEOUT_IN_SECS)
                return host
        return None

    def create_ihost(self, context, values, reason=None):
        """Create an ihost with the supplied data.

        This method allows an ihost to be created.

        :param context: an admin context
        :param values: initial values for new ihost object
        :returns: updated ihost object, including all fields.
        """

        if 'mgmt_mac' not in values:
            raise exception.SysinvException(_(
                "Invalid method call: create_ihost requires mgmt_mac."))

        try:
            mgmt_update_required = False
            mac = values['mgmt_mac']
            mac = mac.rstrip()
            mac = cutils.validate_and_normalize_mac(mac)
            ihost = self.dbapi.ihost_get_by_mgmt_mac(mac)
            LOG.info("Not creating ihost for mac: %s because it "
                      "already exists with uuid: %s" % (values['mgmt_mac'],
                                                        ihost['uuid']))
            mgmt_ip = values.get('mgmt_ip') or ""

            if mgmt_ip and not ihost.mgmt_ip:
                LOG.info("%s create_ihost setting mgmt_ip to %s" %
                         (ihost.uuid, mgmt_ip))
                mgmt_update_required = True
            elif mgmt_ip and ihost.mgmt_ip and \
               (ihost.mgmt_ip.strip() != mgmt_ip.strip()):
                # Changing the management IP on an already configured
                # host should not occur nor be allowed.
                LOG.error("DANGER %s create_ihost mgmt_ip dnsmasq change "
                          "detected from %s to %s." %
                          (ihost.uuid, ihost.mgmt_ip, mgmt_ip))

            if mgmt_update_required:
                ihost = self.dbapi.ihost_update(ihost.uuid, values)

                if ihost.personality and ihost.hostname:
                    ihost_mtc = ihost.as_dict()
                    ihost_mtc['operation'] = 'modify'
                    ihost_mtc = cutils.removekeys_nonmtce(ihost_mtc)
                    LOG.info("%s create_ihost update mtce %s " %
                             (ihost.hostname, ihost_mtc))
                    mtce_api.host_modify(
                             self._api_token, self._mtc_address, self._mtc_port,
                             ihost_mtc,
                             constants.MTC_DEFAULT_TIMEOUT_IN_SECS)

            return ihost
        except exception.NodeNotFound:
            # If host is not found, check if this is cloning scenario.
            # If yes, update management MAC in the DB and create PXE config.
            clone_host = self.handle_dhcp_lease_from_clone(context, mac)
            if clone_host:
                return clone_host

        # assign default system
        system = self.dbapi.isystem_get_one()
        values.update({'forisystemid': system.id})
        values.update({constants.HOST_ACTION_STATE: constants.HAS_REINSTALLING})

        # get tboot value from the active controller
        active_controller = None
        hosts = self.dbapi.ihost_get_by_personality(constants.CONTROLLER)
        for h in hosts:
            if utils.is_host_active_controller(h):
                active_controller = h
                break
        software_load = None
        if active_controller is not None:
            tboot_value = active_controller.get('tboot')
            if tboot_value is not None:
                values.update({'tboot': tboot_value})
            software_load = active_controller.software_load
            LOG.info("create_ihost software_load=%s" % software_load)

        ihost = self.dbapi.ihost_create(values, software_load=software_load)

        # A host is being created, generate discovery log.
        self._log_host_create(ihost, reason)

        ihost_id = ihost.get('uuid')
        LOG.debug("RPC create_ihost called and created ihost %s." % ihost_id)

        return ihost

    def update_ihost(self, context, ihost_obj):
        """Update an ihost with the supplied data.

        This method allows an ihost to be updated.

        :param context: an admin context
        :param ihost_obj: a changed (but not saved) ihost object
        :returns: updated ihost object, including all fields.
        """

        ihost_id = ihost_obj['uuid']
        LOG.debug("RPC update_ihost called for ihost %s." % ihost_id)

        delta = ihost_obj.obj_what_changed()
        if ('id' in delta) or ('uuid' in delta):
            raise exception.SysinvException(_(
                "Invalid method call: update_ihost cannot change id or uuid "))

        ihost_obj.save(context)
        return ihost_obj

    def _dnsmasq_host_entry_to_string(self, ip_addr, hostname,
                                     mac_addr=None, cid=None):
        if IPNetwork(ip_addr).version == constants.IPV6_FAMILY:
            ip_addr = "[%s]" % ip_addr
        if cid:
            line = "id:%s,%s,%s,1d\n" % (cid, hostname, ip_addr)
        elif mac_addr:
            line = "%s,%s,%s,1d\n" % (mac_addr, hostname, ip_addr)
        else:
            line = "%s,%s\n" % (hostname, ip_addr)
        return line

    def _dnsmasq_addn_host_entry_to_string(self, ip_addr, hostname,
                                           aliases=None):
        if aliases is None:
            aliases = []
        line = "%s %s" % (ip_addr, hostname)
        for alias in aliases:
            line = "%s %s" % (line, alias)
        line = "%s\n" % line
        return line

    def _generate_dnsmasq_hosts_file(self, existing_host=None,
                                     deleted_host=None):
        """Regenerates the dnsmasq host and addn_hosts files from database.

        :param existing_host: Include this host in list of hosts.
        :param deleted_host: Skip over writing MAC address for this host.
        """
        if (self.topic == 'test-topic'):
            dnsmasq_hosts_file = '/tmp/dnsmasq.hosts'
        else:
            dnsmasq_hosts_file = tsc.CONFIG_PATH + 'dnsmasq.hosts'

        if (self.topic == 'test-topic'):
            dnsmasq_addn_hosts_file = '/tmp/dnsmasq.addn_hosts'
        else:
            dnsmasq_addn_hosts_file = tsc.CONFIG_PATH + 'dnsmasq.addn_hosts'

        if deleted_host:
            deleted_hostname = deleted_host.hostname
        else:
            deleted_hostname = None

        temp_dnsmasq_hosts_file = dnsmasq_hosts_file + '.temp'
        temp_dnsmasq_addn_hosts_file = dnsmasq_addn_hosts_file + '.temp'
        mgmt_network = self.dbapi.network_get_by_type(
            constants.NETWORK_TYPE_MGMT
        )

        with open(temp_dnsmasq_hosts_file, 'w') as f_out,\
                open(temp_dnsmasq_addn_hosts_file, 'w') as f_out_addn:

            # Write entry for pxecontroller into addn_hosts file
            try:
                self.dbapi.network_get_by_type(
                    constants.NETWORK_TYPE_PXEBOOT
                )
                address = self.dbapi.address_get_by_name(
                    cutils.format_address_name(constants.CONTROLLER_HOSTNAME,
                                               constants.NETWORK_TYPE_PXEBOOT)
                )
            except exception.NetworkTypeNotFound:
                address = self.dbapi.address_get_by_name(
                    cutils.format_address_name(constants.CONTROLLER_HOSTNAME,
                                               constants.NETWORK_TYPE_MGMT)
                )
            addn_line = self._dnsmasq_addn_host_entry_to_string(
                address.address, constants.PXECONTROLLER_HOSTNAME
            )
            f_out_addn.write(addn_line)

            # Loop through mgmt addresses to write to file
            for address in self.dbapi._addresses_get_by_pool_uuid(
                    mgmt_network.pool_uuid):
                line = None
                hostname = re.sub("-%s$" % constants.NETWORK_TYPE_MGMT,
                                  '', str(address.name))

                if address.interface:
                    mac_address = address.interface.imac
                    # For cloning scenario, controller-1 MAC address will
                    # be updated in ethernet_interfaces table only later
                    # when sysinv-agent is initialized on controller-1.
                    # So, use the mac_address passed in (got from PXE request).
                    if (existing_host and
                            constants.CLONE_ISO_MAC in mac_address and
                            hostname == existing_host.hostname):
                        LOG.info("gen dnsmasq (clone):{}:{}->{}"
                                 .format(hostname, mac_address,
                                         existing_host.mgmt_mac))
                        mac_address = existing_host.mgmt_mac
                # If host is being deleted, don't check ihost
                elif deleted_hostname and deleted_hostname == hostname:
                    mac_address = None
                else:
                    try:
                        ihost = self.dbapi.ihost_get_by_hostname(hostname)
                        mac_address = ihost.mgmt_mac
                    except exception.NodeNotFound:
                        if existing_host and existing_host.hostname == hostname:
                            mac_address = existing_host.mgmt_mac
                        else:
                            mac_address = None
                line = self._dnsmasq_host_entry_to_string(address.address,
                                                          hostname,
                                                          mac_address)
                f_out.write(line)

        # Update host files atomically and reload dnsmasq
        if (not os.path.isfile(dnsmasq_hosts_file) or
                not filecmp.cmp(temp_dnsmasq_hosts_file, dnsmasq_hosts_file)):
            os.rename(temp_dnsmasq_hosts_file, dnsmasq_hosts_file)
        if (not os.path.isfile(dnsmasq_addn_hosts_file) or
                not filecmp.cmp(temp_dnsmasq_addn_hosts_file,
                                dnsmasq_addn_hosts_file)):
            os.rename(temp_dnsmasq_addn_hosts_file, dnsmasq_addn_hosts_file)

        # If there is no distributed cloud addn_hosts file, create an empty one
        # so dnsmasq will not complain.
        dnsmasq_addn_hosts_dc_file = os.path.join(tsc.CONFIG_PATH, 'dnsmasq.addn_hosts_dc')
        temp_dnsmasq_addn_hosts_dc_file = os.path.join(tsc.CONFIG_PATH, 'dnsmasq.addn_hosts_dc.temp')

        if not os.path.isfile(dnsmasq_addn_hosts_dc_file):
            with open(temp_dnsmasq_addn_hosts_dc_file, 'w') as f_out_addn_dc:
                f_out_addn_dc.write(' ')
            os.rename(temp_dnsmasq_addn_hosts_dc_file, dnsmasq_addn_hosts_dc_file)

        os.system("pkill -HUP dnsmasq")

    def update_apparmor_config(self, context, ihost_uuid):
        """Update the GRUB CMDLINE to enable/disable apparmor"""
        host = self.dbapi.ihost_get(ihost_uuid)
        personalities = [constants.WORKER,
                         constants.CONTROLLER]
        config_uuid = self._config_update_hosts(context,
                        personalities,
                        [host['uuid']])
        config_dict = {
            "personalities": personalities,
            "host_uuids": [host['uuid']],
            "classes": ['platform::config::apparmor::runtime'],
        }

        self._config_apply_runtime_manifest(context, config_uuid, config_dict)

    def _update_pxe_config(self, host, load=None):
        """Set up the PXE config file for this host so it can run
           the installer.

           This method must always be backward compatible with the previous
           software release. During upgrades, this method is called when
           locking/unlocking hosts running the previous release and when
           downgrading a host. In both cases, it must be able to re-generate
           the host's pxe config files appropriate to that host's software
           version, using the pxeboot-update-<release>.sh script from the
           previous release.

        :param host: host object.
        """
        sw_version = tsc.SW_VERSION

        if load:
            sw_version = load.software_version
        else:
            # No load provided, look it up...
            host_upgrade = self.dbapi.host_upgrade_get_by_host(host.id)
            target_load = self.dbapi.load_get(host_upgrade.target_load)
            sw_version = target_load.software_version

        if (host.personality == constants.CONTROLLER and
                constants.WORKER in tsc.subfunctions):
            if constants.LOWLATENCY in host.subfunctions:
                pxe_config = "pxe-smallsystem_lowlatency-install-%s" % sw_version
            else:
                pxe_config = "pxe-smallsystem-install-%s" % sw_version
        elif host.personality == constants.CONTROLLER:
            pxe_config = "pxe-controller-install-%s" % sw_version
        elif host.personality == constants.WORKER:
            if constants.LOWLATENCY in host.subfunctions:
                pxe_config = "pxe-worker_lowlatency-install-%s" % sw_version
            else:
                pxe_config = "pxe-worker-install-%s" % sw_version
        elif host.personality == constants.STORAGE:
            pxe_config = "pxe-storage-install-%s" % sw_version

        # Defaults for configurable install parameters
        install_opts = []

        boot_device = host.get('boot_device') or "/dev/sda"
        install_opts += ['-b', boot_device]

        rootfs_device = host.get('rootfs_device') or "/dev/sda"
        install_opts += ['-r', rootfs_device]

        hw_settle = host.get('hw_settle') or "0"
        if hw_settle != "0":
            install_opts += ['-H', hw_settle]

        if cutils.get_os_target(sw_version) == constants.OS_DEBIAN:
            install_opts += ['-d']
        else:
            install_output = host.get('install_output') or "text"
            if install_output == "text":
                install_output_arg = "-t"
            elif install_output == "graphical":
                install_output_arg = "-g"
            else:
                LOG.warning("install_output set to invalid value (%s)"
                            % install_output)
                install_output_arg = "-t"
            install_opts += [install_output_arg]

            # This method is called during upgrades to
            # re-generate the host's pxe config files to the appropriate host's
            # software version. It is required specifically when we downgrade a
            # host or when we lock/unlock a host.
            host_uuid = host.get('uuid')
            notify_url = \
                "http://pxecontroller:%d/v1/ihosts/%s/install_progress" % \
                (CONF.sysinv_api_port, host_uuid)
            install_opts += ['-u', notify_url]

            system = self.dbapi.isystem_get_one()

            secprofile = system.security_profile
            # ensure that the securtiy profile selection is valid
            if secprofile not in [constants.SYSTEM_SECURITY_PROFILE_STANDARD,
                                  constants.SYSTEM_SECURITY_PROFILE_EXTENDED]:
                LOG.error("Security Profile (%s) not a valid selection. "
                          "Defaulting to: %s" % (secprofile,
                                                 constants.SYSTEM_SECURITY_PROFILE_STANDARD))
                secprofile = constants.SYSTEM_SECURITY_PROFILE_STANDARD
            install_opts += ['-s', secprofile]

            # If 'tboot' is present in ihost_obj, retrieve and send the value
            if 'tboot' in host:
                tboot = host.get('tboot')
                if tboot is not None and tboot != "":
                    install_opts += ['-T', tboot]

            install_opts += ['-k', system.security_feature]

        # If 'console' is not present in ihost_obj, we use the default.
        # If, however, it is present and is explicitly set to None or "",
        # then we don't specify the -c argument at all.
        if 'console' not in host:
            console = "ttyS0,115200"
        else:
            console = host.get('console')

        if console is not None and console != "":
            install_opts += ['-c', console]

        base_url = "http://pxecontroller:%d" % cutils.get_http_port(self.dbapi)
        install_opts += ['-l', base_url]

        if host['mgmt_mac']:
            dashed_mac = host["mgmt_mac"].replace(":", "-")
            pxeboot_update = "/usr/sbin/pxeboot-update-%s.sh" % sw_version

            # Remove an old file if it exists
            try:
                os.remove("/var/pxeboot/pxelinux.cfg/01-" + dashed_mac)
            except OSError:
                pass

            try:
                os.remove("/var/pxeboot/pxelinux.cfg/efi-01-" + dashed_mac + ".cfg")
                os.remove("/var/pxeboot/pxelinux.cfg/efi-01-" + dashed_mac)
            except OSError:
                pass
            with open(os.devnull, "w") as fnull:
                try:
                    subprocess.check_call(  # pylint: disable=not-callable
                        [pxeboot_update, "-i", "/var/pxeboot/pxelinux.cfg.files/" +
                         pxe_config, "-o", "/var/pxeboot/pxelinux.cfg/01-" +
                         dashed_mac] + install_opts,
                        stdout=fnull,
                        stderr=fnull)
                    source = "/var/pxeboot/pxelinux.cfg/efi-01-" + dashed_mac
                    link_name = "/var/pxeboot/pxelinux.cfg/efi-01-" + dashed_mac + ".cfg"
                    os.symlink(source, link_name)
                except subprocess.CalledProcessError:
                    raise exception.SysinvException(_(
                        "Failed to create pxelinux.cfg file"))

    def _remove_pxe_config(self, host):
        """Delete the PXE config file for this host.

        :param host: host object.
        """
        if host.mgmt_mac:
            dashed_mac = host.mgmt_mac.replace(":", "-")

            # Remove the old file if it exists
            try:
                os.remove("/var/pxeboot/pxelinux.cfg/01-" + dashed_mac)
            except OSError:
                pass

            try:
                os.remove("/var/pxeboot/pxelinux.cfg/efi-01-" + dashed_mac + ".cfg")
                os.remove("/var/pxeboot/pxelinux.cfg/efi-01-" + dashed_mac)
            except OSError:
                pass

    def _create_or_update_address(self, context, hostname, ip_address,
                                  iface_type, iface_id=None):
        if hostname is None or ip_address is None:
            return
        address_name = cutils.format_address_name(hostname, iface_type)
        address_family = IPNetwork(ip_address).version
        try:
            address = self.dbapi.address_get_by_address(ip_address)
            address_uuid = address['uuid']
            # If name is already set, return
            if (self.dbapi.address_get_by_name(address_name) ==
                    address_uuid and iface_id is None):
                return
        except exception.AddressNotFoundByAddress:
            address_uuid = None
        except exception.AddressNotFoundByName:
            pass
        network = self.dbapi.network_get_by_type(iface_type)
        address_pool_uuid = network.pool_uuid
        address_pool = self.dbapi.address_pool_get(address_pool_uuid)
        values = {
            'name': address_name,
            'family': address_family,
            'prefix': address_pool.prefix,
            'address': ip_address,
            'address_pool_id': address_pool.id,
        }

        if iface_id:
            values['interface_id'] = iface_id
        if address_uuid:
            address = self.dbapi.address_update(address_uuid, values)
        else:
            address = self.dbapi.address_create(values)
        self._generate_dnsmasq_hosts_file()
        return address

    def _allocate_pool_address(self, interface_id, pool_uuid, address_name):
        return address_pool.AddressPoolController.assign_address(
            interface_id, pool_uuid, address_name, dbapi=self.dbapi
        )

    def _allocate_cluster_host_address_for_host(self, host):
        """Allocates cluster-host address for a given host.

        Does the following tasks:
        - Check if address exist for host
        - Allocate address for host from cluster pool

        :param host: host object
        """

        # controller must have cluster-host address already allocated
        if (host.personality != constants.CONTROLLER):

            cluster_host_address = self._lookup_static_ip_address(
                host.hostname, constants.NETWORK_TYPE_CLUSTER_HOST)

            if cluster_host_address is None:
                address_name = cutils.format_address_name(
                    host.hostname, constants.NETWORK_TYPE_CLUSTER_HOST)
                LOG.info("{} address not found. Allocating address for {}.".format(
                    address_name, host.hostname))
                host_network = self.dbapi.network_get_by_type(
                    constants.NETWORK_TYPE_CLUSTER_HOST)
                self._allocate_pool_address(None, host_network.pool_uuid,
                                            address_name)

    def _allocate_addresses_for_host(self, context, host):
        """Allocates addresses for a given host.

        Does the following tasks:
        - Check if addresses exist for host
        - Allocate addresses for host from pools
        - Update ihost with mgmt address
        - Regenerate the dnsmasq hosts file

        :param context: request context
        :param host: host object
        """
        mgmt_ip = host.mgmt_ip
        mgmt_interfaces = self.iinterfaces_get_by_ihost_nettype(
            context, host.uuid, constants.NETWORK_TYPE_MGMT
        )
        mgmt_interface_id = None
        if mgmt_interfaces:
            mgmt_interface_id = mgmt_interfaces[0]['id']
        hostname = host.hostname
        address_name = cutils.format_address_name(hostname,
                                                  constants.NETWORK_TYPE_MGMT)
        # if ihost has mgmt_ip, make sure address in address table
        if mgmt_ip:
            self._create_or_update_address(context, hostname, mgmt_ip,
                                           constants.NETWORK_TYPE_MGMT,
                                           mgmt_interface_id)
        # if ihost has no management IP, check for static mgmt IP
        if not mgmt_ip:
            mgmt_ip = self._lookup_static_ip_address(
                hostname, constants.NETWORK_TYPE_MGMT
            )
            if mgmt_ip:
                host.mgmt_ip = mgmt_ip
                self.update_ihost(context, host)
        # if no static address, then allocate one
        if not mgmt_ip:
            mgmt_pool = self.dbapi.network_get_by_type(
                constants.NETWORK_TYPE_MGMT
            ).pool_uuid

            mgmt_ip = self._allocate_pool_address(mgmt_interface_id, mgmt_pool,
                                                  address_name).address
            if mgmt_ip:
                host.mgmt_ip = mgmt_ip
                self.update_ihost(context, host)

        self._generate_dnsmasq_hosts_file(existing_host=host)
        self._allocate_cluster_host_address_for_host(host)

    def get_my_host_id(self):
        if not ConductorManager.my_host_id:
            local_hostname = socket.gethostname()
            controller = self.dbapi.ihost_get(local_hostname)
            ConductorManager.my_host_id = controller['id']
        return ConductorManager.my_host_id

    def get_dhcp_server_duid(self):
        """Retrieves the server DUID from the local DHCP server lease file."""
        lease_filename = tsc.CONFIG_PATH + 'dnsmasq.leases'
        with open(lease_filename, 'r') as lease_file:
            for columns in (line.strip().split() for line in lease_file):
                if len(columns) != 2:
                    continue
                keyword, value = columns
                if keyword.lower() == "duid":
                    return value

    def _dhcp_release(self, interface, ip_address, mac_address, cid=None):
        """Release a given DHCP lease"""
        params = [interface, ip_address, mac_address]
        if cid:
            params += [cid]
        if IPAddress(ip_address).version == 6:
            params = ["--ip", ip_address,
                "--iface", interface,
                "--server-id", self.get_dhcp_server_duid(),
                "--client-id", cid,
                "--iaid", str(cutils.get_dhcp_client_iaid(mac_address))]
            LOG.warning("Invoking dhcp_release6 for {}".format(params))
            subprocess.call(["dhcp_release6"] + params)  # pylint: disable=not-callable
        else:
            LOG.warning("Invoking dhcp_release for {}".format(params))
            subprocess.call(["dhcp_release"] + params)  # pylint: disable=not-callable

    def _find_networktype_for_address(self, ip_address):
        for network in self.dbapi.networks_get_all():
            pool = self.dbapi.address_pool_get(network.pool_uuid)
            subnet = IPNetwork(pool.network + '/' + str(pool.prefix))
            address = IPAddress(ip_address)
            if address in subnet:
                return network.type

    def _find_local_interface_name(self, network_type):
        """Lookup the local interface name for a given network type."""
        host_id = self.get_my_host_id()
        interface_list = self.dbapi.iinterface_get_all(host_id, expunge=True)
        ifaces = dict((i['ifname'], i) for i in interface_list)
        port_list = self.dbapi.port_get_all(host_id)
        ports = dict((p['interface_id'], p) for p in port_list)
        for interface in interface_list:
            if network_type in interface.networktypelist:
                context = {'interfaces': ifaces, 'ports': ports}
                return pinterface.get_interface_os_ifname(context, interface)

    def _find_local_mgmt_interface_vlan_id(self):
        """Lookup the local interface name for a given network type."""
        host_id = self.get_my_host_id()
        interface_list = self.dbapi.iinterface_get_all(host_id, expunge=True)
        for interface in interface_list:
            if constants.NETWORK_TYPE_MGMT in interface.networktypelist:
                if 'vlan_id' not in interface:
                    return 0
                else:
                    return interface['vlan_id']

    def _remove_leases_by_mac_address(self, mac_address):
        """Remove any leases that were added without a CID that we were not
        able to delete.  This is specifically looking for leases on the pxeboot
        network that may still be present but will also handle the unlikely
        event of deleting an old host during an upgrade.  Hosts on previous
        releases did not register a CID on the mgmt interface."""
        lease_filename = tsc.CONFIG_PATH + 'dnsmasq.leases'
        try:
            with open(lease_filename, 'r') as lease_file:
                for columns in (line.strip().split() for line in lease_file):
                    if len(columns) != 5:
                        continue
                    timestamp, address, ip_address, hostname, cid = columns
                    if address != mac_address:
                        continue
                    network_type = self._find_networktype_for_address(ip_address)
                    if not network_type:
                        # Not one of our managed networks
                        LOG.warning("Lease for unknown network found in "
                                    "dnsmasq.leases file: {}".format(columns))
                        continue
                    interface_name = self._find_local_interface_name(
                        network_type
                    )
                    self._dhcp_release(interface_name, ip_address, mac_address)
        except Exception as e:
            LOG.error("Failed to remove leases for %s: %s" % (mac_address,
                                                              str(e)))

    def _remove_lease_for_address(self, hostname, network_type):
        """Remove the lease for a given address"""
        address_name = cutils.format_address_name(hostname, network_type)
        try:
            interface_name = self._find_local_interface_name(network_type)
            if not interface_name:
                return

            address = self.dbapi.address_get_by_name(address_name)
            interface_id = address.interface_id
            ip_address = address.address

            if interface_id:
                interface = self.dbapi.iinterface_get(interface_id)
                mac_address = interface.imac
            elif network_type == constants.NETWORK_TYPE_MGMT:
                ihost = self.dbapi.ihost_get_by_hostname(hostname)
                mac_address = ihost.mgmt_mac
            else:
                return

            cid = cutils.get_dhcp_cid(hostname, network_type, mac_address)
            self._dhcp_release(interface_name, ip_address, mac_address, cid)
        except Exception as e:
            LOG.error("Failed to remove lease %s: %s" % (address_name,
                                                         str(e)))

    def _unallocate_address(self, hostname, network_type):
        """Unallocate address if it exists"""
        address_name = cutils.format_address_name(hostname, network_type)
        if network_type == constants.NETWORK_TYPE_MGMT:
            self._remove_lease_for_address(hostname, network_type)
        try:
            address_uuid = self.dbapi.address_get_by_name(address_name).uuid
            self.dbapi.address_remove_interface(address_uuid)
        except exception.AddressNotFoundByName:
            pass

    def _remove_address(self, hostname, network_type):
        """Remove address if it exists"""
        address_name = cutils.format_address_name(hostname, network_type)
        if network_type == constants.NETWORK_TYPE_MGMT:
            self._remove_lease_for_address(hostname, network_type)
        try:
            address_uuid = self.dbapi.address_get_by_name(address_name).uuid
            self.dbapi.address_destroy(address_uuid)
        except exception.AddressNotFoundByName:
            pass
        except exception.AddressNotFound:
            pass

    def _unallocate_addresses_for_host(self, host):
        """Unallocates management addresses for a given host.

        :param host: host object
        """
        hostname = host.hostname
        self._unallocate_address(hostname, constants.NETWORK_TYPE_MGMT)
        self._unallocate_address(hostname, constants.NETWORK_TYPE_CLUSTER_HOST)
        if host.personality == constants.CONTROLLER:
            self._unallocate_address(hostname, constants.NETWORK_TYPE_OAM)
            self._unallocate_address(hostname, constants.NETWORK_TYPE_PXEBOOT)
        self._remove_leases_by_mac_address(host.mgmt_mac)
        self._generate_dnsmasq_hosts_file(deleted_host=host)

    def _remove_addresses_for_host(self, host):
        """Removes management and cluster-host addresses for a given host.

        :param host: host object
        """
        hostname = host.hostname
        self._remove_address(hostname, constants.NETWORK_TYPE_MGMT)
        self._remove_address(hostname, constants.NETWORK_TYPE_CLUSTER_HOST)
        self._remove_leases_by_mac_address(host.mgmt_mac)
        self._generate_dnsmasq_hosts_file(deleted_host=host)

    def _update_host_lvm_config(self, context, host, force=False):
        personalities = [host.personality]
        # For rook must update lvm filter
        config_dict = {
            "host_uuids": [host.uuid],
        }

        if host.personality == constants.CONTROLLER:
            config_dict["personalities"] = [constants.CONTROLLER]
            config_dict["classes"] = ['platform::lvm::controller::runtime']
        elif host.personality == constants.WORKER:
            config_dict["personalities"] = [constants.WORKER]
            config_dict["classes"] = ['platform::lvm::compute::runtime']

        config_uuid = self._config_update_hosts(context, personalities,
                                                host_uuids=[host.uuid])
        self._config_apply_runtime_manifest(context,
                                            config_uuid,
                                            config_dict,
                                            force=force)

    def _configure_controller_host(self, context, host):
        """Configure a controller host with the supplied data.

        Does the following tasks:
        - Update the puppet hiera data configuration for host
        - Allocates management address if none exists
        - Set up PXE configuration to run installer
        - Update grub for AIO before initial unlock

        :param context: request context
        :param host: host object
        """
        if self.host_load_matches_sw_version(host):
            # update the config if the host is running the same version as
            # the active controller.
            if (host.administrative == constants.ADMIN_UNLOCKED or
                    host.action == constants.FORCE_UNLOCK_ACTION or
                    host.action == constants.UNLOCK_ACTION):

                # Update host configuration
                self._puppet.update_host_config(host)
        else:
            # from active controller, update hieradata for upgrade
            host_uuids = [host.uuid]
            config_uuid = self._config_update_hosts(
                context,
                [constants.CONTROLLER],
                host_uuids,
                reboot=True)
            host_upgrade = self.dbapi.host_upgrade_get_by_host(host.id)
            target_load = self.dbapi.load_get(host_upgrade.target_load)
            self._puppet.update_host_config_upgrade(
                host,
                target_load.software_version,
                config_uuid
            )

        self._allocate_addresses_for_host(context, host)
        # Set up the PXE config file for this host so it can run the installer
        self._update_pxe_config(host)
        self._ceph_mon_create(host)

        if (os.path.isfile(constants.ANSIBLE_BOOTSTRAP_FLAG) and
                host.availability == constants.AVAILABILITY_ONLINE):
            # This must be the initial controller host unlock request.
            personalities = [constants.CONTROLLER]
            if not cutils.is_aio_system(self.dbapi):
                # Standard system, touch the unlock ready flag
                cutils.touch(constants.UNLOCK_READY_FLAG)
            else:
                # AIO, must update grub before the unlock. Sysinv agent expects
                # this exact set of manifests in order to touch the unlock ready
                # flag after they have been applied.
                config_uuid = self._config_update_hosts(context, personalities,
                                                        host_uuids=[host.uuid])
                if utils.config_is_reboot_required(host.config_target):
                    config_uuid = self._config_set_reboot_required(config_uuid)

                config_dict = {
                    "personalities": personalities,
                    "host_uuids": [host.uuid],
                    "classes": ['platform::compute::grub::runtime',
                                'platform::compute::config::runtime']
                }
                self._config_apply_runtime_manifest(
                    context, config_uuid, config_dict, force=True)

            # Regenerate config target uuid, node is going for reboot!
            config_uuid = self._config_update_hosts(context, personalities)
            if utils.config_is_reboot_required(host.config_target):
                config_uuid = self._config_set_reboot_required(config_uuid)
            self._puppet.update_host_config(host, config_uuid)

    def _ceph_mon_create(self, host):
        if not StorageBackendConfig.has_backend(
            self.dbapi,
            constants.CINDER_BACKEND_CEPH
        ):
            return

        ceph_mon = self.dbapi.ceph_mon_get_by_ihost(host.uuid)

        if not ceph_mon:
            system = self.dbapi.isystem_get_one()
            ceph_mon_gib = constants.SB_CEPH_MON_GIB
            ceph_mons = self.dbapi.ceph_mon_get_list()

            if ceph_mons:
                ceph_mon_gib = ceph_mons[0].ceph_mon_gib
            values = {'forisystemid': system.id,
                      'forihostid': host.id,
                      'device_path': host.rootfs_device,
                      'ceph_mon_gib': ceph_mon_gib,
                      'state': constants.SB_STATE_CONFIGURED,
                      'task': constants.SB_TASK_NONE}
            LOG.info("creating ceph_mon for host %s with ceph_mon_gib=%s."
                     % (host.hostname, ceph_mon_gib))
            self.dbapi.ceph_mon_create(values)
        elif ceph_mon[0].device_path != host.rootfs_device:
            LOG.info("updating ceph_mon for host %s with device_path=%s."
                     % (host.hostname, host.rootfs_device))
            self.dbapi.ceph_mon_update(ceph_mon[0].uuid, {'device_path': host.rootfs_device})

    def _remove_ceph_mon(self, host):
        if not StorageBackendConfig.has_backend(
            self.dbapi,
            constants.CINDER_BACKEND_CEPH
        ):
            return

        mon = self.dbapi.ceph_mon_get_by_ihost(host.uuid)
        if mon:
            LOG.info("Deleting ceph monitor for host %s"
                     % str(host.hostname))
            self.dbapi.ceph_mon_destroy(mon[0].uuid)
            # At this point self._ceph should always be set, but we check
            # just to be sure
            if self._ceph is not None:
                self._ceph.remove_ceph_monitor(host.hostname)
            else:
                # This should never happen, but if it does, log it so
                # there is a trace of it
                LOG.error("Error deleting ceph monitor")
        else:
            LOG.info("No ceph monitor present for host %s. "
                     "Skipping deleting ceph monitor."
                     % str(host.hostname))

    def kube_config_kubelet(self, context):
        """Update kubernetes nodes kubelet configuration ConfigMap.

        This method updates kubelet parameters in configmaps/kubelet-config.
        This leverages puppet report status so we can wait for completion
        of the runtime manifest and trigger subsequent per-node configuration.

        :param context: request context
        """
        active_controller = utils.HostHelper.get_active_controller(self.dbapi)
        personalities = [constants.CONTROLLER]
        config_uuid = self._config_update_hosts(context, personalities,
            [active_controller.uuid])
        config_dict = {
            "personalities": personalities,
            "host_uuids": [active_controller.uuid],
            "classes": [
                'platform::kubernetes::master::update_kubelet_params::runtime'],
            puppet_common.REPORT_STATUS_CFG:
                puppet_common.REPORT_KUBE_UPDATE_KUBELET_PARAMS
        }
        self._config_apply_runtime_manifest(
            context, config_uuid=config_uuid, config_dict=config_dict)

    def _update_keystone_password(self, context, username):
        """This method calls a puppet class to update the service config and

           reload the related service on keystone password change"""

        LOG.info("Updating service config for keystone user: %s" % username)
        personalities = [constants.CONTROLLER]
        config_uuid = self._config_update_hosts(context, personalities)
        config_dict = {
            "personalities": personalities,
            "classes": [KEYSTONE_USER_PASSWORD_UPDATE[username]],
        }
        self._config_apply_runtime_manifest(context, config_uuid, config_dict)

    def update_remotelogging_config(self, context):
        """Update the remotelogging configuration"""

        personalities = [constants.CONTROLLER,
                         constants.WORKER,
                         constants.STORAGE]
        config_uuid = self._config_update_hosts(context, personalities)

        config_dict = {
            "personalities": [constants.CONTROLLER],
            "classes": ['platform::sysctl::controller::runtime',
                        'platform::remotelogging::runtime']
        }
        self._config_apply_runtime_manifest(context, config_uuid, config_dict)

        config_dict = {
            "personalities": [constants.WORKER, constants.STORAGE],
            "classes": ['platform::remotelogging::runtime'],
        }
        self._config_apply_runtime_manifest(context, config_uuid, config_dict)

    def docker_registry_image_list(self, context):
        try:
            image_list_response = docker_registry.docker_registry_get("_catalog")
        except requests.exceptions.SSLError:
            LOG.exception("Failed to get docker registry catalog")
            raise exception.DockerRegistrySSLException()
        except Exception:
            LOG.exception("Failed to get docker registry catalog")
            raise exception.DockerRegistryAPIException()

        if image_list_response.status_code != 200:
            LOG.error("Bad response from docker registry: %s"
                % image_list_response.status_code)
            return []

        image_list_response = image_list_response.json()
        images = []
        # responses from the registry looks like this
        # {u'repositories': [u'meliodas/satesatesate', ...]}
        # we need to turn that into what we want to return:
        # [{'name': u'meliodas/satesatesate'}]
        if 'repositories' not in image_list_response:
            return images

        image_list_response = image_list_response['repositories']
        for image in image_list_response:
            images.append({'name': image})

        return images

    def docker_registry_image_tags(self, context, image_name):
        try:
            image_tags_response = docker_registry.docker_registry_get(
                "%s/tags/list" % image_name)
        except requests.exceptions.SSLError:
            LOG.exception("Failed to get docker registry image tags")
            raise exception.DockerRegistrySSLException()
        except Exception:
            LOG.exception("Failed to get docker registry image tags")
            raise exception.DockerRegistryAPIException()

        if image_tags_response.status_code != 200:
            LOG.error("Bad response from docker registry: %s"
                % image_tags_response.status_code)
            return []

        image_tags_response = image_tags_response.json()
        tags = []

        if 'tags' not in image_tags_response:
            return tags

        image_tags_response = image_tags_response['tags']
        # in the case where all tags of an image is deleted but not
        # garbage collected
        # the response will contain "tags:null"
        if image_tags_response is not None:
            for tag in image_tags_response:
                tags.append({'name': image_name, 'tag': tag})

        return tags

    # assumes image_name_and_tag is already error checked to contain "name:tag"
    def docker_registry_image_delete(self, context, image_name_and_tag):
        image_name_and_tag = image_name_and_tag.split(":")

        # first get the image digest for the image name and tag provided
        try:
            digest_resp = docker_registry.docker_registry_get("%s/manifests/%s"
                % (image_name_and_tag[0], image_name_and_tag[1]))
        except requests.exceptions.SSLError:
            LOG.exception("Failed to delete docker registry image %s" %
                          image_name_and_tag)
            raise exception.DockerRegistrySSLException()
        except Exception:
            LOG.exception("Failed to delete docker registry image %s" %
                          image_name_and_tag)
            raise exception.DockerRegistryAPIException()

        if digest_resp.status_code != 200:
            LOG.error("Bad response from docker registry: %s"
                % digest_resp.status_code)
            return

        image_digest = digest_resp.headers['Docker-Content-Digest']

        # now delete the image
        try:
            image_delete_response = docker_registry.docker_registry_delete(
                "%s/manifests/%s" % (image_name_and_tag[0], image_digest))
        except requests.exceptions.SSLError:
            LOG.exception("Failed to delete docker registry image %s" %
                          image_name_and_tag)
            raise exception.DockerRegistrySSLException()
        except Exception:
            LOG.exception("Failed to delete docker registry image %s" %
                          image_name_and_tag)
            raise exception.DockerRegistryAPIException()

        if image_delete_response.status_code != 202:
            LOG.error("Bad response from docker registry: %s"
                % digest_resp.status_code)
            return

    def docker_registry_garbage_collect(self, context):
        """Run garbage collector"""
        active_controller = utils.HostHelper.get_active_controller(self.dbapi)
        personalities = [constants.CONTROLLER]
        config_uuid = self._config_update_hosts(context, personalities,
            [active_controller.uuid])

        config_dict = {
            "personalities": personalities,
            "host_uuids": [active_controller.uuid],
            "classes": ['platform::dockerdistribution::garbagecollect']
        }
        self._config_apply_runtime_manifest(context, config_uuid, config_dict)

    def docker_get_apps_images(self, context):
        """
        Return a dictionary of all apps and associated images from local registry.
        """

        images = {}
        try:
            for kapp in self.dbapi.kube_app_get_all():
                app = self._app.Application(kapp)
                images_to_download = self._app.get_image_tags_by_charts(app)
                stripped_images = [x.replace(constants.DOCKER_REGISTRY_HOST + ':' +
                                             constants.DOCKER_REGISTRY_PORT + '/', '')
                                   for x in images_to_download]
                images[kapp.name] = stripped_images
                LOG.info("Application images for %s are: %s" % (kapp.name,
                                                                str(stripped_images)))
        except Exception as e:
            LOG.info("Get images for all apps error.")
            LOG.exception(e)

        return images

    def _configure_worker_host(self, context, host):
        """Configure a worker host with the supplied data.

        Does the following tasks:
        - Create or update entries in address table
        - Generate the configuration file for the host
        - Allocates management address if none exists
        - Set up PXE configuration to run installer

        :param context: request context
        :param host: host object
        """
        # Only update the config if the host is running the same version as
        # the active controller.
        if self.host_load_matches_sw_version(host):
            # Only generate the config files if the worker host is unlocked.
            if (host.administrative == constants.ADMIN_UNLOCKED or
                    host.action == constants.FORCE_UNLOCK_ACTION or
                    host.action == constants.UNLOCK_ACTION):
                # Generate host configuration file
                self._puppet.update_host_config(host)
        else:
            LOG.info("Host %s is not running active load. "
                     "Skipping manifest generation" % host.hostname)

        self._allocate_addresses_for_host(context, host)
        # Set up the PXE config file for this host so it can run the installer
        self._update_pxe_config(host)

    def _configure_edgeworker_host(self, context, host):
        """Configure an edgeworker host with the supplied data.

        Does the following tasks:
        - Create or update entries in address table
        - Allocates management address if none exists

        :param context: request context
        :param host: host object
        """
        self._allocate_addresses_for_host(context, host)

    def _configure_storage_host(self, context, host):
        """Configure a storage ihost with the supplied data.

        Does the following tasks:
        - Update the puppet hiera data configuration for host
        - Allocates management address if none exists
        - Set up PXE configuration to run installer

        :param context: request context
        :param host: host object
        """

        # Update cluster and peers model.
        # We call this function when setting the personality of a storage host.
        # In cases where we configure the storage-backend before unlocking
        # controller-0, and then configuring all other hosts, ceph will not be
        # responsive (and self._ceph not be set) when setting the storage
        # personality.
        # But that's ok, because this function is also called when unlocking a
        # storage node and we are guaranteed (by consistency checks) a
        # responsive ceph cluster at that point in time and we can update the
        # ceph cluster information succesfully.
        if self._ceph is not None:
            self._ceph.update_ceph_cluster(host)
        else:
            # It's ok, we just log a message for debug purposes
            LOG.debug("Error updating cluster information")

        # Only update the manifest if the host is running the same version as
        # the active controller.
        if self.host_load_matches_sw_version(host):
            # Only generate the manifest files if the storage host is unlocked.
            # At that point changes are no longer allowed to the hostname, so
            # it is OK to allow the node to boot and configure the platform
            # services.
            if (host.administrative == constants.ADMIN_UNLOCKED or
                    host.action == constants.FORCE_UNLOCK_ACTION or
                    host.action == constants.UNLOCK_ACTION):
                # Generate host configuration files
                self._puppet.update_host_config(host)
        else:
            LOG.info("Host %s is not running active load. "
                     "Skipping manifest generation" % host.hostname)

        self._allocate_addresses_for_host(context, host)

        # Set up the PXE config file for this host so it can run the installer
        self._update_pxe_config(host)
        if host['hostname'] == constants.STORAGE_0_HOSTNAME:
            self._ceph_mon_create(host)

    def remove_host_config(self, context, host_uuid):
        """Remove configuration files for a host.

        :param context: an admin context.
        :param host_uuid: host uuid.
        """
        host = self.dbapi.ihost_get(host_uuid)

        self._puppet.remove_host_config(host)

    def _unconfigure_controller_host(self, host):
        """Unconfigure a controller host.

        Does the following tasks:
        - Remove the puppet hiera data configuration for host
        - Remove host entry in the dnsmasq hosts file
        - Delete PXE configuration

        :param host: a host object.
        """
        self._unallocate_addresses_for_host(host)
        self._puppet.remove_host_config(host)
        self._remove_pxe_config(host)

        # Create the simplex flag on this controller because our mate has
        # been deleted.
        cutils.touch(tsc.PLATFORM_SIMPLEX_FLAG)

        if host.hostname == constants.CONTROLLER_0_HOSTNAME:
            self.controller_0_posted = False
        elif host.hostname == constants.CONTROLLER_1_HOSTNAME:
            self.controller_1_posted = False

    def _unconfigure_worker_host(self, host, is_cpe=False):
        """Unconfigure a worker host.

        Does the following tasks:
        - Remove the puppet hiera data configuration for host
        - Remove the host entry from the dnsmasq hosts file
        - Delete PXE configuration

        :param host: a host object.
        :param is_cpe: this node is a combined node
        """
        if not is_cpe:
            self._remove_addresses_for_host(host)
        self._puppet.remove_host_config(host)
        self._remove_pxe_config(host)
        self._remove_ceph_mon(host)

    def _unconfigure_edgeworker_host(self, host):
        """Unconfigure an edgeworker host.

        :param host: a host object.
        """
        self._remove_addresses_for_host(host)

    def _unconfigure_storage_host(self, host):
        """Unconfigure a storage host.

        Does the following tasks:
        - Remove the puppet hiera data configuration for host
        - Remove host entry in the dnsmasq hosts file
        - Delete PXE configuration

        :param host: a host object.
        """
        self._unallocate_addresses_for_host(host)
        self._puppet.remove_host_config(host)
        self._remove_pxe_config(host)

    def configure_ihost(self, context, host,
                        do_worker_apply=False):
        """Configure a host.

        :param context: an admin context.
        :param host: a host object.
        :param do_worker_apply: configure the worker subfunctions of the host.
        """

        LOG.info("configure_ihost %s" % host.hostname)

        # Generate system configuration files
        # TODO(mpeters): remove this once all system reconfigurations properly
        # invoke this method
        self._puppet.update_system_config()
        self._puppet.update_secure_system_config()

        if host.personality == constants.CONTROLLER:
            self._configure_controller_host(context, host)
        elif host.personality == constants.WORKER:
            self._configure_worker_host(context, host)
        elif host.personality == constants.EDGEWORKER:
            self._configure_edgeworker_host(context, host)
        elif host.personality == constants.STORAGE:
            self._configure_storage_host(context, host)
        else:
            raise exception.SysinvException(_(
                "Invalid method call: unsupported personality: %s") %
                                            host.personality)

        if do_worker_apply:
            # Apply the manifests immediately
            puppet_common.puppet_apply_manifest(host.mgmt_ip,
                                                       constants.WORKER,
                                                       do_reboot=True)
        return host

    def unconfigure_ihost(self, context, ihost_obj):
        """Unconfigure a host.

        :param context: an admin context.
        :param ihost_obj: a host object.
        """
        LOG.debug("unconfigure_ihost %s." % ihost_obj.uuid)

        # Configuring subfunctions of the node instead
        if ihost_obj.subfunctions:
            personalities = cutils.get_personalities(ihost_obj)
            is_cpe = cutils.is_cpe(ihost_obj)
        else:
            personalities = (ihost_obj.personality,)
            is_cpe = False

        for personality in personalities:
            if personality == constants.CONTROLLER:
                self._unconfigure_controller_host(ihost_obj)
            elif personality == constants.WORKER:
                self._unconfigure_worker_host(ihost_obj, is_cpe)
            elif personality == constants.EDGEWORKER:
                self._unconfigure_edgeworker_host(ihost_obj)
            elif personality == constants.STORAGE:
                self._unconfigure_storage_host(ihost_obj)
            else:
                # allow a host with no personality to be unconfigured
                pass

    def _update_dependent_interfaces(self, interface, ihost,
                                     phy_intf, oldmac, newmac, depth=1):
        """ Updates the MAC address for dependent logical interfaces.

        :param interface: interface object
        :param ihost: host object
        :param phy_intf: physical interface name
        :oldmac: previous MAC address
        :newmac: MAC address to be updated
        """
        if depth > 5:
            # be safe! dont loop for cyclic DB entries
            LOG.error("Looping? [{}] {}:{}".format(depth, phy_intf, newmac))
            return
        if hasattr(interface, 'used_by'):
            LOG.info("clone_mac_update: {} used_by {} on {}".format(
                interface['ifname'], interface['used_by'], ihost['hostname']))
            for i in interface['used_by']:
                used_by_if = self.dbapi.iinterface_get(i, ihost['uuid'])
                if used_by_if:
                    LOG.debug("mac_update: Found used_by_if: {} {} --> {} [{}]"
                              .format(used_by_if['ifname'],
                                used_by_if['imac'],
                                newmac, oldmac))
                    if oldmac in used_by_if['imac']:
                        updates = {'imac': newmac}
                        self.dbapi.iinterface_update(used_by_if['uuid'], updates)
                        LOG.info("mac_update: MAC updated: {} {} --> {} [{}]"
                                 .format(used_by_if['ifname'],
                                    used_by_if['imac'],
                                    newmac, oldmac))
                # look for dependent interfaces of this one.
                self._update_dependent_interfaces(used_by_if, ihost, phy_intf,
                                                  oldmac, newmac, depth + 1)

    def validate_cloned_interfaces(self, ihost_uuid):
        """Check if all the cloned interfaces are reported by the host.

        :param ihost_uuid: ihost uuid unique id
        """
        LOG.info("clone_mac_update: validate_cloned_interfaces %s" % ihost_uuid)
        try:
            iinterfaces = self.dbapi.iinterface_get_by_ihost(ihost_uuid,
                                                             expunge=True)
        except exc.DetachedInstanceError:
            # A rare DetachedInstanceError exception may occur, retry
            LOG.warn("Detached Instance Error,  retry "
                     "iinterface_get_by_ihost %s" % ihost_uuid)
            iinterfaces = self.dbapi.iinterface_get_by_ihost(ihost_uuid,
                                                             expunge=True)
        for interface in iinterfaces:
            if constants.CLONE_ISO_MAC in interface['imac']:
                LOG.warn("Missing interface [{},{}] on the cloned host"
                         .format(interface['ifname'], interface['id']))
                raise exception.SysinvException(_(
                        "Missing interface on the cloned host"))

    def _update_interface_mac(self, inic, ifname, interface, ihost, oldmac):
        """ Updates the MAC address for logical interfaces.

        :param inic: NIC data reported
        :param interface: interface object
        :param ifname: interface name
        :param ihost: host object
        :param oldmac: previous MAC address
        """
        # Not checking for "interface['ifname'] == ifname",
        # as it could be data0, bond0.100
        updates = {'imac': inic['mac']}
        self.dbapi.iinterface_update(interface['uuid'], updates)
        LOG.info("mac_update: updated if mac {} {} --> {}"
            .format(ifname, interface['imac'], inic['mac']))
        ports = self.dbapi.ethernet_port_get_by_interface(
                                                interface['uuid'])
        for p in ports:
            # Update the corresponding ports too
            LOG.debug("mac_update: port={} mac={} for intf: {}"
                .format(p['id'], p['mac'], interface['uuid']))
            if oldmac in p['mac']:
                updates = {'mac': inic['mac']}
                self.dbapi.ethernet_port_update(p['id'], updates)
                LOG.info("mac_update: updated port: {} {}-->{}"
                    .format(p['id'], p['mac'], inic['mac']))
        # See if there are dependent interfaces.
        # If yes, update them too.
        self._update_dependent_interfaces(interface, ihost,
                                            ifname, oldmac, inic['mac'])
        if (oldmac in ihost['mgmt_mac']):
            LOG.info("mac_update: mgmt_mac {}:{}"
                        .format(ihost['mgmt_mac'], inic['mac']))
            values = {'mgmt_mac': inic['mac']}
            self.dbapi.ihost_update(ihost['uuid'], values)

    def _get_interface_mac_update_dict(self, ihost, inic_pciaddr_dict, interface_mac_update):
        """ Get port list of altered MACs if vendor and device-id is the same on a PCI address.

        :param ihost: host object
        :param inic_pciaddr_dict: NIC data dict reported by sysinv-agent, key is PCI address
        :param interface_mac_update: output dict containing MAC update info
        """
        eth_ports = self.dbapi.ethernet_port_get_by_host(ihost['uuid'])
        for port in eth_ports:
            if port.pciaddr in inic_pciaddr_dict.keys():
                if (inic_pciaddr_dict[port.pciaddr]['pvendor'] == port.pvendor
                        and inic_pciaddr_dict[port.pciaddr]['pdevice'] == port.pdevice
                        and inic_pciaddr_dict[port.pciaddr]['mac'] != port.mac):
                    LOG.debug('add interface for mac update %s' % vars(port))
                    interface_mac_update[port.interface_uuid] = port.pciaddr

    def _set_port_report_mismatch_alarm(self, host, port, reason_text):
        """ Alarm update for port report mismatch

        This method updates the alarm if there are mismatch between data reported by sysinv-agent
        and the database
        :param host: host object
        :param port: port object
        :param reason_text: alarm reason text field
        """
        entity_instance_id = "%s=%s" % (fm_constants.FM_ENTITY_TYPE_PORT,
                                        "{}={}.{}={}".format(fm_constants.FM_ENTITY_TYPE_HOST,
                                                             host['hostname'],
                                                             fm_constants.FM_ENTITY_TYPE_PORT,
                                                             port.uuid))

        fault = fm_api.Fault(
            alarm_id=fm_constants.FM_ALARM_ID_NETWORK_PORT,
            alarm_state=fm_constants.FM_ALARM_STATE_SET,
            entity_type_id=fm_constants.FM_ENTITY_TYPE_PORT,
            entity_instance_id=entity_instance_id,
            severity=fm_constants.FM_ALARM_SEVERITY_MAJOR,
            reason_text=reason_text,
            alarm_type=fm_constants.FM_ALARM_TYPE_4,
            probable_cause=fm_constants.ALARM_PROBABLE_CAUSE_45,
            proposed_repair_action=_("Lock the host, remove any associated 'used by i/f'"
                                     " interfaces, set the associated interface class to"
                                     " 'none', and unlock the host."),
            service_affecting=False)
        self.fm_api.set_fault(fault)

    def _clear_existing_port_report_mismatch_alarms(self, ihost, eth_ports, alarm_port_list):
        port_alarms = self.fm_api.get_faults_by_id(fm_constants.FM_ALARM_ID_NETWORK_PORT)
        if port_alarms:
            alarmed_uuids = [port.uuid for port, reason in alarm_port_list]
            for port in eth_ports:
                entity_instance_id = "%s=%s" % (fm_constants.FM_ENTITY_TYPE_PORT,
                                    "{}={}.{}={}".format(fm_constants.FM_ENTITY_TYPE_HOST,
                                                            ihost['hostname'],
                                                            fm_constants.FM_ENTITY_TYPE_PORT,
                                                            port.uuid))
                for alarm in port_alarms:
                    if (entity_instance_id in alarm.entity_instance_id
                            and port.uuid not in alarmed_uuids):
                        self.fm_api.clear_fault(fm_constants.FM_ALARM_ID_NETWORK_PORT,
                                                entity_instance_id)

    def _get_port_id_subfield(self, input_text):
        str_found = ""
        try:
            regexPattern = '\[' + '(.+?)' + '\]'
            str_found = re.search(regexPattern, input_text).group(1)
        except AttributeError:
            str_found = None
        return str_found

    def _get_port_desc_subfield(self, input_text):
        str_found = ""
        try:
            regexPattern = '(.+?)' + '\['
            str_found = re.search(regexPattern, input_text).group(1)
        except AttributeError:
            str_found = None
        return str_found

    def _get_replaced_ports_on_pciaddr(self, ihost, inic_pciaddr_dict, replaced_ports,
                                       unreported_ports, cannot_replace, updated_description):
        """ Get port list of replaced port device on the same on a PCI address,
            if vendor is different or vendor is the same and device-id differs.
            It is necessary that the associated interface to be of class "none"

        :param ihost: host object
        :param inic_pciaddr_dict: NIC data array reported by sysinv-agent, key is PCI address
        :param replaced_ports: output list containing replaced ports on the DB
        :param unreported_ports: output list containing unreported ports on the DB
        :param cannot_replace: output set containing ports with configured interfaces on the DB
        :param updated_description: output set containing ports that changed the description of
                                vendor and/or device, but not the numerical ID.
        """
        eth_ports = self.dbapi.ethernet_port_get_by_host(ihost['uuid'])
        alarm_port_list = list()
        for port in eth_ports:
            iface = None
            try:
                iface = self.dbapi.iinterface_get(port.interface_id)
            except Exception as ex:
                LOG.exception("Failed to get interface %s for port %s, exception: %s" %
                                (port.interface_id, port.name, type(ex).__name__))
                continue

            if port.pciaddr in inic_pciaddr_dict.keys():
                inic_vendor_id = self._get_port_id_subfield(
                                                        inic_pciaddr_dict[port.pciaddr]['pvendor'])
                inic_device_id = self._get_port_id_subfield(
                                                        inic_pciaddr_dict[port.pciaddr]['pdevice'])
                db_vendor_id = self._get_port_id_subfield(port.pvendor)
                db_device_id = self._get_port_id_subfield(port.pdevice)
                # check if is a new device
                if (inic_vendor_id != db_vendor_id
                        or (inic_vendor_id == db_vendor_id and inic_device_id != db_device_id)):
                    if (iface.ifclass is None and not iface.used_by):
                        LOG.info('Detected port %s addr:%s replaced from "%s/%s" to "%s/%s"'
                                % (port.name, port.pciaddr, port.pvendor, port.pdevice,
                                  inic_pciaddr_dict[port.pciaddr]['pvendor'],
                                  inic_pciaddr_dict[port.pciaddr]['pdevice']))
                        replaced_ports.append(port)
                    else:
                        LOG.info("Cannot replace port {} at addr:{}, has interface {} "
                                 "with class {} or is used by {}"
                                .format(port.name, port.pciaddr, port.interface_id,
                                 iface.ifclass, iface.used_by))
                        cannot_replace.add(port.pciaddr)
                        alarm_port_list.append((port, "OS reports vendor or device-id without match"
                                                " on DB for port {}".format(port.name)))
                # if the OS changed only the description, mark to update the fields pvendor and
                # pdevice
                if (inic_vendor_id == db_vendor_id and inic_device_id == db_device_id):
                    inic_vendor_desc = self._get_port_desc_subfield(
                                                        inic_pciaddr_dict[port.pciaddr]['pvendor'])
                    db_vendor_desc = self._get_port_desc_subfield(port.pvendor)
                    inic_device_desc = self._get_port_desc_subfield(
                                                        inic_pciaddr_dict[port.pciaddr]['pdevice'])
                    db_device_desc = self._get_port_desc_subfield(port.pdevice)
                    if (inic_vendor_desc != db_vendor_desc or inic_device_desc != db_device_desc):
                        port.pvendor = inic_pciaddr_dict[port.pciaddr]['pvendor']
                        port.pdevice = inic_pciaddr_dict[port.pciaddr]['pdevice']
                        updated_description.append(port)
            else:
                if (iface.ifclass is None and not iface.used_by):
                    LOG.info('Detected port %s addr:%s unreported and class=none on DB "%s/%s"'
                            % (port.name, port.pciaddr, port.pvendor, port.pdevice))
                    unreported_ports.append(port)
                else:
                    LOG.info("Unreported port {} at addr:{}, has interface {} with class {}"
                             " or is used by {}".format(port.name, port.pciaddr, port.interface_id,
                                                        iface.ifclass, iface.used_by))
                    # if class is DATA the interface might be owned by user space poll mode driver
                    # like ovs-dpdk and no longer be reported by the OS
                    if (iface.ifclass != constants.INTERFACE_CLASS_DATA):
                        alarm_port_list.append((port, "Port {} on DB is no longer reported"
                                                     " by the OS".format(port.name)))

        # first clear alarms that are no longer valid
        self._clear_existing_port_report_mismatch_alarms(ihost, eth_ports, alarm_port_list)
        for alarm in alarm_port_list:
            self._set_port_report_mismatch_alarm(ihost, alarm[0], alarm[1])

    def _process_port_replacement(self, ihost, inic_pciaddr_dict, cannot_replace):
        """Process NIC card replacement.

        This method compares PCI devices reported by sysinv-agent and the database, searching for
        NIC devices, using PCI address as the search key. If a replacement on the same address is
        detected the old DB entry is erased, the new one will be created via regular processing done
        in iport_update_by_ihost(). The search also detects for NICs no longer reported on a
        particular PCI address.
        If the replaced or unreported ports do not have the associated interface with class none
        or are used by other sub-interfaces, the new reported interface is not processed until the
        operator removes the interface configuration.

        :param ihost: the host object
        :param inic_pciaddr_dict: NIC data array reported by sysinv-agent, key is PCI address
        :param cannot_replace: output set containing ports with configured interfaces on the DB
        :return True if there are removed ports
        """
        replaced_ports = list()
        unreported_ports = list()
        updated_description = list()
        # Get list of replaced device ports on each PCI address reported
        self._get_replaced_ports_on_pciaddr(ihost, inic_pciaddr_dict, replaced_ports,
                                            unreported_ports, cannot_replace, updated_description)
        # remove old port and interface, processing inic_dict_array will create the new ones
        to_destroy = replaced_ports + unreported_ports
        for port in to_destroy:
            op_type = ('replaced' if (port in replaced_ports) else 'unreported')
            try:
                LOG.info("Delete %s port %s associated interface id:%s"
                        % (op_type, port.name, port.interface_id))
                self.dbapi.iinterface_destroy(port.interface_id)
            except Exception as ex:
                LOG.exception("Failed to delete %s interface id %s, exception %s" %
                                (op_type, port.interface_id, type(ex)))
            try:
                LOG.info('Delete %s port %s addr:%s vendor:"%s" device:"%s"'
                        % (op_type, port.name, port.pciaddr, port.pvendor, port.pdevice))
                self.dbapi.ethernet_port_destroy(port.uuid)
            except Exception as ex:
                LOG.exception("Failed to delete %s port id %s, exception %s" %
                                (op_type, port.id, type(ex)))
        # if there is vendor and/or device description update only, save on the database
        for port in updated_description:
            updates = {'pvendor': port.pvendor,
                       'pdevice': port.pdevice}
            LOG.info("Update description for {} with vendor={} and device={}".format(port.name,
                                                                        port.pvendor, port.pdevice))
            self.dbapi.ethernet_port_update(port['id'], updates)

        return (len(to_destroy) > 0)

    def _set_ethernet_port_node_id(self, ihost, port):
        """ Set port node_id

        In case of port replacement search the current inode DB to set the correct node_id, if
        there are no inodes created, the update will be done in inumas_update_by_ihost().

        :param ihost: the host object
        :param port: the port object
        """
        try:
            # Get host numa nodes which may already be in db
            inodes = self.dbapi.inode_get_by_ihost(ihost['uuid'])
        except exception.NodeNotFound:
            LOG.exception("Cannot find inodes for host %s" % ihost['uuid'])
            return
        for inode in inodes:
            port_node = port['numa_node']
            if port_node == -1:
                port_node = 0  # special handling
            if port_node == inode['numa_node']:
                attr = {'node_id': inode['id']}
                LOG.debug("update port %s uuid %s with node_id %s" %
                          (port['name'], port['uuid'], inode['id']))
                self.dbapi.ethernet_port_update(port['uuid'], attr)

    def _fix_db_pciaddr_for_n3000_i40(self, ihost, inic):
        """Fix PCI address for N3000 FPGA onboard devices.

        When N3000 is reset, the onboard devices (0d58) can have their PCI address changed.
        This method will check if the PCI address from the same MAC address has changed
        and will update the database if needed.

        :param ihost: the host object
        :param inic: NIC data reported
        """
        port = self.dbapi.ethernet_port_get_by_mac(inic['mac'])
        if cinterface.get_pci_device_id(port) == dconstants.PCI_DEVICE_ID_FPGA_INTEL_I40_PF:
            if inic['pciaddr'] != port.pciaddr:
                LOG.warning("PCI address mismatch for %s (%s), updating from %s to %s"
                    % (port.name, port.mac, port.pciaddr, inic['pciaddr']))
                updates = {
                    'pciaddr': inic['pciaddr']
                }
                self.dbapi.ethernet_port_update(port.uuid, updates)

    def iport_update_by_ihost(self, context,
                              ihost_uuid, inic_dict_array):
        """Create iports for an ihost with the supplied data.

        This method allows records for iports for ihost to be created.

        :param context: an admin context
        :param ihost_uuid: ihost uuid unique id
        :param inic_dict_array: initial values for iport objects
        :returns: pass or fail
        """
        LOG.debug("Entering iport_update_by_ihost %s %s" %
                  (ihost_uuid, inic_dict_array))
        ihost_uuid.strip()
        try:
            ihost = self.dbapi.ihost_get(ihost_uuid)
        except exception.ServerNotFound:
            LOG.exception("Invalid ihost_uuid %s" % ihost_uuid)
            return

        try:
            hostname = socket.gethostname()
        except socket.error:
            LOG.exception("Failed to get local hostname")
            hostname = None

        has_removed = False
        cannot_replace = set()
        interface_mac_update = dict()
        is_aio_simplex_system = cutils.is_aio_simplex_system(self.dbapi)
        if (is_aio_simplex_system):
            inic_pciaddr_dict = dict()
            for inic in inic_dict_array:
                inic_pciaddr_dict[inic['pciaddr']] = inic
            # If AIO-SX, we can update the NIC's MAC with the same vendor, device-id and PCI address
            # For other system configuration the correct procedure is to perform host-delete and
            # then host-add
            self._get_interface_mac_update_dict(ihost, inic_pciaddr_dict, interface_mac_update)

            # in AIO-SX, if the replaced or unreported ports do not have the associated interface
            # with class none or are used by other sub-interfaces, the new reported interface is not
            # processed until the operator removes the interface configuration.
            has_removed = self._process_port_replacement(ihost, inic_pciaddr_dict, cannot_replace)

        try:
            iinterfaces = self.dbapi.iinterface_get_by_ihost(ihost_uuid,
                                                             expunge=True)
        except exc.DetachedInstanceError:
            # A rare DetachedInstanceError exception may occur, retry
            LOG.warn("Detached Instance Error,  retry "
                     "iinterface_get_by_ihost %s" % ihost_uuid)
            iinterfaces = self.dbapi.iinterface_get_by_ihost(ihost_uuid,
                                                             expunge=True)

        cloning = False
        for inic in inic_dict_array:
            LOG.debug("Processing inic %s" % inic)
            interface_exists = False
            networktype = None
            ifclass = None
            bootp = None
            create_tagged_interface = False
            new_interface = None
            set_address_interface = False
            mtu = constants.DEFAULT_MTU
            port = None
            vlan_id = self._find_local_mgmt_interface_vlan_id()
            # ignore port if no MAC address present, this will
            # occur for data port after they are configured via DPDK driver
            if not inic['mac']:
                continue
            # in AIO-SX, if the replaced port have the associated interface with other class than
            # "none" we skip the processing until the operator modify the database
            if inic['pciaddr'] in cannot_replace:
                LOG.warning("old port's interface still configured, skip replacement for inic=%s"
                            % inic)
                continue
            try:
                inic_dict = {'host_id': ihost['id']}
                inic_dict.update(inic)
                ifname = inic['pname']
                if cutils.is_valid_mac(inic['mac']):
                    # Is this the port that the management interface is on?
                    if inic['mac'].strip() == ihost['mgmt_mac'].strip():
                        if ihost['hostname'] != hostname:
                            # auto create management/pxeboot network for all
                            # nodes but the active controller
                            if vlan_id:
                                create_tagged_interface = True
                                networktype = constants.NETWORK_TYPE_PXEBOOT
                                ifname = 'pxeboot0'
                            else:
                                networktype = constants.NETWORK_TYPE_MGMT
                                ifname = 'mgmt0'
                            ifclass = constants.INTERFACE_CLASS_PLATFORM
                            set_address_interface = True
                        bootp = 'True'

                clone_mac_updated = False
                for interface in iinterfaces:
                    LOG.debug("Checking interface %s" % vars(interface))
                    if interface['imac'] == inic['mac']:
                        # append to port attributes as well
                        inic_dict.update({
                            'interface_id': interface['id'], 'bootp': bootp
                        })

                        # interface already exists so don't create another
                        interface_exists = True
                        LOG.debug("interface mac match inic mac %s, inic_dict "
                                  "%s, interface_exists %s" %
                                  (interface['imac'], inic_dict,
                                   interface_exists))

                        self._fix_db_pciaddr_for_n3000_i40(ihost, inic)
                        break
                    elif (interface.uuid in interface_mac_update.keys()
                            and interface_mac_update[interface.uuid] == inic['pciaddr']):
                        # append to port attributes as well
                        inic_dict.update({
                            'interface_id': interface['id'], 'bootp': bootp
                        })
                        # interface already exists so don't create another
                        interface_exists = True
                        self._update_interface_mac(inic, ifname, interface, ihost, interface.imac)
                        LOG.info("interface mac update inic mac %s, inic_dict "
                                  "%s, interface_exists %s" %
                                  (interface['imac'], inic_dict,
                                   interface_exists))
                    # If there are interfaces with clone labels as MAC addresses,
                    # this is a install-from-clone scenario. Update MAC addresses.
                    elif ((constants.CLONE_ISO_MAC + ihost['hostname'] + inic['pname']) ==
                          interface['imac']):
                        LOG.info("clone_mac_update: updated if mac {} {} --> {}"
                            .format(ifname, interface['imac'], inic['mac']))
                        oldmac = constants.CLONE_ISO_MAC + ihost['hostname'] + ifname
                        self._update_interface_mac(inic, ifname, interface, ihost, oldmac)
                        clone_mac_updated = True

                if clone_mac_updated:
                    # no need create any interfaces or ports for cloning scenario
                    cloning = True
                    continue

                if not interface_exists:
                    interface_dict = {'forihostid': ihost['id'],
                                      'ifname': ifname,
                                      'imac': inic['mac'],
                                      'imtu': mtu,
                                      'iftype': 'ethernet',
                                      'ifclass': ifclass,
                                      }

                    # autocreate untagged interface
                    try:
                        LOG.debug("Attempting to create new untagged interface %s" %
                                  interface_dict)
                        new_interface = self.dbapi.iinterface_create(
                                          ihost['id'],
                                          interface_dict)
                        # append to port attributes as well
                        inic_dict.update(
                            {'interface_id': new_interface['id'],
                             'bootp': bootp
                             })
                        if networktype in [constants.NETWORK_TYPE_MGMT,
                                           constants.NETWORK_TYPE_PXEBOOT]:
                            new_interface_networktype = networktype
                            network = self.dbapi.network_get_by_type(networktype)
                            # create interface network association
                            ifnet_dict = {
                                'interface_id': new_interface['id'],
                                'network_id': network['id']
                            }
                            try:
                                self.dbapi.interface_network_create(ifnet_dict)
                            except Exception:
                                LOG.exception(
                                    "Failed to create interface %s "
                                    "network %s association" %
                                    (new_interface['id'], network['id']))
                    except Exception as ex:
                        LOG.exception("Failed to create new untagged interface %s exception: %s" %
                                      (inic['mac'], type(ex)))
                        pass  # at least create the port

                    if create_tagged_interface:
                        # autocreate tagged management interface
                        network = self.dbapi.network_get_by_type(constants.NETWORK_TYPE_MGMT)
                        interface_dict = {
                            'forihostid': ihost['id'],
                            'ifname': 'mgmt0',
                            'imac': inic['mac'],
                            'imtu': constants.DEFAULT_MTU,
                            'iftype': 'vlan',
                            'ifclass': constants.INTERFACE_CLASS_PLATFORM,
                            'uses': [ifname],
                            'vlan_id': vlan_id,
                        }

                        try:
                            LOG.debug("Attempting to create new vlan interface %s" %
                                      interface_dict)
                            new_interface = self.dbapi.iinterface_create(
                                ihost['id'], interface_dict
                            )
                            new_interface_networktype = constants.NETWORK_TYPE_MGMT
                            network = self.dbapi.network_get_by_type(
                                constants.NETWORK_TYPE_MGMT
                            )
                            # create interface network association
                            ifnet_dict = {
                                'interface_id': new_interface['id'],
                                'network_id': network['id']
                            }
                            try:
                                self.dbapi.interface_network_create(ifnet_dict)
                            except Exception:
                                LOG.exception(
                                    "Failed to create interface %s "
                                    "network %s association" %
                                    (new_interface['id'], network['id']))
                        except Exception:
                            LOG.exception(
                                "Failed to create new vlan interface %s" %
                                inic['mac'])
                            pass  # at least create the port

                try:
                    LOG.debug("Attempting to create/update port %s on host %s" %
                              (inic_dict, ihost['id']))

                    port = self.dbapi.ethernet_port_get_by_mac(inic['mac'])

                    # update existing port with updated attributes
                    try:
                        port_dict = {
                            'sriov_totalvfs': inic['sriov_totalvfs'],
                            'sriov_numvfs': inic['sriov_numvfs'],
                            'sriov_vfs_pci_address':
                                inic['sriov_vfs_pci_address'],
                            'sriov_vf_driver':
                                inic['sriov_vf_driver'],
                            'sriov_vf_pdevice_id':
                                inic['sriov_vf_pdevice_id'],
                            'driver': inic['driver'],
                            'dpdksupport': inic['dpdksupport'],
                            'speed': inic['speed'],
                        }

                        LOG.info("port %s update attr: %s" %
                                 (port.uuid, port_dict))
                        self.dbapi.ethernet_port_update(port.uuid, port_dict)

                        # During WRL to CentOS upgrades the port name can
                        # change. This will update the db to reflect that
                        if port['name'] != inic['pname']:
                            self._update_port_name(port, inic['pname'])
                    except Exception as ex:
                        LOG.exception("Failed to update port %s, exception: %s" %
                                (inic['mac'], type(ex)))
                        pass

                except Exception:
                    # adjust for field naming differences between the NIC
                    # dictionary returned by the agent and the Port model
                    port_dict = inic_dict.copy()
                    port_dict['name'] = port_dict.pop('pname', None)
                    port_dict['namedisplay'] = port_dict.pop('pnamedisplay',
                                                             None)

                    LOG.info("Attempting to create new port %s "
                             "on host %s" % (inic_dict, ihost.uuid))
                    port = self.dbapi.ethernet_port_create(ihost.uuid, port_dict)

                    if (is_aio_simplex_system and has_removed):
                        # In AIO-SX if a replacement has occurred it may be necessary to update
                        # the node_id from the inode database, as inumas_update_by_ihost() updates
                        # the ports only when is creating new inode entries
                        self._set_ethernet_port_node_id(ihost, port)

            except exception.NodeNotFound:
                raise exception.SysinvException(_(
                    "Invalid ihost_uuid: host not found: %s") %
                    ihost_uuid)

            except Exception as ex:  # this info may have been posted previously, update ?
                LOG.exception("got exception: %s" % type(ex))
                pass

            # Set interface ID for management address
            if set_address_interface:
                if new_interface and 'id' in new_interface:
                    values = {'interface_id': new_interface['id']}
                    try:
                        addr_name = cutils.format_address_name(
                            ihost.hostname, new_interface_networktype)
                        address = self.dbapi.address_get_by_name(addr_name)
                        self.dbapi.address_update(address['uuid'], values)
                    except exception.AddressNotFoundByName:
                        pass
                    # Do any potential distributed cloud config
                    # We do this here where the interface is created.
                    cutils.perform_distributed_cloud_config(self.dbapi,
                                                            new_interface['id'])
                if port:
                    values = {'interface_id': port.interface_id}
                try:
                    addr_name = cutils.format_address_name(ihost.hostname,
                                                           networktype)
                    address = self.dbapi.address_get_by_name(addr_name)
                    if address['interface_id'] is None:
                        self.dbapi.address_update(address['uuid'], values)
                except exception.AddressNotFoundByName:
                    pass

        if ihost.invprovision not in [constants.PROVISIONED, constants.PROVISIONING, constants.UPGRADING]:
            LOG.info("Updating %s host invprovision from %s to %s" %
                     (ihost.hostname, ihost.invprovision, constants.UNPROVISIONED))
            value = {'invprovision': constants.UNPROVISIONED}
            self.dbapi.ihost_update(ihost_uuid, value)

        if cloning:
            # if cloning scenario, check and log if there are lesser no:of interfaces
            # on the host being installed with a cloned image. Comparison is against
            # the DB which was backed up on the original system (used for cloning).
            self.validate_cloned_interfaces(ihost_uuid)

    def _update_port_name(self, port, updated_name):
        """
        Sets the port name based on the updated name.
        Will also set the ifname of any associated ethernet/vlan interfaces
        We do not modify any AE interfaces. The names of AE interfaces should
        not be related to any physical ports.
        :param port: the db object of the port to update
        :param updated_name: the new name
        """
        port_name = port['name']
        # Might need to update the associated interface and vlan names as well
        interface = self.dbapi.iinterface_get(port['interface_id'])
        if interface.ifname == port_name:
            LOG.info("Updating interface name: %s to %s" %
                     (interface.ifname, updated_name))
            self.dbapi.iinterface_update(interface.uuid,
                                         {'ifname': updated_name})

            used_by = interface['used_by']
            for ifname in used_by:
                vlan = self.dbapi.iinterface_get(ifname, port['forihostid'])
                if vlan.get('iftype') != constants.INTERFACE_TYPE_VLAN:
                    continue
                if vlan.ifname.startswith((port_name + ".")):
                    new_vlan_name = vlan.ifname.replace(
                        port_name, updated_name, 1)
                    LOG.info("Updating vlan interface name: %s to %s" %
                             (vlan.ifname, new_vlan_name))
                    self.dbapi.iinterface_update(vlan.uuid,
                                                 {'ifname': new_vlan_name})
        LOG.info("Updating port name: %s to %s" % (port_name, updated_name))
        self.dbapi.ethernet_port_update(port['uuid'], {'name': updated_name})

    def lldp_id_to_port(self, id, ports):
        ovs_id = re.sub(r'^{}'.format(constants.LLDP_OVS_PORT_PREFIX), '', id)
        for port in ports:
            if (port['name'] == id or
                    port['uuid'] == id or
                    port['uuid'].find(ovs_id) == 0):
                return port
        return None

    def lldp_tlv_dict(self, agent_neighbour_dict):
        tlv_dict = {}
        for k, v in agent_neighbour_dict.items():
            if v is not None and k in constants.LLDP_TLV_VALID_LIST:
                tlv_dict.update({k: v})
        return tlv_dict

    def lldp_agent_tlv_update(self, tlv_dict, agent):
        tlv_update_list = []
        tlv_create_list = []
        agent_id = agent['id']
        agent_uuid = agent['uuid']

        tlvs = self.dbapi.lldp_tlv_get_by_agent(agent_uuid)
        for k, v in tlv_dict.items():
            for tlv in tlvs:
                if tlv['type'] == k:
                    tlv_value = tlv_dict.get(tlv['type'])
                    entry = {'type': tlv['type'],
                             'value': tlv_value}
                    if tlv['value'] != tlv_value:
                        tlv_update_list.append(entry)
                    break
            else:
                tlv_create_list.append({'type': k,
                                        'value': v})

        if tlv_update_list:
            try:
                tlvs = self.dbapi.lldp_tlv_update_bulk(tlv_update_list,
                                                       agentid=agent_id)
            except Exception as e:
                LOG.exception("Error during bulk TLV update for agent %s: %s",
                    agent_id, str(e))
                raise
        if tlv_create_list:
            try:
                self.dbapi.lldp_tlv_create_bulk(tlv_create_list,
                                                agentid=agent_id)
            except Exception as e:
                LOG.exception("Error during bulk TLV create for agent %s: %s",
                    agent_id, str(e))
                raise

    def lldp_neighbour_tlv_update(self, tlv_dict, neighbour):
        tlv_update_list = []
        tlv_create_list = []
        neighbour_id = neighbour['id']
        neighbour_uuid = neighbour['uuid']

        tlvs = self.dbapi.lldp_tlv_get_by_neighbour(neighbour_uuid)
        for k, v in tlv_dict.items():

            # Since "dot1_vlan_names" has 255 char limit in DB, it
            # is necessary to ensure the vlan list from the tlv
            # packets does not have length greater than 255 before
            # shoving it into DB
            if k == constants.LLDP_TLV_TYPE_DOT1_VLAN_NAMES:
                # trim the listed vlans to 252 char max
                if len(v) >= 256:
                    # if not perfect trim, remove incomplete ending
                    perfect_trim = v[252] in list(', ')
                    v = v[:252]
                    if not perfect_trim:
                        v = v[:v.rfind(',') + 1]

                    # add '...' to indicate there's more
                    v += '...'
                    LOG.info("tlv_value trimmed: %s", v)

            for tlv in tlvs:
                if tlv['type'] == k:
                    tlv_value = v
                    entry = {'type': tlv['type'],
                             'value': tlv_value}
                    if tlv['value'] != tlv_value:
                        tlv_update_list.append(entry)
                    break
            else:
                tlv_create_list.append({'type': k,
                                        'value': v})

        if tlv_update_list:
            try:
                tlvs = self.dbapi.lldp_tlv_update_bulk(
                    tlv_update_list,
                    neighbourid=neighbour_id)
            except Exception as e:
                LOG.exception("Error during bulk TLV update for neighbour"
                              "%s: %s", neighbour_id, str(e))
                raise
        if tlv_create_list:
            try:
                self.dbapi.lldp_tlv_create_bulk(tlv_create_list,
                                                neighbourid=neighbour_id)
            except Exception as e:
                LOG.exception("Error during bulk TLV create for neighbour"
                              "%s: %s",
                              neighbour_id, str(e))
                raise

    def lldp_agent_update_by_host(self, context,
                                  host_uuid, agent_dict_array):
        """Create or update lldp agents for an host with the supplied data.

        This method allows records for lldp agents for ihost to be created or
        updated.

        :param context: an admin context
        :param host_uuid: host uuid unique id
        :param agent_dict_array: initial values for lldp agent objects
        :returns: pass or fail
        """
        LOG.debug("Entering lldp_agent_update_by_host %s %s" %
                  (host_uuid, agent_dict_array))
        host_uuid.strip()
        try:
            db_host = self.dbapi.ihost_get(host_uuid)
        except exception.ServerNotFound:
            raise exception.SysinvException(_(
                "Invalid host_uuid: %s") % host_uuid)

        try:
            db_ports = self.dbapi.port_get_by_host(host_uuid)
        except Exception:
            raise exception.SysinvException(_(
                "Error getting ports for host %s") % host_uuid)

        try:
            db_agents = self.dbapi.lldp_agent_get_by_host(host_uuid)
        except Exception:
            raise exception.SysinvException(_(
                "Error getting LLDP agents for host %s") % host_uuid)

        for agent in agent_dict_array:
            db_port = self.lldp_id_to_port(agent['name_or_uuid'], db_ports)
            if not db_port:
                LOG.debug("Could not find port for agent %s",
                          agent['name_or_uuid'])
                continue

            hostid = db_host['id']
            portid = db_port['id']

            agent_found = None
            for db_agent in db_agents:
                if db_agent['port_id'] == portid:
                    agent_found = db_agent
                    break

            LOG.debug("Processing agent %s" % agent)

            agent_dict = {'host_id': hostid,
                          'port_id': portid,
                          'status': agent['status']}
            update_tlv = False
            try:
                if not agent_found:
                    LOG.info("Attempting to create new LLDP agent "
                             "%s on host %s" % (agent_dict, hostid))
                    if agent['state'] != constants.LLDP_AGENT_STATE_REMOVED:
                        db_agent = self.dbapi.lldp_agent_create(portid,
                                                                hostid,
                                                                agent_dict)
                        update_tlv = True
                else:
                    # If the agent exists, try to update some of the fields
                    # or remove it
                    agent_uuid = db_agent['uuid']
                    if agent['state'] == constants.LLDP_AGENT_STATE_REMOVED:
                        db_agent = self.dbapi.lldp_agent_destroy(agent_uuid)
                    else:
                        attr = {'status': agent['status'],
                                'system_name': agent['system_name']}
                        db_agent = self.dbapi.lldp_agent_update(agent_uuid,
                                                                attr)
                        update_tlv = True

                if update_tlv:
                    tlv_dict = self.lldp_tlv_dict(agent)
                    self.lldp_agent_tlv_update(tlv_dict, db_agent)

            except exception.InvalidParameterValue:
                raise exception.SysinvException(_(
                    "Failed to update/delete non-existing"
                    "lldp agent %s") % agent_uuid)
            except exception.LLDPAgentExists:
                raise exception.SysinvException(_(
                    "Failed to add LLDP agent %s. "
                    "Already exists") % agent_uuid)
            except exception.NodeNotFound:
                raise exception.SysinvException(_(
                    "Invalid host_uuid: host not found: %s") %
                    host_uuid)
            except exception.PortNotFound:
                raise exception.SysinvException(_(
                    "Invalid port id: port not found: %s") %
                    portid)
            except Exception as e:
                raise exception.SysinvException(_(
                    "Failed to update lldp agent: %s") % e)

    def lldp_neighbour_update_by_host(self, context,
                                      host_uuid, neighbour_dict_array):
        """Create or update lldp neighbours for an ihost with the supplied data.

        This method allows records for lldp neighbours for ihost to be created
        or updated.

        :param context: an admin context
        :param host_uuid: host uuid unique id
        :param neighbour_dict_array: initial values for lldp neighbour objects
        :returns: pass or fail
        """
        LOG.debug("Entering lldp_neighbour_update_by_host %s %s" %
                  (host_uuid, neighbour_dict_array))
        host_uuid.strip()
        try:
            db_host = self.dbapi.ihost_get(host_uuid)
        except Exception:
            raise exception.SysinvException(_(
                "Invalid host_uuid: %s") % host_uuid)

        try:
            db_ports = self.dbapi.port_get_by_host(host_uuid)
        except Exception:
            raise exception.SysinvException(_(
                "Error getting ports for host %s") % host_uuid)

        try:
            db_neighbours = self.dbapi.lldp_neighbour_get_by_host(host_uuid)
        except Exception:
            raise exception.SysinvException(_(
                "Error getting LLDP neighbours for host %s") % host_uuid)

        reported = set([(d['msap']) for d in neighbour_dict_array])
        stale = [d for d in db_neighbours if (d['msap']) not in reported]
        for neighbour in stale:
            db_neighbour = self.dbapi.lldp_neighbour_destroy(
                            neighbour['uuid'])

        for neighbour in neighbour_dict_array:
            db_port = self.lldp_id_to_port(neighbour['name_or_uuid'], db_ports)
            if not db_port:
                LOG.debug("Could not find port for neighbour %s",
                          neighbour['name_or_uuid'])
                continue

            LOG.debug("Processing lldp neighbour %s" % neighbour)

            hostid = db_host['id']
            portid = db_port['id']
            msap = neighbour['msap']
            state = neighbour['state']

            neighbour_dict = {'host_id': hostid,
                              'port_id': portid,
                              'msap': msap}

            neighbour_found = False
            for db_neighbour in db_neighbours:
                if db_neighbour['msap'] == msap:
                    neighbour_found = db_neighbour
                    break

            update_tlv = False
            try:
                if not neighbour_found:
                    LOG.info("Attempting to create new lldp neighbour "
                             "%r on host %s" % (neighbour_dict, hostid))
                    db_neighbour = self.dbapi.lldp_neighbour_create(
                        portid, hostid, neighbour_dict)
                    update_tlv = True
                else:
                    # If the neighbour exists, remove it if requested by
                    # the agent. Otherwise, trigger a TLV update.  There
                    # are currently no neighbour attributes that need to
                    # be updated.
                    if state == constants.LLDP_NEIGHBOUR_STATE_REMOVED:
                        db_neighbour = self.dbapi.lldp_neighbour_destroy(
                            db_neighbour['uuid'])
                    else:
                        update_tlv = True
                if update_tlv:
                    tlv_dict = self.lldp_tlv_dict(neighbour)
                    self.lldp_neighbour_tlv_update(tlv_dict,
                                                   db_neighbour)
            except exception.InvalidParameterValue:
                raise exception.SysinvException(_(
                    "Failed to update/delete lldp neighbour. "
                    "Invalid parameter: %r") % tlv_dict)
            except exception.LLDPNeighbourExists:
                raise exception.SysinvException(_(
                    "Failed to add lldp neighbour %r. "
                    "Already exists") % neighbour_dict)
            except exception.NodeNotFound:
                raise exception.SysinvException(_(
                    "Invalid host_uuid: host not found: %s") %
                    host_uuid)
            except exception.PortNotFound:
                raise exception.SysinvException(_(
                    "Invalid port id: port not found: %s") %
                    portid)
            except Exception as e:
                raise exception.SysinvException(_(
                    "Couldn't update LLDP neighbour: %s") % e)

    def _process_fec_device_replacement(self, host, pci_device_dict_array):
        """Process FEC card replacement.

        This method compares PCI devices reported by sysinv-agent and the database, searching for
        FEC devices (N3000 or ACC100), using PCI address as the search key. If a replacement on the
        same address is detected the old DB entry is erased, the new one will be created via
        regular processing done in pci_device_update_by_host().
        The search also detects for FEC devices no longer reported on a particular PCI address. On
        this case the entry is also erased. A logic to consider the case of N3000 reset status was
        also added.

        :param host: the host object
        :param pci_device_dict_array: PCI device report from sysinv-agent
        """
        # create variables for easy handling
        fec_vendor = [dconstants.PCI_DEVICE_VENDOR_INTEL]
        acc100_devs = [dconstants.PCI_DEVICE_ID_ACC100_INTEL_5GNR_FEC_PF]
        fec_devs = fpga_constants.N3000_DEVICES
        fec_devs = fec_devs + acc100_devs

        # prepare report data to be indexed by pciaddr
        pci_addr_dict = dict()
        is_n3000_reset = False
        is_n3000_present = False
        for pci_dev in pci_device_dict_array:
            pci_addr_dict[pci_dev['pciaddr']] = pci_dev
            if (pci_dev['pvendor_id'] in fec_vendor
                    and pci_dev['pdevice_id'] in fpga_constants.N3000_DEVICES):
                is_n3000_reset = pci_dev['fpga_n3000_reset']
                is_n3000_present = True

        # identify FEC devices replaced and unreported
        unreported_fec_device = list()
        replaced_fec_device = list()
        db_devices = self.dbapi.pci_device_get_all(hostid=host['id'])
        for db_dev in db_devices:
            if (db_dev.pciaddr in pci_addr_dict.keys()):
                if (pci_addr_dict[db_dev.pciaddr]['pvendor_id'] in fec_vendor
                        and pci_addr_dict[db_dev.pciaddr]['pdevice_id'] in fec_devs
                        and db_dev.pvendor_id in fec_vendor
                        and db_dev.pdevice_id in fec_devs
                        and pci_addr_dict[db_dev.pciaddr]['pdevice_id'] != db_dev.pdevice_id):
                    LOG.info("Detected a replaced FEC device in %s, from device_id %s to %s" %
                                                    (db_dev.pciaddr, db_dev.pdevice_id,
                                                    pci_addr_dict[db_dev.pciaddr]['pdevice_id']))
                    replaced_fec_device.append(db_dev)
            else:
                if ((db_dev.pvendor_id in fec_vendor) and (db_dev.pdevice_id in fec_devs)):
                    LOG.info("Detected a FEC db entry unreported by sysinv-agent dev-id:%s addr:%s"
                          " uuid:%s" % (db_dev.pdevice_id, db_dev.pciaddr, db_dev.uuid))
                    unreported_fec_device.append(db_dev)

        # remove db entry replaced
        for dev in replaced_fec_device:
            try:
                LOG.info("At %s, delete replaced device %s" % (dev.pciaddr, dev.uuid))
                self.dbapi.pci_device_destroy(dev.uuid)
            except Exception as ex:
                LOG.exception("Failed to delete device uuid:%s, exception:%s" %
                              (dev.uuid, type(ex).__name__))

        # remove db entry unreported
        for dev in unreported_fec_device:
            destroy = False
            if (dev.pdevice_id in fpga_constants.N3000_DEVICES and is_n3000_present
                    and is_n3000_reset):
                destroy = True  # the DB only accepts entries with is_n3000_reset
            if (dev.pdevice_id in fpga_constants.N3000_DEVICES and not is_n3000_present):
                destroy = True  # no longer in use
            elif (dev.pdevice_id in acc100_devs):
                destroy = True  # no longer in use
            if destroy:
                try:
                    LOG.info("Delete unreported FEC device id:%s addr:%s uuid:%s"
                        % (dev.pdevice_id, dev.pciaddr, dev.uuid))
                    self.dbapi.pci_device_destroy(dev.uuid)
                except Exception as ex:
                    LOG.exception("Failed to delete device uuid:%s, exception:%s" %
                                (dev.uuid, type(ex)))

    def pci_device_update_by_host(self, context,
                                  host_uuid, pci_device_dict_array,
                                  cleanup_stale=False):
        """Create devices for an ihost with the supplied data.

        This method allows records for devices for ihost to be created.

        :param context: an admin context
        :param host_uuid: host uuid unique id
        :param pci_device_dict_array: initial values for device objects
        :param cleanup_stale: Do we want to clean up stale device entries?
        :returns: pass or fail
        """
        LOG.debug("Entering device_update_by_host %s %s" %
                  (host_uuid, pci_device_dict_array))
        host_uuid.strip()
        try:
            host = self.dbapi.ihost_get(host_uuid)
        except exception.ServerNotFound:
            LOG.exception("Invalid host_uuid %s" % host_uuid)
            return

        is_aio_simplex_system = cutils.is_aio_simplex_system(self.dbapi)
        if (is_aio_simplex_system):
            # if in AIO-SX, search replaced or unreported FEC entries on the database. If found
            # they are deleted. The new ones will be handled by the loop below
            self._process_fec_device_replacement(host, pci_device_dict_array)

        for pci_dev in pci_device_dict_array:
            LOG.debug("Processing dev %s" % pci_dev)
            is_n3000_dev_not_reset = False
            if 'fpga_n3000_reset' in pci_dev.keys():
                is_n3000_dev_not_reset = (pci_dev['pdevice_id'] in fpga_constants.N3000_DEVICES
                    and pci_dev['pvendor_id'] == fpga_constants.N3000_VENDOR
                    and not pci_dev['fpga_n3000_reset'])
                del pci_dev['fpga_n3000_reset']
            try:
                pci_dev_dict = {'host_id': host['id']}
                pci_dev_dict.update(pci_dev)
                dev_found = None
                try:
                    dev = self.dbapi.pci_device_get(pci_dev['pciaddr'],
                                                    hostid=host['id'])
                    dev_found = dev
                    if not dev:
                        if is_n3000_dev_not_reset:
                            LOG.info("N3000 reset not executed, skip for dev="
                                    "%s on host %s" % (pci_dev_dict, host['id']))
                            continue
                        LOG.info("Attempting to create new device "
                                 "%s on host %s" % (pci_dev_dict, host['id']))
                        dev = self.dbapi.pci_device_create(host['id'],
                                                           pci_dev_dict)
                except Exception:
                    if is_n3000_dev_not_reset:
                        LOG.info("N3000 reset not executed, skip for dev="
                                "%s on host %s" % (pci_dev_dict, host['id']))
                        continue
                    LOG.info("Attempting to create new device "
                             "%s on host %s" % (pci_dev_dict, host['id']))
                    dev = self.dbapi.pci_device_create(host['id'],
                                                       pci_dev_dict)

                # If the device exists, try to update some of the fields
                if dev_found:
                    try:
                        attr = {
                            'pclass_id': pci_dev['pclass_id'],
                            'pvendor_id': pci_dev['pvendor_id'],
                            'pdevice_id': pci_dev['pdevice_id'],
                            'pclass': pci_dev['pclass'],
                            'pvendor': pci_dev['pvendor'],
                            'psvendor': pci_dev['psvendor'],
                            'psdevice': pci_dev['psdevice'],
                            'sriov_totalvfs': pci_dev['sriov_totalvfs'],
                            'sriov_numvfs': pci_dev['sriov_numvfs'],
                            'sriov_vfs_pci_address':
                                pci_dev['sriov_vfs_pci_address'],
                            'sriov_vf_driver': pci_dev.get('sriov_vf_driver', None),
                            'sriov_vf_pdevice_id':
                                pci_dev.get('sriov_vf_pdevice_id', None),
                            'driver': pci_dev['driver'],
                            'extra_info': dev.get('extra_info', None)}
                        LOG.info("update %s attr: %s" % (pci_dev['pciaddr'], attr))

                        if (host['administrative'] == constants.ADMIN_LOCKED
                                and pci_dev['pdevice_id'] in
                                dconstants.SRIOV_ENABLED_FEC_DEVICE_IDS):
                            # For the FEC devices, the actual drivers
                            # are only updated on an unlocked host. The set
                            # of VF PCI addresses may not be known when the
                            # value of sriov_numvfs changes and is applied
                            # to create the VFs on a puppet runtime manifest
                            # apply. This prevents the intended drivers
                            # from being reported as None (reset) when the
                            # binding of the intended driver has not had a
                            # chance to be applied.
                            del attr['driver']
                            del attr['sriov_vf_driver']
                        if is_n3000_dev_not_reset:
                            LOG.info("N3000 reset not executed, skip for dev="
                                    "%s on host %s" % (pci_dev_dict, host['id']))
                            continue
                        dev = self.dbapi.pci_device_update(dev['uuid'], attr)
                    except Exception:
                        LOG.exception("Failed to update port %s" %
                                      dev['pciaddr'])
                        pass

            except exception.NodeNotFound:
                raise exception.SysinvException(_(
                    "Invalid host_uuid: host not found: %s") %
                    host_uuid)
            except Exception:
                pass

        if (cleanup_stale and not is_aio_simplex_system):
            # Since we do not accept unreseted N3000 devices on the database, we still might need to
            # clear stale entries from an upgrade for non AIO-SX setups
            self.cleanup_stale_n3000_devices(host, pci_device_dict_array)

    def cleanup_stale_n3000_devices(self, host, pci_device_dict_array):
        # Special-case the N3000 FPGA because we know it might change
        # PCI addresses.  We want to delete any N3000 devices for this host
        # in the DB which are not listed in pci_device_dict_array.
        update_addrs = [dev['pciaddr'] for dev in pci_device_dict_array]
        LOG.debug("update_addrs: %s" % update_addrs)
        devices = self.dbapi.pci_device_get_all(hostid=host.id)
        LOG.debug("db_addrs: %s" % [dev.pciaddr for dev in devices])
        for device in devices:
            LOG.debug("looking at device %s, %s, %s" %
                      (device.pciaddr, device.pvendor_id, device.pdevice_id))
            if (device.pvendor_id != fpga_constants.N3000_VENDOR or
                    device.pdevice_id not in fpga_constants.N3000_DEVICES):
                continue
            if device.pciaddr not in update_addrs:
                LOG.info("Deleting stale device at address %s" % device.pciaddr)
                self.dbapi.pci_device_destroy(device.id)
            else:
                LOG.debug("Found device at address %s in DB" % device.pciaddr)

    def inumas_update_by_ihost(self, context,
                               ihost_uuid, inuma_dict_array):
        """Create inumas for an ihost with the supplied data.

        This method allows records for inumas for ihost to be created.
        Updates the port node_id once its available.

        :param context: an admin context
        :param ihost_uuid: ihost uuid unique id
        :param inuma_dict_array: initial values for inuma objects
        :returns: pass or fail
        """

        ihost_uuid.strip()
        try:
            ihost = self.dbapi.ihost_get(ihost_uuid)
        except exception.ServerNotFound:
            LOG.exception("Invalid ihost_uuid %s" % ihost_uuid)
            return

        try:
            # Get host numa nodes which may already be in db
            mynumas = self.dbapi.inode_get_by_ihost(ihost_uuid)
        except exception.NodeNotFound:
            raise exception.SysinvException(_(
                "Invalid ihost_uuid: host not found: %s") % ihost_uuid)

        mynuma_nodes = [n.numa_node for n in mynumas]

        # perform update for ports
        ports = self.dbapi.ethernet_port_get_by_host(ihost_uuid)
        for i in inuma_dict_array:
            if 'numa_node' in i and i['numa_node'] in mynuma_nodes:
                LOG.info("Already in db numa_node=%s mynuma_nodes=%s" %
                         (i['numa_node'], mynuma_nodes))
                continue

            try:
                inuma_dict = {'forihostid': ihost['id']}

                inuma_dict.update(i)

                inuma = self.dbapi.inode_create(ihost['id'], inuma_dict)

                for port in ports:
                    port_node = port['numa_node']
                    if port_node == -1:
                        port_node = 0  # special handling

                    if port_node == inuma['numa_node']:
                        attr = {'node_id': inuma['id']}
                        self.dbapi.ethernet_port_update(port['uuid'], attr)

            except exception.NodeNotFound:
                raise exception.SysinvException(_(
                    "Invalid ihost_uuid: host not found: %s") %
                    ihost_uuid)
            except Exception:  # this info may have been posted previously, update ?
                pass

    def _get_default_platform_cpu_count(self, ihost, node,
                                        cpu_count, hyperthreading):
        """Return the initial number of reserved logical cores for platform
        use.  This can be overridden later by the end user."""
        # Reserve all logical cpus on all numa nodes for AIO systemcontroller
        system = self.dbapi.isystem_get_one()
        system_type = system.system_type
        dc_role = system.distributed_cloud_role
        if (system_type == constants.TIS_AIO_BUILD and
                dc_role == constants.DISTRIBUTED_CLOUD_ROLE_SYSTEMCONTROLLER and
                cutils.host_has_function(ihost, constants.CONTROLLER)):
            return cpu_count

        # Reserve one full core for worker or AIO controller on numa node 0.
        # Limiting to 2 logical cores with HyperThreading enabled or disabled.
        cpus = 0
        if cutils.host_has_function(ihost, constants.WORKER) and node == 0:
            cpus = 1 if not hyperthreading else 2
            if cutils.host_has_function(ihost, constants.CONTROLLER):
                cpus = 2
        return cpus

    def _get_default_vswitch_cpu_count(self, ihost, node,
                                       cpu_count, hyperthreading):
        """Return the initial number of reserved logical cores for vswitch
        use.  This can be overridden later by the end user."""
        if constants.VSWITCH_TYPE_NONE == cutils.get_vswitch_type(self.dbapi):
            return 0
        if cutils.host_has_function(ihost, constants.WORKER) and node == 0:
            physical_cores = (cpu_count // 2) if hyperthreading else cpu_count
            system_mode = self.dbapi.isystem_get_one().system_mode
            if system_mode == constants.SYSTEM_MODE_SIMPLEX:
                return 1 if not hyperthreading else 2
            else:
                if physical_cores > 4:
                    return 2 if not hyperthreading else 4
                elif physical_cores > 1:
                    return 1 if not hyperthreading else 2
        return 0

    def _get_default_shared_cpu_count(self, ihost, node,
                                       cpu_count, hyperthreading):
        """Return the initial number of reserved logical cores for shared
        use.  This can be overridden later by the end user."""
        return 0

    def _sort_by_socket_and_coreid(self, icpu_dict):
        """Sort a list of cpu dict objects such that lower numbered sockets
        appear first and that threads of the same core are adjacent in the
        list with the lowest thread number appearing first."""
        return (int(icpu_dict['numa_node']), int(icpu_dict['core']), int(icpu_dict['thread']))

    def _get_hyperthreading_enabled(self, cpu_list):
        """Determine if hyperthreading is enabled based on whether any threads
        exist with a threadId greater than 0"""
        for cpu in cpu_list:
            if int(cpu['thread']) > 0:
                return True
        return False

    def _get_node_cpu_count(self, cpu_list, node):
        count = 0
        for cpu in cpu_list:
            count += 1 if int(cpu['numa_node']) == node else 0
        return count

    def _get_default_cpu_functions(self, host, node, cpu_list, hyperthreading):
        """Return the default list of CPU functions to be reserved for this
        host on the specified numa node."""
        functions = []
        cpu_count = self._get_node_cpu_count(cpu_list, node)
        # Determine how many platform cpus need to be reserved
        count = self._get_default_platform_cpu_count(
            host, node, cpu_count, hyperthreading)
        for i in range(0, count):
            functions.append(constants.PLATFORM_FUNCTION)
        # Determine how many vswitch cpus need to be reserved
        count = self._get_default_vswitch_cpu_count(
            host, node, cpu_count, hyperthreading)
        for i in range(0, count):
            functions.append(constants.VSWITCH_FUNCTION)
        # Determine how many shared cpus need to be reserved
        count = self._get_default_shared_cpu_count(
            host, node, cpu_count, hyperthreading)
        for i in range(0, count):
            functions.append(constants.SHARED_FUNCTION)
        # Assign the default function to the remaining cpus
        for i in range(0, (cpu_count - len(functions))):
            functions.append(cpu_utils.get_default_function(host))
        return functions

    def print_cpu_topology(self, hostname=None, subfunctions=None,
                           reference=None,
                           sockets=None, cores=None, threads=None):
        """Print logical cpu topology table (for debug reasons).

        :param hostname: hostname
        :param subfunctions: subfunctions
        :param reference: reference label
        :param sockets: dictionary of socket_ids, sockets[cpu_id]
        :param cores:   dictionary of core_ids,   cores[cpu_id]
        :param threads: dictionary of thread_ids, threads[cpu_id]
        :returns: None
        """
        if sockets is None or cores is None or threads is None:
            LOG.error("print_cpu_topology: topology not defined. "
                      "sockets=%s, cores=%s, threads=%s"
                      % (sockets, cores, threads))
            return

        # calculate overall cpu topology stats
        n_sockets = len(set(sockets.values()))
        n_cores = len(set(cores.values()))
        n_threads = len(set(threads.values()))
        if n_sockets < 1 or n_cores < 1 or n_threads < 1:
            LOG.error("print_cpu_topology: unexpected topology. "
                      "n_sockets=%d, n_cores=%d, n_threads=%d"
                      % (n_sockets, n_cores, n_threads))
            return

        # build each line of output
        ll = ''
        s = ''
        c = ''
        t = ''
        for cpu in sorted(cores.keys()):
            ll += '%3d' % cpu
            s += '%3d' % sockets[cpu]
            c += '%3d' % cores[cpu]
            t += '%3d' % threads[cpu]

        LOG.info('Logical CPU topology: host:%s (%s), '
                 'sockets:%d, cores/socket=%d, threads/core=%d, reference:%s'
                 % (hostname, subfunctions, n_sockets, n_cores, n_threads,
                    reference))
        LOG.info('%9s : %s' % ('cpu_id', ll))
        LOG.info('%9s : %s' % ('socket_id', s))
        LOG.info('%9s : %s' % ('core_id', c))
        LOG.info('%9s : %s' % ('thread_id', t))

    def icpus_update_by_ihost(self, context,
                              ihost_uuid, icpu_dict_array,
                              force_grub_update=False):
        """Create cpus for an ihost with the supplied data.

        This method allows records for cpus for ihost to be created.

        :param context: an admin context
        :param ihost_uuid: ihost uuid unique id
        :param icpu_dict_array: initial values for cpu objects
        :param force_grub_update: bool value to force grub update
        :returns: pass or fail
        """

        ihost_uuid.strip()
        try:
            ihost = self.dbapi.ihost_get(ihost_uuid)
        except exception.ServerNotFound:
            LOG.exception("Invalid ihost_uuid %s" % ihost_uuid)
            return

        forihostid = ihost['id']
        ihost_inodes = self.dbapi.inode_get_by_ihost(ihost_uuid)

        icpus = self.dbapi.icpu_get_by_ihost(ihost_uuid)

        num_cpus_dict = len(icpu_dict_array)
        num_cpus_db = len(icpus)

        # Capture 'current' topology in dictionary format
        cs = {}
        cc = {}
        ct = {}
        if num_cpus_dict > 0:
            for icpu in icpu_dict_array:
                cpu_id = icpu.get('cpu')
                cs[cpu_id] = icpu.get('numa_node')
                cc[cpu_id] = icpu.get('core')
                ct[cpu_id] = icpu.get('thread')

        # Capture 'previous' topology in dictionary format
        ps = {}
        pc = {}
        pt = {}
        if num_cpus_db > 0:
            for icpu in icpus:
                cpu_id = icpu.get('cpu')
                core_id = icpu.get('core')
                thread_id = icpu.get('thread')
                forinodeid = icpu.get('forinodeid')
                socket_id = None
                for inode in ihost_inodes:
                    if forinodeid == inode.get('id'):
                        socket_id = inode.get('numa_node')
                        break
                ps[cpu_id] = socket_id
                pc[cpu_id] = core_id
                pt[cpu_id] = thread_id

        if num_cpus_dict > 0 and num_cpus_db == 0:
            self.print_cpu_topology(hostname=ihost.get('hostname'),
                                    subfunctions=ihost.get('subfunctions'),
                                    reference='current (initial)',
                                    sockets=cs, cores=cc, threads=ct)

        if num_cpus_dict > 0 and num_cpus_db > 0:
            LOG.debug("num_cpus_dict=%d num_cpus_db= %d. "
                      "icpud_dict_array= %s icpus.as_dict= %s" %
                      (num_cpus_dict, num_cpus_db, icpu_dict_array, icpus))

            # Skip update if topology has not changed
            if ps == cs and pc == cc and pt == ct:
                self.print_cpu_topology(hostname=ihost.get('hostname'),
                                        subfunctions=ihost.get('subfunctions'),
                                        reference='current (unchanged)',
                                        sockets=cs, cores=cc, threads=ct)
                if ihost.administrative == constants.ADMIN_LOCKED:
                    self.update_grub_config(context, ihost_uuid, force_grub_update)
                return

            self.print_cpu_topology(hostname=ihost.get('hostname'),
                                    subfunctions=ihost.get('subfunctions'),
                                    reference='previous',
                                    sockets=ps, cores=pc, threads=pt)
            self.print_cpu_topology(hostname=ihost.get('hostname'),
                                    subfunctions=ihost.get('subfunctions'),
                                    reference='current (CHANGED)',
                                    sockets=cs, cores=cc, threads=ct)

            # there has been an update.  Delete db entries and replace.
            for icpu in icpus:
                self.dbapi.icpu_destroy(icpu.uuid)

        # sort the list of cpus by socket and coreid
        cpu_list = sorted(icpu_dict_array, key=self._sort_by_socket_and_coreid)

        # determine if hyperthreading is enabled
        hyperthreading = self._get_hyperthreading_enabled(cpu_list)

        # build the list of functions to be assigned to each cpu
        functions = {}
        for n in ihost_inodes:
            numa_node = int(n.numa_node)
            functions[numa_node] = self._get_default_cpu_functions(
                ihost, numa_node, cpu_list, hyperthreading)

        for data in cpu_list:
            try:
                forinodeid = None
                for n in ihost_inodes:
                    numa_node = int(n.numa_node)
                    if numa_node == int(data['numa_node']):
                        forinodeid = n['id']
                        break

                cpu_dict = {'forihostid': forihostid,
                            'forinodeid': forinodeid,
                            'allocated_function': functions[numa_node].pop(0)}

                cpu_dict.update(data)

                self.dbapi.icpu_create(forihostid, cpu_dict)

            except exception.NodeNotFound:
                raise exception.SysinvException(_(
                    "Invalid ihost_uuid: host not found: %s") %
                    ihost_uuid)
            except Exception:
                # info may have already been posted
                pass

        # if it is the first controller wait for the initial config to
        # be completed
        if ((utils.is_host_simplex_controller(ihost) and
                (os.path.isfile(tsc.INITIAL_CONFIG_COMPLETE_FLAG) or
                 os.path.isfile(constants.ANSIBLE_BOOTSTRAP_FLAG))) or
                (not utils.is_host_simplex_controller(ihost) and
                 ihost.administrative == constants.ADMIN_LOCKED)):
            LOG.info("Update CPU grub config, host_uuid (%s), name (%s)"
                     % (ihost_uuid, ihost.get('hostname')))
            self.update_grub_config(context, ihost_uuid, force_grub_update)

        return

    def _get_platform_reserved_memory(self, ihost, node):
        low_core = cutils.is_low_core_system(ihost, self.dbapi)
        reserved = cutils.get_required_platform_reserved_memory(
            self.dbapi, ihost, node, low_core)
        return {'platform_reserved_mib': reserved} if reserved else {}

    def imemory_update_by_ihost(self, context,
                                ihost_uuid, imemory_dict_array,
                                force_update):
        """Create or update imemory for an ihost with the supplied data.

        This method allows records for memory for ihost to be created,
        or updated.

        :param context: an admin context
        :param ihost_uuid: ihost uuid unique id
        :param imemory_dict_array: initial values for cpu objects
        :param: force_update: force host memory update
        :returns: pass or fail
        """

        ihost_uuid.strip()
        try:
            ihost = self.dbapi.ihost_get(ihost_uuid)
        except exception.ServerNotFound:
            LOG.exception("Invalid ihost_uuid %s" % ihost_uuid)
            return

        if ihost['administrative'] == constants.ADMIN_LOCKED and \
            ihost['invprovision'] in [constants.PROVISIONED, constants.UPGRADING] and \
                not force_update:
            LOG.debug("Ignore the host memory audit after the host is locked")
            return
        # To avoid agent update mem after conductor update mem when unlock action
        if ihost['administrative'] == constants.ADMIN_LOCKED and \
            ihost['ihost_action'] in [constants.UNLOCK_ACTION,
                constants.FORCE_UNLOCK_ACTION]:
            LOG.debug("Ignore the host memory audit during the host is unlocking")
            return

        forihostid = ihost['id']
        ihost_inodes = self.dbapi.inode_get_by_ihost(ihost_uuid)

        for i in imemory_dict_array:
            forinodeid = None
            inode_uuid = None
            for n in ihost_inodes:
                numa_node = int(n.numa_node)
                if numa_node == int(i['numa_node']):
                    forinodeid = n['id']
                    inode_uuid = n['uuid']
                    inode_uuid.strip()
                    break
            else:
                # not found in host_nodes, do not add memory element
                continue

            mem_dict = {'forihostid': forihostid,
                        'forinodeid': forinodeid}

            mem_dict.update(i)

            # Do not allow updates to the amounts of reserved memory.
            mem_dict.pop('platform_reserved_mib', None)

            # numa_node is not stored against imemory table
            mem_dict.pop('numa_node', None)

            try:
                imems = self.dbapi.imemory_get_by_ihost_inode(ihost_uuid,
                                                              inode_uuid)
                if not imems:
                    # Set the amount of memory reserved for platform use.
                    mem_dict.update(self._get_platform_reserved_memory(
                            ihost, i['numa_node']))
                    self.dbapi.imemory_create(forihostid, mem_dict)
                else:
                    for imem in imems:
                        # Include 4K pages in the displayed VM memtotal
                        if imem.vm_hugepages_nr_4K is not None:
                            vm_4K_mib = \
                                (imem.vm_hugepages_nr_4K //
                                 constants.NUM_4K_PER_MiB)
                            mem_dict['memtotal_mib'] += vm_4K_mib
                            mem_dict['memavail_mib'] += vm_4K_mib

                        if imem.vswitch_hugepages_reqd is not None \
                                and imem.vswitch_hugepages_reqd == mem_dict.get('vswitch_hugepages_nr'):
                            # vswitch_hugepages_reqd matches the current config, so clear it
                            mem_dict['vswitch_hugepages_reqd'] = None
                        if imem.vm_hugepages_nr_2M_pending is not None \
                                and imem.vm_hugepages_nr_2M_pending == mem_dict.get('vm_hugepages_nr_2M'):
                            # vm_hugepages_nr_2M_pending matches the current config, so clear it
                            mem_dict['vm_hugepages_nr_2M_pending'] = None
                        if imem.vm_hugepages_nr_1G_pending is not None \
                                and imem.vm_hugepages_nr_1G_pending == mem_dict.get('vm_hugepages_nr_1G'):
                            # vm_hugepages_nr_1G_pending matches the current config, so clear it
                            mem_dict['vm_hugepages_nr_1G_pending'] = None

                        self.dbapi.imemory_update(imem['uuid'],
                                                         mem_dict)
            except Exception:
                # Set the amount of memory reserved for platform use.
                mem_dict.update(self._get_platform_reserved_memory(
                        ihost, i['numa_node']))
                self.dbapi.imemory_create(forihostid, mem_dict)
                pass

        return

    def _get_disk_available_mib(self, disk, agent_disk_dict):
        partitions = self.dbapi.partition_get_by_idisk(disk['uuid'])

        if not partitions:
            LOG.debug("Disk %s has no partitions" % disk.uuid)
            return agent_disk_dict['available_mib']

        available_mib = agent_disk_dict['available_mib']
        for part in partitions:
            if (part.status in
                    [constants.PARTITION_CREATE_IN_SVC_STATUS,
                     constants.PARTITION_CREATE_ON_UNLOCK_STATUS]):
                available_mib = available_mib - part.size_mib

        LOG.debug("Disk available mib host - %s disk - %s av - %s" %
                  (disk.forihostid, disk.device_node, available_mib))
        return available_mib

    def disk_format_gpt(self, context, agent_idisk, host_id):
        rpcapi = agent_rpcapi.AgentAPI()
        try:
            ihost = self.dbapi.ihost_get(host_id)
            LOG.info("Sending sysinv-agent request to GPT format disk %s of "
                     "host %s." %
                     (agent_idisk.get('device_path'), host_id))
            # If the replaced disk is the cinder disk, we also need to remove
            # PLATFORM_CONF_PATH/.node_cinder_lvm_config_complete to enable
            # cinder provisioning on the new disk.
            is_cinder_device = False
            cinder_device, cinder_size = cutils._get_cinder_device_info(
                self.dbapi, ihost.get('id'))

            if cinder_device:
                if agent_idisk.get('device_path') in cinder_device:
                    is_cinder_device = True

            # On SX we have to wait for disk wipe confirmation
            # before updating DB otherwise user may unlock host without wipe
            # and operation won't be retried.
            # If DB was not updated, operation will be retried on reboot
            # ensuring that the disk was indeed wiped.
            system_mode = utils.get_system_mode(self.dbapi)
            if system_mode == constants.SYSTEM_MODE_SIMPLEX:
                try:
                    os.mknod(constants.DISK_WIPE_IN_PROGRESS_FLAG)
                except OSError:
                    pass

            rpcapi.disk_prepare(context, ihost.uuid, agent_idisk,
                                False, is_cinder_device)

            if system_mode == constants.SYSTEM_MODE_SIMPLEX:
                timeout = 0
                while os.path.isfile(constants.DISK_WIPE_IN_PROGRESS_FLAG):
                    if timeout > constants.DISK_WIPE_COMPLETE_TIMEOUT:
                        # Wipe takes a few seconds. Problem is that if
                        # sysinv-agent is stuck in a long running operation,
                        # such as applying manifests, then the wipe itself
                        # will be delayed and even skipped if user unlocks
                        # the host.
                        msg = ("Wiping device: %s on %s takes too long. "
                               "Aborting! Operation will retry on next "
                               "agent inventory reporting." % (agent_idisk, ihost.uuid))
                        raise exception.SysinvException(msg)
                    time.sleep(1)
                    timeout += 1

        except exception.ServerNotFound:
            LOG.exception("Invalid ihost_id %s" % host_id)
            return

    def host_version_match(self, host_uuid):
        """
        Returns if the host software version matches the software version of
        this node (the active controller)
        :param host_uuid: the uuid of the host
        :return:
        """
        try:
            self.dbapi.software_upgrade_get_one()
        except exception.NotFound:
            # Not upgrading. We assume the host versions match
            # If they somehow don't match we've got bigger problems
            return True

        host_obj = self.dbapi.ihost_get(host_uuid)
        host_version = host_obj.software_load

        return host_version == tsc.SW_VERSION

    def idisk_update_by_ihost(self, context,
                              ihost_uuid, idisk_dict_array):
        """Create or update idisk for an ihost with the supplied data.

        This method allows records for disk for ihost to be created,
        or updated.

        :param context: an admin context
        :param ihost_uuid: ihost uuid unique id
        :param idisk_dict_array: initial values for disk objects
        :returns: pass or fail
        """

        def is_same_disk(i, idisk):
            # Upgrades R3->R4: An update from an N-1 agent will be missing the
            # persistent naming fields.
            if 'device_path' in i:
                if i.get('device_path') is not None:
                    if idisk.device_path == i.get('device_path'):
                        # Update from R4 node: Use R4 disk identification logic
                        return True
                    elif not idisk.device_path:
                        # TODO: remove R5. still need to compare device_node
                        # because not inventoried for R3 node controller-0
                        if idisk.device_node == i.get('device_node'):
                            LOG.info("host_uuid=%s idisk.device_path not"
                                     "set, match on device_node %s" %
                                     (ihost_uuid, idisk.device_node))
                            return True
                else:
                    return False
            elif idisk.device_node == i.get('device_node'):
                # Update from R3 node: Fall back to R3 disk identification
                # logic.
                return True
            return False

        ihost_uuid.strip()
        try:
            ihost = self.dbapi.ihost_get(ihost_uuid)
        except exception.ServerNotFound:
            LOG.exception("Invalid ihost_uuid %s" % ihost_uuid)
            return

        forihostid = ihost['id']

        lvm_config = StorageBackendConfig.get_configured_backend_conf(
            self.dbapi,
            constants.CINDER_BACKEND_LVM
        )

        # Ensure that we properly identify the cinder device on a
        # combo node so that we can prevent it from being used as
        # a physical volume in the nova-local volume group
        cinder_device = None
        if (cutils.host_has_function(ihost, constants.CONTROLLER) and
                cutils.host_has_function(ihost, constants.WORKER)):

            if lvm_config:
                cinder_device = cutils._get_cinder_device(self.dbapi,
                                                          ihost.get('id'))

        idisks = self.dbapi.idisk_get_by_ihost(ihost_uuid)

        for i in idisk_dict_array:
            disk_dict = {'forihostid': forihostid}
            # this could overwrite capabilities - do not overwrite device_function?
            # if not in dictionary and device_function already in capabilities

            disk_dict.update(i)

            if not idisks:
                disk = self.dbapi.idisk_create(forihostid, disk_dict)
            else:
                found = False
                for idisk in idisks:
                    LOG.debug("[DiskEnum] for - current idisk: %s - %s -%s" %
                             (idisk.uuid, idisk.device_node, idisk.device_id))

                    if is_same_disk(i, idisk):
                        found = True
                        # The disk has been replaced?
                        if idisk.serial_id != i.get('serial_id'):
                            LOG.info("Disk uuid: %s changed serial_id from %s "
                                     "to %s", idisk.uuid, idisk.serial_id,
                                     i.get('serial_id'))
                            # If the clone label is in the serial id, this is
                            # install-from-clone scenario. Skip gpt formatting.
                            if ((constants.CLONE_ISO_DISK_SID +
                                 ihost['hostname'] +
                                 i.get('device_node')) == idisk.serial_id):
                                LOG.info("Install from clone. Update disk serial"
                                         " id for disk %s. Skip gpt formatting."
                                         % idisk.uuid)
                            elif (ihost.rootfs_device == idisk.device_path or
                                    ihost.rootfs_device in idisk.device_node):
                                LOG.info("Disk uuid: %s is a root disk, "
                                         "skipping gpt formatting."
                                         % idisk.uuid)
                            else:
                                self.disk_format_gpt(context, i, forihostid)
                            # Update the associated physical volume.
                            if idisk.foripvid:
                                self._ipv_replace_disk(idisk.foripvid)
                        # The disk has been re-enumerated?
                        # Re-enumeration can occur if:
                        # 1) a new disk has been added to the host and the new
                        #    disk is attached to a port that the kernel
                        #    enumerates earlier than existing disks
                        # 2) a new disk has been added to the host and the new
                        #    disk is attached to a new disk controller that the
                        #    kernel enumerates earlier than the existing disk
                        #    controller
                        if idisk.device_node != i.get('device_node'):
                            LOG.info("Disk uuid: %s has been re-enumerated "
                                     "from %s to %s.", idisk.uuid,
                                     idisk.device_node, i.get('device_node'))
                            disk_dict.update({
                                'device_node': i.get('device_node')})

                        LOG.debug("[DiskEnum] found disk: %s - %s - %s - %s -"
                                  "%s" % (idisk.uuid, idisk.device_node,
                                   idisk.device_id, idisk.capabilities,
                                   disk_dict['capabilities']))

                        # disk = self.dbapi.idisk_update(idisk['uuid'],
                        #                                disk_dict)
                        disk_dict_capabilities = disk_dict.get('capabilities')
                        if (disk_dict_capabilities and
                                ('device_function' not in
                                    disk_dict_capabilities)):
                            dev_function = idisk.capabilities.get(
                                'device_function')
                            if dev_function:
                                disk_dict['capabilities'].update(
                                    {'device_function': dev_function})
                                LOG.debug("update disk_dict=%s" %
                                          str(disk_dict))

                        available_mib = self._get_disk_available_mib(
                            idisk, disk_dict)
                        disk_dict.update({'available_mib': available_mib})

                        LOG.debug("[DiskEnum] updating disk uuid %s with"
                                  "values: %s" %
                                  (idisk['uuid'], str(disk_dict)))
                        disk = self.dbapi.idisk_update(idisk['uuid'],
                                                       disk_dict)
                    elif not idisk.device_path:
                        if idisk.device_node == i.get('device_node'):
                            found = True
                            disk = self.dbapi.idisk_update(idisk['uuid'],
                                                           disk_dict)
                            self.dbapi.journal_update_path(disk)

                if not found:
                    disk = self.dbapi.idisk_create(forihostid, disk_dict)

                # Update the capabilities if the device is a cinder
                # disk
                if ((cinder_device is not None) and
                        (disk.device_path == cinder_device)):

                    idisk_capabilities = disk.capabilities
                    if 'device_function' not in idisk_capabilities:
                        # Only update if it's not already present
                        idisk_dict = {'device_function': 'cinder_device'}
                        idisk_capabilities.update(idisk_dict)

                        idisk_val = {'capabilities': idisk_capabilities}
                        self.dbapi.idisk_update(idisk.uuid, idisk_val)

        # Check if this is the controller or storage-0, if so, autocreate.
        # Monitor stor entry if ceph is configured.
        if ((ihost.personality == constants.STORAGE and
                ihost.hostname == constants.STORAGE_0_HOSTNAME) or
                (ihost.personality == constants.CONTROLLER)):
            if StorageBackendConfig.has_backend_configured(
                self.dbapi,
                constants.CINDER_BACKEND_CEPH
            ):
                ihost.capabilities.update({
                    constants.IHOST_STOR_FUNCTION:
                        constants.STOR_FUNCTION_MONITOR})
                self.dbapi.ihost_update(ihost_uuid,
                    {'capabilities': ihost.capabilities})

        # Check whether a disk has been removed.
        if idisks and len(idisk_dict_array) > 0:
            if len(idisks) > len(idisk_dict_array):
                # Compare tuples of device_path.
                for pre_disk in idisks:
                    found = False
                    for cur_disk in idisk_dict_array:
                        cur_device_path = cur_disk.get('device_path') or ""
                        if pre_disk.device_path == cur_device_path:
                            found = True
                            break

                    if not found:
                        # remove if not associated with storage
                        if not pre_disk.foristorid:
                            LOG.warn("Disk removed: %s dev_node=%s "
                                     "dev_path=%s serial_id=%s." %
                                     (pre_disk.uuid,
                                      pre_disk.device_node,
                                      pre_disk.device_path,
                                      pre_disk.serial_id))
                            self.dbapi.idisk_destroy(pre_disk.uuid)
                        else:
                            LOG.warn("Disk missing: %s dev_node=%s "
                                     "dev_path=%s serial_id=%s" %
                                     (pre_disk.uuid,
                                      pre_disk.device_node,
                                      pre_disk.device_path,
                                      pre_disk.serial_id))

        return

    def ilvg_update_by_ihost(self, context,
                             ihost_uuid, ilvg_dict_array):
        """Create or update ilvg for an ihost with the supplied data.

        This method allows records for local volume groups for ihost to be
        created, or updated.

        :param context: an admin context
        :param ihost_uuid: ihost uuid unique id
        :param ilvg_dict_array: initial values for local volume group objects
        :returns: pass or fail
        """

        ihost_uuid.strip()
        try:
            ihost = self.dbapi.ihost_get(ihost_uuid)
        except exception.ServerNotFound:
            LOG.exception("Invalid ihost_uuid %s" % ihost_uuid)
            return

        try:
            self.dbapi.software_upgrade_get_one()
        except exception.NotFound:
            # No upgrade in progress
            pass
        else:
            if ihost.software_load != tsc.SW_VERSION:
                LOG.info("Ignore updating lvg for host: %s. Version "
                         "%s mismatch." % (ihost.hostname, ihost.software_load))
                return
            elif (ihost.invprovision == constants.UPGRADING and
                    ihost.personality != constants.STORAGE):
                # storage nodes allocate all root disk for platform. Let the
                # inventory report to tell what the disk is used after upgrade
                LOG.info("Ignore updating lvg for host: %s. Upgrading" %
                         ihost.hostname)
                return

        forihostid = ihost['id']

        ilvgs = self.dbapi.ilvg_get_by_ihost(ihost_uuid)

        # Process the response from the agent
        for i in ilvg_dict_array:

            lvg_dict = {
                'forihostid': forihostid,
            }

            lvg_dict.update(i)

            found = False
            for ilvg in ilvgs:
                if ilvg.lvm_vg_name == i['lvm_vg_name']:
                    found = True
                    if ilvg.lvm_vg_uuid != i['lvm_vg_uuid']:
                        # The volume group has been replaced.
                        LOG.info("LVG uuid: %s changed UUID from %s to %s",
                                 ilvg.uuid, ilvg.lvm_vg_uuid,
                                 i['lvm_vg_uuid'])
                        # May need to take some action => None for now

                    if ilvg.vg_state == constants.LVG_ADD:
                        lvg_dict.update({'vg_state': constants.PROVISIONED})

                    # Update the database
                    self.dbapi.ilvg_update(ilvg['uuid'], lvg_dict)
                    break

            if not found:
                lvg_dict.update({'vg_state': constants.PROVISIONED})
                try:
                    self.dbapi.ilvg_create(forihostid, lvg_dict)
                except Exception:
                    LOG.exception("Local Volume Group Creation failed")

        # Purge the database records for volume groups that have been
        # removed
        for ilvg in ilvgs:
            if ilvg.lvm_vg_name.startswith("ceph-"):
                found = False
                for i in ilvg_dict_array:
                    if ilvg.lvm_vg_name == i['lvm_vg_name']:
                        found = True

                if not found:
                    try:
                        LOG.info("remove out-of-date rook provisioned lv %s" % ilvg.lvm_vg_name)
                        ipvs = self.dbapi.ipv_get_by_ihost(ihost_uuid)
                        for ipv in ipvs:
                            if ipv.lvm_vg_name == ilvg.lvm_vg_name:
                                LOG.info("remove out-of-date rook provisioned pv %s" % ipv.lvm_vg_name)
                                self._ipv_handle_phys_storage_removal(ipv, ilvg.lvm_vg_name)

                        self.dbapi.ilvg_destroy(ilvg.id)
                    except Exception:
                        LOG.exception("Local Volume Group removal failed")

            if ilvg.vg_state == constants.LVG_DEL:
                # Make sure that the agent hasn't reported that it is
                # still present on the host
                found = False
                for i in ilvg_dict_array:
                    if ilvg.lvm_vg_name == i['lvm_vg_name']:
                        found = True

                if not found:
                    try:
                        self.dbapi.ilvg_destroy(ilvg.id)
                    except Exception:
                        LOG.exception("Local Volume Group removal failed")

        return

    def create_host_filesystems(self, context,
                                ihost_uuid, fs_dict_array):
        """Create a filesystems for an ihost with the supplied data.

        This method allows records for filesystems for ihost to be
        created.

        :param context: an admin context
        :param ihost_uuid: ihost uuid unique id
        :param fs_dict_array: initial values for filesystems group objects
        :returns: pass or fail
        """

        ihost_uuid.strip()
        try:
            ihost = self.dbapi.ihost_get(ihost_uuid)
        except exception.ServerNotFound:
            LOG.exception("Invalid ihost_uuid %s" % ihost_uuid)
            return

        host_fs_list = self.dbapi.host_fs_get_by_ihost(ihost_uuid)
        forihostid = ihost['id']

        for fs in fs_dict_array:
            fs_dict = {
                'forihostid': forihostid,
            }
            fs_dict.update(fs)
            found = False

            for host_fs in host_fs_list:
                if host_fs.name == fs['name']:
                    found = True
                    LOG.info("Host FS '%s' already exists" % fs['name'])
                    break
            if not found:
                try:

                    LOG.info("Creating Host FS:%s:%s %d for host id %d" %
                             (fs_dict['name'], fs_dict['logical_volume'],
                              fs_dict['size'], fs_dict['forihostid']))
                    self.dbapi.host_fs_create(forihostid, fs_dict)
                except Exception:
                    LOG.exception("Host FS Creation failed")

        return

    def _fill_partition_info(self, db_part, ipart):
        db_part_dict = db_part.as_dict()
        keys = ['start_mib', 'end_mib', 'size_mib', 'type_name', 'type_guid']
        values = {}
        for key in keys:
            if (key in db_part_dict and key in ipart and
                    not db_part_dict.get(key, None)):
                values.update({key: ipart.get(key)})

        # If the report from the manage-partitions script is lost
        # (although the partition was created successfully)
        # the partition goes into an error state.
        # In such a case, the agent should report the correct info,
        # so we should allow the transition from and error state
        # to a ready state.
        states = [constants.PARTITION_CREATE_IN_SVC_STATUS,
                  constants.PARTITION_CREATE_ON_UNLOCK_STATUS,
                  constants.PARTITION_ERROR_STATUS]

        if db_part.status in states and not db_part.foripvid:
            LOG.debug("Update the state to ready for partition %s" %
                      db_part.uuid)
            values.update({'status': constants.PARTITION_READY_STATUS})

        try:
            self.dbapi.partition_update(db_part.uuid, values)
        except Exception:
            LOG.exception("Updating partition (%s) with values %s failed." %
                          (db_part.uuid, str(values)))

    def _build_device_node_path(self, idisk_uuid):
        """Builds the partition device path and device node based on last
           partition number and assigned disk.
        """
        idisk = self.dbapi.idisk_get(idisk_uuid)
        partitions = self.dbapi.partition_get_by_idisk(
            idisk_uuid, sort_key='device_path')
        if partitions:
            device_node = "%s%s" % (idisk.device_node, len(partitions) + 1)
            device_path = cutils.get_part_device_path(idisk.device_path,
                                                     str(len(partitions) + 1))
        else:
            device_node = idisk.device_node + '1'
            device_path = cutils.get_part_device_path(idisk.device_path, "1")

        return device_node, device_path

    def _check_cgts_vg_extend(self, host, disk, pv4_name):
        """If the current R5 main cgts-vg partition is too small for the R4
           cgts-vg, create an extra partition & PV for cgts-vg.
           TODO: This function is only useful for supporting R4 -> R5 upgrades.
                 Remove in future release.
        """
        pvs = self.dbapi.ipv_get_by_ihost(host.id)
        pv_cgts_vg = next((pv for pv in pvs if pv.lvm_pv_name == pv4_name), None)
        if not pv_cgts_vg:
            raise exception.SysinvException(_("ERROR: No %s PV for Volume Group %s on host %s") %
                (pv4_name, constants.LVG_CGTS_VG, host.hostname))

        partitions = self.dbapi.partition_get_by_ihost(host.id)
        partition4 = next((p for p in partitions if p.device_node == pv4_name), None)
        part_size_mib = float(pv_cgts_vg.lvm_pv_size) / (1024 ** 2) - int(partition4.size_mib)  # pylint: disable=W1619
        if part_size_mib > 0:
            LOG.info("%s is not enough for R4 cgts-vg" % pv4_name)
        else:
            LOG.info("%s is enough for R4 cgts-vg, returning" % pv4_name)
            return

        part_device_node, part_device_path = self._build_device_node_path(disk.uuid)
        LOG.info("Extra cgts partition size: %s device node: %s "
                 "device path: %s" %
                 (part_size_mib, part_device_node, part_device_path))

        partition_dict = {
            'idisk_id': disk.id,
            'idisk_uuid': disk.uuid,
            'size_mib': part_size_mib,
            'device_node': part_device_node,
            'device_path': part_device_path,
            'status': constants.PARTITION_CREATE_ON_UNLOCK_STATUS,
            'type_guid': constants.USER_PARTITION_PHYSICAL_VOLUME,
            'forihostid': host.id
        }
        new_partition = self.dbapi.partition_create(host.id, partition_dict)

        pv_dict = {
            'pv_state': constants.PV_ADD,
            'pv_type': constants.PV_TYPE_PARTITION,
            'disk_or_part_uuid': new_partition.uuid,
            'disk_or_part_device_node': new_partition.device_node,
            'disk_or_part_device_path': new_partition.device_path,
            'lvm_pv_name': new_partition.device_node,
            'lvm_vg_name': constants.LVG_CGTS_VG,
            'forihostid': host.id,
            'forilvgid': pv_cgts_vg.forilvgid
        }
        new_pv = self.dbapi.ipv_create(host.id, pv_dict)

        new_partition = self.dbapi.partition_update(new_partition.uuid, {'foripvid': new_pv.id})

    def _check_pv_partition(self, pv):
        """Ensure a proper physical volume transition from R4.
           TODO: This function is only useful for supporting R4 -> R5 upgrades.
                 Remove in future release.
        """
        R4_part_number = "5"
        pv_name = pv['lvm_pv_name']
        partitions = self.dbapi.partition_get_by_ihost(pv['forihostid'])

        if not partitions:
            LOG.info("No partitions present for host %s yet, try later" % pv['forihostid'])
            return

        disk_uuid = pv['disk_or_part_uuid']
        disk = self.dbapi.idisk_get(disk_uuid)

        # Treat AIO controller differently.
        # The 5th partition becomes the 4th partition.
        host = self.dbapi.ihost_get(pv['forihostid'])

        rootfs_partition = False
        for p in partitions:
            if (host.rootfs_device in p.device_node or
                    host.rootfs_device in p.device_path):
                rootfs_partition = True
                break

        if not rootfs_partition:
            LOG.info("Host %s has no rootfs partitions, return" % host.hostname)
            return

        if (host.personality == constants.CONTROLLER and
            (host.rootfs_device in pv['disk_or_part_device_node'] or
             host.rootfs_device in pv['disk_or_part_device_path'])):
            if R4_part_number in pv_name:
                pv4_name = "%s4" % disk.device_node
                self.dbapi.ipv_update(pv['uuid'], {'lvm_pv_name': pv4_name})
                pv_name = pv4_name

                # Check if we need to extend cgts-vg to match its R4 size.
                self._check_cgts_vg_extend(host, disk, pv4_name)

        partition = next((p for p in partitions if p.device_node == pv_name), None)

        # If the PV partition exists, only update the PV info.
        if partition:
            if partition.device_node == pv_name:
                values = {
                    'disk_or_part_uuid': partition.uuid,
                    'disk_or_part_device_node': partition.device_node,
                    'disk_or_part_device_path': partition.device_path
                }
                self.dbapi.ipv_update(pv['uuid'], values)
                self.dbapi.partition_update(partition.uuid, {'foripvid': pv['id']})
                self.dbapi.idisk_update(disk_uuid, {'foripvid': None})
                return

        # If the PV partition does not exist, we need to create the DB entry for it
        # and then update the PV.

        # If the required size for the PV is larger then the available space,
        # log a warning, but use the available space for the PV partition.
        if disk.available_mib < pv['lvm_pv_size'] // (1024 ** 2):
            LOG.warning("ERROR not enough space to create the needed partition: %s < %s" %
                        (disk.available_mib, pv['lvm_pv_size']))

        part_device_node, part_device_path = self._build_device_node_path(disk_uuid)
        part_size_mib = disk.available_mib

        for part in partitions:
            if (part.status in
                    [constants.PARTITION_CREATE_IN_SVC_STATUS,
                     constants.PARTITION_CREATE_ON_UNLOCK_STATUS] and
                    part.idisk_uuid == disk.uuid):
                part_size_mib = part_size_mib - part.size_mib

        partition_dict = {
            'idisk_id': disk.id,
            'idisk_uuid': disk.uuid,
            'size_mib': part_size_mib,
            'device_node': part_device_node,
            'device_path': part_device_path,
            'foripvid': pv['id'],
            'status': constants.PARTITION_CREATE_ON_UNLOCK_STATUS,
            'type_guid': constants.USER_PARTITION_PHYSICAL_VOLUME
        }
        new_partition = self.dbapi.partition_create(pv['forihostid'], partition_dict)

        pv_update_dict = {
            'disk_or_part_uuid': new_partition.uuid,
            'disk_or_part_device_node': part_device_node,
            'disk_or_part_device_path': part_device_path,
            'lvm_pv_name': part_device_node
        }
        self.dbapi.idisk_update(disk_uuid, {'foripvid': None})
        self.dbapi.ipv_update(pv['uuid'], pv_update_dict)

    def _prepare_for_ipv_removal(self, ipv):
        if ipv['pv_type'] == constants.PV_TYPE_DISK:
            if ipv.get('disk_or_part_uuid'):
                try:
                    self.dbapi.idisk_update(ipv['disk_or_part_uuid'],
                                            {'foripvid': None})
                except exception.DiskNotFound:
                    pass
        elif ipv['pv_type'] == constants.PV_TYPE_PARTITION:
            if not ipv.get('disk_or_part_uuid'):
                return

            try:
                ihost = self.dbapi.ihost_get(ipv.get('forihostid'))
                values = {'foripvid': None}
                if ihost['invprovision'] in [constants.PROVISIONED, constants.UPGRADING]:
                    values.update(
                        {'status': constants.PARTITION_READY_STATUS})
                self.dbapi.partition_update(ipv['disk_or_part_uuid'], values)
            except exception.DiskPartitionNotFound:
                pass

    # TODO(rchurch): Update this for cinder disk removal
    def _ipv_handle_phys_storage_removal(self, ipv, storage):
        """ Remove a PV from a missing disk or partition"""
        if ipv['lvm_pv_name'] == constants.CINDER_DRBD_DEVICE:
            # Special Case: combo node /dev/drbd4 for cinder will
            # not show up in the disk list so allow it to remain.
            return

        # For any other system type & VG the removal is done automatically
        # as users don't have the option (yet).
        try:
            self._prepare_for_ipv_removal(ipv)
            self.dbapi.ipv_destroy(ipv.id)
        except Exception:
            LOG.exception("Remove ipv for missing %s failed" % storage)

    def update_partition_config(self, context, partition):
        """Configure the partition with the supplied data.

        :param context: an admin context.
        :param partition: data about the partition
        """
        LOG.debug("PART conductor-manager partition: %s" % str(partition))
        # Get host.
        host_uuid = partition.get('ihost_uuid')
        try:
            db_host = self.dbapi.ihost_get(host_uuid)
        except exception.ServerNotFound:
            LOG.exception("Invalid host_uuid %s" % host_uuid)
            return

        personalities = [db_host.personality]
        config_uuid = self._config_update_hosts(context,
                                                personalities,
                                                host_uuids=[host_uuid],
                                                reboot=False)
        config_dict = {
            "host_uuids": [host_uuid],
            'personalities': personalities,
            "classes": ['platform::partitions::runtime'],
            "idisk_uuid": partition.get('idisk_uuid'),
            "partition_uuid": partition.get('uuid'),
            puppet_common.REPORT_STATUS_CFG: puppet_common.REPORT_DISK_PARTITON_CONFIG
        }

        # Currently sysinv agent does not create the needed partition during nova-local
        # configuration without the existence of the initial_config_complete flag.
        # During Ansible bootstrap, force manifest apply as the generation of this
        # file is deferred until host unlock where full controller manifest is applied.
        force_apply = False if cutils.is_initial_config_complete() else True
        self._config_apply_runtime_manifest(context,
                                            config_uuid,
                                            config_dict,
                                            force=force_apply)

    def ipartition_update_by_ihost(self, context,
                                   ihost_uuid, ipart_dict_array):
        """Update existing partition information based on information received
           from the agent."""
        LOG.debug("PART ipartition_update_by_ihost %s ihost_uuid "
                 "ipart_dict_array: %s" % (ihost_uuid, str(ipart_dict_array)))

        # Get host.
        ihost_uuid.strip()
        try:
            db_host = self.dbapi.ihost_get(ihost_uuid)
        except exception.ServerNotFound:
            LOG.exception("Invalid ihost_uuid %s" % ihost_uuid)
            return

        try:
            self.dbapi.software_upgrade_get_one()
        except exception.NotFound:
            # No upgrade in progress
            pass
        else:
            if db_host.software_load != tsc.SW_VERSION:
                LOG.info("Ignore updating disk partition for host: %s. Version "
                         "%s mismatch." % (db_host.hostname, db_host.software_load))
                return
            elif (db_host.invprovision == constants.UPGRADING and
                    db_host.personality != constants.STORAGE):
                # storage nodes allocate all root disk for platform. Let the
                # inventory report to tell what the disk is used after upgrade
                LOG.info("Ignore updating disk partition for host: %s. Upgrading" %
                         db_host.hostname)
                return

        # Get the id of the host.
        forihostid = db_host['id']

        # Obtain the partitions, disks and physical volumes that are currently
        # present in the DB.
        db_parts = self.dbapi.partition_get_by_ihost(ihost_uuid)
        db_disks = self.dbapi.idisk_get_by_ihost(ihost_uuid)

        # Check that the DB partitions are in sync with the DB disks and PVs.
        for db_part in db_parts:
            if not db_part.device_path:
                # Should not happen unless pyudev gives us wrong data
                # or we have a programming error.
                LOG.error("PART ipartition_update_by_ihost: "
                          "Disk partition %s is missing its "
                          "device path, ignoring!" % db_part.uuid)
                continue

            # Obtain the disk the partition is on.
            part_disk = None
            for d in db_disks:
                if d.device_path in db_part.device_path:
                    part_disk = d
                    break
                elif constants.DEVICE_NAME_MPATH in d.device_node:
                    path_split = d.device_path.split(constants.DEVICE_NAME_MPATH)
                    if (path_split[0] in db_part.device_path and
                            path_split[1] in db_part.device_path):
                        is_part_of_disk = True
                        part_disk = d
                        break

            if not part_disk:
                # Should not happen as we only store partitions associated
                # with a disk.
                LOG.error("PART ipartition_update_by_ihost: "
                          "Disk for partition %s is not "
                          "present in database, ignoring!" % db_part.uuid)
                continue

            partition_dict = {'forihostid': forihostid}
            partition_update_needed = False

            if part_disk.uuid != db_part['idisk_uuid']:
                # TO DO: What happens when a disk is replaced
                partition_update_needed = True
                partition_dict.update({'idisk_uuid': part_disk.uuid})
                LOG.info("Disk for partition %s has changed." %
                         db_part['uuid'])

            if partition_update_needed:
                self.dbapi.partition_update(db_part['uuid'],
                                            partition_dict)
                LOG.debug("PART conductor - partition needs to be "
                          "updated.")

        # Go through the partitions reported by the agent and make needed
        # modifications.
        for ipart in ipart_dict_array:
            # Not to add ceph osd related partitions
            if (ipart['type_guid'] in constants.CEPH_PARTITIONS):
                continue

            part_dict = {
                'forihostid': forihostid,
                'status': constants.PARTITION_IN_USE_STATUS,  # Be conservative here
            }

            part_dict.update(ipart)

            found = False

            # If the paths match, then the partition already exists in the DB.
            for db_part in db_parts:
                if ipart['device_path'] == db_part.device_path:
                    found = True

                    # On CentOS to Debian upgrade partitions may differ
                    # ipart 'start_mib' and 'end_mib' values are strings
                    # whereas db_part are integers.
                    if (str(ipart['start_mib']) != str(db_part['start_mib']) or
                            str(ipart['end_mib']) != str(db_part['end_mib']) or
                            ipart['type_guid'] != db_part['type_guid']):
                        LOG.info("PART update part start/end/size/type/name")
                        self.dbapi.partition_update(
                            db_part.uuid,
                            {'start_mib': ipart['start_mib'],
                             'end_mib': ipart['end_mib'],
                             'size_mib': ipart['size_mib'],
                             'type_guid': ipart['type_guid'],
                             'type_name': ipart['type_name']}
                        )

                    if ipart['device_node'] != db_part.device_node:
                        LOG.info("PART update part device node")
                        self.dbapi.partition_update(
                            db_part.uuid,
                            {'device_node': ipart['device_node']})
                    LOG.debug("PART conductor - found partition: %s" %
                              db_part.device_path)

                    self._fill_partition_info(db_part, ipart)

                    # Try to resize the underlying FS.
                    if db_part.foripvid:
                        pv = self.dbapi.ipv_get(db_part.foripvid)
                        if (pv and pv.lvm_vg_name == constants.LVG_CINDER_VOLUMES):
                            try:
                                self._resize_cinder_volumes(delayed=True)
                            except retrying.RetryError:
                                LOG.info("Cinder volumes resize failed")
                    break

            # If we've found no matching path, then this is a new partition.
            if not found:
                LOG.debug("PART conductor - partition not found, adding...")
                # Complete disk info.
                for db_disk in db_disks:
                    is_part_of_disk = False
                    if db_disk.device_path in ipart['device_path']:
                        is_part_of_disk = True
                    elif constants.DEVICE_NAME_MPATH in db_disk.device_node:
                        path_split = db_disk.device_path.split(constants.DEVICE_NAME_MPATH)
                        if path_split[0] in ipart['device_path'] and path_split[1] in ipart['device_path']:
                            is_part_of_disk = True
                    if is_part_of_disk:
                        part_dict.update({'idisk_id': db_disk.id,
                                          'idisk_uuid': db_disk.uuid})
                        LOG.debug("PART conductor - disk - part_dict: %s " %
                                  str(part_dict))

                        new_part = None
                        try:
                            LOG.info("Partition create on host: %s. Details: %s" % (forihostid, part_dict))
                            new_part = self.dbapi.partition_create(
                                forihostid, part_dict)
                        except Exception as e:
                            LOG.exception("Partition creation failed on host: %s. "
                                          "Details: %s" % (forihostid, str(e)))

                        # If the partition has been successfully created, update its status.
                        if new_part:
                            if new_part.type_guid != constants.USER_PARTITION_PHYSICAL_VOLUME:
                                status = {'status': constants.PARTITION_IN_USE_STATUS}
                            else:
                                status = {'status': constants.PARTITION_READY_STATUS}
                            self.dbapi.partition_update(new_part.uuid, status)
                        break
                else:
                    # This shouldn't happen as disks are reported before partitions
                    LOG.warning("Found partition not associated with any disks, "
                                "underlying disk should be created on next inventory "
                                "reporting, ignoring for now. Details: ihost_uuid: %s "
                                "ipart_dict_array: %s" % (ihost_uuid, part_dict))

        # Check to see if partitions have been removed.
        for db_part in db_parts:
            found = False
            for ipart in ipart_dict_array:
                if db_part.device_path:
                    if ipart['device_path'] == db_part.device_path:
                        found = True
                        break

            # PART - TO DO - Maybe some extra checks will be needed here,
            # depending on the status.
            if not found:
                delete_partition = True

                # If it's still used by a PV, don't remove the partition yet.
                if db_part.foripvid:
                    delete_partition = False
                # If the partition is in creating state, don't remove it.
                elif (db_part.status ==
                        constants.PARTITION_CREATE_ON_UNLOCK_STATUS or
                      db_part.status ==
                        constants.PARTITION_CREATE_IN_SVC_STATUS):
                    delete_partition = False
                elif not cutils.is_partition_the_last(self.dbapi,
                                                      db_part.as_dict()):
                    delete_partition = False
                    LOG.debug("Partition %s(%s) is missing, but it cannot "
                              "be deleted since it's not the last "
                              "partition on disk." %
                              (db_part.uuid, db_part.device_path))

                if delete_partition:
                    LOG.info("Deleting missing partition %s - %s" %
                             (db_part.uuid, db_part.device_path))
                    self.dbapi.partition_destroy(db_part.uuid)
                else:
                    LOG.warn("Partition missing: %s - %s" %
                             (db_part.uuid, db_part.device_path))

    def ipv_update_by_ihost(self, context,
                            ihost_uuid, ipv_dict_array):
        """Create or update ipv for an ihost with the supplied data.

        This method allows records for a physical volume for ihost to be
        created, or updated.

        :param context: an admin context
        :param ihost_uuid: ihost uuid unique id
        :param ipv_dict_array: initial values for a physical volume objects
        :returns: pass or fail
        """

        def is_same_disk(idisk, ipv):
            if 'disk_or_part_device_path' in ipv:
                if ipv.get('disk_or_part_device_path') is not None:
                    if idisk.device_path == ipv.get('disk_or_part_device_path'):
                        return True
                else:
                    return False
            return False

        ihost_uuid.strip()
        try:
            ihost = self.dbapi.ihost_get(ihost_uuid)
        except exception.ServerNotFound:
            LOG.exception("Invalid ihost_uuid %s" % ihost_uuid)
            return

        try:
            self.dbapi.software_upgrade_get_one()
        except exception.NotFound:
            # No upgrade in progress
            pass
        else:
            if ihost.software_load != tsc.SW_VERSION:
                LOG.info("Ignore updating physical volume for host: %s. Version "
                         "%s mismatch." % (ihost.hostname, ihost.software_load))
                return
            elif (ihost.invprovision == constants.UPGRADING and
                    ihost.personality != constants.STORAGE):
                # storage nodes allocate all root disk for platform. Let the
                # inventory report to tell what the disk is used after upgrade
                LOG.info("Ignore updating physical volume for host: %s. Upgrading" %
                        ihost.hostname)
                return

        forihostid = ihost['id']

        ipvs = self.dbapi.ipv_get_by_ihost(ihost_uuid)
        ilvgs = self.dbapi.ilvg_get_by_ihost(ihost_uuid)
        idisks = self.dbapi.idisk_get_by_ihost(ihost_uuid)
        partitions = self.dbapi.partition_get_by_ihost(ihost_uuid)
        # Cinder is now optional. A PV must be defined for it as part of
        # provisioning. When looking for disk re-enumerations, identify it so
        # when the DRBD device is reported by the agent we can reconcile the PV
        # entry.
        cinder_pv_id = None

        # Timeout for PV operations
        # In case of major failures (e.g. sysinv restart, system reset)
        # PVs may remain stuck in adding or removing. Semantic checks
        # will then prevent any other operation on the PVs

        # First remove any invalid timeout (i.e. PV was removed)
        ipv_uuids = [i['uuid'] for i in ipvs]
        for k in self._pv_op_timeouts.keys():
            if k not in ipv_uuids:
                del self._pv_op_timeouts[k]

        # Make sure that the Physical Volume to Disk info is still valid
        for ipv in ipvs:
            # Handle the case where the disk has been
            # removed/replaced/re-enumerated.
            pv_disk_is_present = False
            if ipv['pv_type'] == constants.PV_TYPE_DISK:
                for idisk in idisks:
                    if is_same_disk(idisk, ipv):
                        pv_disk_is_present = True
                        ipv_update_needed = False
                        pv_dict = {'forihostid': forihostid}

                        # Disk has been removed/replaced => UUID has changed.
                        if idisk.uuid != ipv['disk_or_part_uuid']:
                            ipv_update_needed = True
                            pv_dict.update({'disk_or_part_uuid': idisk.uuid})
                            LOG.info("Disk for ipv %s has changed." % ipv['uuid'])

                        # Disk has been re-enumerated.
                        if idisk.device_node != ipv['disk_or_part_device_node']:
                            ipv_update_needed = True
                            # If the PV name contained the device node, replace
                            # it accordingly.
                            new_lvm_pv_name = ipv['lvm_pv_name']
                            if ipv['disk_or_part_device_node'] in ipv['lvm_pv_name']:
                                new_lvm_pv_name = new_lvm_pv_name.replace(
                                    ipv['disk_or_part_device_node'],
                                    idisk.device_node)
                            # Update PV dictionary containing changes.
                            pv_dict.update({
                                'disk_or_part_device_node': idisk.device_node,
                                'lvm_pv_name': new_lvm_pv_name
                            })
                            # Update current PV object.
                            ipv.disk_or_part_device_node = idisk.device_node
                            ipv.lvm_pv_name = new_lvm_pv_name
                            LOG.info("Disk for ipv %s has been re-enumerated." %
                                     ipv['uuid'])

                        if ipv_update_needed:
                            try:
                                self.dbapi.ipv_update(ipv['uuid'], pv_dict)
                            except Exception:
                                LOG.exception("Update ipv for changed idisk "
                                              "details failed.")
                            break
                    elif not ipv['disk_or_part_device_path']:
                        # Device path is provided for the first time, update pv
                        # entry.
                        if idisk.device_node == ipv['disk_or_part_device_node']:
                            pv_disk_is_present = True
                            self._update_ipv_device_path(idisk, ipv)

                if not pv_disk_is_present:
                    self._ipv_handle_phys_storage_removal(ipv, 'idisk')

            elif ipv['pv_type'] == constants.PV_TYPE_PARTITION and ipv['disk_or_part_uuid']:
                try:
                    partition = self.dbapi.partition_get(
                        ipv['disk_or_part_uuid'])

                    # Disk on which the partition was created was re-enumerated.
                    # This assumes that the partition information is correctly updated
                    # for re-enumeration before we update the PVs
                    if (ipv['disk_or_part_device_node'] != partition['device_node']):
                        pv_dict = {'forihostid': forihostid,
                                   'disk_or_part_device_node': partition['device_node']}
                        ipv.disk_or_part_device_node = partition['device_node']

                        # the lvm_pv_name for cinder volumes is always /dev/drbd4
                        if ipv['lvm_pv_name'] != constants.CINDER_DRBD_DEVICE:
                            pv_dict.update({'lvm_pv_name': partition['device_node']})
                            ipv.lvm_pv_name = partition['device_node']

                        LOG.info("Disk information for PV %s has been changed "
                                 "due to disk re-enumeration." % ipv['uuid'])

                        try:
                            self.dbapi.ipv_update(ipv['uuid'], pv_dict)
                        except Exception:
                            LOG.exception("Update ipv for changed partition "
                                           "details failed.")

                    if (ipv['pv_state'] == constants.PROVISIONED and
                        partition.status not in
                        [constants.PARTITION_CREATE_ON_UNLOCK_STATUS,
                         constants.PARTITION_CREATE_IN_SVC_STATUS,
                         constants.PARTITION_IN_USE_STATUS]):
                        self.dbapi.partition_update(
                            partition.uuid,
                            {'status': constants.PARTITION_IN_USE_STATUS})
                except exception.DiskPartitionNotFound:
                    if ipv['lvm_vg_name'] != constants.LVG_CINDER_VOLUMES:
                        self._check_pv_partition(ipv)

                # Save the physical PV associated with cinder volumes for use later
                if ipv['lvm_vg_name'] == constants.LVG_CINDER_VOLUMES:
                    cinder_pv_id = ipv['id']

        # Some of the PVs may have been updated, so get them again.
        ipvs = self.dbapi.ipv_get_by_ihost(ihost_uuid)

        # Process the response from the agent
        regex = re.compile("^/dev/.*[a-z][1-9][0-9]?$")
        for i in ipv_dict_array:
            # Between a disk being wiped and the PV recreated, PVs are reported
            # as unknown. These values must not reach the DB.
            if constants.PV_NAME_UNKNOWN in i['lvm_pv_name']:
                LOG.info("Unknown PV on host %s: %s" %
                         (forihostid, i['lvm_pv_uuid']))
                continue

            pv_dict = {
                'forihostid': forihostid,
            }
            pv_dict.update(i)

            # get the LVG info
            for ilvg in ilvgs:
                if ilvg.lvm_vg_name == i['lvm_vg_name']:
                    pv_dict['forilvgid'] = ilvg.id
                    pv_dict['lvm_vg_name'] = ilvg.lvm_vg_name

            # Check to see if a device path for the agent provided
            # PV device node already exists in the inventory
            device_path = cutils.get_pv_device_path(self.dbapi, ihost_uuid, i)

            # Search the current pv to see if this one exists
            found = False
            for ipv in ipvs:
                if ipv.lvm_pv_name == i['lvm_pv_name'] or ipv.disk_or_part_device_path == device_path:
                    found = True
                    if ipv.lvm_pv_uuid != i['lvm_pv_uuid']:
                        # The physical volume has been replaced.
                        LOG.info("PV uuid: %s changed UUID from %s to %s, "
                                 "lvm_pv_name=%s->%s, disk_or_part_device_path=%s->%s",
                                 ipv.uuid, ipv.lvm_pv_uuid, i['lvm_pv_uuid'],
                                 ipv.lvm_pv_name, i['lvm_pv_name'],
                                 ipv.disk_or_part_device_path, device_path)
                        # May need to take some action => None for now

                    system_mode = self.dbapi.isystem_get_one().system_mode
                    if (ipv.pv_state == constants.PV_ADD and not
                        (system_mode == constants.SYSTEM_MODE_SIMPLEX and
                            pv_dict['lvm_vg_name'] == constants.LVG_CINDER_VOLUMES)):
                        pv_dict.update({'pv_state': constants.PROVISIONED})

                    # Update the database
                    try:
                        self.dbapi.ipv_update(ipv['uuid'], pv_dict)
                        if ipv['pv_type'] == constants.PV_TYPE_PARTITION:
                            self.dbapi.partition_update(
                                ipv['disk_or_part_uuid'],
                                {'status': constants.PARTITION_IN_USE_STATUS})
                    except Exception:
                        LOG.exception("Update ipv with latest info failed")

                    if ipv['pv_type'] == constants.PV_TYPE_PARTITION:
                        continue

                    # Handle the case where the disk has been removed/replaced
                    idisk = self.dbapi.idisk_get_by_ihost(ihost_uuid)
                    pv_disk_is_present = False
                    for d in idisk:
                        if ((d.device_node in ipv['lvm_pv_name']) or
                            ((i['lvm_pv_name'] ==
                                constants.CINDER_DRBD_DEVICE) and
                             ((ipv['disk_or_part_device_node'] and
                               (d.device_node in
                                ipv['disk_or_part_device_node']))))):
                            pv_disk_is_present = True
                            if d.uuid != ipv['disk_or_part_uuid']:
                                # UUID has changed
                                pv_dict.update({'disk_or_part_uuid': d.uuid})
                                try:
                                    self.dbapi.ipv_update(ipv['uuid'], pv_dict)
                                except Exception:
                                    LOG.exception("Update ipv for changed "
                                                  "idisk uuid failed")
                            break
                    if not pv_disk_is_present:
                        self._ipv_handle_phys_storage_removal(ipv, 'idisk')
                    break

            # Create the physical volume if it doesn't currently exist for rook
            if ((not found) and ('forilvgid' in pv_dict) and
                    pv_dict['lvm_vg_name'].startswith("ceph-")):

                # Lookup the uuid of the disk
                pv_dict['disk_or_part_uuid'] = None
                pv_dict['disk_or_part_device_node'] = None

                # Determine the volume type => look for a partition number.
                if "nvme" not in i["lvm_pv_name"]:
                    if regex.match(i['lvm_pv_name']):
                        pv_dict['pv_type'] = constants.PV_TYPE_PARTITION
                    else:
                        pv_dict['pv_type'] = constants.PV_TYPE_DISK
                else:
                    # for nvme disk, it named with /dev/nvme0n1
                    # for nvme partition, it name with /dev/nvme0n1p0, /dev/nvme0n1p1
                    nvme_regex = re.compile("^/dev/nvme.*p[1-9][0-9]?$")
                    if nvme_regex.match(i['lvm_pv_name']):
                        pv_dict['pv_type'] = constants.PV_TYPE_PARTITION
                    else:
                        pv_dict['pv_type'] = constants.PV_TYPE_DISK

                LOG.info("add rook provisioned node %s, type %s" % (i['lvm_pv_name'], pv_dict['pv_type']))

                # Lookup the uuid of the disk
                pv_dict['disk_or_part_uuid'] = None
                pv_dict['disk_or_part_device_node'] = None

                if pv_dict['pv_type'] == constants.PV_TYPE_DISK:
                    idisk = self.dbapi.idisk_get_by_ihost(ihost_uuid)
                    for d in idisk:
                        if d.device_node in i['lvm_pv_name']:
                            pv_dict['disk_or_part_uuid'] = d.uuid
                            pv_dict['disk_or_part_device_node'] = d.device_node
                            pv_dict['disk_or_part_device_path'] = d.device_path
                elif pv_dict['pv_type'] == constants.PV_TYPE_PARTITION:
                    ipartition = self.dbapi.partition_get_by_ihost(ihost_uuid)
                    for p in ipartition:
                        if p.device_node in i['lvm_pv_name']:
                            pv_dict['disk_or_part_uuid'] = p.uuid
                            pv_dict['disk_or_part_device_node'] = p.device_node
                            pv_dict['disk_or_part_device_path'] = p.device_path

                LOG.info("pv_dict %s" % pv_dict)
                pv_dict['pv_state'] = constants.PROVISIONED

                # Create the Physical Volume
                pv = None
                try:
                    pv = self.dbapi.ipv_create(forihostid, pv_dict)
                except Exception:
                    LOG.exception("PV Volume Creation failed")

                if pv.get('pv_type') == constants.PV_TYPE_PARTITION:
                    try:
                        self.dbapi.partition_update(
                            pv.disk_or_part_uuid,
                            {'foripvid': pv.id,
                             'status': constants.PARTITION_IN_USE_STATUS})
                    except Exception:
                        LOG.exception("Updating partition (%s) for ipv id "
                                      "failed (%s)" % (pv.disk_or_part_uuid,
                                                       pv.uuid))
                elif pv.get('pv_type') == constants.PV_TYPE_DISK:
                    try:
                        self.dbapi.idisk_update(pv.disk_or_part_uuid,
                                                {'foripvid': pv.id})
                    except Exception:
                        LOG.exception("Updating idisk (%s) for ipv id "
                                      "failed (%s)" % (pv.disk_or_part_uuid,
                                                       pv.uuid))

            # Special Case: DRBD has provisioned the cinder partition. Update the existing PV partition
            if not found and i['lvm_pv_name'] == constants.CINDER_DRBD_DEVICE:
                if cinder_pv_id:
                    cinder_pv = self.dbapi.ipv_get(cinder_pv_id)
                    if cinder_pv.pv_state == constants.PV_ADD:
                        self.dbapi.ipv_update(
                            cinder_pv.uuid,
                            {'lvm_pv_name': i['lvm_pv_name'],
                             'lvm_pe_alloced': i['lvm_pe_alloced'],
                             'lvm_pe_total': i['lvm_pe_total'],
                             'lvm_pv_uuid': i['lvm_pv_uuid'],
                             'lvm_pv_size': i['lvm_pv_size'],
                             'pv_state': constants.PROVISIONED})

                        self.dbapi.partition_update(
                            cinder_pv.disk_or_part_uuid,
                            {'status': constants.PARTITION_IN_USE_STATUS})

                        mate_hostname = cutils.get_mate_controller_hostname()
                        try:
                            standby_controller = self.dbapi.ihost_get_by_hostname(
                                mate_hostname)
                            standby_ipvs = self.dbapi.ipv_get_by_ihost(
                                standby_controller['uuid'])
                            for pv in standby_ipvs:
                                if pv.lvm_vg_name == constants.LVG_CINDER_VOLUMES:
                                    self.dbapi.ipv_update(
                                        pv.uuid,
                                        {'pv_state': constants.PROVISIONED,
                                         'lvm_pv_name': constants.CINDER_DRBD_DEVICE})
                                    self.dbapi.ilvg_update(
                                        pv.forilvgid,
                                        {'vg_state': constants.PROVISIONED})
                                    self.dbapi.partition_update(
                                        pv.disk_or_part_uuid,
                                        {'status': constants.PARTITION_IN_USE_STATUS})
                        except exception.NodeNotFound:
                            # We don't have a mate, standby, controller
                            pass
                        except Exception as e:
                            LOG.exception("Updating mate cinder PV/LVG state failed: %s", str(e))

                    found = True
                else:
                    LOG.error("Agent reports a DRBD cinder device, but no physical device found in the inventory.")
                    # Do not create an unaffiliated DRBD PV, go to the next agent reported PV
                    continue

            # Create the physical volume if it doesn't currently exist but only
            # if it's associated with an existing volume group. A physical
            # volume without a volume group should not happen, but we want to
            # avoid creating an orphaned physical volume because semantic
            # checks will prevent if from being removed.
            if ((not found) and ('forilvgid' in pv_dict) and
                    (pv_dict['lvm_vg_name'] in constants.LVG_ALLOWED_VGS)):
                # Determine the volume type => look for a partition number.
                if regex.match(i['lvm_pv_name']):
                    pv_dict['pv_type'] = constants.PV_TYPE_PARTITION
                else:
                    pv_dict['pv_type'] = constants.PV_TYPE_DISK

                # Lookup the uuid of the disk
                pv_dict['disk_or_part_uuid'] = None
                pv_dict['disk_or_part_device_node'] = None

                idisk = self.dbapi.idisk_get_by_ihost(ihost_uuid)
                for d in idisk:
                    if d.device_node in i['lvm_pv_name']:
                        if pv_dict['pv_type'] == constants.PV_TYPE_DISK:
                            pv_dict['disk_or_part_uuid'] = d.uuid
                            pv_dict['disk_or_part_device_node'] = d.device_node
                            pv_dict['disk_or_part_device_path'] = d.device_path
                        elif pv_dict['pv_type'] == constants.PV_TYPE_PARTITION:
                            partitions = self.dbapi.partition_get_by_idisk(d.uuid)
                            for p in partitions:
                                partition_number = (
                                    re.match('.*?([0-9]+)$',
                                             i['lvm_pv_name']).group(1))
                                if '-part' + partition_number in p.device_path:
                                    pv_dict['disk_or_part_uuid'] = p.uuid
                                    pv_dict['disk_or_part_device_node'] = i['lvm_pv_name']
                                    pv_dict['disk_or_part_device_path'] = p.device_path

                pv_dict['pv_state'] = constants.PROVISIONED

                # Create the Physical Volume
                pv = None
                try:
                    LOG.info(
                        "Creating a not found PV associated with a valid VG: %s" % str(pv_dict))
                    pv = self.dbapi.ipv_create(forihostid, pv_dict)
                except Exception:
                    LOG.exception("PV Volume Creation failed")

                if pv.get('pv_type') == constants.PV_TYPE_PARTITION:
                    try:
                        self.dbapi.partition_update(
                            pv.disk_or_part_uuid,
                            {'foripvid': pv.id,
                             'status': constants.PARTITION_IN_USE_STATUS})
                    except Exception:
                        LOG.exception("Updating partition (%s) for ipv id "
                                      "failed (%s)" % (pv.disk_or_part_uuid,
                                                       pv.uuid))
                elif pv.get('pv_type') == constants.PV_TYPE_DISK:
                    try:
                        self.dbapi.idisk_update(pv.disk_or_part_uuid,
                                                {'foripvid': pv.id})
                    except Exception:
                        LOG.exception("Updating idisk (%s) for ipv id "
                                      "failed (%s)" % (pv.disk_or_part_uuid,
                                                       pv.uuid))
            else:
                if not found:
                    # TODO(rchurch): Eval the restriction on requiring a valid LVG
                    # name. We may have scenarios where a PV is in transition and
                    # needs to be added so that the global filter is set correctly
                    # by a followup manifest application.
                    LOG.info("Inconsistent Data: Not adding PV: %s" % pv_dict)

        # Some of the PVs may have been updated, so get them again.
        ipvs = self.dbapi.ipv_get_by_ihost(ihost_uuid)

        # Purge the records that have been requested to be removed and
        # update the failed ones
        for ipv in ipvs:
            # Make sure that the agent hasn't reported that it is
            # still present on the host
            found = False
            for ipv_in_agent in ipv_dict_array:
                if ipv.lvm_pv_name == ipv_in_agent['lvm_pv_name']:
                    found = True
                    break

            update = {}
            if not found:
                LOG.info("PV not found in Agent. uuid: %(ipv)s current state: "
                         "%(st)s" % {'ipv': ipv['uuid'],
                                     'st': ipv['pv_state']})
                if ipv.pv_state in [constants.PV_DEL, constants.PV_ERR]:
                    try:
                        #
                        # Simplex should not be a special case anymore.
                        #
                        # system_mode = self.dbapi.isystem_get_one().system_mode
                        # if not (system_mode == constants.SYSTEM_MODE_SIMPLEX and
                        #         ipv['lvm_vg_name'] == constants.LVG_CINDER_VOLUMES):
                        #     # Make sure the disk or partition is free of this
                        #     # PV before removal.
                        self._prepare_for_ipv_removal(ipv)
                        self.dbapi.ipv_destroy(ipv.id)
                    except Exception:
                        LOG.exception("Physical Volume removal failed")
                else:
                    if ipv.pv_state == constants.PROVISIONED:
                        # Our drive may have issues (e.g. toast or wiped)
                        if 'drbd' in ipv.lvm_pv_name:
                            # TODO(rchurch): Can't destroy the standby PV (even
                            # though it disappears) or we lose the physical PV
                            # mapping in the DB. Use a different PV state for
                            # standby controller
                            continue
                        if ipv.lvm_vg_name.startswith("ceph-"):
                            # rook removed osd, destroy the standby PV
                            LOG.info("remove out-of-date rook provisioned pv %s" % ipv.lvm_pv_name)
                            self._prepare_for_ipv_removal(ipv)
                            self.dbapi.ipv_destroy(ipv.id)
            else:
                if (ipv.pv_state == constants.PV_ERR and
                        ipv.lvm_vg_name == ipv_in_agent['lvm_vg_name']):
                    # PV is back!
                    update = {'pv_state': constants.PROVISIONED}

            if update:
                try:
                    self.dbapi.ipv_update(ipv['uuid'], update)
                except Exception:
                    LOG.exception("Updating ipv id %s "
                                  "failed" % ipv['uuid'])

        return

    @retry(retry_on_result=lambda x: x is False,
           wait_fixed=(constants.INIT_CEPH_INFO_INTERVAL_SECS * 1000))
    def _init_ceph_cluster_info(self):
        if not self._ceph:
            try:
                _, fsid = self._ceph_api.fsid(body='text', timeout=10)
            except Exception as e:
                LOG.debug("Ceph REST API not responsive. Error = %s" % str(e))
                return False
            LOG.info("Ceph cluster has become responsive")
            self._ceph = iceph.CephOperator(self.dbapi)

        try:
            # We manually check for the crushmap_applied flag because we don't
            # want to re-fix the crushmap if it's already been fixed and the
            # fix_crushmap function returns False if it finds the flag.
            crushmap_flag_file = os.path.join(
                constants.SYSINV_CONFIG_PATH,
                constants.CEPH_CRUSH_MAP_APPLIED)
            if not os.path.isfile(crushmap_flag_file):
                return cceph.fix_crushmap(self.dbapi)
            return True

        except Exception as e:
            # fix_crushmap will throw an exception if the storage_model
            # is unclear. This happens on a standard (2+2) setup, before
            # adding storage-0 or adding the 3rd monitor to a compute node.
            # In such cases we just wait until the mode has become clear,
            # so we just return False and retry.
            LOG.debug("Error fixing crushmap. Exception %s" % str(e))
            return False

    def _fix_storage_install_uuid(self):
        """
        Fixes install_uuid for storage nodes during a restore procedure
        in which customer wants to recover its Ceph data by keeping
        cluster intact. During this procedure storage nodes are kept
        powered on (available) and do not get to be reinstalled yet
        controller-0 gets reinstalled.

        Since we do not know when sysinv-agents from storage nodes
        connect to rabbitmq and are ready to process requests, we
        periodically send messages to fix install_uuid.
        We stop doing it once restore procedure finishes.
        """
        admin_context = ctx.RequestContext('admin', 'admin', is_admin=True)
        while os.path.isfile(tsc.SKIP_CEPH_OSD_WIPING):
            # Update install UUID for storage nodes
            stor_nodes = self.dbapi.ihost_get_by_personality(constants.STORAGE)
            stor_nodes_uuids = [n.uuid for n in stor_nodes]
            if stor_nodes_uuids:
                self.update_install_uuid(admin_context,
                                         stor_nodes_uuids,
                                         tsc.install_uuid)
            greenthread.sleep(constants.FIX_INSTALL_UUID_INTERVAL_SECS)

    @periodic_task.periodic_task(spacing=CONF.conductor_periodic_task_intervals.agent_update_request)
    def _agent_update_request(self, context):
        """
        Check DB for inventory objects with an inconsistent state and
        request an update from sysinv agent.
        Currently requesting updates for:
        - ipv:  if state is not 'provisioned'
        - ilvg: if state is not 'provisioned'
        """
        LOG.debug("Calling _agent_update_request")
        update_hosts = {}

        # Check if the LVM backend is in flux. If so, skip the audit as we know
        # VG/PV states are going to be transitory. Otherwise, maintain the
        # audit for nova storage.
        skip_lvm_audit = False
        lvm_backend = StorageBackendConfig.get_backend(self.dbapi, constants.SB_TYPE_LVM)
        if lvm_backend and lvm_backend.state != constants.SB_STATE_CONFIGURED:
            skip_lvm_audit = True

        if not skip_lvm_audit:
            ipvs = self.dbapi.ipv_get_all()
            ilvgs = self.dbapi.ilvg_get_all()

            def update_hosts_dict(host_id, val):
                if host_id not in update_hosts:
                    update_hosts[host_id] = set()
                update_hosts[host_id].add(val)

            # Check LVGs
            for ilvg in ilvgs:
                if ilvg['vg_state'] != constants.PROVISIONED:
                    host_id = ilvg['forihostid']
                    update_hosts_dict(host_id, constants.LVG_AUDIT_REQUEST)

            # Check PVs
            for ipv in ipvs:
                if ipv['pv_state'] != constants.PROVISIONED:
                    host_id = ipv['forihostid']
                    update_hosts_dict(host_id, constants.PV_AUDIT_REQUEST)

            # Make sure we get at least one good report for PVs & LVGs
            hosts = self.dbapi.ihost_get_list()
            for host in hosts:
                if host.availability != constants.AVAILABILITY_OFFLINE:
                    idisks = self.dbapi.idisk_get_by_ihost(host.uuid)
                    if not idisks:
                        update_hosts_dict(host.id, constants.DISK_AUDIT_REQUEST)
                    ipvs = self.dbapi.ipv_get_by_ihost(host.uuid)
                    if not ipvs:
                        update_hosts_dict(host.id, constants.PARTITION_AUDIT_REQUEST)
                        update_hosts_dict(host.id, constants.PV_AUDIT_REQUEST)
                    ilvgs = self.dbapi.ilvg_get_by_ihost(host.uuid)
                    if not ilvgs:
                        update_hosts_dict(host.id, constants.LVG_AUDIT_REQUEST)
                    host_fs = self.dbapi.host_fs_get_by_ihost(host.uuid)
                    if not host_fs:
                        update_hosts_dict(host.id, constants.FILESYSTEM_AUDIT_REQUEST)

        # Check partitions.
        partitions = self.dbapi.partition_get_all()
        # Transitory partition states.
        states = [constants.PARTITION_CREATE_IN_SVC_STATUS,
                  constants.PARTITION_CREATE_ON_UNLOCK_STATUS,
                  constants.PARTITION_DELETING_STATUS,
                  constants.PARTITION_MODIFYING_STATUS]

        # Over an upgrade, if there's a need to create new partitions to be
        # included in a volume group over an upgrade, this would be staged
        # during data migration and later created via puppet on unlock. As
        # the agent inventory has already been provided, the partition
        # states will not be updated until the next agent restart.
        for part in partitions:
            if ((part.status in states) or
                    (not part.get('start_mib') or
                     not part.get('end_mib'))):
                host_id = part['forihostid']
                update_hosts_dict(host_id, constants.PARTITION_AUDIT_REQUEST)

        # Send update request if required
        if update_hosts:
            rpcapi = agent_rpcapi.AgentAPI()
            for host_id, update_set in update_hosts.items():

                ihost = self.dbapi.ihost_get(host_id)
                if (ihost.invprovision not in [constants.PROVISIONED, constants.UPGRADING] and
                        tsc.system_type != constants.TIS_AIO_BUILD):
                    continue
                if ihost:
                    LOG.info("Sending agent update request for host %s "
                             "to update (%s)" %
                             (host_id, (', '.join(update_set))))

                    # Get the cinder device to force detection even
                    # when filtered by LVM's global_filter.
                    ipvs = self.dbapi.ipv_get_by_ihost(ihost['uuid'])
                    cinder_device = None
                    for ipv in ipvs:
                        if ipv['lvm_vg_name'] == constants.LVG_CINDER_VOLUMES:
                            cinder_device = ipv.get('disk_or_part_device_path')

                    rpcapi.agent_update(context, ihost['uuid'],
                                        list(update_set), cinder_device)
                else:
                    LOG.error("Host: %s not found in database" % host_id)

    def _clear_ceph_stor_state(self, ihost_uuid):
        """ Once a node starts, clear status of OSD storage devices

        On reboot storage devices are expected to be 'configured', even if they
        were in 'configuration-failed'.
        This code will not be reached if manifests fail.
        Also, realtime status of Ceph's OSD is queried by pmon/sm, no need to do
        it in sysinv.
        """
        stors = self.dbapi.istor_get_by_ihost(ihost_uuid)
        for stor in stors:
            if stor.state != constants.SB_STATE_CONFIGURED:
                LOG.info("State of stor: '%s' is '%s', resetting to '%s'." %
                         (stor.uuid, stor.state,
                          constants.SB_STATE_CONFIGURED))
                values = {'state': constants.SB_STATE_CONFIGURED}
                self.dbapi.istor_update(stor.uuid, values)

    def iplatform_update_by_ihost(self, context,
                                  ihost_uuid, imsg_dict):
        """Update node data when sysinv-agent is started after a boot.

        This method is invoked on initialization and allows
        updates that need to happen once, when a node is started.
        Note, swact also results in restart of services, but not
        of sysinv-agent.

        :param context: an admin context
        :param ihost_uuid: ihost uuid unique id
        :param imsg_dict:  inventory message
        :returns: pass or fail
        """
        ihost_uuid.strip()
        LOG.info("Updating platform data for host: %s "
                 "with: %s" % (ihost_uuid, imsg_dict))

        try:
            ihost = self.dbapi.ihost_get(ihost_uuid)
        except exception.ServerNotFound:
            LOG.exception("Invalid ihost_uuid %s" % ihost_uuid)
            return

        availability = imsg_dict.get('availability')
        max_cpu_dict = imsg_dict.get('max_cpu_dict')

        val = {}

        action_state = imsg_dict.get(constants.HOST_ACTION_STATE)
        if action_state and action_state != ihost.action_state:
            LOG.info("%s updating action_state=%s" % (ihost.hostname, action_state))
            val[constants.HOST_ACTION_STATE] = action_state

        iscsi_initiator_name = imsg_dict.get('iscsi_initiator_name')
        if (iscsi_initiator_name and
                ihost.iscsi_initiator_name is None):
            LOG.info("%s updating iscsi initiator=%s" %
                        (ihost.hostname, iscsi_initiator_name))
            val['iscsi_initiator_name'] = iscsi_initiator_name

        if max_cpu_dict:
            ihost.capabilities.update({
                constants.IHOST_IS_MAX_CPU_MHZ_CONFIGURABLE:
                max_cpu_dict.get(constants.IHOST_IS_MAX_CPU_MHZ_CONFIGURABLE)})
            ihost.max_cpu_mhz_allowed = max_cpu_dict.get('max_cpu_mhz_allowed')
            val.update({'capabilities': ihost.capabilities,
                        constants.IHOST_MAX_CPU_MHZ_ALLOWED: ihost.max_cpu_mhz_allowed})

        if val:
            ihost = self.dbapi.ihost_update(ihost_uuid, val)

        if not availability:
            return

        if ((ihost.personality == constants.STORAGE and
                ihost.hostname == constants.STORAGE_0_HOSTNAME) or
                (ihost.personality == constants.CONTROLLER)):

            # monitor stor entry if ceph is configured initially or
            # 1st pair of storage nodes are provisioned (so that controller
            # node can be locked/unlocked)
            ceph_backend = StorageBackendConfig.get_backend(
                self.dbapi,
                constants.CINDER_BACKEND_CEPH
            )

            if ceph_backend and ceph_backend.task != \
                    constants.SB_TASK_PROVISION_STORAGE:
                ihost.capabilities.update({
                    constants.IHOST_STOR_FUNCTION:
                        constants.STOR_FUNCTION_MONITOR})
                self.dbapi.ihost_update(ihost_uuid,
                    {'capabilities': ihost.capabilities})

        if availability == constants.AVAILABILITY_AVAILABLE:
            config_uuid = imsg_dict['config_applied']
            if imsg_dict.get(constants.SYSINV_AGENT_FIRST_REPORT):
                if StorageBackendConfig.has_backend_configured(
                        self.dbapi,
                        constants.SB_TYPE_CEPH):
                    # This should be run once after a node boot
                    self._clear_ceph_stor_state(ihost_uuid)

                # On first_report which occurs on restart, check if the
                # reboot flag matches the applied config; as it is possible
                # to apply the puppet manifest on a restart.
                if (uuidutils.is_uuid_like(ihost.config_target) and
                    ihost.uptime < MAX_UPTIME_TO_CLEAR_REBOOT_REQUIRED and
                    config_uuid == self._config_clear_reboot_required(
                        ihost.config_target)):
                    LOG.info("config match on %s reboot config %s to %s" %
                             (ihost.hostname, config_uuid, ihost.config_target))
                    config_uuid = ihost.config_target
            self._update_host_config_applied(context, ihost, config_uuid)

        # Check if apps need to be re-applied when host services are
        # available (after unlock), but only if system restore is not in
        # progress
        if not os.path.isfile(tsc.RESTORE_IN_PROGRESS_FLAG):
            self.evaluate_apps_reapply(context, trigger={'type': constants.APP_EVALUATE_REAPPLY_HOST_AVAILABILITY,
                                                         'availability': availability})

        # Clear any "reboot needed" DB entry for the host if it is set.
        # If there are no more pending device image update entries in the DB
        # for any host, and if no host has the "reboot needed" DB entry set,
        # then the "device image update in progress" alarm is cleared.
        if availability == constants.AVAILABILITY_AVAILABLE:
            if imsg_dict.get(constants.SYSINV_AGENT_FIRST_REPORT):
                if ihost.reboot_needed:
                    ihost.reboot_needed = False
                    ihost.save(context)
                self._clear_device_image_alarm(context)

    def iconfig_update_by_ihost(self, context,
                                ihost_uuid, imsg_dict):
        """Update applied iconfig for an ihost with the supplied data.

        This method allows records for iconfig for ihost to be updated.

        :param context: an admin context
        :param ihost_uuid: ihost uuid unique id
        :param imsg_dict: inventory message dict
        :returns: pass or fail
        """

        ihost_uuid.strip()
        try:
            ihost = self.dbapi.ihost_get(ihost_uuid)
        except exception.ServerNotFound:
            LOG.exception("Invalid ihost_uuid %s" % ihost_uuid)
            return

        config_dict = imsg_dict.get('config_dict')
        if config_dict:
            status = imsg_dict.get('status')
            error = imsg_dict.get('error')
            self.report_config_status(context, config_dict, status, error)

        config_uuid = imsg_dict['config_applied']
        self._update_host_config_applied(context, ihost, config_uuid)

    def initial_inventory_completed(self, context, host_uuid):
        host_uuid.strip()
        try:
            self.dbapi.ihost_update(
                host_uuid,
                {'inv_state': constants.INV_STATE_INITIAL_INVENTORIED})
        except exception.ServerNotFound:
            LOG.error("initial_inventory_completed invalid host_uuid %s" %
                      host_uuid)

    def subfunctions_update_by_ihost(self, context,
                                ihost_uuid, subfunctions):
        """Update subfunctions for a host.

        This method allows records for subfunctions to be updated.

        :param context: an admin context
        :param ihost_uuid: ihost uuid unique id
        :param subfunctions: subfunctions provided by the ihost
        :returns: pass or fail
        """
        ihost_uuid.strip()
        ihost_val = {'subfunctions': subfunctions}
        self.dbapi.ihost_update(ihost_uuid, ihost_val)

    def get_isystem(self, context):
        """Return isystem object

        This method returns a isystem object

        :returns: isystem object, including all fields
        """
        system = self.dbapi.isystem_get_one()
        return system

    def get_ihost_by_macs(self, context, ihost_macs):
        """Finds ihost db entry based upon the mac list

        This method returns an ihost if it matches a mac

        :param context: an admin context
        :param ihost_macs: list of mac addresses
        :returns: ihost object, including all fields.
        """

        ihosts = self.dbapi.ihost_get_list()

        LOG.debug("Checking ihost db for macs: %s" % ihost_macs)
        for mac in ihost_macs:
            try:
                mac = mac.rstrip()
                mac = cutils.validate_and_normalize_mac(mac)
            except Exception:
                LOG.warn("get_ihost_by_macs invalid mac: %s" % mac)
                continue

            for host in ihosts:
                if host.mgmt_mac == mac:
                    LOG.info("Host found ihost db for macs: %s" % host.hostname)
                    return host
        LOG.debug("RPC get_ihost_by_macs called but found no ihost.")

    def get_ihost_by_hostname(self, context, ihost_hostname):
        """Finds ihost db entry based upon the ihost hostname

        This method returns an ihost if it matches the ihost
        hostname.

        :param context: an admin context
        :param ihost_hostname: ihost hostname
        :returns: ihost object, including all fields.
        """

        try:
            ihost = self.dbapi.ihost_get_by_hostname(ihost_hostname)

            return ihost

        except exception.NodeNotFound:
            pass

        LOG.debug("RPC ihost_get_by_hostname called but found no ihost.")

    @staticmethod
    def _controller_config_active_check():
        """Determine whether the active configuration has been finalized"""

        if not os.path.isfile(tsc.INITIAL_CONFIG_COMPLETE_FLAG):
            return False

        # Defer running the manifest apply if backup/restore operations are
        # in progress.
        if (os.path.isfile(tsc.BACKUP_IN_PROGRESS_FLAG) or
                os.path.isfile(tsc.RESTORE_IN_PROGRESS_FLAG)):
            return False

        if not os.path.isfile(CONFIG_CONTROLLER_FINI_FLAG):
            return True

        return False

    @periodic_task.periodic_task(
        spacing=CONF.conductor_periodic_task_intervals.controller_config_active_apply)
    def _controller_config_active_apply(self, context):
        """Check whether target config has been applied to active
           controller to run postprocessing"""

        # check whether target config may be finished based upon whether
        # the active controller has the active config target
        if not self._controller_config_active_check():
            return  # already finalized on this active controller

        try:
            hostname = socket.gethostname()
            controller_hosts =\
                self.dbapi.ihost_get_by_personality(constants.CONTROLLER)
        except Exception as e:
            LOG.warn("Failed to get local host object: %s", str(e))
            return

        active_host = None
        standby_host = None
        for controller_host in controller_hosts:
            if controller_host.hostname == hostname:
                active_host = controller_host
            else:
                standby_host = controller_host

        if (active_host and active_host.config_target and
           active_host.config_applied == active_host.config_target):
            # active controller has applied target, apply pending config if
            # required
            oam_config_runtime_apply_file = self._get_oam_runtime_apply_file()

            if (os.path.isfile(oam_config_runtime_apply_file) or
               os.path.isfile(constants.HTTPS_CONFIG_REQUIRED) or
               os.path.isfile(constants.ADMIN_ENDPOINT_CONFIG_REQUIRED)):

                if cutils.is_initial_config_complete():
                    # apply keystone changes to current active controller
                    personalities = [constants.CONTROLLER]
                    config_uuid = self._config_update_hosts(context, personalities,
                                                            host_uuids=[active_host.uuid])
                    config_dict = {
                        "personalities": personalities,
                        "host_uuids": [active_host.uuid],
                        "classes": ['openstack::keystone::endpoint::runtime',
                                    'platform::firewall::runtime']
                    }
                    self._config_apply_runtime_manifest(
                        context, config_uuid, config_dict)

                    if os.path.isfile(oam_config_runtime_apply_file):
                        LOG.info("oam config applied %s" % config_dict)
                        os.remove(oam_config_runtime_apply_file)
                    if os.path.isfile(constants.HTTPS_CONFIG_REQUIRED):
                        LOG.info("https config applied %s" % config_dict)
                        os.remove(constants.HTTPS_CONFIG_REQUIRED)
                    if os.path.isfile(constants.ADMIN_ENDPOINT_CONFIG_REQUIRED):
                        LOG.info("admin endpoint config applied %s" % config_dict)
                        os.remove(constants.ADMIN_ENDPOINT_CONFIG_REQUIRED)

            # apply filesystem config changes if all controllers at target
            standby_config_target_flipped = None
            if standby_host and standby_host.config_target:
                standby_config_target_flipped = utils.config_flip_reboot_required(standby_host.config_target)
            if not standby_host or (standby_host and
               (standby_host.config_applied == standby_host.config_target or
               standby_host.config_applied == standby_config_target_flipped)):
                all_fs_resized = self._resize_filesystems_update_db(context, standby_host)

                if all_fs_resized:
                    self._update_alarm_status(context, active_host)
                    if standby_host and standby_host.config_applied == standby_host.config_target:
                        self._update_alarm_status(context, standby_host)
        else:
            # Ignore the reboot required bit for active controller when doing the comparison
            active_config_target_flipped = None
            if active_host and active_host.config_target:
                active_config_target_flipped = utils.config_flip_reboot_required(active_host.config_target)
            standby_config_target_flipped = None
            if standby_host and standby_host.config_target:
                standby_config_target_flipped = utils.config_flip_reboot_required(standby_host.config_target)
            if active_host and active_config_target_flipped and \
               active_host.config_applied == active_config_target_flipped:
                # apply filesystem config changes if all controllers at target
                # Ignore the reboot required bit
                if not standby_host or (standby_host and
                   (standby_host.config_applied == standby_host.config_target or
                   standby_host.config_applied == standby_config_target_flipped)):
                    all_fs_resized = self._resize_filesystems_update_db(context, standby_host)

                    if (all_fs_resized and standby_host and
                       standby_host.config_applied == standby_host.config_target):
                        self._update_alarm_status(context, standby_host)

    def _resize_filesystems_update_db(self, context, standby_host):
        """Resize the filesystems upon completion of storage config.
           Update sysinv db for each filesystem updated so that if one fails other
           successfully resized filesystems are properly updated on the database"""
        all_fs_resized, drbd_fs_resized = self._config_resize_filesystems(context, standby_host)
        controller_fs_list = self.dbapi.controller_fs_get_list()

        for fs in controller_fs_list:
            name = fs.get('name')
            if ((fs.get('state') != constants.CONTROLLER_FS_AVAILABLE) and
               (constants.FILESYSTEM_DRBD_DICT.get(name) in drbd_fs_resized)):
                self.dbapi.controller_fs_update(fs.uuid, {'state': constants.CONTROLLER_FS_AVAILABLE})

        if all_fs_resized:
            cutils.touch(CONFIG_CONTROLLER_FINI_FLAG)

        return all_fs_resized

    @periodic_task.periodic_task(spacing=CONF.conductor_periodic_task_intervals.ihost_action)
    def _audit_ihost_action(self, context):
        """Audit whether the ihost_action needs to be terminated or escalated.
        """
        hosts = self.dbapi.ihost_get_list()
        for ihost in hosts:
            # only audit configured hosts
            if ihost.personality:
                if ihost.administrative == constants.ADMIN_UNLOCKED:
                    ihost_action_str = ihost.ihost_action or ""

                    if (ihost_action_str.startswith(constants.FORCE_LOCK_ACTION) or
                            ihost_action_str.startswith(constants.LOCK_ACTION)):

                        task_str = ihost.task or ""
                        if (('--' in ihost_action_str and
                              ihost_action_str.startswith(
                                   constants.FORCE_LOCK_ACTION)) or
                              ('----------' in ihost_action_str and
                              ihost_action_str.startswith(constants.LOCK_ACTION))):

                            ihost_mtc = ihost.as_dict()
                            keepkeys = ['ihost_action', 'vim_progress_status']
                            ihost_mtc = cutils.removekeys_nonmtce(ihost_mtc,
                                                                keepkeys)

                            if ihost_action_str.startswith(constants.FORCE_LOCK_ACTION):
                                timeout_in_secs = 6
                                ihost_mtc['operation'] = 'modify'
                                ihost_mtc['action'] = constants.FORCE_LOCK_ACTION
                                ihost_mtc['task'] = constants.FORCE_LOCKING
                                LOG.warn("ihost_action override %s" %
                                        ihost_mtc)
                                mtce_api.host_modify(
                                    self._api_token, self._mtc_address, self._mtc_port,
                                    ihost_mtc, timeout_in_secs)

                            # need time for FORCE_LOCK mtce to clear
                            if ('----' in ihost_action_str):
                                ihost_action_str = ""
                            else:
                                ihost_action_str += "-"

                            if (task_str.startswith(constants.FORCE_LOCKING) or
                            task_str.startswith(constants.LOCKING)):
                                val = {'task': "",
                                    'ihost_action': ihost_action_str,
                                    'vim_progress_status': ""}
                            else:
                                val = {'ihost_action': ihost_action_str,
                                    'vim_progress_status': ""}
                        else:
                            ihost_action_str += "-"
                            if (task_str.startswith(constants.FORCE_LOCKING) or
                            task_str.startswith(constants.LOCKING)):
                                task_str += "-"
                                val = {'task': task_str,
                                    'ihost_action': ihost_action_str}
                            else:
                                val = {'ihost_action': ihost_action_str}

                        self.dbapi.ihost_update(ihost.uuid, val)
                else:  # Administrative locked already
                    task_str = ihost.task or ""
                    if (task_str.startswith(constants.FORCE_LOCKING) or
                    task_str.startswith(constants.LOCKING)):
                        val = {'task': ""}
                        self.dbapi.ihost_update(ihost.uuid, val)

                vim_progress_status_str = ihost.get('vim_progress_status') or ""
                if (vim_progress_status_str and
                   (vim_progress_status_str != constants.VIM_SERVICES_ENABLED) and
                   (vim_progress_status_str != constants.VIM_SERVICES_DISABLED)):
                    if ('..' in vim_progress_status_str):
                        LOG.info("Audit clearing vim_progress_status=%s" %
                                vim_progress_status_str)
                        vim_progress_status_str = ""
                    else:
                        vim_progress_status_str += ".."

                    val = {'vim_progress_status': vim_progress_status_str}
                    self.dbapi.ihost_update(ihost.uuid, val)

    @periodic_task.periodic_task(spacing=CONF.conductor_periodic_task_intervals.upgrade_status)
    def _audit_upgrade_status(self, context):
        """Audit upgrade related status"""
        try:
            upgrade = self.dbapi.software_upgrade_get_one()
        except exception.NotFound:
            # Not upgrading. No need to update status
            return

        if upgrade.state == constants.UPGRADE_ACTIVATING_HOSTS:
            hosts = self.dbapi.ihost_get_list()
            out_of_date_hosts = [host for host in hosts
                                 if host.config_target and host.config_target != host.config_applied]
            if not out_of_date_hosts:
                LOG.info("Manifests applied. Upgrade activation complete.")
                self._upgrade_manifest_start_time = None
                self.dbapi.software_upgrade_update(
                    upgrade.uuid,
                    {'state': constants.UPGRADE_ACTIVATION_COMPLETE})
            else:
                LOG.info("Upgrade manifests running, config out-of-date hosts: %s" %
                         str([host.hostname for host in out_of_date_hosts]))
                # if the timeout interval is reached and hosts are
                # still out-of-date then mark activation as failed
                if not self._upgrade_manifest_start_time:
                    self._upgrade_manifest_start_time = datetime.utcnow()
                if (datetime.utcnow() - self._upgrade_manifest_start_time).total_seconds() >= \
                        constants.UPGRADE_ACTIVATION_MANIFEST_TIMEOUT_IN_SECS:
                    self._upgrade_manifest_start_time = None
                    LOG.error("Upgrade activation failed, upgrade manifests apply timeout.")
                    self.dbapi.software_upgrade_update(
                        upgrade.uuid,
                        {'state': constants.UPGRADE_ACTIVATION_FAILED})

        elif upgrade.state == constants.UPGRADE_DATA_MIGRATION:
            # Progress upgrade state if necessary...
            if os.path.isfile(tsc.CONTROLLER_UPGRADE_COMPLETE_FLAG):
                self.dbapi.software_upgrade_update(
                    upgrade.uuid,
                    {'state': constants.UPGRADE_DATA_MIGRATION_COMPLETE})
            elif os.path.isfile(tsc.CONTROLLER_UPGRADE_FAIL_FLAG):
                self.dbapi.software_upgrade_update(
                    upgrade.uuid,
                    {'state': constants.UPGRADE_DATA_MIGRATION_FAILED})

        elif upgrade.state == constants.UPGRADE_UPGRADING_CONTROLLERS:
            # In CPE upgrades, after swacting to controller-1, we need to clear
            # the VIM upgrade flag on Controller-0 to allow VMs to be migrated
            # to controller-1.
            if constants.WORKER in tsc.subfunctions:
                try:
                    controller_0 = self.dbapi.ihost_get_by_hostname(
                        constants.CONTROLLER_0_HOSTNAME)
                    if not utils.is_host_active_controller(controller_0):
                        vim_api.set_vim_upgrade_state(controller_0, False)
                except Exception:
                    LOG.exception("Unable to set VIM upgrade state to False")
        elif upgrade.state == constants.UPGRADE_UPGRADING_HOSTS:
            # As part of a 3-host Ceph monitor quorum, over a platform upgrade
            # we may need to take action once all monitors are running
            ceph_storage_backend = StorageBackendConfig.get_backend(
                self.dbapi,
                constants.SB_TYPE_CEPH
            )
            if ceph_storage_backend:
                monitor_list = self.dbapi.ceph_mon_get_list()
                LOG.info("Ceph Upgrade: Checking monitor states")
                for mon in monitor_list:

                    host = self.dbapi.ihost_get(mon.forihostid)
                    host_upgrade = self.dbapi.host_upgrade_get(host.id)
                    host_load = self.dbapi.load_get(host_upgrade.software_load)

                    if host_load.software_version != upgrade.to_release:
                        LOG.info("Ceph Upgrade: Monitor %s is not upgraded to %s" %
                                 (mon.hostname, upgrade.to_release))
                        return

                    mon_config_target = host.config_target
                    mon_config_applied = host.config_applied
                    if mon_config_target and mon_config_target != mon_config_applied:
                        LOG.info("Ceph Upgrade: Monitor %s has not applied the "
                                 "latest configuration changes" % mon.hostname)
                        return
                LOG.info("Ceph Upgrade: Enabling monitor msgr2")
                try:
                    # This operation takes less than one second to be executed.
                    # Ten seconds is more than enough to have this executed.
                    # In case ceph cluster loses quorum, this operation won't hang
                    # because the request method actually needs to query the ceph cluster
                    # to retrieve password and service url before running this command.
                    # Those operations also timeout after 5 seconds.
                    self._ceph_api.enable_msgr2(timeout=10)
                except Exception as e:
                    LOG.info("Ceph Upgrade: Exception %s" % e)
                LOG.info("Ceph Upgrade: Enabled monitor msgr2")

    @periodic_task.periodic_task(spacing=CONF.conductor_periodic_task_intervals.install_states)
    def _audit_install_states(self, context):
        # A node could shutdown during it's installation and the install_state
        # for example could get stuck at the value "installing". To avoid
        # this situation we audit the sanity of the states by appending the
        # character '+' to the states in the database. After 15 minutes of the
        # states not changing, set the install_state to failed.

        # The duration (in minutes) to wait until the install_state fails
        MAX_COUNT = 15

        # Allow longer duration for booting phase
        MAX_COUNT_BOOTING = 40

        hosts = self.dbapi.ihost_get_list()
        for host in hosts:
            LOG.debug("Auditing %s, install_state is %s",
                      host.hostname, host.install_state)
            LOG.debug("Auditing %s, availability is %s",
                      host.hostname, host.availability)

            if (host.administrative == constants.ADMIN_LOCKED and
                    host.install_state is not None):

                install_state = host.install_state.rstrip('+')

                if host.install_state != constants.INSTALL_STATE_FAILED:
                    if (install_state == constants.INSTALL_STATE_BOOTING and
                            host.availability !=
                            constants.AVAILABILITY_OFFLINE):
                        host.install_state = constants.INSTALL_STATE_COMPLETED

                    if (install_state != constants.INSTALL_STATE_INSTALLED and
                            install_state !=
                            constants.INSTALL_STATE_COMPLETED):
                        # define the quantity of '+' signs that will be added to install_state_info
                        # accordingly to the interval set to this audit.
                        periodic_interval = max(60,
                            CONF.conductor_periodic_task_intervals.install_states)
                        factor = periodic_interval // 60 + \
                            (1 if periodic_interval % 60 > 0 else 0)
                        if (install_state ==
                                constants.INSTALL_STATE_INSTALLING and
                                host.install_state_info is not None):
                            host.install_state_info += factor * "+"
                            if host.install_state_info.count('+') >= MAX_COUNT:
                                LOG.info(
                                    "Auditing %s, install_state changed from "
                                    "'%s' to '%s'", host.hostname,
                                    host.install_state,
                                    constants.INSTALL_STATE_FAILED)
                                host.install_state = \
                                    constants.INSTALL_STATE_FAILED
                        else:
                            if install_state == constants.INSTALL_STATE_BOOTING:
                                max_count = MAX_COUNT_BOOTING
                            else:
                                max_count = MAX_COUNT
                            host.install_state += factor * "+"
                            if host.install_state.count('+') >= max_count:
                                LOG.info(
                                    "Auditing %s, install_state changed from "
                                    "'%s' to '%s'", host.hostname,
                                    host.install_state,
                                    constants.INSTALL_STATE_FAILED)
                                host.install_state = \
                                    constants.INSTALL_STATE_FAILED

                # It is possible we get stuck in an installed failed state. For
                # example if a node gets powered down during an install booting
                # state and then powered on again. Clear it if the node is
                # online.
                elif (host.availability == constants.AVAILABILITY_ONLINE and
                        host.install_state == constants.INSTALL_STATE_FAILED):
                    host.install_state = constants.INSTALL_STATE_COMPLETED

                self.dbapi.ihost_update(host.uuid,
                                        {'install_state': host.install_state,
                                         'install_state_info':
                                             host.install_state_info})
    PUPPET_RUNTIME_CLASS_ROUTES = 'platform::network::routes::runtime'
    PUPPET_RUNTIME_CLASS_DOCKERDISTRIBUTION = 'platform::dockerdistribution::runtime'
    PUPPET_RUNTIME_FILES_DOCKER_REGISTRY_KEY_FILE = constants.DOCKER_REGISTRY_KEY_FILE
    PUPPET_RUNTIME_FILES_DOCKER_REGISTRY_CERT_FILE = constants.DOCKER_REGISTRY_CERT_FILE
    PUPPET_RUNTIME_FILES_DOCKER_REGISTRY_PKCS1_KEY_FILE = constants.DOCKER_REGISTRY_PKCS1_KEY_FILE
    PUPPET_RUNTIME_FILES_DOCKER_CERT_FILE = constants.DOCKER_CERT_FILE

    PUPPET_RUNTIME_FILTER_CLASSES = [
        PUPPET_RUNTIME_CLASS_ROUTES,
        PUPPET_RUNTIME_CLASS_DOCKERDISTRIBUTION
    ]
    PUPPET_RUNTIME_FILTER_FILES = [
        PUPPET_RUNTIME_FILES_DOCKER_REGISTRY_KEY_FILE,
        PUPPET_RUNTIME_FILES_DOCKER_REGISTRY_CERT_FILE,
        PUPPET_RUNTIME_FILES_DOCKER_REGISTRY_PKCS1_KEY_FILE,
        PUPPET_RUNTIME_FILES_DOCKER_CERT_FILE
    ]
    PUPPET_FILTER_FILES_RESTORING_APPS = [
        PUPPET_RUNTIME_FILES_DOCKER_REGISTRY_KEY_FILE,
        PUPPET_RUNTIME_FILES_DOCKER_REGISTRY_CERT_FILE,
        PUPPET_RUNTIME_FILES_DOCKER_REGISTRY_PKCS1_KEY_FILE,
        PUPPET_RUNTIME_FILES_DOCKER_CERT_FILE
    ]

    def _check_ready_route_runtime_config(self):
        if self._check_runtime_class_apply_in_progress(
                [self.PUPPET_RUNTIME_CLASS_ROUTES]):
            return False
        return True

    def _ready_to_apply_runtime_config(
            self, context, personalities=None, host_uuids=None,
            filter_classes=None, filter_files=None):
        """Determine whether ready to apply runtime config"""

        if filter_classes is None:
            filter_classes = set()
        if filter_files is None:
            filter_files = set()

        if personalities is None:
            personalities = []
        if host_uuids is None:
            host_uuids = []

        check_required = False
        if constants.CONTROLLER in personalities:
            check_required = True
        if constants.WORKER in personalities and cutils.is_aio_system(self.dbapi):
            check_required = True
        if host_uuids and self.host_uuid not in host_uuids:
            check_required = False

        if not check_required and not filter_classes:
            return True

        if not os.path.exists(constants.SYSINV_REPORTED):
            LOG.info("_ready_to_apply_runtime_config path does not exist: %s" %
                     constants.SYSINV_REPORTED)
            return False

        # check if needed to wait for filter class
        for filter_class in filter_classes:
            if filter_class == self.PUPPET_RUNTIME_CLASS_ROUTES:
                if not self._check_ready_route_runtime_config():
                    LOG.info("config type %s filter_mapping %s False (wait)" %
                             (CONFIG_APPLY_RUNTIME_MANIFEST, filter_class))
                    return False
            if filter_class == self.PUPPET_RUNTIME_CLASS_DOCKERDISTRIBUTION:
                if self.check_restoring_apps_in_progress():
                    LOG.info("config type %s filter_mapping %s False (wait)" %
                             (CONFIG_APPLY_RUNTIME_MANIFEST, filter_class))
                    return False
            LOG.info("config type %s filter_mapping %s True (continue)" %
                     (CONFIG_APPLY_RUNTIME_MANIFEST, filter_class))

        # check if needed to wait for filter files
        for filter_file in filter_files:
            if filter_file in self.PUPPET_FILTER_FILES_RESTORING_APPS:
                if self.check_restoring_apps_in_progress():
                    LOG.info("config type %s filter_mapping %s False (wait)" %
                             (CONFIG_UPDATE_FILE, filter_file))
                    return False
            LOG.info("config type %s filter_mapping %s True (continue)" %
                     (CONFIG_UPDATE_FILE, filter_file))

        return True

    @cutils.synchronized(LOCK_RUNTIME_CONFIG_CHECK)
    def _audit_deferred_runtime_config(self, context):
        """Apply deferred config runtime manifests when ready"""

        LOG.debug("_audit_deferred_runtime_config %s" %
                  self._host_deferred_runtime_config)

        if not self._host_deferred_runtime_config or \
                not self._ready_to_apply_runtime_config(context):
            return

        # apply the deferred runtime manifests
        for config in list(self._host_deferred_runtime_config):
            config_type = config.get('config_type')
            LOG.info("found _audit_deferred_runtime_config request apply %s" %
                        config)
            if config_type == CONFIG_APPLY_RUNTIME_MANIFEST:
                # config runtime manifest system allows for filtering on scoped runtime classes
                # to allow for more efficient handling while another scoped class apply may
                # already be in progress
                config_dict = config.get('config_dict') or {}
                classes_list = list(config_dict.get('classes') or [])
                filter_classes = [x for x in self.PUPPET_RUNTIME_FILTER_CLASSES if x in classes_list]
                LOG.info("config type %s found filter_classes=%s cd= %s" %
                            (config_type, filter_classes, config_dict))
                self._config_apply_runtime_manifest(
                    context,
                    config['config_uuid'],
                    config['config_dict'],
                    force=config.get('force', False),
                    filter_classes=filter_classes)
            elif config_type == CONFIG_UPDATE_FILE:
                config_dict = config.get('config_dict') or {}
                file_names = list(config_dict.get('file_names') or [])
                filter_files = [x for x in self.PUPPET_RUNTIME_FILTER_FILES if x in file_names]
                LOG.info("config type %s found filter_files=%s cd= %s" %
                         (config_type, filter_files, config_dict))
                self._config_update_file(
                    context,
                    config['config_uuid'],
                    config['config_dict'],
                    filter_files=filter_files)
            else:
                LOG.error("Removed unsupported deferred config_type %s" %
                            config_type)

    @periodic_task.periodic_task(spacing=CONF.conductor_periodic_task_intervals.deferred_runtime_config)
    def _audit_deferred_runtime_config_periodic(self, context):
        # check whether there are deferred runtime manifests to apply
        self._audit_deferred_runtime_config(context)

    @periodic_task.periodic_task(spacing=CONF.conductor_periodic_task_intervals.kubernetes_local_secrets)
    def _kubernetes_local_secrets_audit(self, context):
        # Audit kubernetes local registry secrets info
        LOG.debug("Sysinv Conductor running periodic audit task for k8s local registry secrets.")
        if self._app:
            self._app.audit_local_registry_secrets(context)

    @periodic_task.periodic_task(spacing=CONF.conductor_periodic_task_intervals.kubernetes_labels)
    def _audit_kubernetes_labels(self, context):
        if not cutils.is_initial_config_complete():
            LOG.debug("_audit_kubernetes_labels skip")
            return

        LOG.debug("Starting kubernetes label audit")
        sysinv_labels = self.dbapi.label_get_all()
        nodes = self._kube.kube_get_nodes()

        hosts = self.dbapi.ihost_get_list()
        for host in hosts:
            try:
                for node in nodes:
                    if host.hostname == node.metadata.name:
                        node_labels = node.metadata.labels
                        host_labels = [l for l in sysinv_labels if l.host_id == host.id]
                        for host_label in host_labels:
                            if host_label.label_key not in node_labels.keys():
                                LOG.info("Label audit: creating %s=%s on node %s"
                                         % (host_label.label_key,
                                            host_label.label_value, host.hostname))
                                body = {
                                    'metadata': {
                                        'labels': {host_label.label_key: host_label.label_value}
                                    }
                                }
                                self._kube.kube_patch_node(host.hostname, body)
            except Exception as e:
                LOG.warning("Failed to sync kubernetes label to host %s: %s" %
                            (host.hostname, e))

    def set_backend_to_err(self, backend):
        """Set backend state to error"""

        values = {'state': constants.SB_STATE_CONFIG_ERR, 'task': None}
        self.dbapi.storage_backend_update(backend.uuid, values)

        # Raise alarm
        reason = "Backend %s configuration timed out." % backend.backend
        self._update_storage_backend_alarm(fm_constants.FM_ALARM_STATE_SET,
                                           backend.backend,
                                           reason)

    @periodic_task.periodic_task(spacing=CONF.conductor_periodic_task_intervals.storage_backend_failure)
    def _storage_backend_failure_audit(self, context):
        """Check if storage backend is stuck in 'configuring'"""

        backend_list = self.dbapi.storage_backend_get_list_by_state(
            backend_state=constants.SB_STATE_CONFIGURING)
        backend_cache = {}
        for bk in backend_list:
            # TODO(oponcea): Update when sm supports in-service config reload.
            if (constants.SB_TASK_APPLY_MANIFESTS in str(bk.task)):
                backend_cache[bk.backend] = bk.state
                if bk.backend not in self._stor_bck_op_timeouts:
                    self._stor_bck_op_timeouts[bk.backend] = int(time.time())
                else:
                    d = int(time.time()) - self._stor_bck_op_timeouts[bk.backend]
                    if d >= constants.SB_CONFIGURATION_TIMEOUT:
                        LOG.error("Storage backend %(name)s configuration "
                                  "timed out at: %(task)s. Raising alarm!" %
                                  {'name': bk.backend, 'task': bk.task})
                        self.set_backend_to_err(bk)

        # Clear cache
        for backend in self._stor_bck_op_timeouts.copy().keys():
            if backend not in backend_cache:
                self._stor_bck_op_timeouts.pop(backend)

    @periodic_task.periodic_task(spacing=CONF.conductor_periodic_task_intervals.image_conversion)
    def _audit_image_conversion(self, context):
        """
        Raise alarm if:
           - image-conversion is not added on both controllers;
           - the size of the filesystem is not the same
             on both controllers
        """
        chosts = self.dbapi.ihost_get_by_personality(constants.CONTROLLER)
        if len(chosts) <= 1:
            # No alarm is raised if setup has only one controller
            return

        conversion_list = []
        for host in chosts:
            hostfs_list = self.dbapi.host_fs_get_by_ihost(host.uuid)
            for host_fs in hostfs_list:
                if host_fs['name'] == constants.FILESYSTEM_NAME_IMAGE_CONVERSION:
                    conversion_list.append(host_fs['size'])

        reason_text = "image-conversion must be added on both controllers"
        if not conversion_list:
            # If no conversion filesystem is present on any host
            # any alarm present is cleared
            self._update_image_conversion_alarm(fm_constants.FM_ALARM_STATE_CLEAR,
                                               constants.FILESYSTEM_NAME_IMAGE_CONVERSION)
        elif (len(conversion_list) == 1):
            self._update_image_conversion_alarm(fm_constants.FM_ALARM_STATE_SET,
                                               constants.FILESYSTEM_NAME_IMAGE_CONVERSION,
                                               reason_text)
        else:
            # If conversion filesystem is present on both controllers
            # with different sizes
            self._update_image_conversion_alarm(fm_constants.FM_ALARM_STATE_CLEAR,
                                        constants.FILESYSTEM_NAME_IMAGE_CONVERSION)
            if (conversion_list[0] != conversion_list[1]):
                reason_text = "image-conversion size must be the same on both controllers"
                self._update_image_conversion_alarm(fm_constants.FM_ALARM_STATE_SET,
                                             constants.FILESYSTEM_NAME_IMAGE_CONVERSION,
                                             reason_text)
            elif conversion_list[0] == conversion_list[1]:
                self._update_image_conversion_alarm(fm_constants.FM_ALARM_STATE_CLEAR,
                                             constants.FILESYSTEM_NAME_IMAGE_CONVERSION)

    def _auto_upload_managed_app(self, context, app_name):
        if self._patching_operation_is_occurring():
            return

        LOG.info("Platform managed application %s: Creating..." % app_name)
        app_data = {'name': app_name,
                    'app_version': constants.APP_VERSION_PLACEHOLDER,
                    'manifest_name': constants.APP_MANIFEST_NAME_PLACEHOLDER,
                    'manifest_file': constants.APP_TARFILE_NAME_PLACEHOLDER,
                    'status': constants.APP_UPLOAD_IN_PROGRESS}
        try:
            self.dbapi.kube_app_create(app_data)
            app = kubeapp_obj.get_by_name(context, app_name)
        except exception.KubeAppAlreadyExists as e:
            LOG.exception(e)
            return
        except exception.KubeAppNotFound as e:
            LOG.exception(e)
            return

        tarfile = self._search_tarfile(app_name, managed_app=True)
        if tarfile is None:
            # Skip if no tarball or multiple tarballs found
            return

        tarball = self._check_tarfile(app_name, tarfile)
        if ((tarball.manifest_name is None) or
                (tarball.manifest_file is None)):
            app.status = constants.APP_UPLOAD_FAILURE
            app.save()
            return

        app.name = tarball.app_name
        app.app_version = tarball.app_version
        app.manifest_name = tarball.manifest_name
        app.manifest_file = os.path.basename(tarball.manifest_file)
        app.save()

        # Action: Upload.
        # Do not block this audit task or any other periodic task. This
        # could be long running. The next audit cycle will pick up the
        # latest status.
        LOG.info("Platform managed application %s: "
                    "Uploading..." % app_name)

        hook_info = LifecycleHookInfo()
        hook_info.mode = constants.APP_LIFECYCLE_MODE_AUTO

        greenthread.spawn(self.perform_app_upload, context,
                          app, tarball.tarball_name, hook_info)

    def _auto_apply_managed_app(self, context, app_name):
        try:
            app = kubeapp_obj.get_by_name(context, app_name)
        except exception.KubeAppNotFound as e:
            LOG.exception(e)
            return

        hook_info = LifecycleHookInfo()
        hook_info.init(constants.APP_LIFECYCLE_MODE_AUTO,
                       constants.APP_LIFECYCLE_TYPE_SEMANTIC_CHECK,
                       constants.APP_LIFECYCLE_TIMING_PRE,
                       constants.APP_APPLY_OP)
        try:
            self.app_lifecycle_actions(context, app, hook_info)
        except exception.LifecycleSemanticCheckException as e:
            LOG.info("Auto-apply failed prerequisites for {}: {}".format(app.name, e))
            return
        except Exception as e:
            LOG.exception("Automatic operation:{} "
                          "for app {} failed with: {}".format(hook_info,
                                                              app.name,
                                                              e))
            return

        if self._patching_operation_is_occurring():
            return

        self._inner_sync_auto_apply(context, app_name)

    def _auto_update_app(self, context, app_name, managed_app):
        """Auto update applications"""
        try:
            app = kubeapp_obj.get_by_name(context, app_name)
        except exception.KubeAppNotFound as e:
            LOG.exception(e)
            return

        if app.status != constants.APP_APPLY_SUCCESS:
            # In case the previous re-apply fails
            return

        try:
            hook_info = LifecycleHookInfo()
            hook_info.init(constants.APP_LIFECYCLE_MODE_AUTO,
                           constants.APP_LIFECYCLE_TYPE_SEMANTIC_CHECK,
                           constants.APP_LIFECYCLE_TIMING_PRE,
                           constants.APP_UPDATE_OP)
            hook_info[LifecycleConstants.EXTRA][LifecycleConstants.FROM_APP] = True
            self.app_lifecycle_actions(context, app, hook_info)
        except exception.LifecycleSemanticCheckException as e:
            LOG.info("Auto-update failed prerequisites for {}: {}".format(app.name, e))
            return
        except exception.LifecycleSemanticCheckOperationNotSupported as e:
            LOG.debug(e)
            return
        except Exception as e:
            LOG.exception("Automatic operation:{} "
                          "for app {} failed with: {}".format(hook_info,
                                                              app.name,
                                                              e))
            return

        if self._patching_operation_is_occurring():
            return

        LOG.debug("Application %s: Checking "
                  "for update ..." % app_name)
        tarfile = self._search_tarfile(app_name, managed_app=managed_app)
        if tarfile is None:
            # Skip if no tarball or multiple tarballs found
            return

        applied_app = '{}-{}'.format(app.name, app.app_version)
        if applied_app in tarfile:
            # Skip if the tarfile version is already applied
            return

        LOG.info("Found new tarfile version for %s: %s"
                 % (app.name, tarfile))
        tarball = self._check_tarfile(app_name, tarfile,
                                      preserve_metadata=True)
        if ((tarball.app_name is None) or
            (tarball.app_version is None) or
             (tarball.manifest_name is None) or
              (tarball.manifest_file is None)):
            # Skip if tarball check fails
            return

        if not tarball.metadata:
            # Skip if app doesn't have metadata
            return

        auto_update = tarball.metadata.get(
            constants.APP_METADATA_UPGRADES, {}).get(
            constants.APP_METADATA_AUTO_UPDATE, False)
        if not bool(strtobool(str(auto_update))):
            # Skip if app is not set to auto_update
            return

        if tarball.app_version in \
            app.app_metadata.get(
                constants.APP_METADATA_UPGRADES, {}).get(
                constants.APP_METADATA_FAILED_VERSIONS, []):
            # Skip if this version was previously failed to
            # be updated
            LOG.error("Application %s with version %s was previously "
                      "failed to be updated from version %s by auto-update"
                      % (app.name, tarball.app_version, app.app_version))
            return

        self._inner_sync_auto_update(context, app, tarball)

    @cutils.synchronized(LOCK_APP_AUTO_MANAGE)
    def _inner_sync_auto_update(self, context, applied_app, tarball):
        # Check no other app is in progress of apply/update/recovery
        for other_app in self.dbapi.kube_app_get_all():
            if other_app.status in [constants.APP_APPLY_IN_PROGRESS,
                                    constants.APP_UPDATE_IN_PROGRESS,
                                    constants.APP_RECOVER_IN_PROGRESS]:
                LOG.info("%s requires update but %s "
                         "is in progress of apply/update/recovery. "
                         "Will retry on next audit",
                         applied_app.name, other_app.name)
                return

        # Set the status for the current applied app to inactive
        applied_app.status = constants.APP_INACTIVE_STATE
        applied_app.progress = None
        applied_app.save()

        try:
            target_app = kubeapp_obj.get_inactive_app_by_name_version(
                context, tarball.app_name, tarball.app_version)
            target_app.status = constants.APP_UPDATE_IN_PROGRESS
            target_app.save()
            if cutils.is_aio_simplex_system(self.dbapi):
                operation = constants.APP_APPLY_OP
            else:
                operation = constants.APP_ROLLBACK_OP
        except exception.KubeAppInactiveNotFound:
            target_app_data = {
                'name': tarball.app_name,
                'app_version': tarball.app_version,
                'manifest_name': tarball.manifest_name,
                'manifest_file': os.path.basename(tarball.manifest_file),
                'status': constants.APP_UPDATE_IN_PROGRESS,
                'active': True
            }
            operation = constants.APP_APPLY_OP

            try:
                target_db_app = self.dbapi.kube_app_create(target_app_data)
                target_app = kubeapp_obj.get_by_name(context, target_db_app.name)
            except exception.KubeAppAlreadyExists as e:
                applied_app.status = constants.APP_APPLY_SUCCESS
                applied_app.progress = constants.APP_PROGRESS_COMPLETED
                applied_app.save()
                LOG.exception(e)
                return

        LOG.info("Platform managed application %s: "
                 "Auto updating..." % target_app.name)
        hook_info = LifecycleHookInfo()
        hook_info.mode = constants.APP_LIFECYCLE_MODE_AUTO
        greenthread.spawn(self.perform_app_update, context, applied_app,
                          target_app, tarball.tarball_name, operation, hook_info)

    def _search_tarfile(self, app_name, managed_app):
        """Search a specified application tarfile from the directory
           containing apps bundled with the iso"""

        tarfiles = []
        for f in os.listdir(constants.HELM_APP_ISO_INSTALL_PATH):
            if re.match('{}-[^-]*-[^-]*.tgz'.format(app_name), f):
                tarfiles.append(f)

        if not tarfiles:
            if managed_app:
                LOG.error("Failed to find an application tarball for {}.".format(app_name))
            return None
        elif len(tarfiles) > 1:
            LOG.error("Found multiple application tarballs for {}.".format(app_name))
            return None
        tarball_name = '{}/{}'.format(
            constants.HELM_APP_ISO_INSTALL_PATH, tarfiles[0])
        return tarball_name

    def _check_tarfile(self, app_name, tarball_name, preserve_metadata=False):
        """Extract/Verify a given application tarfile

        :params app_name: application name
        :params tarball_name: absolute path of app tarfile
        :params preserve_metadata: preserve app metadata in the
                                   returned tuple when true
        :returns: a namedtuple
        """

        with cutils.TempDirectory() as app_path:
            if not cutils.extract_tarfile(app_path, tarball_name):
                LOG.error("Failed to extract tar file {}.".format(
                    os.path.basename(tarball_name)))
                return AppTarBall(tarball_name, None, None, None, None, None)

            # If checksum file is included in the tarball, verify its contents.
            if not cutils.verify_checksum(app_path):
                LOG.error("Checksum validation failed for %s." % app_name)
                return AppTarBall(tarball_name, None, None, None, None, None)

            try:
                name, version, patches = \
                    self._kube_app_helper._verify_metadata_file(
                        app_path, app_name, None)
                manifest_name, manifest_file = \
                    self._kube_app_helper._find_manifest(app_path, app_name)
                self._kube_app_helper._extract_helm_charts(app_path)
            except exception.SysinvException as e:
                LOG.error("Extracting tarfile for %s failed: %s." % (
                    app_name, str(e)))
                return AppTarBall(tarball_name, None, None, None, None, None)

            if preserve_metadata:
                metadata_file = os.path.join(app_path,
                                             constants.APP_METADATA_FILE)
                if os.path.exists(metadata_file):
                    with io.open(metadata_file, 'r', encoding='utf-8') as f:
                        # The RoundTripLoader removes the superfluous quotes by default.
                        # Set preserve_quotes=True to preserve all the quotes.
                        # The assumption here: there is just one yaml section
                        metadata = yaml.load(
                                f, Loader=yaml.RoundTripLoader, preserve_quotes=True)
                        return AppTarBall(tarball_name, name, version,
                                          manifest_name, manifest_file, metadata)

            LOG.debug("Tar file of application %s verified." % app_name)
            return AppTarBall(tarball_name, name, version,
                                manifest_name, manifest_file, None)

    def _patching_operation_is_occurring(self):
        # Makes sure a patching operation is not currently underway. We want
        # all hosts to be patch-current before taking any application
        # actions
        #
        # Execute this check in a function as the rest_api has info logs on
        # the request/response. Call this only when an action will occur and
        # not on in every audit cycle
        try:
            self._kube_app_helper._check_patching_operation()
            return False
        except exception.SysinvException as e:
            LOG.info("{}. Patching operations are in progress. Suspending "
                        "actions on platform managed application until patching is "
                        "completed.".format(e))
        except Exception as e:
            LOG.error("{}. Communication Error with patching subsystem. "
                        "Preventing managed application actions.".format(e))
        return True

    def _auto_recover_managed_app(self, context, app_name):
        try:
            app = kubeapp_obj.get_by_name(context, app_name)
        except exception.KubeAppNotFound as e:
            LOG.exception(e)
            return

        if self._app.is_app_aborted(app_name):
            return

        if constants.APP_PROGRESS_IMAGES_DOWNLOAD_FAILED not in app.progress:
            return

        if app.recovery_attempts >= constants.APP_AUTO_RECOVERY_MAX_COUNT:
            return

        tz = app.updated_at.tzinfo
        if (datetime.now(tz) - app.updated_at).total_seconds() \
                < CONF.conductor.managed_app_auto_recovery_interval:
            return

        app.status = constants.APP_UPLOAD_SUCCESS
        LOG.info("Reset managed application %s status to %s",
                app_name, app.status)
        app.recovery_attempts += 1
        app.save()
        self._auto_apply_managed_app(context, app_name)

    def _load_metadata_of_missing_apps(self):
        """ Load metadata of apps from the directory containing
        apps bundled with the iso.
        """
        for tarfile in os.listdir(constants.HELM_APP_ISO_INSTALL_PATH):
            # Get the app name from the tarball name
            # If the app has the metadata loaded already, by conductor restart,
            # then skip the tarball extraction
            app_name = None
            pattern = re.compile("^(.*)-([0-9]+\.[0-9]+-[0-9]+)")

            match = pattern.search(tarfile)
            if match:
                app_name = match.group(1)

            if app_name and \
                    app_name in self.apps_metadata[constants.APP_METADATA_APPS]:
                LOG.info("{} metadata already loaded, skip loading from "
                         "the bundled tarball.".format(app_name))
                continue

            # Proceed with extracting the tarball
            tarball_name = '{}/{}'.format(
                constants.HELM_APP_ISO_INSTALL_PATH, tarfile)

            with cutils.TempDirectory() as app_path:
                if not cutils.extract_tarfile(app_path, tarball_name):
                    LOG.error("Failed to extract tar file {}.".format(
                        os.path.basename(tarball_name)))
                    continue

                # If checksum file is included in the tarball, verify its contents.
                if not cutils.verify_checksum(app_path):
                    LOG.error("Checksum validation failed for %s." % tarball_name)
                    continue

                try:
                    name, version, patches = \
                        self._kube_app_helper._verify_metadata_file(
                            app_path, None, None)
                except exception.SysinvException as e:
                    LOG.error("Extracting tarfile for %s failed: %s." % (
                        tarball_name, str(e)))
                    continue

                metadata_file = os.path.join(app_path,
                                             constants.APP_METADATA_FILE)
                if os.path.exists(metadata_file):
                    with io.open(metadata_file, 'r', encoding='utf-8') as f:
                        # The RoundTripLoader removes the superfluous quotes by default.
                        # Set preserve_quotes=True to preserve all the quotes.
                        # The assumption here: there is just one yaml section
                        metadata = yaml.load(
                            f, Loader=yaml.RoundTripLoader, preserve_quotes=True)

                if name and metadata:
                    # Update metadata only if it was not loaded during conductor init
                    # The reason is that we don't want to lose the modified version
                    # by loading the default metadata from the bundled app.
                    kube_app.AppOperator.update_and_process_app_metadata(
                        self.apps_metadata, name, metadata, overwrite=False)

        # Prevent this function from running until conductor restart
        self._has_loaded_missing_apps_metadata = True

    def _k8s_application_images_audit(self, context):
        """
        Make sure that the required images for k8s applications are present
        """

        LOG.debug("Helper Task: _k8s_application_images_audit: Starting")

        try:
            for kapp in self.dbapi.kube_app_get_all():
                if kapp.status == constants.APP_RESTORE_REQUESTED:
                    app = kubeapp_obj.get_by_name(context, kapp.name)

                    LOG.info("Request downloading images for %s: " % kapp.name)
                    app.status = constants.APP_APPLY_IN_PROGRESS
                    app.progress = constants.APP_PROGRESS_DOWNLOAD_IMAGES
                    app.save()

                    greenthread.spawn(self._restore_download_images, app)

        except Exception as e:
            LOG.info("Helper Task: _k8s_application_images_audit: Will retry")
            LOG.exception(e)

        LOG.debug("Helper Task: _k8s_application_images_audit: Finished")

    def check_restoring_apps_in_progress(self):
        """ Check if restoring apps is possible to be in progress """
        try:
            for kapp in self.dbapi.kube_app_get_all():
                if kapp.status == constants.APP_RESTORE_REQUESTED or \
                        kapp.status == constants.APP_APPLY_IN_PROGRESS:
                    return True

            return False
        except Exception as e:
            LOG.exception(e)

        return True

    def _restore_download_images(self, app):
        try:
            rapp = self._app.Application(app)
            self._app.download_images(rapp)

            app.status = constants.APP_APPLY_SUCCESS
            app.progress = constants.APP_PROGRESS_COMPLETED
            app.save()
        except Exception as e:
            LOG.exception(e)
            app.status = constants.APP_RESTORE_REQUESTED
            app.progress = constants.APP_PROGRESS_IMAGES_DOWNLOAD_FAILED
            app.save()

    @staticmethod
    def _check_software_orchestration_in_progress():
        """Returns the progress of upgrades, patches and firmware updates."""

        try:
            vim_resp = vim_api.vim_get_sw_update_strategy(
                None,
                constants.VIM_DEFAULT_TIMEOUT_IN_SECS)
            # A timeout will return None for vim_resp
            if vim_resp is None:
                LOG.info("vim_api get_sw_update_strategy timed out")
                return False
            if vim_resp.get('sw-update-type') is not None and \
               vim_resp.get('in-progress') is not None:
                return vim_resp['in-progress']
        except Exception as e:
            LOG.warn("Failed vim_api get_sw_update_strategy. (%s)" % str(e))
            return False

        return False

    def _verify_restore_in_progress(self):
        """Check if restore is in progress"""

        try:
            self.dbapi.restore_get_one(
                filters={'state': constants.RESTORE_STATE_IN_PROGRESS})
        except exception.NotFound:
            return False
        else:
            return True

    def _detect_swact_once(self, context):
        """ Detect that a swact occurred to trigger a reapply evaluation
        """
        # Detection may be done only once per conductor restart
        if not self._do_detect_swact:
            return

        # No meaning on AIO-SX
        if cutils.is_aio_simplex_system(self.dbapi):
            self._do_detect_swact = False
            return

        new_active = cutils.get_local_controller_hostname()

        # Define file
        file = constants.SYSINV_CONDUCTOR_ACTIVE_PATH

        # Read file
        if os.path.exists(file):
            with open(file, 'r') as reader:
                stored = reader.read()

            # Difference detected
            if stored != new_active:
                LOG.info("Detected swact from {} to {}"
                         "".format(stored, new_active))

                # Save the new active
                with open(file, 'w') as writer:
                    writer.write(new_active)

                # Trigger reapply evaluation
                self.evaluate_apps_reapply(
                    context,
                    trigger={'type': constants.APP_EVALUATE_REAPPLY_TYPE_DETECTED_SWACT})

        else:
            LOG.info("Initial save active controller {}"
                     "".format(new_active))

            # Save the new active
            with open(file, 'w') as writer:
                writer.write(new_active)

        # No need to detect again until conductor restart
        self._do_detect_swact = False

    @periodic_task.periodic_task(spacing=CONF.conductor_periodic_task_intervals.k8s_application,
                                 run_immediately=True)
    def _k8s_application_audit(self, context):
        """Make sure that the required k8s applications are running"""

        LOG.debug("Periodic Task: _k8s_application_audit: Starting")
        # Make sure that the active controller is unlocked/enabled. Only
        # install an application if the controller has been provisioned.
        active_ctrl = utils.HostHelper.get_active_controller(self.dbapi)

        if (active_ctrl is None or
                ((active_ctrl.administrative != constants.ADMIN_UNLOCKED) or
                 (active_ctrl.operational != constants.OPERATIONAL_ENABLED))):
            return

        if not self.check_nodes_stable():
            LOG.info("Node(s) are in an unstable state. Defer audit.")
            return

        # Defer platform managed application activity during update orchestration.
        if self._check_software_orchestration_in_progress():
            LOG.debug("Software update orchestration in progress. Defer audit.")
            return

        if self._verify_restore_in_progress():
            self._k8s_application_images_audit(context)
            LOG.info("Restore in progress - defer platform managed application "
                     "activity")
            return

        # Ensure that FluxCD pods are ready.
        if not self._app.check_fluxcd_pod_status():
            LOG.warning("FluxCD pods are not ready. Defer audit.")
            return

        # Defer platform managed application activity while an upgrade is active
        try:
            self.verify_upgrade_not_in_progress()
        except Exception:
            LOG.info("Upgrade in progress - defer platform managed application "
                     "activity")
            return

        # Load metadata of apps from predefined directory to allow platform
        # managed apps list to be populated
        # Run only once per conductor start
        if not self._has_loaded_missing_apps_metadata:
            self._load_metadata_of_missing_apps()

        # Detect swact
        self._detect_swact_once(context)

        # cache a database query
        app_statuses = {}

        # Upload missing system apps
        for app_name in self.apps_metadata[constants.APP_METADATA_PLATFORM_MANAGED_APPS].keys():
            # Handle initial loading states
            try:
                app = kubeapp_obj.get_by_name(context, app_name)
                app_statuses[app_name] = app.status
            except exception.KubeAppNotFound:
                app_statuses[app_name] = constants.APP_NOT_PRESENT

            if app_statuses[app_name] == constants.APP_NOT_PRESENT:
                if app_name in self.apps_metadata[constants.APP_METADATA_DESIRED_STATES].keys() and \
                        self.apps_metadata[constants.APP_METADATA_DESIRED_STATES][
                            app_name] in [constants.APP_UPLOAD_SUCCESS, constants.APP_APPLY_SUCCESS]:
                    self._auto_upload_managed_app(context, app_name)

        # Check the application state and take the appropriate action
        # App applies need to be done in a specific order
        for app_name in self.determine_apps_reapply_order(name_only=True, filter_active=False):
            if app_name not in self.apps_metadata[constants.APP_METADATA_PLATFORM_MANAGED_APPS].keys():
                continue

            status = app_statuses[app_name]
            LOG.debug("Platform managed application %s: %s" % (app_name, status))

            if status == constants.APP_UPLOAD_IN_PROGRESS:
                # Action: do nothing
                pass
            elif status == constants.APP_UPLOAD_FAILURE:
                # Action: Raise alarm?
                pass
            elif status == constants.APP_UPLOAD_SUCCESS:
                if app_name in self.apps_metadata[constants.APP_METADATA_DESIRED_STATES].keys() and \
                        self.apps_metadata[constants.APP_METADATA_DESIRED_STATES][
                            app_name] == constants.APP_APPLY_SUCCESS:
                    self._auto_apply_managed_app(context, app_name)
            elif status == constants.APP_APPLY_IN_PROGRESS:
                # Action: do nothing
                pass
            elif status == constants.APP_APPLY_FAILURE:
                self._auto_recover_managed_app(context, app_name)
            elif status == constants.APP_APPLY_SUCCESS:
                self.check_pending_app_reapply(context)
                self._auto_update_app(context, app_name, managed_app=True)

        # Special case, we want to apply some logic to non-managed applications
        for app_name in self.apps_metadata[constants.APP_METADATA_APPS].keys():
            if app_name in self.apps_metadata[constants.APP_METADATA_PLATFORM_MANAGED_APPS].keys():
                continue

            # Handle initial loading states
            status = constants.APP_NOT_PRESENT
            try:
                app = kubeapp_obj.get_by_name(context, app_name)
                status = app.status
            except exception.KubeAppNotFound:
                pass

            LOG.debug("Platform non-managed application %s: %s" % (app_name, status))

            # Automatically update non-managed applications
            if status == constants.APP_APPLY_SUCCESS:
                self.check_pending_app_reapply(context)
                self._auto_update_app(context, app_name, managed_app=False)

        LOG.debug("Periodic Task: _k8s_application_audit: Finished")

    def check_pending_app_reapply(self, context):
        if self._verify_restore_in_progress():
            LOG.info("Restore in progress - Ignore app reapply checks.")
            return

        # Defer application reapply while an upgrade is active
        try:
            self.verify_upgrade_not_in_progress()
        except Exception:
            LOG.info("Upgrade in progress - Ignore app reapply checks")
            return

        # Defer application reapply during update orchestration
        if self._check_software_orchestration_in_progress():
            LOG.info("Software update orchestration in progress. "
                     "Ignore app reapply checks.")
            return

        # Pick first app that needs to be re-applied
        for index, app_name in enumerate(
                self.determine_apps_reapply_order(name_only=True, filter_active=False)):
            if self._app.needs_reapply(app_name):
                break
        else:
            # No app needs reapply
            return
        if not self.check_nodes_stable():
            LOG.info("%s requires re-apply but there are "
                     "currently node(s) in an unstable state. Will "
                     "retry on next audit", app_name)
            return

        self._inner_sync_auto_apply(context, app_name, status_constraints=[constants.APP_APPLY_SUCCESS])

    @cutils.synchronized(LOCK_APP_AUTO_MANAGE)
    def _inner_sync_auto_apply(self, context, app_name, status_constraints=None):

        # Check no other app apply is in progress
        for other_app in self.dbapi.kube_app_get_all():
            if other_app.status == constants.APP_APPLY_IN_PROGRESS:
                LOG.info("%s requires re-apply but %s "
                            "apply is in progress. "
                            "Will retry on next audit",
                         app_name, other_app.name)
                return

        # Check app is present
        try:
            app = kubeapp_obj.get_by_name(context, app_name)
        except exception.KubeAppNotFound:
            LOG.info("%s app not present, skipping re-apply" % app_name)
            return

        # Check status conditions list
        if status_constraints and app.status not in status_constraints:
            LOG.info("{} app is present but status {} isn't any of the desired {}, "
                     "skipping re-apply"
                     .format(app_name, app.status, status_constraints))
            return

        LOG.info("Auto reapplying %s app" % app_name)
        app.status = constants.APP_APPLY_IN_PROGRESS
        app.save()

        lifecycle_hook_info = LifecycleHookInfo()
        lifecycle_hook_info.mode = constants.APP_LIFECYCLE_MODE_AUTO
        greenthread.spawn(self.perform_app_apply, context,
                          app, app.mode, lifecycle_hook_info)

    def _upgrade_downgrade_kube_components(self):
        self._upgrade_downgrade_static_images()
        self._upgrade_downgrade_kube_networking()

    @retry(retry_on_result=lambda x: x is False,
           wait_fixed=(CONF.conductor.kube_upgrade_downgrade_retry_interval * 1000))
    @cutils.synchronized(LOCK_IMAGE_PULL)
    def _upgrade_downgrade_kube_networking(self):
        try:
            # Get the kubernetes version from the upgrade table
            # if an upgrade exists
            kube_upgrade = self.dbapi.kube_upgrade_get_one()
            kube_version = \
                kubernetes.get_kube_networking_upgrade_version(kube_upgrade)
        except exception.NotFound:
            # Not upgrading kubernetes, get the kubernetes version
            # from the kubeadm config map
            kube_version = self._kube.kube_get_kubernetes_version()

        if not kube_version:
            LOG.error("Unable to get the current kubernetes version.")
            return False

        try:
            LOG.info("_upgrade_downgrade_kube_networking executing"
                     " playbook: %s for version %s" %
                     (constants.ANSIBLE_KUBE_NETWORKING_PLAYBOOK, kube_version))

            playbook_cmd = ['ansible-playbook', '-e', 'kubernetes_version=%s' % kube_version,
                            constants.ANSIBLE_KUBE_NETWORKING_PLAYBOOK]
            returncode = cutils.run_playbook(playbook_cmd)

            if returncode:
                raise Exception("ansible-playbook returned an error: %s" % returncode)
        except Exception as e:
            LOG.error("Failed to upgrade/downgrade kubernetes "
                      "networking images: {}".format(e))
            return False

        return True

    @retry(retry_on_result=lambda x: x is False,
           wait_fixed=(CONF.conductor.kube_upgrade_downgrade_retry_interval * 1000))
    @cutils.synchronized(LOCK_IMAGE_PULL)
    def _upgrade_downgrade_static_images(self):
        try:
            # Get the kubernetes version from the upgrade table
            # if an upgrade exists
            kube_upgrade = self.dbapi.kube_upgrade_get_one()
            kube_version = \
                kubernetes.get_kube_networking_upgrade_version(kube_upgrade)
        except exception.NotFound:
            # Not upgrading kubernetes, get the kubernetes version
            # from the kubeadm config map
            kube_version = self._kube.kube_get_kubernetes_version()

        if not kube_version:
            LOG.error("Unable to get the current kubernetes version.")
            return False

        try:
            LOG.info("_upgrade_downgrade_kube_static_images executing"
                     " playbook: %s for version %s" %
                     (constants.ANSIBLE_KUBE_STATIC_IMAGES_PLAYBOOK, kube_version))

            playbook_cmd = ['ansible-playbook', '-e', 'kubernetes_version=%s' % kube_version,
                            constants.ANSIBLE_KUBE_STATIC_IMAGES_PLAYBOOK]
            returncode = cutils.run_playbook(playbook_cmd)

            if returncode:
                raise Exception("ansible-playbook returned an error: %s" % returncode)
        except Exception as e:
            LOG.error("Failed to upgrade/downgrade kubernetes "
                      "static images: {}".format(e))
            return False

        return True

    def check_nodes_stable(self):
        """Check if the nodes are in a stable state in order to allow apps to be applied"""
        try:
            hosts = self.dbapi.ihost_get_list()
            for host in hosts:
                if host.availability == constants.AVAILABILITY_INTEST:
                    return False
                if host.task:
                    return False
                if (host.personality == constants.CONTROLLER and
                        not host.vim_progress_status.startswith(
                            constants.VIM_SERVICES_ENABLED)):
                    return False
        except Exception as e:
            LOG.warn("Failed check_nodes_stable. (%s)" % str(e))
            return False

        return True

    def get_k8s_namespaces(self, context):
        """ Get Kubernetes namespaces
        :returns: list of namespaces
        """
        try:
            cmd = ['kubectl',
                   '--kubeconfig={}'.format(kubernetes.KUBERNETES_ADMIN_CONF),
                   'get', 'namespaces', '-o',
                   'go-template=\'{{range .items}}{{.metadata.name}}\'{{end}}\'']
            stdout, stderr = cutils.execute(*cmd, run_as_root=False)
            namespaces = [n for n in stdout.split("\'") if n]
            return namespaces
        except exception.ProcessExecutionError as e:
            raise exception.SysinvException(
                _("Error getting Kubernetes list of namespaces, "
                  "Details: %s") % str(e))

    def configure_isystemname(self, context, systemname):
        """Configure the systemname with the supplied data.

        :param context: an admin context.
        :param systemname: the systemname
        """

        LOG.debug("configure_isystemname: sending systemname to agent(s)")
        rpcapi = agent_rpcapi.AgentAPI()
        rpcapi.configure_isystemname(context, systemname=systemname)

        return

    def get_ceph_tier_size(self, context, tier_name):
        """Get the usage information for a specific ceph tier."""

        if not StorageBackendConfig.has_backend_configured(
                self.dbapi,
                constants.CINDER_BACKEND_CEPH):
            return 0

        if self._ceph is None:
            return 0

        if not self._ceph.get_ceph_cluster_info_availability():
            return 0

        tiers_dict = self._ceph.get_ceph_tiers_size()
        tier_root = tier_name + constants.CEPH_CRUSH_TIER_SUFFIX
        return tiers_dict.get(tier_root, 0)

    def get_ceph_pools_df_stats(self, context):
        """Get the usage information for the ceph pools."""
        if not StorageBackendConfig.has_backend_configured(
                self.dbapi,
                constants.CINDER_BACKEND_CEPH):
            return

        if self._ceph is None:
            return

        if not self._ceph.get_ceph_cluster_info_availability():
            return

        return self._ceph.get_pools_df_stats()

    def get_ceph_cluster_df_stats(self, context):
        """Get the usage information for the ceph pools."""
        if not StorageBackendConfig.has_backend_configured(
               self.dbapi,
               constants.CINDER_BACKEND_CEPH):
            return

        if self._ceph is None:
            return

        if not self._ceph.get_ceph_cluster_info_availability():
            return

        return self._ceph.get_cluster_df_stats()

    def get_cinder_lvm_usage(self, context):
        """Get the usage information for the LVM pools."""

        if StorageBackendConfig.has_backend_configured(
                self.dbapi, constants.SB_TYPE_LVM):
            pools = self._openstack.get_cinder_pools()
            for pool in pools:
                if (getattr(pool, 'volume_backend_name', '') ==
                        constants.CINDER_BACKEND_LVM):
                    return pool.to_dict()

        return None

    def get_cinder_volume_type_names(self, context):
        """Get the names of all currently defined cinder volume types."""

        volume_types_list = self._openstack.get_cinder_volume_types()
        return [t.name for t in volume_types_list]

    def _ipv_replace_disk(self, pv_id):
        """Handle replacement of the disk this physical volume is attached to.
        """
        # Not sure yet what the proper response is here
        pass

    def get_ceph_pool_replication(self, context, ceph_backend=None):
        """Get ceph storage backend pool replication parameters

        :param context: request context.
        :param ceph_backend: ceph backend object type
        :returns: tuple with (replication, min_replication)
        """
        return StorageBackendConfig.get_ceph_pool_replication(self.dbapi, ceph_backend)

    def delete_osd_pool(self, context, pool_name):
        """delete an OSD pool

        :param context: request context
        :parm pool_name: pool to delete
        """

        response = self._ceph.delete_osd_pool(pool_name)

        return response

    def list_osd_pools(self, context):
        """list all OSD pools

        :param context: request context
        :returns: a list of ceph pools
        """

        response = self._ceph.list_osd_pools()

        return response

    def unconfigure_osd_istor(self, context, istor_obj):
        """Synchronously, have a conductor unconfigure an OSD istor.

        Does the following tasks:
        - Removes the OSD from the crush map.
        - Deletes the OSD's auth key.
        - Deletes the OSD.

        :param context: request context.
        :param istor_obj: an istor object.
        """

        if istor_obj['osdid'] is None:
            LOG.info("OSD not assigned - nothing to do")
            return

        LOG.info("About to delete OSD with osdid:%s", str(istor_obj['osdid']))

        # Mark the OSD down in case it is still up
        self._ceph.mark_osd_down(istor_obj['osdid'])

        # Remove the OSD from the crush map
        self._ceph.osd_remove_crush_auth(istor_obj['osdid'])

        # Remove the OSD
        response, body = self._ceph_osd_remove(
            istor_obj['osdid'], body='json')
        if not response.ok:
            LOG.error("OSD remove failed for OSD %s: %s",
                      "osd." + str(istor_obj['osdid']), response.reason)
            response.raise_for_status()

    # @staticmethod can't be used with @retry decorator below because
    # it raises a "'staticmethod' object is not callable" exception
    def _osd_must_be_down(result):  # pylint: disable=no-self-argument
        response, body = result  # pylint: disable=unpacking-non-sequence
        if not response.ok:
            LOG.error("OSD remove failed: {}".format(body))
        if (response.status_code == httplib.BAD_REQUEST and
            isinstance(body, dict) and
            body.get('status', '').endswith(
                    "({})".format(-errno.EBUSY))):
            LOG.info("Retry OSD remove")
            return True
        else:
            return False

    @retry(retry_on_result=_osd_must_be_down,
           stop_max_attempt_number=CONF.conductor.osd_remove_retry_count,
           wait_fixed=(CONF.conductor.osd_remove_retry_interval * 1000))
    def _ceph_osd_remove(self, *args, **kwargs):
        return self._ceph.osd_remove(*args, **kwargs)

    def kill_ceph_storage_monitor(self, context):
        """Stop the ceph storage monitor.
        pmon will not restart it.
        This should only be used in an upgrade/rollback.
        This should not be called for an AIO (SX or DX).

        :param context: request context.
        """
        try:
            with open(os.devnull, "w") as fnull:
                subprocess.check_call(["mv", "/etc/pmon.d/ceph.conf",  # pylint: disable=not-callable
                                      "/etc/pmond.ceph.conf.bak"],
                                      stdout=fnull, stderr=fnull)

                subprocess.check_call(["systemctl", "restart", "pmon"],  # pylint: disable=not-callable
                                      stdout=fnull, stderr=fnull)

                subprocess.check_call(["/etc/init.d/ceph", "stop", "mon"],  # pylint: disable=not-callable
                                      stdout=fnull, stderr=fnull)

                subprocess.check_call(["mv", "/etc/services.d/controller/ceph.sh",  # pylint: disable=not-callable
                                       "/etc/services.d.controller.ceph.sh"],
                                      stdout=fnull, stderr=fnull)
        except subprocess.CalledProcessError as e:
            LOG.exception(e)
            raise exception.SysinvException(
                _("Unable to shut down ceph storage monitor."))

    def update_dns_config(self, context):
        """Update the DNS configuration"""
        personalities = [constants.CONTROLLER]
        config_uuid = self._config_update_hosts(context, personalities)
        config_dict = {
            "personalities": personalities,
            "classes": ['platform::dns::resolv::runtime'],
        }
        self._config_apply_runtime_manifest(context, config_uuid, config_dict)

    # TODO(fcorream): update_platform_nfs_ip_references is just necessary to allow
    # an upgrade from StarlingX releases 6 or 7 to new releases.
    # remove it when StarlingX rel. 6 or 7 are not being used anymore
    def update_platform_nfs_ip_references(self, context):
        """Update platform nfs ip references during upgrade"""

        address_name = cutils.format_address_name('controller-platform-nfs',
                                                  constants.NETWORK_TYPE_MGMT)

        if not cutils.is_aio_simplex_system(self.dbapi):
            personalities = [constants.CONTROLLER]

            config_uuid = self._config_update_hosts(context, personalities)
            config_dict = {
                 "personalities": personalities,
                 "classes": ['platform::network::update_platform_nfs_ip_references'],
            }
            self._config_apply_runtime_manifest(context, config_uuid, config_dict)

        try:
            # remove IP address from DB
            address_uuid = self.dbapi.address_get_by_name(address_name).uuid
            self.dbapi.address_destroy(address_uuid)
            LOG.info("{} removed from addresses DB".format(address_name))
        except exception.AddressNotFoundByName:
            LOG.info("exception: AddressNotFoundByName: {}".format(address_name))
        except exception.AddressNotFound:
            LOG.info("exception: AddressNotFound: {}".format(address_name))
        except Exception as e:
            LOG.exception(e)
            LOG.error("exception: address: {} could not be deleted".format(address_name))

    def update_clock_synchronization_config(self, context, host):
        """Update clock_synchronization configuration of a host"""
        personalities = [host.get('personality')]
        self._config_update_hosts(context, personalities, [host.get('uuid')],
                                  reboot=True)

    def update_ntp_config(self, context):
        """Update the NTP configuration"""
        personalities = [constants.CONTROLLER,
                         constants.WORKER,
                         constants.STORAGE]
        self._config_update_hosts(context, personalities, reboot=True)

    def update_ptp_config(self, context, do_apply=False):
        """Update the PTP configuration"""
        self._update_ptp_host_configs(context, do_apply)

    def _update_ptp_host_configs(self, context, do_apply=False):
        """Issue config updates to hosts with ptp clocks"""

        # With deprecation of single-instance PTP API, this call is now
        # supposed to happen only when a PTP service parameter is DELETED
        # (with do_apply=False)
        personalities = [constants.CONTROLLER,
                         constants.WORKER,
                         constants.STORAGE]

        hosts = self.dbapi.ihost_get_list()
        ptp_hosts = [host.uuid for host in hosts if host.clock_synchronization == constants.PTP]

        if ptp_hosts:
            self._config_update_hosts(context, personalities, host_uuids=ptp_hosts)
            if do_apply:
                LOG.warning("Legacy PTP configuration is DEPRECATED")

    def _update_ptp_create_instance(self, name, service):
        values = dict(name=name, service=service)
        new_ptp_instance = self.dbapi.ptp_instance_create(values)
        LOG.debug("Created PTP instance %s id %d uuid %s" %
                  (name, new_ptp_instance.id, new_ptp_instance.uuid))
        return (new_ptp_instance.id, new_ptp_instance.uuid)

    def _update_ptp_create_interface(self, name, instance_id):
        values = dict(name=name, ptp_instance_id=instance_id)
        new_ptp_interface = self.dbapi.ptp_interface_create(values)
        LOG.debug("Created PTP interface %s id %d uuid %s" %
                  (name, new_ptp_interface.id, new_ptp_interface.uuid))
        return new_ptp_interface.id

    def _update_ptp_add_parameter_to_instance(self, instance_uuid, name, value):
        try:
            ptp_parameter = self.dbapi.ptp_parameter_get_by_namevalue(name,
                                                                      value)
        except exception.NotFound:
            values = dict(name=name, value=value)
            LOG.debug("Creating PTP parameter %s=%s" % (name, value))
            ptp_parameter = self.dbapi.ptp_parameter_create(values)

        param_uuid = ptp_parameter.uuid
        self.dbapi.ptp_instance_parameter_add(instance_uuid, param_uuid)
        LOG.debug("Adding PTP parameter %s to %s" %
                  (param_uuid, instance_uuid))

    def _update_ptp_assign_instance_to_host(self, instance_id, host_id):
        values = dict(host_id=host_id, ptp_instance_id=instance_id)
        self.dbapi.ptp_instance_assign(values)
        LOG.debug("Assigned PTP instance %d to host %d" %
                  (instance_id, host_id))

    def _update_ptp_assign_ptp_to_interface(self,
                                            ptp_interface_id,
                                            interface_id):
        values = dict(interface_id=interface_id,
                      ptp_interface_id=ptp_interface_id)
        self.dbapi.ptp_interface_assign(values)
        LOG.debug("Assigned PTP interface %d to interface %d" %
                  (ptp_interface_id, interface_id))

    def _update_ptp_parameters(self):
        """This function moves PTP legacy configuration from other tables. Once
        it is done, the subsequent calls will find the generated PTP instance at
        database and will return quickly.
        The following is moved from some tables to others:
        - Global (system-wide) ptp4l configuration in 'ptp' table, by creating
          a "legacy" 'ptp4l' entry in 'ptp_instances' table and inserting the
          corresponding entries in 'ptp_parameters';
        - If advanced (specialized) ptp4l configuration is found in
          'service_parameter' table, it inserts the corresponding entry(ies) in
          'ptp_parameters' and refers to the "legacy" 'ptp4l' instance created
           for global (system-wide) configuration;
        - If phc2sys configuration is found in 'service_parameter' table, it
          inserts a 'phc2sys' entry in 'ptp_instances' table and inserts the
          corresponding entry(ies) in 'ptp_parameters';
        - If any interface has 'ptp_role' not equal to 'none', it inserts a
          'ptp4l' entry in 'ptp_instances' and inserts the corresponding entry
          in 'ptp_parameters'.
        """
        # TODO: this method is supposed to be called in the context of the same
        # patch that is deprecating the former PTP APIs. Thus, in a future
        # release (probably the next one) it can be removed
        check_file = tsc.PTP_UPDATE_PARAMETERS_FLAG
        if os.path.isfile(check_file):
            LOG.debug("Already done with legacy PTP configuration")
            return

        # Add check file to avoid re-running this method (with late creation of
        # legacy instances)
        open(check_file, 'w').close()

        try:
            # This additional check ensures that patch re-apply won't fail
            # because legacy entries weren't removed together with the check
            # file and the patch itself, when it got removed earlier
            legacy_names = [constants.PTP_INSTANCE_LEGACY_PTP4L,
                            constants.PTP_INSTANCE_LEGACY_PHC2SYS]
            for name in legacy_names:
                try:
                    ptp_instance = self.dbapi.ptp_instance_get_by_name(name)
                    LOG.info("Legacy PTP instance %s found with id = %s, "
                             "skipping update" % (name, ptp_instance['id']))
                    return
                except exception.NotFound:
                    LOG.debug("Legacy PTP instance %s not found" % name)

            # List all the hosts with clock_synchronization=ptp
            hosts_list = self.dbapi.ihost_get_list()
            ptp_hosts_list = [
                host
                for host in hosts_list
                if host['clock_synchronization'] == constants.PTP]
            LOG.debug("There are %d hosts with clock_synchronization=ptp" %
                      len(ptp_hosts_list))

            # List all PTP parameters in service-parameters table (to be
            # migrated)
            ptp_svc_parameters_list = self.dbapi.service_parameter_get_all(
                service=constants.SERVICE_TYPE_PTP)
            LOG.debug("There are %d PTP rows in 'service_parameter' table" %
                      len(ptp_svc_parameters_list))

            if len(ptp_hosts_list) == 0 and len(ptp_svc_parameters_list) == 0:
                # No need for upgrade
                return

            # List all the interfaces with ptp_role!=none
            ifaces_list = self.dbapi.iinterface_get_list()
            ptp_ifaces_list = [
                iface
                for iface in ifaces_list
                if iface['ptp_role'] != constants.INTERFACE_PTP_ROLE_NONE]
            LOG.debug("There are %d interfaces with ptp_role != none" %
                      len(ptp_ifaces_list))

            LOG.info("Creating PTP instances for legacy parameters")

            # Take system-wide parameters from legacy configuration
            ptp_config = self.dbapi.ptp_get_one()  # there is a single entry
            delay_mechanism = str(ptp_config.mechanism).upper()
            time_stamping = str(ptp_config.mode).lower()
            network_transport = str(ptp_config.transport).upper()

            # Legacy instance for system-wide parameters and those of section
            # "global" in service-parameters table
            (ptp4l_id, ptp4l_uuid) = self._update_ptp_create_instance(
                constants.PTP_INSTANCE_LEGACY_PTP4L,
                constants.PTP_INSTANCE_TYPE_PTP4L)

            # Legacy PTP interface associated to legacy ptp4l instance
            ptp4lif_id = self._update_ptp_create_interface(
                constants.PTP_INTERFACE_LEGACY_PTP4L, ptp4l_id)

            # Legacy instance for parameters of section "phc2sys"
            (phc2sys_id, phc2sys_uuid) = self._update_ptp_create_instance(
                constants.PTP_INSTANCE_LEGACY_PHC2SYS,
                constants.PTP_INSTANCE_TYPE_PHC2SYS)

            # Legacy PTP interface associated to legacy phc2sys instance
            phc2sysif_id = self._update_ptp_create_interface(
                constants.PTP_INTERFACE_LEGACY_PHC2SYS, phc2sys_id)

            # Add 'uds_address' parameter to phy2sys instance for linkage with
            # ptp4l instance
            uds_address_path = \
                '/var/run/ptp4l-%s' % constants.PTP_INSTANCE_LEGACY_PTP4L
            self._update_ptp_add_parameter_to_instance(
                phc2sys_uuid,
                constants.PTP_PARAMETER_UDS_ADDRESS,
                uds_address_path)

            # Assign legacy instances to all hosts with
            # clock_synchronization=ptp
            for host in ptp_hosts_list:
                self._update_ptp_assign_instance_to_host(ptp4l_id, host['id'])
                self._update_ptp_assign_instance_to_host(phc2sys_id, host['id'])

            # Assign legacy PTP interfaces to all interfaces with ptp_role!=none
            for iface in ptp_ifaces_list:
                self._update_ptp_assign_ptp_to_interface(ptp4lif_id,
                                                         iface['id'])
                self._update_ptp_assign_ptp_to_interface(phc2sysif_id,
                                                         iface['id'])

            # Copy service-parameter PTP entries, if any
            domain_number = constants.PTP_PARAMETER_DEFAULT_DOMAIN
            for param in ptp_svc_parameters_list:

                if param['name'] == constants.PTP_PARAMETER_UPDATE_RATE or \
                        (param['name'] ==
                         constants.PTP_PARAMETER_SUMMARY_UPDATES):
                    LOG.info("Found %s parameter, ignored" % param['name'])
                    continue

                if param['name'] == constants.PTP_PARAMETER_DOMAIN_NUMBER:
                    domain_number = param['value']  # overwrite default
                    continue  # skip it for below

                if param['name'] == constants.PTP_PARAMETER_DELAY_MECHANISM:
                    delay_mechanism = str(param['value']).upper()  # overwrite
                    continue  # skip it for below

                if param['name'] == constants.PTP_PARAMETER_TIME_STAMPING:
                    time_stamping = str(param['value']).lower()  # overwrite
                    continue  # skip it for below

                if param['name'] == constants.PTP_PARAMETER_NETWORK_TRANSPORT:
                    network_transport = str(param['value']).upper()  # overwrt
                    continue  # skip it for below

                if param['section'] == \
                        constants.SERVICE_PARAM_SECTION_PTP_GLOBAL:
                    owner_uuid = ptp4l_uuid
                elif param['section'] == \
                        constants.SERVICE_PARAM_SECTION_PTP_PHC2SYS:
                    owner_uuid = phc2sys_uuid
                else:
                    raise Exception("Unexpected PTP section in "
                                    "'service-parameter' table")

                self._update_ptp_add_parameter_to_instance(owner_uuid,
                                                           param['name'],
                                                           param['value'])

                # Whatever 'global' parameter has been found, it must be
                # added also to phc2sys instance, since now this has own
                # configuration file
                if param['section'] == \
                        constants.SERVICE_PARAM_SECTION_PTP_GLOBAL:
                    self._update_ptp_add_parameter_to_instance(phc2sys_uuid,
                                                               param['name'],
                                                               param['value'])

            self._update_ptp_add_parameter_to_instance(
                ptp4l_uuid,
                constants.PTP_PARAMETER_DOMAIN_NUMBER,
                domain_number)
            self._update_ptp_add_parameter_to_instance(
                phc2sys_uuid,
                constants.PTP_PARAMETER_DOMAIN_NUMBER,
                domain_number)
            self._update_ptp_add_parameter_to_instance(
                ptp4l_uuid,
                constants.PTP_PARAMETER_DELAY_MECHANISM,
                delay_mechanism)
            self._update_ptp_add_parameter_to_instance(
                phc2sys_uuid,
                constants.PTP_PARAMETER_DELAY_MECHANISM,
                delay_mechanism)
            self._update_ptp_add_parameter_to_instance(
                ptp4l_uuid,
                constants.PTP_PARAMETER_TIME_STAMPING,
                time_stamping)
            self._update_ptp_add_parameter_to_instance(
                phc2sys_uuid,
                constants.PTP_PARAMETER_TIME_STAMPING,
                time_stamping)
            self._update_ptp_add_parameter_to_instance(
                ptp4l_uuid,
                constants.PTP_PARAMETER_NETWORK_TRANSPORT,
                network_transport)
            self._update_ptp_add_parameter_to_instance(
                phc2sys_uuid,
                constants.PTP_PARAMETER_NETWORK_TRANSPORT,
                network_transport)

            # Add 'boundary_clock_jbod' parameter to ptp4l instance if mode is
            # "hardware"
            if time_stamping == 'hardware':
                self._update_ptp_add_parameter_to_instance(
                    ptp4l_uuid,
                    constants.PTP_PARAMETER_BC_JBOD,
                    constants.PTP_BOUNDARY_CLOCK_JBOD_1)

        except Exception as e:
            LOG.exception(e)

    def update_ptp_instances_config(self, context):
        personalities = [constants.CONTROLLER,
                         constants.WORKER,
                         constants.STORAGE]
        hosts = self.dbapi.ihost_get_list()
        runtime_hosts = []
        for host in hosts:
            if (host.clock_synchronization == constants.PTP and
                    host.administrative == constants.ADMIN_UNLOCKED and
                    host.operational == constants.OPERATIONAL_ENABLED):
                runtime_hosts.append(host.uuid)

        if runtime_hosts:
            config_dict = {
                "personalities": personalities,
                "classes": ['platform::ptpinstance::runtime'],
                "host_uuids": runtime_hosts
            }
            config_uuid = self._config_update_hosts(context, personalities,
                                                    host_uuids=runtime_hosts)
            self._config_apply_runtime_manifest(context, config_uuid, config_dict)

    def update_system_mode_config(self, context):
        """Update the system mode configuration"""
        personalities = [constants.CONTROLLER]

        # Update manifest files if system mode is updated for simplex to
        # duplex migration
        system = self.dbapi.isystem_get_one()
        if system.capabilities.get('simplex_to_duplex_migration') or \
           system.capabilities.get('simplex_to_duplex-direct_migration'):
            config_uuid = self._config_update_hosts(context, personalities)

            config_dict = {
                "personalities": personalities,
                "classes": ['platform::kubernetes::duplex_migration::runtime'],
            }
            self._config_apply_runtime_manifest(context, config_uuid, config_dict)

        self._config_update_hosts(context, personalities, reboot=True)

    def configure_system_timezone(self, context):
        """Configure the system_timezone with the supplied data.

        :param context: an admin context.
        """

        # update manifest files and notify agents to apply timezone files
        personalities = [constants.WORKER,
                         constants.STORAGE]
        config_uuid = self._config_update_hosts(context, personalities)

        # NOTE: no specific classes need to be specified since the default
        # platform::config will be applied that will configure the timezone
        config_dict = {"personalities": personalities}

        self._config_apply_runtime_manifest(context, config_uuid, config_dict)

        # for controller nodes, we also update the horizon interface
        # so that it can see the new timezone setting
        personalities = [constants.CONTROLLER]
        config_uuid = self._config_update_hosts(context, personalities)
        config_dict = {
            "personalities": personalities,
            "classes": ['openstack::horizon::runtime']
        }
        self._config_apply_runtime_manifest(context, config_uuid, config_dict)

    def delete_flag_file(self, context, flag_file):
        """delete a flag file.

        :param context: an admin context.
        :param flag_file: path to the flag file
        """
        try:
            os.remove(flag_file)
        except OSError:
            LOG.error("Failed to delete %s flag."
                     % flag_file)
            pass

    def update_route_config(self, context, host_id):
        """add or remove a static route

        :param context: an admin context.
        :param host_id: the host id
        """

        # update manifest files and notifiy agents to apply them
        personalities = [constants.CONTROLLER,
                         constants.WORKER,
                         constants.STORAGE]
        host = self.dbapi.ihost_get(host_id)

        config_uuid = self._config_update_hosts(context, personalities,
                                                host_uuids=[host.uuid])
        config_dict = {
            "personalities": personalities,
            'host_uuids': [host.uuid],
            "classes": 'platform::network::routes::runtime',
            puppet_common.REPORT_STATUS_CFG:
                puppet_common.REPORT_ROUTE_CONFIG,
        }

        self._config_apply_runtime_manifest(context, config_uuid, config_dict,
                                            filter_classes=[self.PUPPET_RUNTIME_CLASS_ROUTES])

    def update_sriov_config(self, context, host_uuid):
        """update sriov configuration for a host

        :param context: an admin context
        :param host_uuid: the host uuid
        """

        # update manifest files and notify agent to apply them
        personalities = [constants.CONTROLLER,
                         constants.WORKER]
        config_uuid = self._config_update_hosts(context, personalities,
                                                host_uuids=[host_uuid])

        config_dict = {
            "personalities": personalities,
            'host_uuids': [host_uuid],
            "classes": ['platform::network::interfaces::sriov::runtime',
                        'platform::devices::fpga::fec::runtime'],
            puppet_common.REPORT_INVENTORY_UPDATE:
                puppet_common.REPORT_PCI_SRIOV_CONFIG,
        }

        self._config_apply_runtime_manifest(
            context, config_uuid, config_dict, force=True)

    def update_sriov_vf_config(self, context, host_uuid):
        """update sriov vf configuration for a host

        :param context: an admin context
        :param host_uuid: the host uuid
        """
        # update manifest files and notify agent to apply them
        personalities = [constants.CONTROLLER,
                         constants.WORKER]
        config_uuid = self._config_update_hosts(context, personalities,
                                                host_uuids=[host_uuid])

        config_dict = {
            "personalities": personalities,
            'host_uuids': [host_uuid],
            "classes": ['platform::network::interfaces::sriov::vf::runtime']
        }

        self._config_apply_runtime_manifest(
            context, config_uuid, config_dict, force=True)

    def update_pcidp_config(self, context, host_uuid):
        """update pcidp configuration for a host

        :param context: an admin context
        :param host_uuid: the host uuid
        """
        # update manifest files and notify agent to apply them
        personalities = [constants.CONTROLLER,
                         constants.WORKER]
        config_uuid = self._config_update_hosts(context, personalities,
                                                host_uuids=[host_uuid])

        config_dict = {
            "personalities": personalities,
            'host_uuids': [host_uuid],
            "classes": ['platform::kubernetes::worker::pci::runtime'],
            puppet_common.REPORT_INVENTORY_UPDATE:
                puppet_common.REPORT_PCI_SRIOV_CONFIG,
        }

        self._config_apply_runtime_manifest(
            context, config_uuid, config_dict, force=True)

    def configure_system_https(self, context):
        """Update the system https configuration.

        :param context: an admin context.
        """
        personalities = [constants.CONTROLLER]
        system = self.dbapi.isystem_get_one()

        if system.capabilities.get('https_enabled', False):
            certificates = self.dbapi.certificate_get_list()
            for certificate in certificates:
                if certificate.certtype == constants.CERT_MODE_SSL:
                    break
            else:
                self._config_selfsigned_certificate(context)

        config_dict = {
            "personalities": personalities,
            "classes": ['platform::haproxy::runtime',
                        'openstack::keystone::endpoint::runtime',
                        'openstack::horizon::runtime',
                        'platform::firewall::runtime']
        }

        config_uuid = self._config_update_hosts(context, personalities)
        self._config_apply_runtime_manifest(context, config_uuid, config_dict)

        cutils.touch(constants.HTTPS_CONFIG_REQUIRED)

    @staticmethod
    def _get_oam_runtime_apply_file(standby_controller=False):
        """Get the file which indicates a runtime oam manifest apply is
        required for a controller.
        """
        if standby_controller:
            hostname = cutils.get_mate_controller_hostname()
        else:
            hostname = cutils.get_local_controller_hostname()

        oam_config_required_flag = os.path.join(
            tsc.CONFIG_PATH, '.oam_config_required_') + hostname

        return oam_config_required_flag

    def initialize_oam_config(self, context, host):
        """Initialize a new OAM network configuration"""

        extoam = self.dbapi.iextoam_get_one()

        self._update_hosts_file('oamcontroller', extoam.oam_floating_ip,
                                active=True)

        cutils.touch(os.path.join(
            tsc.CONFIG_PATH, '.oam_config_required_') + host['hostname'])

    def update_oam_config(self, context):
        """Update the OAM network configuration"""

        personalities = [constants.CONTROLLER]
        config_uuid = self._config_update_hosts(context, personalities)

        config_dict = {}
        is_aio_simplex_system = cutils.is_aio_simplex_system(self.dbapi)
        if is_aio_simplex_system:
            # update all necessary config at runtime for AIO-SX
            config_dict = {
                "personalities": personalities,
                "classes": ['platform::network::runtime',
                            'platform::kubernetes::certsans::runtime',
                            'platform::firewall::runtime',
                            'platform::smapi',
                            'platform::sm::update_oam_config::runtime',
                            'platform::nfv::webserver::runtime',
                            'platform::haproxy::runtime',
                            'openstack::keystone::endpoint::runtime::post',
                            'platform::dockerdistribution::config',
                            'platform::dockerdistribution::runtime']
            }
        else:
            # update kube-apiserver cert's SANs at runtime
            config_dict = {
                "personalities": personalities,
                "classes": ['platform::kubernetes::certsans::runtime']
            }

        self._config_apply_runtime_manifest(context, config_uuid, config_dict)

        # there is still pending reboot required config to apply if not AIO-SX
        if not is_aio_simplex_system:
            self._config_update_hosts(context, [constants.CONTROLLER], reboot=True)

        extoam = self.dbapi.iextoam_get_one()

        self._update_hosts_file('oamcontroller', extoam.oam_floating_ip,
                                active=False)

        if not is_aio_simplex_system:
            cutils.touch(
                self._get_oam_runtime_apply_file(standby_controller=True))

    def update_user_config(self, context):
        """Update the user configuration"""
        LOG.info("update_user_config")

        personalities = [constants.CONTROLLER,
                         constants.WORKER,
                         constants.STORAGE]
        config_uuid = self._config_update_hosts(context, personalities)

        config_dict = {
            "personalities": personalities,
            "classes": ['platform::users::runtime']
        }
        self._config_apply_runtime_manifest(context, config_uuid, config_dict)

    def update_controller_rollback_flag(self, context):
        """Update the controller upgrade rollback flag"""
        LOG.info("update_controller_rollback_flag")

        cutils.touch(tsc.UPGRADE_ROLLBACK_FLAG)

    def update_controller_upgrade_flag(self, context):
        """Update the controller upgrade flag"""
        LOG.info("update_controller_upgrade_flag")

        cutils.touch(tsc.CONTROLLER_UPGRADE_FLAG)

    def update_storage_config(self, context,
                              update_storage=False,
                              reinstall_required=False,
                              reboot_required=True,
                              filesystem_list=None):
        """Update the storage configuration"""
        host_uuid_list = []
        if update_storage:
            personalities = [constants.CONTROLLER, constants.STORAGE,
                constants.WORKER]
            ceph_mons = self.dbapi.ceph_mon_get_list()
            for mon in ceph_mons:
                host_uuid_list.append(mon['ihost_uuid'])
        else:
            personalities = [constants.CONTROLLER]

        if reinstall_required:
            self._config_reinstall_hosts(context, personalities)
        else:
            config_uuid = self._config_update_hosts(context,
                                                    personalities,
                                                    host_uuids=host_uuid_list,
                                                    reboot=reboot_required)

            if not reboot_required and filesystem_list:
                # apply the manifest at runtime, otherwise a reboot is required
                # map the updated file system to the runtime puppet class
                classmap = {
                    constants.FILESYSTEM_NAME_DOCKER_DISTRIBUTION:
                        'platform::drbd::dockerdistribution::runtime',
                    constants.FILESYSTEM_NAME_DATABASE:
                        'platform::drbd::pgsql::runtime',
                    constants.FILESYSTEM_NAME_PLATFORM:
                        'platform::drbd::platform::runtime',
                    constants.FILESYSTEM_NAME_EXTENSION:
                        'platform::drbd::extension::runtime',
                    constants.FILESYSTEM_NAME_DC_VAULT:
                        'platform::drbd::dc_vault::runtime',
                    constants.FILESYSTEM_NAME_ETCD:
                        'platform::drbd::etcd::runtime',
                }

                puppet_class = None
                if filesystem_list:
                    puppet_class = [classmap.get(fs) for fs in filesystem_list]
                config_dict = {
                    "personalities": personalities,
                    "classes": puppet_class
                }

                LOG.info("update_storage_config: %s" % config_dict)

                self._config_apply_runtime_manifest(context,
                                                    config_uuid,
                                                    config_dict)

    def update_admin_config(self, context, host):
        """Update the admin network configuration"""

        personalities = [constants.CONTROLLER]
        config_uuid = self._config_update_hosts(context,
                                                personalities,
                                                host_uuids=[host.uuid])
        config_dict = {
            "personalities": personalities,
            "host_uuids": [host['uuid']],
            "classes": ['platform::sm::disable_admin_config::runtime',
                        'platform::sm::update_admin_config::runtime',
                        'platform::network::runtime',
                        'platform::sm::enable_admin_config::runtime',
                        'platform::haproxy::runtime',
                        'openstack::keystone::endpoint::runtime']
        }
        self._config_apply_runtime_manifest(context, config_uuid, config_dict)

    def update_host_filesystem_config(self, context,
                                      host=None,
                                      filesystem_list=None):
        """Update the filesystem configuration for a host"""

        config_uuid = self._config_update_hosts(context,
                                                personalities=host.personality,
                                                host_uuids=[host.uuid])

        LOG.info("update_host_filesystem_config config_uuid=%s" % config_uuid)

        if filesystem_list:
            # map the updated file system to the runtime puppet class
            classmap = {
                constants.FILESYSTEM_NAME_BACKUP:
                    'platform::filesystem::backup::runtime',
                constants.FILESYSTEM_NAME_SCRATCH:
                    'platform::filesystem::scratch::runtime',
                constants.FILESYSTEM_NAME_DOCKER:
                    'platform::filesystem::docker::runtime',
                constants.FILESYSTEM_NAME_KUBELET:
                    'platform::filesystem::kubelet::runtime',
                constants.FILESYSTEM_NAME_IMAGE_CONVERSION:
                    'platform::filesystem::conversion::runtime',
                constants.FILESYSTEM_NAME_INSTANCES:
                    'platform::filesystem::instances::runtime',
                constants.FILESYSTEM_NAME_LOG:
                    'platform::filesystem::log::runtime',
                constants.FILESYSTEM_NAME_VAR:
                    'platform::filesystem::var::runtime',
                constants.FILESYSTEM_NAME_ROOT:
                    'platform::filesystem::root::runtime',
            }

            puppet_class = [classmap.get(fs) for fs in filesystem_list]
            config_dict = {
                "personalities": host.personality,
                "classes": puppet_class,
                "host_uuids": [host.uuid]
            }

            self._config_apply_runtime_manifest(context,
                                                config_uuid,
                                                config_dict)

    def update_lvm_config(self, context):
        personalities = [constants.CONTROLLER]

        config_uuid = self._config_update_hosts(context, personalities)

        config_dict = {
            "personalities": personalities,
            "classes": ['platform::lvm::controller::runtime']
        }

        self._config_apply_runtime_manifest(context,
                                            config_uuid,
                                            config_dict)

    def update_drbd_config(self, context):
        """Update the drbd configuration"""
        LOG.info("update_drbd_config")

        personalities = [constants.CONTROLLER]
        config_uuid = self._config_update_hosts(context, personalities)

        config_dict = {
            "personalities": personalities,
            "classes": ['platform::drbd::runtime']
        }
        self._config_apply_runtime_manifest(context, config_uuid, config_dict)

    def update_external_cinder_config(self, context):
        """Update the manifests for Cinder External(shared) backend"""
        personalities = [constants.CONTROLLER]

        # Retrieve cinder endpoints from primary region
        endpoint_list = self._openstack._get_cinder_endpoints()

        # Update service table
        self.update_service_table_for_cinder(endpoint_list, external=True)

        # TODO (tliu) classes may be removable from the config_dict
        classes = []

        config_dict = {
            "personalities": personalities,
            "classes": classes,
            puppet_common.REPORT_STATUS_CFG: puppet_common.REPORT_EXTERNAL_BACKEND_CONFIG,
        }

        config_uuid = self._config_update_hosts(context,
                                                personalities,
                                                reboot=False)

        self._config_apply_runtime_manifest(context,
                                            config_uuid,
                                            config_dict)

    def update_lvm_cinder_config(self, context):
        """Update the manifests and network config for Cinder LVM backend"""
        personalities = [constants.CONTROLLER]

        # Get active hosts
        # TODO (rchurch): ensure all applicable unlocked hosts have the
        # _config_update_hosts() updated.
        ctrls = self.dbapi.ihost_get_by_personality(constants.CONTROLLER)
        valid_ctrls = [ctrl for ctrl in ctrls if
                       (ctrl.administrative == constants.ADMIN_LOCKED and
                        ctrl.availability == constants.AVAILABILITY_ONLINE) or
                       (ctrl.administrative == constants.ADMIN_UNLOCKED and
                        ctrl.operational == constants.OPERATIONAL_ENABLED)]

        # Create Cinder MGMT ip address, if needed
        self.reserve_ip_for_cinder(context)

        # Update service table
        self.update_service_table_for_cinder()

        classes = ['platform::partitions::runtime',
                   'platform::lvm::controller::runtime',
                   'platform::haproxy::runtime',
                   'platform::drbd::runtime',
                   'platform::sm::norestart::runtime']

        host_ids = [ctrl.uuid for ctrl in valid_ctrls]
        config_dict = {
            "personalities": personalities,
            "classes": classes,
            "host_uuids": host_ids,
            puppet_common.REPORT_STATUS_CFG: puppet_common.REPORT_LVM_BACKEND_CONFIG
        }

        # TODO(oponcea) once sm supports in-service config reload always
        # set reboot=False
        active_controller = utils.HostHelper.get_active_controller(self.dbapi)
        if utils.is_host_simplex_controller(active_controller):
            reboot = False
        else:
            reboot = True

        # Set config out-of-date for controllers
        self._config_update_hosts(context, personalities,
                                  host_uuids=host_ids, reboot=reboot)

        # TODO(oponcea): Set config_uuid to a random value to keep Config out-of-date.
        # Once sm supports in-service config reload set config_uuid=config_uuid.
        self._config_apply_runtime_manifest(context,
                                            str(uuid.uuid4()),
                                            config_dict)

        # Update initial task states
        storage_backends = self.dbapi.storage_backend_get_list()
        for sb in storage_backends:
            if sb.backend == constants.SB_TYPE_LVM:
                tasks = {}
                for ctrl in valid_ctrls:
                    tasks[ctrl.hostname] = constants.SB_STATE_CONFIGURING
                values = {'state': constants.SB_STATE_CONFIGURING,
                          'task': str(tasks)}
                self.dbapi.storage_backend_update(sb.uuid, values)

    def update_service_table_for_cinder(self, endpoints=None, external=False):
        """ Update service table for region name """
        system = self.dbapi.isystem_get_one()
        if system and system.capabilities.get('region_config'):
            cinder_service = self.dbapi.service_get(constants.SERVICE_TYPE_CINDER)
            capabilities = {'service_name': constants.SERVICE_TYPE_CINDER,
                            'service_type': constants.SERVICE_TYPE_VOLUME,
                            'user_name': constants.SERVICE_TYPE_CINDER}
            if endpoints:
                for ep in endpoints:
                    if ep.url.find('/v1/') != -1:
                        if ep.interface == constants.OS_INTERFACE_PUBLIC:
                            capabilities.update({'cinder_public_uri_v1': ep.url})
                        elif ep.interface == constants.OS_INTERFACE_INTERNAL:
                            capabilities.update({'cinder_internal_uri_v1': ep.url})
                        elif ep.interface == constants.OS_INTERFACE_ADMIN:
                            capabilities.update({'cinder_admin_uri_v1': ep.url})
                    elif ep.url.find('/v2/') != -1:
                        if ep.interface == constants.OS_INTERFACE_PUBLIC:
                            capabilities.update({'cinder_public_uri_v2': ep.url})
                        elif ep.interface == constants.OS_INTERFACE_INTERNAL:
                            capabilities.update({'cinder_internal_uri_v2': ep.url})
                        elif ep.interface == constants.OS_INTERFACE_ADMIN:
                            capabilities.update({'cinder_admin_uri_v2': ep.url})
                    elif ep.url.find('/v3/') != -1:
                        if ep.interface == constants.OS_INTERFACE_PUBLIC:
                            capabilities.update({'cinder_public_uri_v3': ep.url})
                        elif ep.interface == constants.OS_INTERFACE_INTERNAL:
                            capabilities.update({'cinder_internal_uri_v3': ep.url})
                        elif ep.interface == constants.OS_INTERFACE_ADMIN:
                            capabilities.update({'cinder_admin_uri_v3': ep.url})

            if external:
                region_name = openstack.get_region_name('region_1_name')
                if region_name is None:
                    region_name = constants.REGION_ONE_NAME
            else:
                region_name = system.region_name

            values = {'enabled': True,
                      'region_name': region_name,
                      'capabilities': capabilities}
            self.dbapi.service_update(cinder_service.name, values)

    def update_install_uuid(self, context, host_uuids, install_uuid):
        """ Update install_uuid on the specified host or hosts """

        LOG.debug("update_install_uuid host_uuids=%s install_uuid=%s "
                  % (host_uuids, install_uuid))
        rpcapi = agent_rpcapi.AgentAPI()
        rpcapi.iconfig_update_install_uuid(context, host_uuids, install_uuid)

    def update_ceph_config(self, context, sb_uuid, services):
        """Update the manifests for Ceph backend and services"""

        personalities = [constants.CONTROLLER]

        # Update service table
        self.update_service_table_for_cinder()

        ctrls = self.dbapi.ihost_get_by_personality(constants.CONTROLLER)
        valid_ctrls = [ctrl for ctrl in ctrls if
                       ctrl.administrative == constants.ADMIN_UNLOCKED and
                       ctrl.availability in [constants.AVAILABILITY_AVAILABLE,
                                             constants.AVAILABILITY_DEGRADED]]
        classes = ['platform::partitions::runtime',
                   'platform::lvm::controller::runtime',
                   'platform::haproxy::runtime',
                   'openstack::keystone::endpoint::runtime',
                   'platform::ceph::runtime_base',
                   ]

        for ctrl in valid_ctrls:
            self._ceph_mon_create(ctrl)

        if cutils.is_aio_duplex_system(self.dbapi):
            # On 2 node systems we have a floating Ceph monitor.
            classes.append('platform::drbd::cephmon::runtime')

        classes.append('platform::sm::ceph::runtime')
        host_ids = [ctrl.uuid for ctrl in valid_ctrls]
        config_dict = {"personalities": personalities,
                       "host_uuids": host_ids,
                       "classes": classes,
                       puppet_common.REPORT_STATUS_CFG: puppet_common.REPORT_CEPH_BACKEND_CONFIG,
                       }

        # Set config out-of-date for controllers
        config_uuid = self._config_update_hosts(context,
                                                personalities,
                                                host_uuids=host_ids)

        self._config_apply_runtime_manifest(context,
                                            config_uuid=config_uuid,
                                            config_dict=config_dict)

        tasks = {}
        for ctrl in valid_ctrls:
            tasks[ctrl.hostname] = constants.SB_TASK_APPLY_MANIFESTS

        # Update initial task states
        values = {'state': constants.SB_STATE_CONFIGURING,
                  'task': str(tasks)}
        self.dbapi.storage_ceph_update(sb_uuid, values)

    def update_ceph_base_config(self, context, personalities):
        """ Update Ceph configuration, monitors and ceph.conf only"""
        valid_nodes = []
        for personality in personalities:
            nodes = self.dbapi.ihost_get_by_personality(personality)
            valid_nodes += [
                node for node in nodes if
                (node.administrative == constants.ADMIN_UNLOCKED and
                 node.operational == constants.OPERATIONAL_ENABLED)]

        host_ids = [node.uuid for node in valid_nodes]
        config_uuid = self._config_update_hosts(context, personalities,
                                                host_uuids=host_ids)

        config_dict = {
            "personalities": personalities,
            "host_uuids": host_ids,
            "classes": ['platform::ceph::runtime_base'],
            puppet_common.REPORT_STATUS_CFG: puppet_common.REPORT_CEPH_MONITOR_CONFIG
        }
        self._config_apply_runtime_manifest(context, config_uuid, config_dict)

    def update_ceph_osd_config(self, context, host, stor_uuid, runtime_manifests=True):
        """ Update Ceph OSD configuration at runtime"""
        personalities = [host.personality]
        config_uuid = self._config_update_hosts(context, personalities, [host.uuid],
                                                reboot=not runtime_manifests)

        if runtime_manifests:
            # Make sure that we have the correct CRUSH map before applying
            # the manifests.
            cceph.fix_crushmap(self.dbapi)

            config_dict = {
                "personalities": host.personality,
                "host_uuids": [host.uuid],
                "stor_uuid": stor_uuid,
                "classes": ['platform::ceph::runtime_osds'],
                puppet_common.REPORT_STATUS_CFG: puppet_common.REPORT_CEPH_OSD_CONFIG
            }
            self._config_apply_runtime_manifest(context, config_uuid, config_dict)

    def update_ceph_external_config(self, context, sb_uuid, services):
        """Update the manifests for Cinder/Glance External Ceph backend"""

        if (constants.SB_SVC_CINDER in services or
                constants.SB_SVC_GLANCE in services):
            personalities = [constants.CONTROLLER]

            # Update service table
            self.update_service_table_for_cinder()

            ctrls = self.dbapi.ihost_get_by_personality(constants.CONTROLLER)
            valid_ctrls = [ctrl for ctrl in ctrls if
                           (ctrl.administrative == constants.ADMIN_LOCKED and
                            ctrl.availability == constants.AVAILABILITY_ONLINE) or
                           (ctrl.administrative == constants.ADMIN_UNLOCKED and
                            ctrl.operational == constants.OPERATIONAL_ENABLED)]

            classes = ['platform::partitions::runtime',
                       'platform::lvm::controller::runtime',
                       'platform::haproxy::runtime',
                       'openstack::keystone::endpoint::runtime',
                       ]

            # TODO (tliu) determine if this SB_SVC_CINDER section can be removed
            if constants.SB_SVC_CINDER in services:
                LOG.info("No cinder manifests for update_ceph_external_config")
            classes.append('platform::sm::norestart::runtime')

            report_config = puppet_common.REPORT_CEPH_EXTERNAL_BACKEND_CONFIG

            host_ids = [ctrl.uuid for ctrl in valid_ctrls]
            config_dict = {"personalities": personalities,
                           "host_uuids": host_ids,
                           "classes": classes,
                           puppet_common.REPORT_STATUS_CFG: report_config, }

            # TODO(oponcea) once sm supports in-service config reload always
            # set reboot=False
            active_controller = utils.HostHelper.get_active_controller(self.dbapi)
            if utils.is_host_simplex_controller(active_controller):
                reboot = False
            else:
                if constants.SB_SVC_CINDER in services:
                    # If it is the first time to start cinder service and it
                    # is not a simplex configuration, then set reboot to false
                    if StorageBackendConfig.is_service_enabled(
                            self.dbapi,
                            constants.SB_SVC_CINDER,
                            filter_unconfigured=True,
                            filter_shared=True):
                        reboot = False
                    else:
                        reboot = True
                else:
                    reboot = False

            # Set config out-of-date for controllers
            config_uuid = self._config_update_hosts(context,
                                                    personalities,
                                                    host_uuids=host_ids,
                                                    reboot=reboot)

            tasks = {}
            for ctrl in valid_ctrls:
                tasks[ctrl.hostname] = constants.SB_TASK_APPLY_MANIFESTS

            # Update initial task states
            values = {'state': constants.SB_STATE_CONFIGURING,
                      'task': str(tasks)}

            self.dbapi.storage_ceph_external_update(sb_uuid, values)

            # TODO(oponcea): Set config_uuid to a random value to keep Config out-of-date.
            # Once sm supports in-service config reload, allways set config_uuid=config_uuid
            # in _config_apply_runtime_manifest and remove code bellow.
            if reboot:
                new_uuid = str(uuid.uuid4())
            else:
                new_uuid = config_uuid

            # Apply runtime config but keep reboot required flag set in
            # _config_update_hosts() above. Node needs a reboot to clear it.
            new_uuid = self._config_clear_reboot_required(new_uuid)
            self._config_apply_runtime_manifest(context,
                                                config_uuid=new_uuid,
                                                config_dict=config_dict)
        else:
            values = {'state': constants.SB_STATE_CONFIGURED,
                      'task': None}
            self.dbapi.storage_ceph_external_update(sb_uuid, values)

    def update_ceph_rook_config(self, context, sb_uuid, services):
        """Update the manifests for Rook Ceph backend and services"""

        personalities = [constants.CONTROLLER]

        # Update service table
        self.update_service_table_for_cinder()

        ctrls = self.dbapi.ihost_get_by_personality(constants.CONTROLLER)
        valid_ctrls = [ctrl for ctrl in ctrls if
                       ctrl.administrative == constants.ADMIN_UNLOCKED and
                       ctrl.availability in [constants.AVAILABILITY_AVAILABLE,
                                             constants.AVAILABILITY_DEGRADED]]

        classes = ['platform::rook::runtime']
        if cutils.is_aio_duplex_system(self.dbapi):
            # On 2 node systems we have a floating Ceph monitor.
            classes.append('platform::drbd::rookmon::runtime')
            classes.append('platform::sm::ceph::runtime')

        host_ids = [ctrl.uuid for ctrl in valid_ctrls]
        config_dict = {"personalities": personalities,
                       "host_uuids": host_ids,
                       "classes": classes,
                       puppet_common.REPORT_STATUS_CFG: puppet_common.REPORT_CEPH_ROOK_CONFIG,
                       }

        # Set config out-of-date for controllers
        config_uuid = self._config_update_hosts(context,
                                                personalities,
                                                host_uuids=host_ids)

        self._config_apply_runtime_manifest(context,
                                            config_uuid=config_uuid,
                                            config_dict=config_dict)

        tasks = {}
        for ctrl in valid_ctrls:
            tasks[ctrl.hostname] = constants.SB_TASK_APPLY_MANIFESTS

        # Update initial task states
        values = {'state': constants.SB_STATE_CONFIGURING,
                  'task': str(tasks)}
        self.dbapi.storage_ceph_rook_update(sb_uuid, values)

    def _update_image_conversion_alarm(self, alarm_state, fs_name, reason_text=None):
        """ Raise conversion configuration alarm"""
        entity_instance_id = "%s=%s" % (fm_constants.FM_ENTITY_TYPE_IMAGE_CONVERSION,
                                        fs_name)

        if alarm_state == fm_constants.FM_ALARM_STATE_SET:
            fault = fm_api.Fault(
                alarm_id=fm_constants.FM_ALARM_ID_IMAGE_CONVERSION,
                alarm_state=alarm_state,
                entity_type_id=fm_constants.FM_ENTITY_TYPE_IMAGE_CONVERSION,
                entity_instance_id=entity_instance_id,
                severity=fm_constants.FM_ALARM_SEVERITY_CRITICAL,
                reason_text=reason_text,
                alarm_type=fm_constants.FM_ALARM_TYPE_4,
                probable_cause=fm_constants.ALARM_PROBABLE_CAUSE_7,
                proposed_repair_action=_("Add image-conversion filesystem on both controllers."
                                         "Consult the System Administration Manual "
                                         "for more details. If problem persists, "
                                         "contact next level of support."),
                service_affecting=True)
            self.fm_api.set_fault(fault)
        else:
            self.fm_api.clear_fault(fm_constants.FM_ALARM_ID_IMAGE_CONVERSION,
                                    entity_instance_id)

    def _update_storage_backend_alarm(self, alarm_state, backend, reason_text=None):
        """ Update storage backend configuration alarm"""
        entity_instance_id = "%s=%s" % (fm_constants.FM_ENTITY_TYPE_STORAGE_BACKEND,
                                        backend)
        fault = fm_api.Fault(
            alarm_id=fm_constants.FM_ALARM_ID_STORAGE_BACKEND_FAILED,
            alarm_state=alarm_state,
            entity_type_id=fm_constants.FM_ENTITY_TYPE_STORAGE_BACKEND,
            entity_instance_id=entity_instance_id,
            severity=fm_constants.FM_ALARM_SEVERITY_CRITICAL,
            reason_text=reason_text,
            alarm_type=fm_constants.FM_ALARM_TYPE_4,
            probable_cause=fm_constants.ALARM_PROBABLE_CAUSE_7,
            proposed_repair_action=_("Update storage backend configuration to retry. "
                                     "Consult the System Administration Manual "
                                     "for more details. If problem persists, "
                                     "contact next level of support."),
            service_affecting=True)
        if alarm_state == fm_constants.FM_ALARM_STATE_SET:
            self.fm_api.set_fault(fault)
        else:
            self.fm_api.clear_fault(fm_constants.FM_ALARM_ID_STORAGE_BACKEND_FAILED,
                                    entity_instance_id)

    def report_config_status(self, context, iconfig, status, error=None):
        """ Callback from Sysinv Agent on manifest apply success or failure

        Finalize configuration after manifest apply successfully or perform
        cleanup, log errors and raise alarms in case of failure.

        :param context: request context
        :param iconfig: configuration context
        :param status: operation status
        :param error: err content as a dict of type:
                error = {
                        'class': str(ex.__class__.__name__),
                        'module': str(ex.__class__.__module__),
                        'message': six.text_type(ex),
                        'tb': traceback.format_exception(*ex),
                        'args': ex.args,
                        'kwargs': ex.kwargs
                        }

        The iconfig context is expected to contain a valid REPORT_STATUS_CFG
        key, so that we can correctly identify the set of pupet clasees executed.
        """
        reported_cfg = iconfig.get(puppet_common.REPORT_STATUS_CFG)
        if not reported_cfg:
            LOG.error("Function report_config_status was called without"
                      " a reported configuration! iconfig: %s" % iconfig)
            return

        def _process_config_report(callback_success, callback_success_args,
                                   callback_failure, callback_failure_args):
            success = False
            if status == puppet_common.REPORT_SUCCESS:
                # Configuration was successful
                success = True
                callback_success(*callback_success_args)
            elif status == puppet_common.REPORT_FAILURE:
                # Configuration has failed
                callback_failure(*callback_failure_args)
            else:
                err_args = {
                    'cfg': reported_cfg,
                    'status': status,
                    'iconfig': iconfig
                }
                LOG.error("No match for sysinv-agent manifest application reported! "
                          "reported_cfg: %(cfg)s status: %(status)s "
                          "iconfig: %(iconfig)s" % err_args)

            return success

        success = False
        host_uuid = iconfig.get('host_uuid')

        # Identify the set of manifests executed
        if reported_cfg == puppet_common.REPORT_ROUTE_CONFIG:
            # The agent is reporting the runtime route config has been applied.  Clear the corresponding
            # runtime class in progress flag and check for outstanding deferred runtime config.
            if status == puppet_common.REPORT_SUCCESS:
                success = True
                LOG.info("config runtime success, clear runtime apply in progress classes %s  host_uuids=%s" %
                         (iconfig.get('classes'), iconfig.get('host_uuids')))
                self._clear_runtime_class_apply_in_progress(classes_list=iconfig.get('classes'),
                                                            host_uuids=iconfig.get('host_uuids'))
                self._audit_deferred_runtime_config(context)
            else:
                # Config out of date alarm will be raised
                LOG.info("Route config manifest failed for host: %s" % host_uuid)
        elif reported_cfg == puppet_common.REPORT_UPGRADE_ACTIONS:
            if status == puppet_common.REPORT_SUCCESS:
                success = True
            else:
                LOG.info("Upgrade manifest failed for host: %s" % host_uuid)
                self.report_upgrade_config_failure()
        elif reported_cfg == puppet_common.REPORT_DISK_PARTITON_CONFIG:
            partition_uuid = iconfig['partition_uuid']
            idisk_uuid = iconfig['idisk_uuid']

            success = _process_config_report(
                self.report_partition_mgmt_success, [host_uuid, idisk_uuid,
                                                     partition_uuid],
                self.report_partition_mgmt_failure, [host_uuid, idisk_uuid,
                                                     partition_uuid, error]
            )
        elif reported_cfg == puppet_common.REPORT_LVM_BACKEND_CONFIG:
            success = _process_config_report(
                self.report_lvm_cinder_config_success, [context, host_uuid],
                self.report_lvm_cinder_config_failure, [host_uuid, error]
            )
        elif reported_cfg == puppet_common.REPORT_CEPH_BACKEND_CONFIG:
            success = _process_config_report(
                self.report_ceph_config_success, [context, host_uuid],
                self.report_ceph_config_failure, [host_uuid, error]
            )
        elif reported_cfg == puppet_common.REPORT_CEPH_EXTERNAL_BACKEND_CONFIG:
            success = _process_config_report(
                self.report_ceph_external_config_success, [context, host_uuid],
                self.report_ceph_external_config_failure, [host_uuid, error]
            )
        elif reported_cfg == puppet_common.REPORT_EXTERNAL_BACKEND_CONFIG:
            success = _process_config_report(
                self.report_external_config_success, [host_uuid],
                self.report_external_config_failure, [host_uuid, error]
            )
        elif reported_cfg == puppet_common.REPORT_CEPH_SERVICES_CONFIG:
            success = _process_config_report(
                self.report_ceph_services_config_success, [host_uuid],
                self.report_ceph_services_config_failure, [host_uuid, error]
            )
        elif reported_cfg == puppet_common.REPORT_CEPH_MONITOR_CONFIG:
            success = _process_config_report(
                self.report_ceph_base_config_success, [host_uuid],
                self.report_ceph_base_config_failure, [host_uuid, error]
            )
        elif reported_cfg == puppet_common.REPORT_CEPH_OSD_CONFIG:
            stor_uuid = iconfig['stor_uuid']

            success = _process_config_report(
                self.report_ceph_osd_config_success, [host_uuid, stor_uuid],
                self.report_ceph_osd_config_failure, [host_uuid, stor_uuid, error]
            )
        elif reported_cfg == puppet_common.REPORT_CEPH_RADOSGW_CONFIG:
            if status == puppet_common.REPORT_SUCCESS:
                # Configuration was successful
                success = True
        elif reported_cfg == puppet_common.REPORT_CEPH_ROOK_CONFIG:
            success = _process_config_report(
                self.report_ceph_rook_config_success, [context, host_uuid],
                self.report_ceph_rook_config_failure, [host_uuid, error]
            )
        # Kubernetes root CA host update
        elif reported_cfg in [puppet_common.REPORT_KUBE_CERT_UPDATE_TRUSTBOTHCAS,
                              puppet_common.REPORT_KUBE_CERT_UPDATE_UPDATECERTS,
                              puppet_common.REPORT_KUBE_CERT_UPDATE_TRUSTNEWCA]:
            success = _process_config_report(
                self.report_kube_rootca_update_success, [host_uuid, reported_cfg],
                self.report_kube_rootca_update_failure, [host_uuid, reported_cfg,
                                                         error]
            )
        # Kubernetes root CA pods update
        elif reported_cfg in \
                [puppet_common.REPORT_KUBE_CERT_UPDATE_PODS_TRUSTBOTHCAS,
                 puppet_common.REPORT_KUBE_CERT_UPDATE_PODS_TRUSTNEWCA]:
            success = _process_config_report(
                self.report_kube_rootca_pods_update_success, [reported_cfg],
                self.report_kube_rootca_pods_update_failure, [reported_cfg, error]
            )
        elif reported_cfg == puppet_common.REPORT_HTTP_CONFIG:
            success = _process_config_report(
                self.report_sysparam_http_update_success, [],
                self.report_sysparam_http_update_failure, [error]
            )
        # Kubernetes kubelet parameters update and per node configuration
        elif reported_cfg == puppet_common.REPORT_KUBE_UPDATE_KUBELET_PARAMS:
            # The agent is reporting the runtime update_kubelet_params has been applied.
            host_uuid = iconfig['host_uuid']
            if status == puppet_common.REPORT_SUCCESS:
                # Update action was successful.
                # Invoke per-node kubelet upgrade runtime configuration.
                success = True
                self.handle_kube_update_params_success(context, host_uuid)
            elif status == puppet_common.REPORT_FAILURE:
                # Update action has failed
                args = {'cfg': reported_cfg, 'status': status, 'iconfig': iconfig}
                LOG.error("config runtime failure, "
                          "reported_cfg: %(cfg)s status: %(status)s "
                          "iconfig: %(iconfig)s" % args)
            else:
                args = {'cfg': reported_cfg, 'status': status, 'iconfig': iconfig}
                LOG.error("No match for sysinv-agent manifest application reported! "
                          "reported_cfg: %(cfg)s status: %(status)s "
                          "iconfig: %(iconfig)s" % args)
        else:
            LOG.error("Reported configuration '%(cfg)s' is not handled by"
                      " report_config_status! iconfig: %(iconfig)s" %
                      {'iconfig': iconfig, 'cfg': reported_cfg})

        if success:
            self.check_pending_app_reapply(context)

    def verify_k8s_upgrade_not_in_progress(self):
        """ Check if there is a kubernetes upgrade in progress.

        Raise an exception if one is found.
        """
        try:
            kube_upgrade = self.dbapi.kube_upgrade_get_one()
            if kube_upgrade.state == kubernetes.KUBE_UPGRADE_COMPLETE:
                return
        except exception.NotFound:
            pass
        else:
            raise exception.SysinvException(_(
                "Kubernetes upgrade is in progress and not completed."))

    def verify_upgrade_not_in_progress(self):
        """ Check if there is an upgrade in progress.

        Raise an exception if one is found.
        """
        try:
            self.dbapi.software_upgrade_get_one()
        except exception.NotFound:
            pass
        else:
            raise exception.SysinvException(_("Platform upgrade in progress."))

        try:
            self.verify_k8s_upgrade_not_in_progress()
        except Exception as e:
            raise e

    def report_partition_mgmt_success(self, host_uuid, idisk_uuid,
                                      partition_uuid):
        """ Disk partition management success callback for Sysinv Agent

        Finalize the successful operation performed on a host disk partition.
        The Agent calls this if manifests are applied correctly.
        """
        try:
            partition = self.dbapi.partition_get(partition_uuid)
        except exception.DiskPartitionNotFound:
            # A parition was succesfully deleted by the manifest
            LOG.info("PART manifest application for partition %s on host %s"
                     "was successful" % (partition_uuid, host_uuid))
            return

        # A partition was successfully created or modified...
        states = [constants.PARTITION_CREATE_IN_SVC_STATUS,
                  constants.PARTITION_CREATE_ON_UNLOCK_STATUS,
                  constants.PARTITION_DELETING_STATUS,
                  constants.PARTITION_MODIFYING_STATUS]

        if partition.status not in states:
            LOG.info("PART manifest application for partition %s on host %s "
                     "was successful" % (partition_uuid, host_uuid))
        else:
            LOG.warning("PART manifest application for partition %s on host "
                        "%s was successful, but the partition remained in a "
                        "transitional state." % (partition_uuid, host_uuid))
            updates = {'status': constants.PARTITION_ERROR_STATUS}
            self.dbapi.partition_update(partition.uuid, updates)

    def report_partition_mgmt_failure(self, host_uuid, idisk_uuid,
                                      partition_uuid, error):
        """ Disk partition management failure callback for Sysinv Agent

        Finalize the failed operation performed on a host disk partition.
        The Agent calls this if manifests are applied correctly.
        """
        LOG.info("PART manifest application for partition %s on host %s "
                 "failed" % (partition_uuid, host_uuid))

        partition = self.dbapi.partition_get(partition_uuid)

        if partition.status < constants.PARTITION_ERROR_STATUS:
            updates = {'status': constants.PARTITION_ERROR_STATUS_INTERNAL}
            self.dbapi.partition_update(partition.uuid, updates)

        reason = jsonutils.loads(str(error)).get('message', "")
        LOG.error("Error handling partition on disk %(idisk_uuid)s, host "
                  "%(host_uuid)s: %(reason)s." %
                  {'idisk_uuid': idisk_uuid, 'host_uuid': host_uuid,
                   'reason': reason})

    def update_partition_information(self, context, partition_data):
        """ Synchronously, have the conductor update partition information.

        Partition information as changed on a given host. Update the inventory
        database with the new partition information provided.
        """
        LOG.info("PART updating information for partition %s on host %s was "
                 "successful: %s" % (partition_data['uuid'],
                                     partition_data['ihost_uuid'],
                                     partition_data))
        partition_status = partition_data.get('status')

        part_updates = {'status': partition_status}
        if partition_status == constants.PARTITION_READY_STATUS:
            part_updates.update({
                'start_mib': partition_data.get('start_mib', None),
                'end_mib': partition_data.get('end_mib', None),
                'size_mib': partition_data.get('size_mib', None),
                'device_path': partition_data.get('device_path', None),
                'type_name': partition_data.get('type_name', None)
            })
            disk_updates = {
                'available_mib': partition_data.get('available_mib')}

            # Update the disk usage info
            partition = self.dbapi.partition_get(partition_data['uuid'])
            self.dbapi.idisk_update(partition.idisk_uuid, disk_updates)

            # Update the partition info
            self.dbapi.partition_update(partition_data['uuid'], part_updates)

            # TODO(oponcea) Uncomment this once sysinv-conductor RPCAPI supports eventlets
            # Currently we wait for the partition update sent by the Agent.
            # If this is the cinder-volumes partition, then resize its PV and thinpools
            # pv = self.dbapi.ipv_get(partition.foripvid)
            # if (pv and pv.lvm_vg_name == constants.LVG_CINDER_VOLUMES):
            #    self._resize_cinder_volumes(delayed=True)

        elif partition_status == constants.PARTITION_DELETED_STATUS:
            disk_updates = {
                'available_mib': partition_data.get('available_mib')}

            # Update the disk usage info
            partition = self.dbapi.partition_get(partition_data['uuid'])
            self.dbapi.idisk_update(partition.idisk_uuid, disk_updates)

            # Delete the partition
            self.dbapi.partition_destroy(partition_data['uuid'])

        elif partition_status >= constants.PARTITION_ERROR_STATUS:
            LOG.error("PART Unexpected Error.")
            self.dbapi.partition_update(partition_data['uuid'], part_updates)

    def _update_vim_config(self, context):
        """ Update the VIM's configuration. """
        personalities = [constants.CONTROLLER]

        config_uuid = self._config_update_hosts(context, personalities)

        config_dict = {
            "personalities": personalities,
            "classes": ['platform::nfv::runtime']
        }

        self._config_apply_runtime_manifest(context,
                                            config_uuid,
                                            config_dict)

    def _config_sm_stx_openstack(self, context):
        """ provision dbmon """
        personalities = [constants.CONTROLLER]

        config_uuid = self._config_update_hosts(context, personalities)

        config_dict = {
            "personalities": personalities,
            "classes": ['platform::dcorch::stx_openstack::runtime',
                        'platform::sm::stx_openstack::runtime',
                        'platform::dcdbsync::stx_openstack::runtime']
        }

        self._config_apply_runtime_manifest(context,
                                            config_uuid,
                                            config_dict)

    def _update_config_for_stx_openstack(self, context):
        """ Update the runtime configurations that are required
            for stx-openstack application
        """
        personalities = [constants.CONTROLLER]

        config_uuid = self._config_update_hosts(context, personalities)

        config_dict = {
            "personalities": personalities,
            "classes": ['platform::nfv::runtime',
                        'platform::dcdbsync::stx_openstack::runtime',
                        'platform::dcorch::stx_openstack::runtime',
                        'platform::sm::stx_openstack::runtime']
        }

        self._config_apply_runtime_manifest(context,
                                            config_uuid,
                                            config_dict)

    def _update_radosgw_config(self, context):
        """ Update ceph radosgw configuration. """
        personalities = [constants.CONTROLLER]

        config_uuid = self._config_update_hosts(context, personalities)

        config_dict = {
            "personalities": personalities,
            "classes": ['platform::ceph::rgw::keystone::runtime'],
            puppet_common.REPORT_STATUS_CFG:
                puppet_common.REPORT_CEPH_RADOSGW_CONFIG

        }

        self._config_apply_runtime_manifest(context,
                                            config_uuid,
                                            config_dict)

    def _update_config_for_rook_ceph(self, context):
        rpcapi = agent_rpcapi.AgentAPI()
        controller_hosts = \
            self.dbapi.ihost_get_by_personality(constants.CONTROLLER)
        worker_hosts = \
            self.dbapi.ihost_get_by_personality(constants.WORKER)
        hosts = controller_hosts + worker_hosts

        for host in hosts:
            rpcapi.update_host_lvm(context, host.uuid)
            self._update_host_lvm_config(context, host)

    def report_lvm_cinder_config_success(self, context, host_uuid):
        """ Callback for Sysinv Agent

        Configuring LVM backend was successful, finalize operation.
        The Agent calls this if LVM manifests are applied correctly.
        Both controllers have to get their manifests applied before accepting
        the entire operation as successful.
        """
        LOG.debug("LVM manifests success on host: %s" % host_uuid)
        lvm_conf = StorageBackendConfig.get_backend(self.dbapi,
                                                    constants.CINDER_BACKEND_LVM)
        ctrls = self.dbapi.ihost_get_by_personality(constants.CONTROLLER)

        # Note that even if nodes are degraded we still accept the answer.
        valid_ctrls = [ctrl for ctrl in ctrls if
                       (ctrl.administrative == constants.ADMIN_LOCKED and
                        ctrl.availability == constants.AVAILABILITY_ONLINE) or
                       (ctrl.administrative == constants.ADMIN_UNLOCKED and
                        ctrl.operational == constants.OPERATIONAL_ENABLED)]

        # Set state for current node
        for host in valid_ctrls:
            if host.uuid == host_uuid:
                break
        else:
            LOG.error("Host %(host) is not in the required state!" % host_uuid)
            host = self.dbapi.ihost_get(host_uuid)
            if not host:
                LOG.error("Host %s is invalid!" % host_uuid)
                return
        tasks = eval(lvm_conf.get('task', '{}'))
        if tasks:
            tasks[host.hostname] = constants.SB_STATE_CONFIGURED
        else:
            tasks = {host.hostname: constants.SB_STATE_CONFIGURED}

        # Check if all hosts configurations have applied correctly
        # and mark config cuccess
        config_success = True
        for host in valid_ctrls:
            if tasks.get(host.hostname, '') != constants.SB_STATE_CONFIGURED:
                config_success = False

        values = None
        if lvm_conf.state != constants.SB_STATE_CONFIG_ERR:
            if config_success:
                # All hosts have completed configuration
                values = {'state': constants.SB_STATE_CONFIGURED, 'task': None}
                # Clear alarm, if any
                self._update_storage_backend_alarm(fm_constants.FM_ALARM_STATE_CLEAR,
                                                   constants.CINDER_BACKEND_LVM)
                # The VIM needs to know when a cinder backend was added.
                self._update_vim_config(context)
            else:
                # This host_uuid has completed configuration
                values = {'task': str(tasks)}
        if values:
            self.dbapi.storage_backend_update(lvm_conf.uuid, values)

    def report_lvm_cinder_config_failure(self, host_uuid, error):
        """ Callback for Sysinv Agent

        Configuring LVM backend failed, set backend to err and raise alarm
        The agent calls this if LVM manifests failed to apply
        """
        args = {'host': host_uuid, 'error': error}
        LOG.error("LVM manifests failed on host: %(host)s. Error: %(error)s" % args)

        # Set lvm backend to error state
        lvm_conf = StorageBackendConfig.get_backend(self.dbapi,
                                                    constants.CINDER_BACKEND_LVM)
        values = {'state': constants.SB_STATE_CONFIG_ERR, 'task': None}
        self.dbapi.storage_backend_update(lvm_conf.uuid, values)

        # Raise alarm
        reason = "LVM configuration failed to apply on host: %(host)s" % args
        self._update_storage_backend_alarm(fm_constants.FM_ALARM_STATE_SET,
                                           constants.CINDER_BACKEND_LVM,
                                           reason)

    def report_external_config_success(self, host_uuid):
        """
           Callback for Sysinv Agent
        """
        LOG.info("external manifests success on host: %s" % host_uuid)
        conf = StorageBackendConfig.get_backend(self.dbapi,
                                                constants.SB_TYPE_EXTERNAL)
        values = {'state': constants.SB_STATE_CONFIGURED, 'task': None}
        self.dbapi.storage_backend_update(conf.uuid, values)

        # Clear alarm, if any
        # self._update_storage_backend_alarm(fm_constants.FM_ALARM_STATE_CLEAR,
        #                                   constants.SB_TYPE_EXTERNAL)

    def report_external_config_failure(self, host_uuid, error):
        """
           Callback for Sysinv Agent

        """
        args = {'host': host_uuid, 'error': error}
        LOG.error("External manifests failed on host: %(host)s. Error: %(error)s" % args)

        # Set external backend to error state
        conf = StorageBackendConfig.get_backend(self.dbapi,
                                                constants.SB_TYPE_EXTERNAL)
        values = {'state': constants.SB_STATE_CONFIG_ERR, 'task': None}
        self.dbapi.storage_backend_update(conf.uuid, values)

        # Raise alarm
        # reason = "Share cinder configuration failed to apply on host: %(host)s" % args
        # self._update_storage_backend_alarm(fm_constants.FM_ALARM_STATE_SET,
        #                                   constants.SB_TYPE_EXTERNAL,
        #                                   reason)

    def report_ceph_external_config_success(self, context, host_uuid):
        """ Callback for Sysinv Agent

        Configuring Ceph External was successful, finalize operation.
        The Agent calls this if Ceph manifests are applied correctly.
        Both controllers have to get their manifests applied before accepting
        the entire operation as successful.
        """
        LOG.info("Ceph manifests success on host: %s" % host_uuid)

        # As we can have multiple external_ceph backends, need to find the one
        # that is in configuring state.
        ceph_conf = StorageBackendConfig.get_configuring_target_backend(
            self.dbapi, target=constants.SB_TYPE_CEPH_EXTERNAL)

        if ceph_conf:
            # For NOVA, if nova.conf needs to be updated on worker nodes, the
            # task should be set to what? constants.SB_TASK_RECONFIG_WORKER?

            config_done = True
            active_controller = utils.HostHelper.get_active_controller(self.dbapi)
            if not utils.is_host_simplex_controller(active_controller):
                ctrls = self.dbapi.ihost_get_by_personality(constants.CONTROLLER)
                for host in ctrls:
                    if host.uuid == host_uuid:
                        break
                else:
                    LOG.error("Host %s is not a controller?" % host_uuid)
                    return
                tasks = eval(ceph_conf.get('task', '{}'))
                if tasks:
                    tasks[host.hostname] = None
                else:
                    tasks = {host.hostname: None}

                for h in ctrls:
                    if tasks[h.hostname]:
                        config_done = False
                        break

            if config_done:
                values = {'state': constants.SB_STATE_CONFIGURED,
                          'task': None}
                # The VIM needs to know when a cinder backend was added.
                services = utils.SBApiHelper.getListFromServices(ceph_conf.as_dict())
                if constants.SB_SVC_CINDER in services:
                    self._update_vim_config(context)

                # Clear alarm, if any
                self._update_storage_backend_alarm(fm_constants.FM_ALARM_STATE_CLEAR,
                                                   constants.CINDER_BACKEND_CEPH)
            else:
                values = {'task': str(tasks)}

            self.dbapi.storage_backend_update(ceph_conf.uuid, values)

    def report_ceph_external_config_failure(self, host_uuid, error):
        """ Callback for Sysinv Agent

        Configuring External Ceph backend failed, set backend to err and raise alarm
        The agent calls this if Ceph manifests failed to apply
        """

        args = {'host': host_uuid, 'error': error}
        LOG.error("Ceph external manifests failed on host: %(host)s. Error: %(error)s" % args)

        # As we can have multiple external_ceph backends, need to find the one
        # that is in configuring state.
        ceph_conf = StorageBackendConfig.get_configuring_target_backend(
            self.dbapi, target=constants.SB_TYPE_CEPH_EXTERNAL)

        # Set ceph backend to error state
        values = {'state': constants.SB_STATE_CONFIG_ERR, 'task': None}
        self.dbapi.storage_backend_update(ceph_conf.uuid, values)

        # Raise alarm
        reason = "Ceph external configuration failed to apply on host: %(host)s" % args
        self._update_storage_backend_alarm(fm_constants.FM_ALARM_STATE_SET,
                                           constants.CINDER_BACKEND_CEPH,
                                           reason)

    def report_ceph_rook_config_success(self, context, host_uuid):
        """ Callback for Sysinv Agent

        Configuring Ceph Rook was successful, finalize operation.
        The Agent calls this if Ceph manifests are applied correctly.
        Both controllers have to get their manifests applied before accepting
        the entire operation as successful.
        """
        LOG.info("Ceph manifests success on host: %s" % host_uuid)

        # As we can have multiple rook_ceph backends, need to find the one
        # that is in configuring state.
        ceph_conf = StorageBackendConfig.get_configuring_target_backend(
            self.dbapi, target=constants.SB_TYPE_CEPH_ROOK)

        if ceph_conf:
            config_done = True
            active_controller = utils.HostHelper.get_active_controller(self.dbapi)
            if not utils.is_host_simplex_controller(active_controller):
                ctrls = self.dbapi.ihost_get_by_personality(constants.CONTROLLER)
                for host in ctrls:
                    if host.uuid == host_uuid:
                        break
                else:
                    LOG.error("Host %s is not a controller?" % host_uuid)
                    return
                tasks = eval(ceph_conf.get('task', '{}'))
                if tasks:
                    tasks[host.hostname] = None
                else:
                    tasks = {host.hostname: None}

                for h in ctrls:
                    if tasks[h.hostname]:
                        config_done = False
                        break

            if config_done:
                values = {'state': constants.SB_STATE_CONFIGURED,
                          'task': None}

                # Clear alarm, if any
                self._update_storage_backend_alarm(fm_constants.FM_ALARM_STATE_CLEAR,
                                                   constants.SB_TYPE_CEPH_ROOK)
            else:
                values = {'task': str(tasks)}

            self.dbapi.storage_backend_update(ceph_conf.uuid, values)

    def report_ceph_rook_config_failure(self, host_uuid, error):
        """ Callback for Sysinv Agent

        Configuring Rook Ceph backend failed, set backend to err and raise alarm
        The agent calls this if Ceph manifests failed to apply
        """

        args = {'host': host_uuid, 'error': error}
        LOG.error("Ceph rook manifests failed on host: %(host)s. Error: %(error)s" % args)

        # As we can have multiple rook_ceph backends, need to find the one
        # that is in configuring state.
        ceph_conf = StorageBackendConfig.get_configuring_target_backend(
            self.dbapi, target=constants.SB_TYPE_CEPH_ROOK)

        # Set ceph backend to error state
        values = {'state': constants.SB_STATE_CONFIG_ERR, 'task': None}
        self.dbapi.storage_backend_update(ceph_conf.uuid, values)

        # Raise alarm
        reason = "Ceph rook configuration failed to apply on host: %(host)s" % args
        self._update_storage_backend_alarm(fm_constants.FM_ALARM_STATE_SET,
                                           constants.SB_TYPE_CEPH_ROOK,
                                           reason)

    def report_ceph_config_success(self, context, host_uuid):
        """ Callback for Sysinv Agent

        Configuring Ceph was successful, finalize operation.
        The Agent calls this if Ceph manifests are applied correctly.
        Both controllers have to get their manifests applied before accepting
        the entire operation as successful.
        """
        LOG.info("Ceph manifests success on host: %s" % host_uuid)
        ceph_conf = StorageBackendConfig.get_backend(self.dbapi,
                                                     constants.CINDER_BACKEND_CEPH)

        # Only update the state/task if the backend hasn't been previously
        # configured. Subsequent re-applies of the runtime manifest that need to
        # have the controllers rebooted should be handled by SB_TASK changes
        # (i.e adding object GW)
        if ceph_conf.state != constants.SB_STATE_CONFIGURED:
            active_controller = utils.HostHelper.get_active_controller(self.dbapi)
            if utils.is_host_simplex_controller(active_controller):
                state = constants.SB_STATE_CONFIGURED
                if cutils.is_aio_system(self.dbapi):
                    task = None
                    greenthread.spawn(self._init_ceph_cluster_info)
                else:
                    task = constants.SB_TASK_PROVISION_STORAGE
                values = {'state': state,
                          'task': task}
            else:
                # TODO(oponcea): Remove when sm supports in-service config reload
                # and any logic dealing with constants.SB_TASK_RECONFIG_CONTROLLER.
                ctrls = self.dbapi.ihost_get_by_personality(constants.CONTROLLER)
                # Note that even if nodes are degraded we still accept the answer.
                valid_ctrls = [ctrl for ctrl in ctrls if
                               (ctrl.administrative == constants.ADMIN_LOCKED and
                                ctrl.availability == constants.AVAILABILITY_ONLINE) or
                               (ctrl.administrative == constants.ADMIN_UNLOCKED and
                                ctrl.operational == constants.OPERATIONAL_ENABLED)]

                # Set state for current node
                for host in valid_ctrls:
                    if host.uuid == host_uuid:
                        break
                else:
                    LOG.error("Host %s is not in the required state!" % host_uuid)
                    host = self.dbapi.ihost_get(host_uuid)
                    if not host:
                        LOG.error("Host %s is invalid!" % host_uuid)
                        return

                tasks = eval(ceph_conf.get('task', '{}'))
                if tasks:
                    tasks[host.hostname] = constants.SB_STATE_CONFIGURED
                else:
                    tasks = {host.hostname: constants.SB_STATE_CONFIGURED}

                config_success = True
                for host in valid_ctrls:
                    if tasks.get(host.hostname, '') != constants.SB_STATE_CONFIGURED:
                        config_success = False

                if ceph_conf.state != constants.SB_STATE_CONFIG_ERR:
                    if config_success:
                        values = {'task': constants.SB_TASK_PROVISION_STORAGE}
                        greenthread.spawn(self._init_ceph_cluster_info)
                    else:
                        values = {'task': str(tasks)}
            self.dbapi.storage_backend_update(ceph_conf.uuid, values)

            # The VIM needs to know when a cinder backend was added.
            services = utils.SBApiHelper.getListFromServices(ceph_conf.as_dict())
            if constants.SB_SVC_CINDER in services:
                self._update_vim_config(context)

        # Clear alarm, if any
        self._update_storage_backend_alarm(fm_constants.FM_ALARM_STATE_CLEAR,
                                           constants.CINDER_BACKEND_CEPH)

    def report_ceph_config_failure(self, host_uuid, error):
        """ Callback for Sysinv Agent

        Configuring Ceph backend failed, set ackend to err and raise alarm
        The agent calls this if LVM manifests failed to apply
        """
        args = {'host': host_uuid, 'error': error}
        LOG.error("Ceph manifests failed on host: %(host)s. Error: %(error)s" % args)

        # Set ceph backend to error state
        ceph_conf = StorageBackendConfig.get_backend(self.dbapi,
                                                     constants.CINDER_BACKEND_CEPH)
        values = {'state': constants.SB_STATE_CONFIG_ERR, 'task': None}
        self.dbapi.storage_backend_update(ceph_conf.uuid, values)

        # Raise alarm
        reason = "Ceph configuration failed to apply on host: %(host)s" % args
        self._update_storage_backend_alarm(fm_constants.FM_ALARM_STATE_SET,
                                           constants.CINDER_BACKEND_CEPH,
                                           reason)

    def report_ceph_services_config_success(self, host_uuid):
        """
           Callback for Sysinv Agent
        """

        LOG.info("Ceph service update succeeded on host: %s" % host_uuid)

        # Get the backend that is configuring
        backend_list = self.dbapi.storage_ceph_get_list()
        backend = None
        for b in backend_list:
            if b.state == constants.SB_STATE_CONFIGURING:
                backend = b
                break

        ctrls = self.dbapi.ihost_get_by_personality(constants.CONTROLLER)
        # Note that even if nodes are degraded we still accept the answer.
        valid_ctrls = [ctrl for ctrl in ctrls if
                       (ctrl.administrative == constants.ADMIN_LOCKED and
                        ctrl.availability == constants.AVAILABILITY_ONLINE) or
                       (ctrl.administrative == constants.ADMIN_UNLOCKED and
                        ctrl.operational == constants.OPERATIONAL_ENABLED)]

        # Set state for current node
        for host in valid_ctrls:
            if host.uuid == host_uuid:
                break
        else:
            LOG.error("Host %s is not in the required state!" % host_uuid)
            host = self.dbapi.ihost_get(host_uuid)
            if not host:
                LOG.error("Host %s is invalid!" % host_uuid)
                return
        tasks = eval(backend.get('task', '{}'))
        if tasks:
            tasks[host.hostname] = constants.SB_STATE_CONFIGURED
        else:
            tasks = {host.hostname: constants.SB_STATE_CONFIGURED}

        # Check if all hosts configurations have applied correctly
        # and mark config cuccess
        config_success = True
        for host in valid_ctrls:
            if tasks.get(host.hostname, '') != constants.SB_STATE_CONFIGURED:
                config_success = False

        values = None
        if backend.state != constants.SB_STATE_CONFIG_ERR:
            if config_success:
                # All hosts have completed configuration
                values = {'state': constants.SB_STATE_CONFIGURED, 'task': None}
            else:
                # This host_uuid has completed configuration
                values = {'task': str(tasks)}
        if values:
            self.dbapi.storage_backend_update(backend.uuid, values)

    def report_ceph_services_config_failure(self, host_uuid, error):
        """
           Callback for Sysinv Agent

        """
        LOG.error("Ceph service update failed on host: %(host)s. Error: "
                  "%(error)s" % {'host': host_uuid, 'error': error})

        backend_list = self.dbapi.storage_ceph_get_list()
        backend = None
        for b in backend_list:
            if b.state == constants.SB_STATE_CONFIGURING:
                backend = b
                break

        # Set external backend to error state
        values = {'state': constants.SB_STATE_CONFIG_ERR, 'task': None}
        self.dbapi.storage_backend_update(backend.uuid, values)

    def report_ceph_base_config_success(self, host_uuid):
        """
           Callback for Sysinv Agent
        """

        LOG.info("Ceph monitor update succeeded on host: %s" % host_uuid)

        # Get the monitor that is configuring
        monitor_list = self.dbapi.ceph_mon_get_list()
        monitor = None
        for mon in monitor_list:
            if mon.state == constants.SB_STATE_CONFIGURING:
                monitor = mon
                break

        ctrls = self.dbapi.ihost_get_by_personality(constants.CONTROLLER)
        # Note that even if nodes are degraded we still accept the answer.
        valid_ctrls = [ctrl for ctrl in ctrls if
                       (ctrl.administrative == constants.ADMIN_LOCKED and
                        ctrl.availability == constants.AVAILABILITY_ONLINE) or
                       (ctrl.administrative == constants.ADMIN_UNLOCKED and
                        ctrl.operational == constants.OPERATIONAL_ENABLED)]

        # Set state for current node
        for host in valid_ctrls:
            if host.uuid == host_uuid:
                break
        else:
            LOG.error("Host %s is not in the required state!" % host_uuid)
            host = self.dbapi.ihost_get(host_uuid)
            if not host:
                LOG.error("Host %s is invalid!" % host_uuid)
                return
            elif host.personality == constants.WORKER:
                LOG.info("Ignoring report from worker hosts")
                return
        tasks = eval(monitor.get('task', '{}'))
        if tasks:
            tasks[host.hostname] = constants.SB_STATE_CONFIGURED
        else:
            tasks = {host.hostname: constants.SB_STATE_CONFIGURED}

        # Check if all hosts configurations have applied correctly
        # and mark config success
        config_success = True
        for host in valid_ctrls:
            if tasks.get(host.hostname, '') != constants.SB_STATE_CONFIGURED:
                config_success = False

        values = None
        if monitor.state != constants.SB_STATE_CONFIG_ERR:
            if config_success:
                # All hosts have completed configuration
                values = {'state': constants.SB_STATE_CONFIGURED, 'task': None}
            else:
                # This host_uuid has completed configuration
                values = {'task': str(tasks)}
        if values:
            self.dbapi.ceph_mon_update(monitor.uuid, values)

    def report_ceph_base_config_failure(self, host_uuid, error):
        """
           Callback for Sysinv Agent
        """
        LOG.error("Ceph monitor update failed on host: %(host)s. Error: "
                  "%(error)s" % {'host': host_uuid, 'error': error})

        host = self.dbapi.ihost_get(host_uuid)
        if host and host.personality == constants.WORKER:
            # Ignoring report from worker
            return

        monitor_list = self.dbapi.ceph_mon_get_list()
        monitor = None
        for mon in monitor_list:
            if mon.state == constants.SB_STATE_CONFIGURING:
                monitor = mon
                break

        # Set monitor to error state
        values = {'state': constants.SB_STATE_CONFIG_ERR, 'task': None}
        self.dbapi.ceph_mon_update(monitor.uuid, values)

    def report_ceph_osd_config_success(self, host_uuid, stor_uuid):
        """
           Callback for Sysinv Agent on ceph OSD config success
        """

        LOG.info("Ceph OSD stor '%s' update succeeded on host: %s" % (stor_uuid, host_uuid))

        values = {'state': constants.SB_STATE_CONFIGURED}
        self.dbapi.istor_update(stor_uuid, values)

    def report_ceph_osd_config_failure(self, host_uuid, stor_uuid, error):
        """
           Callback for Sysinv Agent on ceph OSD config failure
        """
        LOG.error("Ceph OSD stor '%(stor)s' update failed on host: %(host)s. Error: "
                  "%(error)s" % {'stor': stor_uuid, 'host': host_uuid, 'error': error})

        # Set OSD to error state
        values = {'state': constants.SB_STATE_CONFIG_ERR}
        self.dbapi.istor_update(stor_uuid, values)

    def report_upgrade_config_failure(self):
        """
           Callback for Sysinv Agent on upgrade manifest failure
        """
        try:
            upgrade = self.dbapi.software_upgrade_get_one()
        except exception.NotFound:
            LOG.error("Upgrade record not found during config failure")
            return
        self.dbapi.software_upgrade_update(
            upgrade.uuid,
            {'state': constants.UPGRADE_ACTIVATION_FAILED})

    def handle_kube_update_params_success(self, context, host_uuid):
        """
           Callback for Sysinv Agent on kube update params success.

           This is invoked after kubelet-config ConfigMap is updated,
           and does per-node kubernetes configuration.

           This will download the current kubelet-config ConfigMap,
           regenerate the configuration file /var/lib/kubelet/config.yaml,
           and restart kubelet per node.

        :param context: request context
        :param host_uuid: host unique id
        """
        LOG.info("Kube update params phase succeeded on host: %s"
                % (host_uuid))

        personalities = [constants.CONTROLLER, constants.WORKER]
        hosts = self.dbapi.ihost_get_list()
        host_uuids = [x.uuid for x in hosts if x.personality in personalities]
        config_uuid = self._config_update_hosts(context, personalities,
                                                host_uuids=host_uuids)
        config_dict = {
            "personalities": personalities,
            "host_uuids": host_uuids,
            "classes": [
                'platform::kubernetes::update_kubelet_config::runtime']
        }
        self._config_apply_runtime_manifest(
            context, config_uuid=config_uuid, config_dict=config_dict)

    def report_kube_rootca_update_success(self, host_uuid, reported_cfg):
        """
           Callback for Sysinv Agent on kube root CA update success
        """
        LOG.info("Kube root CA update phase '%s' succeeded on host: %s"
                % (reported_cfg, host_uuid))

        # If the update is aborted, don't update anything
        c_update = self.dbapi.kube_rootca_update_get_one()
        if c_update.state == kubernetes.KUBE_ROOTCA_UPDATE_ABORTED:
            LOG.info("Current update has been aborted at host: %s, config: %s"
                    % (host_uuid, reported_cfg))
            return

        values = {}
        h_update = self.dbapi.kube_rootca_host_update_get_by_host(host_uuid)

        if reported_cfg == puppet_common.REPORT_KUBE_CERT_UPDATE_TRUSTBOTHCAS:
            state = kubernetes.KUBE_ROOTCA_UPDATED_HOST_TRUSTBOTHCAS
            values.update({'state': state})
        elif reported_cfg == puppet_common.REPORT_KUBE_CERT_UPDATE_UPDATECERTS:
            state = kubernetes.KUBE_ROOTCA_UPDATED_HOST_UPDATECERTS
            values.update({'state': state})
        elif reported_cfg == puppet_common.REPORT_KUBE_CERT_UPDATE_TRUSTNEWCA:
            state = kubernetes.KUBE_ROOTCA_UPDATED_HOST_TRUSTNEWCA
            values.update({'state': state,
                           'effective_rootca_cert': h_update.target_rootca_cert})
        else:
            LOG.info("Not supported reported_cfg: %s" % reported_cfg)
            raise exception.SysinvException(_(
                "Not supported reported_cfg: %s" % reported_cfg))

        # Update host 'update state'
        self.dbapi.kube_rootca_host_update_update(h_update.id, values)

        # The host state has been updated.  Now query all hosts.
        # If all hosts are updated, update cluster 'update state'
        h_updates = self.dbapi.kube_rootca_host_update_get_list()

        matching = 0
        for h_update in h_updates:
            if h_update.state == state:
                matching += 1
        if matching == len(h_updates):
            # All hosts are up to date.
            self.dbapi.kube_rootca_update_update(c_update.id, {'state': state})

    def report_kube_rootca_update_failure(self, host_uuid, reported_cfg,
                                          error):
        """
           Callback for Sysinv Agent on kube root CA update failure
        """
        LOG.info("Kube root CA update phase '%s' failed on host: %s, error: %s"
                % (reported_cfg, host_uuid, error))

        # If the update is aborted, don't update anything
        c_update = self.dbapi.kube_rootca_update_get_one()
        if c_update.state == kubernetes.KUBE_ROOTCA_UPDATE_ABORTED:
            LOG.info("Current update has been aborted at host: %s, config: %s"
                    % (host_uuid, reported_cfg))
            return

        if reported_cfg == puppet_common.REPORT_KUBE_CERT_UPDATE_TRUSTBOTHCAS:
            state = kubernetes.KUBE_ROOTCA_UPDATING_HOST_TRUSTBOTHCAS_FAILED
        elif reported_cfg == puppet_common.REPORT_KUBE_CERT_UPDATE_UPDATECERTS:
            state = kubernetes.KUBE_ROOTCA_UPDATING_HOST_UPDATECERTS_FAILED
        elif reported_cfg == puppet_common.REPORT_KUBE_CERT_UPDATE_TRUSTNEWCA:
            state = kubernetes.KUBE_ROOTCA_UPDATING_HOST_TRUSTNEWCA_FAILED
        else:
            LOG.info("Not supported reported_cfg: %s" % reported_cfg)
            raise exception.SysinvException(_(
                "Not supported reported_cfg: %s" % reported_cfg))

        # Update host 'update state'
        h_update = self.dbapi.kube_rootca_host_update_get_by_host(host_uuid)
        self.dbapi.kube_rootca_host_update_update(h_update.id,
                                                  {'state': state})

        # Update cluster 'update state'
        self.dbapi.kube_rootca_update_update(c_update.id, {'state': state})

    def report_kube_rootca_pods_update_success(self, reported_cfg):
        """
           Callback for Sysinv Agent on kube root CA pods update success
        """
        LOG.info("Kube root CA update phase '%s' succeeded for pods"
                % (reported_cfg))

        # If the update is aborted, don't update anything
        c_update = self.dbapi.kube_rootca_update_get_one()
        if c_update.state == kubernetes.KUBE_ROOTCA_UPDATE_ABORTED:
            LOG.info("Current update has been aborted at config: %s"
                    % (reported_cfg))
            return

        if reported_cfg == \
                puppet_common.REPORT_KUBE_CERT_UPDATE_PODS_TRUSTBOTHCAS:
            state = kubernetes.KUBE_ROOTCA_UPDATED_PODS_TRUSTBOTHCAS
        elif reported_cfg == \
                puppet_common.REPORT_KUBE_CERT_UPDATE_PODS_TRUSTNEWCA:
            state = kubernetes.KUBE_ROOTCA_UPDATED_PODS_TRUSTNEWCA
        else:
            LOG.info("Not supported reported_cfg: %s" % reported_cfg)
            raise exception.SysinvException(_(
                "Not supported reported_cfg: %s" % reported_cfg))

        # Update cluster 'update state'
        self.dbapi.kube_rootca_update_update(c_update.id, {'state': state})

    def report_kube_rootca_pods_update_failure(self, reported_cfg, error):
        """
           Callback for Sysinv Agent on kube root CA pods update failure
        """
        LOG.info("Kube root CA update phase '%s' failed for pods, error: %s"
                % (reported_cfg, error))

        # If the update is aborted, don't update anything
        c_update = self.dbapi.kube_rootca_update_get_one()
        if c_update.state == kubernetes.KUBE_ROOTCA_UPDATE_ABORTED:
            LOG.info("Current update has been aborted at config: %s"
                    % (reported_cfg))
            return

        if reported_cfg == \
                puppet_common.REPORT_KUBE_CERT_UPDATE_PODS_TRUSTBOTHCAS:
            state = kubernetes.KUBE_ROOTCA_UPDATING_PODS_TRUSTBOTHCAS_FAILED
        elif reported_cfg == \
                puppet_common.REPORT_KUBE_CERT_UPDATE_PODS_TRUSTNEWCA:
            state = kubernetes.KUBE_ROOTCA_UPDATING_PODS_TRUSTNEWCA_FAILED
        else:
            LOG.info("Not supported reported_cfg: %s" % reported_cfg)
            raise exception.SysinvException(_(
                "Not supported reported_cfg: %s" % reported_cfg))

        # Update cluster 'update state'
        self.dbapi.kube_rootca_update_update(c_update.id, {'state': state})

    def report_sysparam_http_update_success(self):
        """
           Callback for system-parameter HTTP change
        """
        LOG.info("Change of system parameter HTTP '%s' succeeded, updating "
                 "helmrepositories.")
        kube_operator = kubernetes.KubeOperator()

        try:
            helmrepo_list = kube_operator.list_custom_resources(
                constants.FLUXCD_CRD_HELM_REPO_GROUP,
                constants.FLUXCD_CRD_HELM_REPO_VERSION,
                constants.FLUXCD_CRD_HELM_REPO_PLURAL,
            )
        except Exception as err:
            LOG.error("Failed to get helmrepositories: %s" % err)
            return

        if not helmrepo_list:
            LOG.error("Resource helmrepositories not found")
            return

        for helmrepo in helmrepo_list.get("items"):

            helmrepo["spec"]["url"] = \
                cutils.replace_helmrepo_url_with_floating_address(
                    dbapi.get_instance(), helmrepo["spec"]["url"])
            try:
                group, version = helmrepo['apiVersion'].split('/')
                kube_operator.apply_custom_resource(
                    group,
                    version,
                    helmrepo['metadata']['namespace'],
                    constants.FLUXCD_CRD_HELM_REPO_PLURAL,
                    helmrepo['metadata']['name'],
                    helmrepo
                )
            except Exception as err:
                LOG.error("Failed to create helmrepository resource %s: %s"
                          % (helmrepo['metadata']['name'], err))
                continue

            LOG.info(
                "Changed helmrepository %s from namespace %s: url=%s"
                % (helmrepo['metadata']['name'],
                   helmrepo['metadata']['namespace'],
                   helmrepo['spec']['url'])
            )

            self._check_helmrepository_creation(
                helmrepo['metadata']['namespace'],
                helmrepo['metadata']['name']
            )

    def report_sysparam_http_update_failure(self, error):
        """
           Callback for system-parameter HTTP change failure
        """
        LOG.info("Change of system parameter HTTP failed, error: %s"
                 % error)

    def _check_helmrepository_creation(self, namespace, name):
        """ Checks if the helmrepository was created correctly

        :param namespace: the namespace of the helmrepository
        :param name: the name of the helmrepository to check
        """
        kube_operator = kubernetes.KubeOperator()
        helmrepo = kube_operator.get_custom_resource(
            constants.FLUXCD_CRD_HELM_REPO_GROUP,
            constants.FLUXCD_CRD_HELM_REPO_VERSION,
            namespace,
            constants.FLUXCD_CRD_HELM_REPO_PLURAL,
            name
        )
        if helmrepo is None:
            msg = "HelmRepository %s on namespace %s: creation timeout" \
                  % (namespace, name)
            LOG.error(msg)
            raise exception.SysinvException(_(msg))

    def create_controller_filesystems(self, context, rootfs_device):
        """ Create the storage config based on disk size for database, platform,
            extension, rabbit, etcd, docker-distribution, dc-vault(SC)

            :param context: an admin context.
            :param rootfs_device: the root disk device
        """
        database_storage = 0

        # Get the distributed cloud role to determine filesystems size
        system = self.dbapi.isystem_get_one()
        system_dc_role = system.get("distributed_cloud_role", None)
        system_type = system.get("system_type", None)

        # Set default filesystem sizes
        platform_storage = constants.DEFAULT_PLATFORM_STOR_SIZE
        if (system_dc_role == constants.DISTRIBUTED_CLOUD_ROLE_SYSTEMCONTROLLER and
                system_type == constants.TIS_STD_BUILD):
            platform_storage = constants.DEFAULT_PLATFORM_SYSTEMCONTROLLER_STOR_SIZE
        extension_lv_size = constants.DEFAULT_EXTENSION_STOR_SIZE
        etcd_lv_size = constants.ETCD_STOR_SIZE
        docker_distribution_lv_size = \
            constants.DOCKER_DISTRIBUTION_STOR_SIZE

        LOG.info("Local Region Name: %s" % system.region_name)

        disk_size = cutils.get_disk_capacity_mib(rootfs_device)
        disk_size = int(disk_size // 1024)

        if disk_size > constants.DEFAULT_SMALL_DISK_SIZE:

            LOG.info("Disk size : %s ... large disk defaults" % disk_size)

            # Defaults: 500G root disk
            #
            #          8 G - /var/log (reserved in kickstart)
            #         16 G - /scratch (reserved in kickstart)
            #          2 G - pgsql_lv (DRBD bootstrap manifest)
            #          2 G - rabbit_lv (DRBD bootstrap manifest)
            #         10 G - platform_lv (DRBD bootstrap manifest)
            #                (20 G if Standard System Controller)
            #          1 G - extension_lv (DRBD bootstrap manifest)
            #        -----
            #         39 G - cgts-vg contents when we get to these checks
            #        (49 G if Standard System Controller)
            #
            #       Final defaults view after controller manifests
            #          8 G - /var/log (reserved in kickstart)
            #         16 G - /scratch (reserved in kickstart)
            #         20 G - /var/lib/postgresql
            #          2 G - /var/lib/rabbitmq
            #         10 G - /opt/platform
            #                (20 G if Standard System Controller)
            #          1 G - /opt/extension
            #         25 G - /opt/backup
            #                (35 G if Standard System Controller)
            #         30 G - /var/lib/docker
            #         16 G - /var/lib/docker-distribution
            #          5 G - /opt/etcd
            #         10 G - /var/lib/kubelet
            #         20 G - /var/lib/ceph/mon
            #         15 G - /opt/dc-vault (DRBD ctlr manifest for DCSC)
            #        -----
            #        178 G
            #       (198 G if Standard System Controller)
            #
            #  The absolute minimum disk size for these default settings:
            #      2.0 G - buffer
            #      0.5 G - /boot
            #     10.0 G - /opt/platform-backup
            #     20.0 G - /
            #    178.0 G - cgts-vg PV
            #   -------
            #    ~ 210 G min size disk
            #     (230 G if Standard System Controller)
            #
            database_storage = constants.DEFAULT_DATABASE_STOR_SIZE

        elif disk_size >= constants.MINIMUM_SMALL_DISK_SIZE:

            LOG.info("Disk size : %s ... small disk defaults" % disk_size)

            # Small disk: under 240G and over 196G root disk
            #
            #          8 G - /var/log (reserved in kickstart)
            #         16 G - /scratch (reserved in kickstart)
            #          2 G - pgsql_lv (DRBD bootstrap manifest)
            #          2 G - rabbit_lv (DRBD bootstrap manifest)
            #         10 G - platform_lv (DRBD bootstrap manifest)
            #          1 G - extension_lv (DRBD bootstrap manifest)
            #        -----
            #         39 G - cgts-vg contents when we get to these checks
            #
            #
            #       Final defaults view after controller manifests
            #          8 G - /var/log (reserved in kickstart)
            #         16 G - /scratch (reserved in kickstart)
            #         10 G - /var/lib/postgresql
            #          2 G - /var/lib/rabbitmq
            #         10 G - /opt/platform
            #          1 G - /opt/extension
            #         20 G - /opt/backup
            #         30 G - /var/lib/docker
            #         16 G - /var/lib/docker-distribution
            #         20 G - /var/lib/ceph/mon
            #          5 G - /opt/etcd
            #         10 G - /var/lib/kubelet
            #         15 G - /opt/dc-vault (DRBD ctlr manifest for DCSC)
            #        -----
            #        163 G
            #
            #  The absolute minimum disk size for these default settings:
            #     2.0 G - buffer
            #     0.5 G - /boot
            #    10.0 G - /opt/platform-backup
            #    20.0 G - /
            #   163.0 G - cgts-vg PV
            #   -------
            #   ~ 196 G min size disk
            #
            database_storage = \
                constants.DEFAULT_SMALL_DATABASE_STOR_SIZE

        elif (disk_size >= constants.MINIMUM_TINY_DISK_SIZE and
              cutils.is_virtual_system_config(self.dbapi) and
              cutils.is_aio_system(self.dbapi)):

            LOG.info("Disk size : %s ... tiny disk defaults for virtual system configruation" % disk_size)

            # Tiny disk(StarlingX running in VM, AIO only): under 154G and over 60G root disk
            #
            #          3 G - /var/log (reserved in kickstart)
            #          2 G - /scratch (reserved in kickstart)
            #          2 G - pgsql_lv (DRBD bootstrap manifest)
            #          2 G - rabbit_lv (DRBD bootstrap manifest)
            #          1 G - platform_lv (DRBD bootstrap manifest)
            #          1 G - extension_lv (DRBD bootstrap manifest)
            #        -----
            #         11 G - cgts-vg contents when we get to these checks
            #
            #
            #       Final defaults view after controller manifests
            #          3 G - /var/log (reserved in kickstart)
            #          2 G - /scratch (reserved in kickstart)
            #          2 G - /var/lib/postgresql
            #          2 G - /var/lib/rabbitmq
            #          1 G - /opt/platform
            #          1 G - /opt/extension
            #          1 G - /opt/backup
            #         20 G - /var/lib/docker
            #          8 G - /var/lib/docker-distribution
            #          2 G - /var/lib/kubelet
            #          1 G - /opt/etcd
            #        -----
            #         43 G
            #
            #  The absolute minimum disk size for these default settings:
            #     0.5 G - /boot
            #     1.0 G - /opt/platform-backup
            #    15.0 G - /
            #    43.0 G - cgts-vg PV
            #   -------
            #    ~ 60 G min size disk
            #

            database_storage = \
                constants.DEFAULT_TINY_DATABASE_STOR_SIZE
            platform_storage = \
                constants.DEFAULT_TINY_PLATFORM_STOR_SIZE
            docker_distribution_lv_size = \
                constants.TINY_DOCKER_DISTRIBUTION_STOR_SIZE
            etcd_lv_size = constants.TINY_ETCD_STOR_SIZE

        else:
            LOG.info("Disk size : %s ... disk too small" % disk_size)
            raise exception.SysinvException("Disk size requirements not met.")

        # platform fs added to platform-lv
        data = {
            'name': constants.FILESYSTEM_NAME_PLATFORM,
            'size': platform_storage,
            'logical_volume': constants.FILESYSTEM_LV_DICT[
                constants.FILESYSTEM_NAME_PLATFORM],
            'replicated': True,
        }
        LOG.info("Creating FS:%s:%s %d" % (
            data['name'], data['logical_volume'], data['size']))
        self.dbapi.controller_fs_create(data)

        # pgsql fs added to pgsql-lv
        data = {
            'name': constants.FILESYSTEM_NAME_DATABASE,
            'size': database_storage,
            'logical_volume': constants.FILESYSTEM_LV_DICT[
                constants.FILESYSTEM_NAME_DATABASE],
            'replicated': True,
        }
        LOG.info("Creating FS:%s:%s %d" % (
            data['name'], data['logical_volume'], data['size']))
        self.dbapi.controller_fs_create(data)

        # extension fs added to extension-lv
        data = {
            'name': constants.FILESYSTEM_NAME_EXTENSION,
            'size': extension_lv_size,
            'logical_volume': constants.FILESYSTEM_LV_DICT[
                constants.FILESYSTEM_NAME_EXTENSION],
            'replicated': True,
        }
        LOG.info("Creating FS:%s:%s %d" % (
            data['name'], data['logical_volume'], data['size']))
        self.dbapi.controller_fs_create(data)

        # ETCD fs added to etcd-lv
        data_etcd = {
                'name': constants.FILESYSTEM_NAME_ETCD,
                'size': etcd_lv_size,
                'logical_volume': constants.FILESYSTEM_LV_DICT[
                    constants.FILESYSTEM_NAME_ETCD],
                'replicated': True,
        }
        LOG.info("Creating FS:%s:%s %d" % (
            data_etcd['name'], data_etcd['logical_volume'], data_etcd['size']))
        self.dbapi.controller_fs_create(data_etcd)

        # docker-distribution fs added to dockerdistribution-lv
        data = {
            'name': constants.FILESYSTEM_NAME_DOCKER_DISTRIBUTION,
            'size': docker_distribution_lv_size,
            'logical_volume': constants.FILESYSTEM_LV_DICT[
                constants.FILESYSTEM_NAME_DOCKER_DISTRIBUTION],
            'replicated': True,
        }
        LOG.info("Creating FS:%s:%s %d" % (
            data['name'], data['logical_volume'], data['size']))
        self.dbapi.controller_fs_create(data)

        # dc-vault fs added to dc-vault-lv
        if system_dc_role == constants.DISTRIBUTED_CLOUD_ROLE_SYSTEMCONTROLLER:
            data = {
                'name': constants.FILESYSTEM_NAME_DC_VAULT,
                'size': constants.DEFAULT_DC_VAULT_STOR_SIZE,
                'logical_volume': constants.FILESYSTEM_LV_DICT[
                    constants.FILESYSTEM_NAME_DC_VAULT],
                'replicated': True,
            }
            LOG.info("Creating FS:%s:%s %d" % (
                data['name'], data['logical_volume'], data['size']))
            self.dbapi.controller_fs_create(data)

    def update_service_config(self, context, service=None, do_apply=False,
                              section=None, name=None):
        """Update the service parameter configuration"""

        LOG.info("Updating parameters configuration for service: %s" % service)

        config_uuid = None
        # All other services
        personalities = [constants.CONTROLLER]
        reboot = False
        # On service parameter add just update the host profile
        # for personalities pertinent to that service
        if service == constants.SERVICE_TYPE_HTTP:
            personalities = [constants.CONTROLLER,
                             constants.WORKER,
                             constants.STORAGE]
        elif service == constants.SERVICE_TYPE_OPENSTACK:
            # Do nothing. Does not need to update target config of any hosts
            personalities = None
        elif service == constants.SERVICE_TYPE_PTP:
            self._update_ptp_host_configs(context, do_apply=do_apply)
            personalities = None
        elif service == constants.SERVICE_TYPE_DOCKER:
            reboot = True
            if section == constants.SERVICE_PARAM_SECTION_DOCKER_PROXY or \
                    name == constants.SERVICE_PARAM_NAME_DOCKER_AUTH_SECRET:
                reboot = False
        elif service == constants.SERVICE_TYPE_KUBERNETES:
            reboot = True
            # kube apiserver service parameters can be applied without a reboot
            if section == constants.SERVICE_PARAM_SECTION_KUBERNETES_APISERVER:
                reboot = False
            # The KUBERNETES_POD_MAX_PIDS affects workers.
            # A smarter way would be for update_service_config to receive the
            # diff list or dict, to only target required personalities.
            if section == constants.SERVICE_PARAM_SECTION_KUBERNETES_CONFIG:
                personalities = [constants.CONTROLLER, constants.WORKER]
        elif service == constants.SERVICE_TYPE_PLATFORM:
            if section == constants.SERVICE_PARAM_SECTION_COLLECTD:
                reboot = True
                personalities = [constants.CONTROLLER,
                                 constants.WORKER,
                                 constants.STORAGE]
            elif section == constants.SERVICE_PARAM_SECTION_PLATFORM_KERNEL:
                reboot = True
                personalities = [constants.CONTROLLER,
                                 constants.WORKER]
                config_uuid = self._config_update_hosts(context, personalities, reboot=True)

                config_dict = {
                    'personalities': personalities,
                    "classes": ['platform::compute::grub::runtime']
                }

                # Apply runtime config but keep reboot required flag set in
                # _config_update_hosts() above. Node needs a reboot to clear it.
                config_uuid = self._config_clear_reboot_required(config_uuid)
                self._config_apply_runtime_manifest(context, config_uuid, config_dict, force=True)
            elif section == constants.SERVICE_PARAM_SECTION_PLATFORM_CONFIG and \
                    name == constants.SERVICE_PARAM_NAME_PLAT_CONFIG_INTEL_NIC_DRIVER_VERSION:
                reboot = True
                personalities = [constants.CONTROLLER,
                                 constants.WORKER,
                                 constants.STORAGE]
                config_uuid = self._config_update_hosts(context, personalities, reboot=True)

                config_dict = {
                    'personalities': personalities,
                    "classes": ['platform::compute::grub::runtime']
                }

                # Apply runtime config but keep reboot required flag set in
                # _config_update_hosts() above. Node needs a reboot to clear it.
                config_uuid = self._config_clear_reboot_required(config_uuid)
                self._config_apply_runtime_manifest(context, config_uuid, config_dict, force=True)
            elif section == constants.SERVICE_PARAM_SECTION_PLATFORM_COREDUMP:
                personalities = [constants.CONTROLLER,
                                 constants.WORKER,
                                 constants.STORAGE]

                config_uuid = self._config_update_hosts(context, personalities)

                config_dict = {
                    'personalities': personalities,
                    "classes": ['platform::coredump::runtime']
                }

                self._config_apply_runtime_manifest(context, config_uuid, config_dict, force=True)
            elif section == constants.SERVICE_PARAM_SECTION_PLATFORM_POSTGRESQL:
                personalities = [constants.CONTROLLER]

                config_uuid = self._config_update_hosts(context, personalities)

                config_dict = {
                    'personalities': personalities,
                    "classes": ['platform::postgresql::runtime']
                }

                self._config_apply_runtime_manifest(context, config_uuid, config_dict, force=True)
        # we should not set the reboot flag on operations that are not
        # reboot required. An apply of a service parameter is not reboot
        # required. If we set the flag, we could accidentally clear
        # config out-of-date alarms.
        if do_apply:
            reboot = False

        if personalities is not None:
            config_uuid = self._config_update_hosts(context,
                                                    personalities,
                                                    reboot=reboot)

        if do_apply:
            if service == constants.SERVICE_TYPE_IDENTITY:
                remote_ldap_domains = [constants.SERVICE_PARAM_SECTION_IDENTITY_LDAP_DOMAIN1,
                                       constants.SERVICE_PARAM_SECTION_IDENTITY_LDAP_DOMAIN2,
                                       constants.SERVICE_PARAM_SECTION_IDENTITY_LDAP_DOMAIN3]
                local_openldap = [constants.SERVICE_PARAM_SECTION_IDENTITY_LOCAL_OPENLDAP]

                if section in remote_ldap_domains:
                    personalities = [
                            constants.CONTROLLER,
                            constants.WORKER,
                            constants.STORAGE]
                    config_dict = {
                        'personalities': personalities,
                        "classes": ['platform::sssd::domain::runtime']
                    }
                    LOG.info("Applying SSSD domain runtime manifest")
                    self._config_apply_runtime_manifest(context, config_uuid, config_dict)
                elif section in local_openldap:
                    personalities = [constants.CONTROLLER]
                    config_dict = {
                        "personalities": personalities,
                        "classes": ['platform::ldap::insecure::runtime']
                    }
                    self._config_apply_runtime_manifest(context, config_uuid, config_dict)
                else:
                    personalities = [constants.CONTROLLER]
                    config_dict = {
                        "personalities": personalities,
                        "classes": ['platform::haproxy::runtime',
                            'openstack::keystone::server::runtime']
                    }
                    self._config_apply_runtime_manifest(context, config_uuid, config_dict)

            elif service == constants.SERVICE_TYPE_HORIZON:
                config_dict = {
                    "personalities": personalities,
                    "classes": ['openstack::horizon::runtime']
                }
                self._config_apply_runtime_manifest(context, config_uuid, config_dict)

            elif service == constants.SERVICE_TYPE_PLATFORM:
                config_dict = {
                    "personalities": personalities,
                    "classes": ['platform::mtce::runtime']
                }
                self._config_apply_runtime_manifest(context, config_uuid, config_dict)

            elif service == constants.SERVICE_TYPE_RADOSGW:
                personalities = [constants.CONTROLLER]
                config_dict = {
                    "personalities": personalities,
                    "classes": ['platform::ceph::rgw::runtime',
                                'platform::sm::rgw::runtime',
                                'platform::haproxy::runtime'],
                    puppet_common.REPORT_STATUS_CFG:
                        puppet_common.REPORT_CEPH_RADOSGW_CONFIG
                }
                self._config_apply_runtime_manifest(context, config_uuid, config_dict)

            elif service == constants.SERVICE_TYPE_BARBICAN:
                personalities = [constants.CONTROLLER]
                config_dict = {
                    "personalities": personalities,
                    "classes": ['openstack::barbican::runtime']
                }
                self._config_apply_runtime_manifest(context, config_uuid, config_dict)

            elif service == constants.SERVICE_TYPE_KUBERNETES:
                personalities = [constants.CONTROLLER]
                config_dict = {
                    "personalities": personalities,
                    "classes": ['platform::kubernetes::master::change_apiserver_parameters']
                }
                self._config_apply_runtime_manifest(context, config_uuid, config_dict)

            elif service == constants.SERVICE_TYPE_HTTP:
                # the platform::config class will be applied that will
                # configure the http port
                personalities = [constants.WORKER, constants.STORAGE]
                config_dict = {
                    "personalities": personalities,
                    "classes": ['platform::patching::runtime']}
                self._config_apply_runtime_manifest(context, config_uuid,
                                                    config_dict)

                # the runtime classes on controllers will be applied
                personalities = [constants.CONTROLLER]
                config_dict = {
                    "personalities": personalities,
                    "classes": ['openstack::lighttpd::runtime',
                                'platform::helm::runtime',
                                'platform::firewall::runtime',
                                'platform::patching::runtime'],
                    puppet_common.REPORT_STATUS_CFG:
                        puppet_common.REPORT_HTTP_CONFIG
                }
                self._config_apply_runtime_manifest(context, config_uuid,
                                                    config_dict)
            elif service == constants.SERVICE_TYPE_DOCKER:
                personalities = [constants.CONTROLLER]
                config_dict = {
                    "personalities": personalities,
                    "classes": ['platform::docker::runtime']
                }
                self._config_apply_runtime_manifest(context, config_uuid, config_dict)
            elif service == constants.SERVICE_TYPE_CEPH:
                if StorageBackendConfig.has_backend(
                        self.dbapi, constants.CINDER_BACKEND_CEPH):

                    personalities = [constants.CONTROLLER,
                                    constants.WORKER,
                                    constants.STORAGE]

                    monitors = self.dbapi.ceph_mon_get_list()
                    host_uuids = []
                    for mon in monitors:
                        host_uuids.append(mon.ihost_uuid)
                    config_uuid = self._config_update_hosts(context,
                                                            personalities,
                                                            host_uuids)
                    config_dict = {
                        "personalities": personalities,
                        "host_uuids": host_uuids,
                        "classes": ['platform::ceph::mon::runtime']
                    }
                    self._config_apply_runtime_manifest(context,
                                                        config_uuid=config_uuid,
                                                        config_dict=config_dict)

    def update_security_feature_config(self, context):
        """Update the kernel options configuration"""
        # Move the edgeworker personality out since it is not configured by puppet
        personalities = [i for i in constants.PERSONALITIES if i != constants.EDGEWORKER]

        config_uuid = self._config_update_hosts(context, personalities, reboot=True)

        config_dict = {
            'personalities': personalities,
            'classes': ['platform::grub::runtime']
        }

        # Apply runtime config but keep reboot required flag set in
        # _config_update_hosts() above. Node needs a reboot to clear it.
        config_uuid = self._config_clear_reboot_required(config_uuid)
        self._config_apply_runtime_manifest(context, config_uuid, config_dict, force=True)

    def update_sdn_controller_config(self, context):
        """Update the SDN controller configuration"""
        LOG.info("update_sdn_controller_config")

        # Apply Neutron manifest on Controller(this
        # will update the SNAT rules for the SDN controllers)
        self._config_update_hosts(context, [constants.WORKER], reboot=True)

        config_uuid = self._config_update_hosts(context,
                                               [constants.CONTROLLER])
        config_dict = {
            "personalities": [constants.CONTROLLER],
            "classes": [],
        }
        self._config_apply_runtime_manifest(context, config_uuid, config_dict)

    def update_sdn_enabled(self, context):
        """Update the sdn enabled flag.

        :param context: an admin context.
        """
        LOG.info("update_sdn_enabled")

        personalities = [constants.CONTROLLER]
        config_dict = {
            "personalities": personalities,
            "classes": ['platform::sysctl::controller::runtime']
        }
        config_uuid = self._config_update_hosts(context, personalities)
        self._config_apply_runtime_manifest(context, config_uuid, config_dict)

        personalities = [constants.WORKER]
        self._config_update_hosts(context, personalities, reboot=True)

    def update_vswitch_type(self, context):
        """Update the system vswitch type.

        :param context: an admin context.
        """
        LOG.info("update_vswitch_type")

        personalities = [constants.CONTROLLER]
        config_dict = {
            "personalities": personalities,
            "classes": ['platform::sysctl::controller::runtime',
                        'platform::nfv::runtime']
        }
        config_uuid = self._config_update_hosts(context, personalities)
        self._config_apply_runtime_manifest(context, config_uuid, config_dict)

        if tsc.system_type == constants.TIS_AIO_BUILD:
            personalities = [constants.CONTROLLER]
        else:
            personalities = [constants.WORKER]

        self._config_update_hosts(context, personalities, reboot=True)

    def _update_hosts_file(self, hostname, address, active=True):
        """Update or add an entry to the /etc/hosts configuration file

        :param hostname: The hostname to update or add
        :param address: The address to update or add
        :param active: Flag indicating whether to update the active hosts file
        """
        hosts_file = '/etc/hosts'
        hosts_file_temp = hosts_file + '.temp'

        with open(hosts_file, 'r') as f_in:
            with open(hosts_file_temp, 'w') as f_out:
                for line in f_in:
                    # copy all entries except for the updated host
                    if hostname not in line:
                        f_out.write(line)
                f_out.write("%s %s\n" % (address, hostname))

        # Copy the updated file to shared storage
        shutil.copy2(hosts_file_temp, tsc.CONFIG_PATH + 'hosts')

        if active:
            # Atomically replace the active hosts file
            os.rename(hosts_file_temp, hosts_file)
        else:
            # discard temporary file
            os.remove(hosts_file_temp)

    def update_grub_config(self, context, host_uuid, force_grub_update=False):
        """Update the grub configuration on a host"""

        # only apply the manifest on the host that has worker sub function
        host = self.dbapi.ihost_get(host_uuid)
        if constants.WORKER in host.subfunctions:
            force = (not utils.is_host_simplex_controller(host) or
                     force_grub_update)
            LOG.info("update_grub_config, host uuid: (%s), force: (%s)",
                     host_uuid, str(force))
            personalities = [constants.CONTROLLER, constants.WORKER]
            config_uuid = self._config_update_hosts(context,
                                                    personalities,
                                                    host_uuids=[host_uuid])
            config_dict = {
                "personalities": personalities,
                "host_uuids": [host_uuid],
                "classes": ['platform::compute::grub::runtime',
                            'platform::compute::config::runtime']
            }
            self._config_apply_runtime_manifest(context, config_uuid,
                                                config_dict,
                                                force=force)

    @staticmethod
    def _write_config(filename, path, file_content):
        filepath = os.path.join(path, filename)
        fd, tmppath = tempfile.mkstemp(dir=path, prefix=filename,
                                       text=True)

        with open(tmppath, 'w') as f:
            f.write(file_content)
        # Atomically replace the updated file
        os.close(fd)
        os.rename(tmppath, filepath)

    def _drbd_connected(self):
        connected = False

        output = subprocess.check_output("drbd-overview",  # pylint: disable=not-callable
                                         stderr=subprocess.STDOUT,
                                         universal_newlines=True)
        output = [_f for _f in output.split('\n') if _f]

        for row in output:
            if "Connected" in row:
                connected = True
            else:
                connected = False
                break

        return connected

    def _drbd_fs_sync(self):
        output = subprocess.check_output("drbd-overview",  # pylint: disable=not-callable
                                         stderr=subprocess.STDOUT,
                                         universal_newlines=True)
        output = [_f for _f in output.split('\n') if _f]

        fs = []
        for row in output:
            # Check PausedSyncS as well as drbd sync is changed to serial
            # Check Connected because there are cases when drbd-overview
            # showed Connected instead of PausedSyncS and SyncSource states
            if "drbd-pgsql" in row and ("SyncSource" in row or "PausedSyncS" in row
                                        or "Connected" in row):
                fs.append(constants.DRBD_PGSQL)
            if "drbd-platform" in row and ("SyncSource" in row or "PausedSyncS" in row
                                           or "Connected" in row):
                fs.append(constants.DRBD_PLATFORM)
            if "drbd-extension" in row and ("SyncSource" in row or "PausedSyncS" in row
                                            or "Connected" in row):
                fs.append(constants.DRBD_EXTENSION)
            if "drbd-dc-vault" in row and ("SyncSource" in row or "PausedSyncS" in row
                                           or "Connected" in row):
                fs.append(constants.DRBD_DC_VAULT)
            if "drbd-etcd" in row and ("SyncSource" in row or "PausedSyncS" in row
                                       or "Connected" in row):
                fs.append(constants.DRBD_ETCD)
            if "drbd-dockerdistribution" in row and ("SyncSource" in row or "PausedSyncS" in row
                                                     or "Connected" in row):
                fs.append(constants.DRBD_DOCKER_DISTRIBUTION)
        return fs

    def _drbd_fs_updated(self, context):
        drbd_dict = subprocess.check_output("drbd-overview",  # pylint: disable=not-callable
                                            stderr=subprocess.STDOUT,
                                            universal_newlines=True)
        drbd_dict = [_f for _f in drbd_dict.split('\n') if _f]

        drbd_patch_size = 0
        dc_lv_size = 0
        dockerdistribution_size = 0
        dockerdistribution_lv_size = 0
        drbd_etcd_size = 0
        etcd_lv_size = 0

        for row in drbd_dict:
            if "sync\'ed" not in row:
                if 'drbd-pgsql' in row:
                    drbd_pgsql_size = self._get_drbd_fs_size("drbd0")[0]
                elif 'drbd-platform' in row:
                    drbd_platform_size = self._get_drbd_fs_size("drbd2")[0]
                elif 'drbd-extension' in row:
                    drbd_extension_size = self._get_drbd_fs_size("drbd5")[0]
                elif 'drbd-dc-vault' in row:
                    drbd_patch_size = self._get_drbd_fs_size("drbd6")[0]
                elif 'drbd-etcd' in row:
                    drbd_etcd_size = self._get_drbd_fs_size("drbd7")[0]
                elif 'drbd-dockerdistribution' in row:
                    dockerdistribution_size = self._get_drbd_fs_size("drbd8")[0]

        lvdisplay_dict = self.get_controllerfs_lv_sizes(context)
        if lvdisplay_dict.get('pgsql-lv', None):
            pgsql_lv_size = float(lvdisplay_dict['pgsql-lv'])
        if lvdisplay_dict.get('platform-lv', None):
            platform_lv_size = float(lvdisplay_dict['platform-lv'])
        if lvdisplay_dict.get('extension-lv', None):
            extension_lv_size = float(lvdisplay_dict['extension-lv'])
        if lvdisplay_dict.get('dc-vault-lv', None):
            dc_lv_size = float(lvdisplay_dict['dc-vault-lv'])
        if lvdisplay_dict.get('etcd-lv', None):
            etcd_lv_size = float(lvdisplay_dict['etcd-lv'])
        if lvdisplay_dict.get('dockerdistribution-lv', None):
            dockerdistribution_lv_size = float(lvdisplay_dict['dockerdistribution-lv'])

        LOG.info("drbd-overview: pgsql-%s, platform-%s, extension-%s,"
                 " dc-vault-%s, etcd-%s, dockerdistribution-%s",
                 drbd_pgsql_size, drbd_platform_size, drbd_extension_size,
                 drbd_patch_size, drbd_etcd_size, dockerdistribution_size)
        LOG.info("lvdisplay: pgsql-%s, platform-%s, extension-%s,"
                 " dc-vault-%s, etcd-%s, dockerdistribution-%s",
                 pgsql_lv_size, platform_lv_size, extension_lv_size,
                 dc_lv_size, etcd_lv_size, dockerdistribution_lv_size)

        drbd_fs_updated = []
        if math.ceil(drbd_pgsql_size) < math.ceil(pgsql_lv_size):
            drbd_fs_updated.append(constants.DRBD_PGSQL)
        if math.ceil(drbd_platform_size) < math.ceil(platform_lv_size):
            drbd_fs_updated.append(constants.DRBD_PLATFORM)
        if math.ceil(drbd_extension_size) < math.ceil(extension_lv_size):
            drbd_fs_updated.append(constants.DRBD_EXTENSION)
        if math.ceil(drbd_patch_size) < math.ceil(dc_lv_size):
            drbd_fs_updated.append(constants.DRBD_DC_VAULT)
        if math.ceil(drbd_etcd_size) < math.ceil(etcd_lv_size):
            drbd_fs_updated.append(constants.DRBD_ETCD)
        if math.ceil(dockerdistribution_size) < math.ceil(dockerdistribution_lv_size):
            drbd_fs_updated.append(constants.DRBD_DOCKER_DISTRIBUTION)

        return drbd_fs_updated

    def _get_drbd_fs_size(self, drbd_dev):
        """ Get drbd filesystem size

        :param drbd_dev: drbd device name
        :returns: tuple with (drbd_filesystem_size, return_code)
        """
        cmd = "dumpe2fs -h /dev/{}".format(drbd_dev)
        dumpfs_proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE, shell=True,
                                       universal_newlines=True)
        dumpfs_out, dumpfs_err = dumpfs_proc.communicate()
        total_size = 0
        retcode = dumpfs_proc.returncode
        log_msg = "Executed _get_drbd_fs_size: drbd_dev: {} return code: {}"\
            .format(drbd_dev, retcode)
        if retcode == 0:
            dumpfs_dict = [_f for _f in dumpfs_out.split('\n') if _f]
            block_size = 0
            block_count = 0
            try:
                for row in dumpfs_dict:
                    if "Block size" in row:
                        block_size = int([i for i in row.split() if i][2])
                    elif "Block count" in row:
                        block_count = int([i for i in row.split() if i][2])
                total_size = cutils.bytes_to_GiB(block_count * block_size)
            except IndexError:
                retcode = 1
        else:
            log_msg += "\nstdout={}\nstderr={}".format(dumpfs_out, dumpfs_err)
        LOG.info(log_msg)
        return total_size, retcode

    def _get_drbd_dev_size(self, drbd_dev):
        """ Get drbd device size

        :param drbd_dev: drbd device name
        :returns: tuple with (drbd_device_size, return_code)
        """
        cmd = "blockdev --getpbsz /dev/{}".format(drbd_dev)
        blockdev_proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                         stderr=subprocess.PIPE, shell=True,
                                         universal_newlines=True)
        blockdev_out, blockdev_err = blockdev_proc.communicate()
        total_size = 0
        retcode = blockdev_proc.returncode
        log_msg = "Executed _get_drbd_dev_size: drbd_dev: {} return code: {}"\
            .format(drbd_dev, retcode)
        if retcode == 0:
            sector_size = 0
            drbd_size_in_sectors = 0
            try:
                sector_size = int(blockdev_out.strip())
                drbd_size_in_sectors_file_path = "/sys/block/{}/size".format(drbd_dev)
                with open(drbd_size_in_sectors_file_path) as f:
                    drbd_size_in_sectors = int(f.read().strip())
            except ValueError:
                retcode = 1
            total_size = cutils.bytes_to_GiB(sector_size * drbd_size_in_sectors)
        else:
            log_msg += "\nstdout={}\nstderr={}".format(blockdev_out, blockdev_err)
        LOG.info(log_msg)
        return total_size, retcode

    def _verify_drbd_dev_resized(self, context, drbd_dev, drbd_lv):
        return self._verify_drbd_resized_generic(context, drbd_dev,
                                                 drbd_lv, self._get_drbd_dev_size)

    def _verify_drbd_fs_resized(self, context, drbd_dev, drbd_lv):
        return self._verify_drbd_resized_generic(context, drbd_dev,
                                                 drbd_lv, self._get_drbd_fs_size)

    def _verify_drbd_resized_generic(self, context, drbd_dev, drbd_lv,
                                     get_actual_size_func, delay=15, max_retries=3):
        retries = 0
        resized = False
        while retries < max_retries:
            lvdisplay_dict = self.get_controllerfs_lv_sizes(context)
            drbd_actual_size, retcode = get_actual_size_func(drbd_dev)
            if retcode == 0 and lvdisplay_dict.get(drbd_lv, None):
                drbd_lv_size = float(lvdisplay_dict[drbd_lv])
                if math.ceil(drbd_actual_size) >= math.ceil(drbd_lv_size):
                    resized = True
                    break
            retries += 1
            time.sleep(delay)
        return resized

    def _resize2fs_drbd_dev(self, context, retry_attempts, drbd_dev, drbd_lv):
        resized = False
        if self._verify_drbd_dev_resized(context, drbd_dev, drbd_lv):
            progress = "resize2fs {}".format(drbd_dev)
            cmd = ["resize2fs", "/dev/{}".format(drbd_dev)]
            stdout, __ = cutils.execute(*cmd, attempts=retry_attempts, run_as_root=True)
            if self._verify_drbd_fs_resized(context, drbd_dev, drbd_lv):
                LOG.info("Performed %s" % progress)
                resized = True
            else:
                LOG.warn("{} filesystem not resized yet".format(drbd_dev))
        else:
            LOG.warn("{} device not resized yet".format(drbd_dev))
        return resized

    def _config_resize_filesystems(self, context, standby_host):
        """Resize the filesystems upon completion of storage config.
           Retry in case of errors or racing issues when resizing fails."""

        retry_attempts = 3
        rc = False
        drbd_fs_resized = set()

        with open(os.devnull, "w"):
            try:
                if standby_host:
                    if not self._drbd_connected():
                        return rc, drbd_fs_resized

                if not os.path.isfile(CFS_DRBDADM_RECONFIGURED):
                    progress = "drbdadm resize all"
                    if standby_host:
                        cmd = ["drbdadm", "resize", "all"]
                    else:
                        cmd = ["drbdadm", "--", "--assume-peer-has-space", "resize", "all"]
                    stdout, __ = cutils.execute(*cmd, attempts=retry_attempts, run_as_root=True)
                    LOG.info("Performed %s" % progress)
                    cutils.touch(CFS_DRBDADM_RECONFIGURED)

                loop_timeout = 0
                max_loop = 5
                drbd_fs_updated = set(self._drbd_fs_updated(context))

                if not drbd_fs_updated:
                    rc = True
                else:
                    while(loop_timeout <= max_loop):
                        if constants.DRBD_PGSQL in (drbd_fs_updated - drbd_fs_resized):
                            if (not standby_host or (standby_host and
                                 constants.DRBD_PGSQL in self._drbd_fs_sync())):
                                # database_gib /var/lib/postgresql
                                drbd_dev = "drbd0"
                                drbd_lv = "pgsql-lv"
                                if self._resize2fs_drbd_dev(context, retry_attempts,
                                                            drbd_dev, drbd_lv):
                                    drbd_fs_resized.add(constants.DRBD_PGSQL)

                        if constants.DRBD_PLATFORM in (drbd_fs_updated - drbd_fs_resized):
                            if (not standby_host or (standby_host and
                                 constants.DRBD_PLATFORM in self._drbd_fs_sync())):
                                # platform_gib /opt/platform
                                drbd_dev = "drbd2"
                                drbd_lv = "platform-lv"
                                if self._resize2fs_drbd_dev(context, retry_attempts,
                                                            drbd_dev, drbd_lv):
                                    drbd_fs_resized.add(constants.DRBD_PLATFORM)

                        if constants.DRBD_EXTENSION in (drbd_fs_updated - drbd_fs_resized):
                            if (not standby_host or (standby_host and
                                 constants.DRBD_EXTENSION in self._drbd_fs_sync())):
                                # extension_gib /opt/extension
                                drbd_dev = "drbd5"
                                drbd_lv = "extension-lv"
                                if self._resize2fs_drbd_dev(context, retry_attempts,
                                                            drbd_dev, drbd_lv):
                                    drbd_fs_resized.add(constants.DRBD_EXTENSION)

                        if constants.DRBD_DC_VAULT in (drbd_fs_updated - drbd_fs_resized):
                            if (not standby_host or (standby_host and
                                 constants.DRBD_DC_VAULT in self._drbd_fs_sync())):
                                # patch_gib /opt/dc-vault
                                drbd_dev = "drbd6"
                                drbd_lv = "dc-vault-lv"
                                if self._resize2fs_drbd_dev(context, retry_attempts,
                                                            drbd_dev, drbd_lv):
                                    drbd_fs_resized.add(constants.DRBD_DC_VAULT)

                        if constants.DRBD_ETCD in (drbd_fs_updated - drbd_fs_resized):
                            if (not standby_host or (standby_host and
                                 constants.DRBD_ETCD in self._drbd_fs_sync())):
                                # patch_gib /opt/etcd
                                drbd_dev = "drbd7"
                                drbd_lv = "etcd-lv"
                                if self._resize2fs_drbd_dev(context, retry_attempts,
                                                            drbd_dev, drbd_lv):
                                    drbd_fs_resized.add(constants.DRBD_ETCD)

                        if constants.DRBD_DOCKER_DISTRIBUTION in (drbd_fs_updated - drbd_fs_resized):
                            if (not standby_host or (standby_host and
                                 constants.DRBD_DOCKER_DISTRIBUTION in self._drbd_fs_sync())):
                                # patch_gib /var/lib/docker-distribution
                                drbd_dev = "drbd8"
                                drbd_lv = "dockerdistribution-lv"
                                if self._resize2fs_drbd_dev(context, retry_attempts,
                                                            drbd_dev, drbd_lv):
                                    drbd_fs_resized.add(constants.DRBD_DOCKER_DISTRIBUTION)

                        if drbd_fs_updated == drbd_fs_resized:
                            LOG.info("resizing filesystems completed")
                            rc = True
                            break
                        else:
                            LOG.warn("Failed to resize filesystems: " +
                                     ", ".join(drbd_fs_updated - drbd_fs_resized) +
                                     ". Retry {} of {}".format(loop_timeout, max_loop))

                        loop_timeout += 1
                        time.sleep(1)
                    else:
                        LOG.warn("resizing filesystems not completed")
            except exception.ProcessExecutionError as ex:
                LOG.warn("Failed to perform storage resizing (cmd: '%(cmd)s', "
                         "return code: %(rc)s, stdout: '%(stdout)s).', "
                         "stderr: '%(stderr)s'" %
                         {"cmd": ex.cmd, "stdout": ex.stdout,
                          "stderr": ex.stderr, "rc": ex.exit_code})

        # Add fs name to drbd_fs_resized if state is None
        # and not in drbd_fs_updated nor drbd_fs_resized
        # as initial configuration case (which needs to be added into
        # drbd_fs_resized to update state from "None" to "available")
        controller_fs_list = self.dbapi.controller_fs_get_list()
        for fs in controller_fs_list:
            fs_name = constants.FILESYSTEM_DRBD_DICT.get(fs.get('name'))
            if ((fs.get('state') is None) and
               (fs_name not in drbd_fs_updated) and
               (fs_name not in drbd_fs_resized)):
                drbd_fs_resized.add(fs_name)

        return rc, drbd_fs_resized

    # Retrying a few times and waiting between each retry should provide
    # enough protection in the unlikely case LVM's own locking mechanism
    # is unreliable.
    @retry(stop_max_attempt_number=5, wait_fixed=1000,
           retry_on_result=(lambda x: True if x == constants.CINDER_RESIZE_FAILURE else False))
    def _resize_cinder_volumes(self, delayed=False):
        """Resize cinder-volumes drbd-backed PV and cinder-volumes-pool LV to
        match the new (increased) size"""

        if not StorageBackendConfig.has_backend_configured(
            self.dbapi,
            constants.CINDER_BACKEND_LVM
        ):
            return

        cmd = []
        try:
            if delayed:
                cmd = ["drbdadm", "cstate", constants.CINDER_LVM_DRBD_RESOURCE]
                stdout, __ = cutils.execute(*cmd, run_as_root=True)
                if utils.get_system_mode(self.dbapi) != constants.SYSTEM_MODE_SIMPLEX:
                    # Wait for drbd connect.
                    # It is possible that drbd is already in sync state
                    # (e.g. When the disk partition for the cinder-volumes is
                    # increased on the newly standby controller after controller
                    # swact), so we check for drbd "Connected" and "SyncSource".
                    # It is also possible that drbd is in "PausedSyncS" if we are
                    # doing serial syncing and another FS is syncing.
                    if ("Connected" not in stdout and
                            "SyncSource" not in stdout and
                            "PausedSyncS" not in stdout):
                        return constants.CINDER_RESIZE_FAILURE
                else:
                    # For simplex we just need to have drbd up
                    if "WFConnection" not in stdout:
                        return constants.CINDER_RESIZE_FAILURE

            # Force a drbd resize on AIO SX as peer is not configured.
            # DRBD resize is automatic when both peers are connected.
            if utils.get_system_mode(self.dbapi) == constants.SYSTEM_MODE_SIMPLEX:
                # get the commands executed by 'drbdadm resize' and append some options
                cmd = ["drbdadm", "--dry-run", "resize", constants.CINDER_LVM_DRBD_RESOURCE]
                stdout, __ = cutils.execute(*cmd, run_as_root=True)
                for line in stdout.splitlines():
                    if 'drbdsetup resize' in line:
                        cmd = line.split()
                        cmd = cmd + ['--assume-peer-has-space=yes']
                    else:
                        cmd = line.split()
                    __, __ = cutils.execute(*cmd, run_as_root=True)

            # Resize the pv
            cmd = ["pvresize", "/dev/drbd/by-res/%s/0" % constants.CINDER_LVM_DRBD_RESOURCE]
            stdout, __ = cutils.execute(*cmd, run_as_root=True)
            LOG.info("Resized %s PV" % constants.CINDER_LVM_DRBD_RESOURCE)

            # Resize the Thin pool LV. Abort if pool doesn't exist, it may not be configured at all
            data_lv = "%s/%s" % (constants.LVG_CINDER_VOLUMES, constants.CINDER_LVM_POOL_LV)
            metadata_lv = "%s/%s" % (constants.LVG_CINDER_VOLUMES, constants.CINDER_LVM_POOL_META_LV)
            cmd = ["lvs", "-o", "vg_name,lv_name", "--noheadings", "--separator", "/", data_lv]
            stdout, __ = cutils.trycmd(*cmd, attempts=3, run_as_root=True)
            if data_lv in stdout:
                # Extend metadata portion of the thinpool to be at least 1 GiB
                cmd = ["lvextend", "-L1g", metadata_lv]
                # It's ok if it returns 0 or 5 (ECMD_FAILED in lvm cmds), it most likely
                # means that the size is equal or greater than what we intend to configure.
                # But we have to retry in case it gets ECMD_PROCESSED which seems to happen
                # randomly and rarely yet is important not to fail the operation.
                stdout, __ = cutils.execute(*cmd, check_exit_code=[0, 5],
                                            run_as_root=True, attempts=3)

                # Get the VG size and VG free
                cmd = ['vgs', 'cinder-volumes', '-o', 'vg_size,vg_free',
                       '--noheadings', '--units', 'm', '--nosuffix']
                stdout, __ = cutils.execute(*cmd, run_as_root=True, attempts=3)
                vg_size_str, vg_free_str = stdout.split()
                vg_size = float(vg_size_str)
                vg_free = float(vg_free_str)

                # Leave ~1% in VG for metadata expansion and recovery,
                # result rounded to multiple of block size (4MiB)
                extend_lv_by = (vg_free - vg_size * 0.01) // 4 * 4

                LOG.info("Cinder-volumes VG size: %(size)sMiB free: %(free)sMiB, "
                         "cinder volumes pool delta to desired 99%% of VG: %(delta)sMiB" %
                         {"size": vg_size, "free": vg_free, "delta": extend_lv_by})

                if extend_lv_by > 0:
                    # Get current size of the data LV for logging
                    cmd = ['lvs', '-o', 'lv_size', '--noheadings',
                           '--units', 'm', '--nosuffix', data_lv]
                    stdout, __ = cutils.execute(*cmd, run_as_root=True, attempts=3)
                    data_old_size = float(stdout)

                    # Extend the data part of the thinpool
                    cmd = ["lvextend", "-L+%.2fm" % extend_lv_by, data_lv]
                    cutils.execute(*cmd, check_exit_code=[0, 5],
                                   run_as_root=True, attempts=3)

                    # Get new size of the data LV for logging
                    cmd = ['lvs', '-o', 'lv_size', '--noheadings',
                           '--units', 'm', '--nosuffix', data_lv]
                    stdout, __ = cutils.execute(*cmd, run_as_root=True, attempts=3)
                    data_new_size = float(stdout)

                    LOG.info(_("Resized %(name)s thinpool LV from %(old)sMiB to %(new)sMiB") %
                             {"name": constants.CINDER_LVM_POOL_LV,
                              "old": data_old_size,
                              "new": data_new_size})
                else:
                    LOG.info("Cinder %s already uses 99%% or more of "
                             "available space" % constants.CINDER_LVM_POOL_LV)
        except exception.ProcessExecutionError as ex:
            LOG.warn("Failed to resize cinder volumes (cmd: '%(cmd)s', "
                     "return code: %(rc)s, stdout: '%(stdout)s).', "
                     "stderr: '%(stderr)s'" %
                     {"cmd": " ".join(cmd), "stdout": ex.stdout,
                      "stderr": ex.stderr, "rc": ex.exit_code})
            # We avoid re-raising this as it may brake critical operations after this one
            return constants.CINDER_RESIZE_FAILURE

    def _remove_config_from_reboot_config_list(self, ihost_uuid, config_uuid):
        LOG.info("_remove_config_from_reboot_config_list host: %s,config_uuid: %s" %
                  (ihost_uuid, config_uuid))
        if ihost_uuid in self._host_reboot_config_uuid:
            try:
                self._host_reboot_config_uuid[ihost_uuid].remove(config_uuid)
            except ValueError:
                LOG.info("_remove_config_from_reboot_config_list fail"
                         " host:%s config_uuid %s" % (ihost_uuid, config_uuid))
                pass

    def _clear_config_from_reboot_config_list(self, ihost_uuid):
        LOG.info("_clear_config_from_reboot_config_list host:%s", ihost_uuid)
        if ihost_uuid in self._host_reboot_config_uuid:
            try:
                del self._host_reboot_config_uuid[ihost_uuid][:]
            except ValueError:
                LOG.info("_clear_config_from_reboot_config_list fail"
                         " host: %s", ihost_uuid)
                pass

    def _config_out_of_date(self, context, ihost_obj):

        def _align_config_target(context, ihost_obj, applied):
            LOG.info("Config target with no reboot required, "
                     "align host_uuid=%s target applied=%s" %
                     (ihost_obj.uuid, applied))
            ihost_obj.config_target = applied
            ihost_obj.save(context)

        target = ihost_obj.config_target
        applied = ihost_obj.config_applied
        applied_reboot = None

        if applied is not None:
            try:
                applied_reboot = self._config_set_reboot_required(applied)
            except ValueError:
                # for worker node, the applied might be 'install'
                applied_reboot = applied
                pass
        hostname = ihost_obj.hostname

        if not hostname:
            hostname = ihost_obj.get('uuid') or ""

        if not target:
            LOG.warn("%s: iconfig no target, but config %s applied" %
                     (hostname, applied))
            return False
        elif target == applied:
            self._clear_config_from_reboot_config_list(ihost_obj.uuid)
            if ihost_obj.personality == constants.CONTROLLER:

                controller_fs_list = self.dbapi.controller_fs_get_list()
                for controller_fs in controller_fs_list:
                    if controller_fs['replicated']:
                        if (controller_fs.get('state') ==
                           constants.CONTROLLER_FS_RESIZING_IN_PROGRESS):
                            LOG.info("%s: drbd resize config pending. "
                                     "manifests up to date: "
                                     "target %s, applied %s " %
                                     (hostname, target, applied))
                            return True
            else:
                LOG.info("%s: iconfig up to date: target %s, applied %s " %
                         (hostname, target, applied))
                return False
        elif target == applied_reboot:
            if ihost_obj.uuid in self._host_reboot_config_uuid:
                if len(self._host_reboot_config_uuid[ihost_obj.uuid]) == 0:
                    # There are no further config required for host, update config_target
                    _align_config_target(context, ihost_obj, applied)
                    return False
                else:
                    LOG.info("%s: %s reboot required config_applied %s host_reboot_config %s " %
                             (ihost_obj.hostname, ihost_obj.uuid, applied,
                              self._host_reboot_config_uuid[ihost_obj.uuid]))
                return True
            else:
                if self.host_uuid == ihost_obj.uuid:
                    # In the active controller case, can clear if no reboot required config.
                    # The is tracked on initialization and protected from host-swact semantic.
                    _align_config_target(context, ihost_obj, applied)
                    return False
                return True
        else:
            LOG.warn("%s: iconfig out of date: target %s, applied %s " %
                     (hostname, target, applied))
            return True

    @staticmethod
    def _get_fm_entity_instance_id(ihost_obj):
        """
        Create 'entity_instance_id' from ihost_obj data
        """

        entity_instance_id = "%s=%s" % (fm_constants.FM_ENTITY_TYPE_HOST,
                                        ihost_obj.hostname)
        return entity_instance_id

    def _log_host_create(self, host, reason=None):
        """
        Create host discovery event customer log.
        """
        if host.hostname:
            hostid = host.hostname
        else:
            hostid = host.mgmt_mac

        if reason is not None:
            reason_text = ("%s has been 'discovered' on the network. (%s)" %
                (hostid, reason))
        else:
            reason_text = ("%s has been 'discovered'." % hostid)

        # action event -> FM_ALARM_TYPE_4 = 'equipment'
        # FM_ALARM_SEVERITY_CLEAR to be consistent with 200.x series Info
        log_data = {'hostid': hostid,
                    'event_id': fm_constants.FM_LOG_ID_HOST_DISCOVERED,
                    'entity_type': fm_constants.FM_ENTITY_TYPE_HOST,
                    'entity': 'host=%s.event=discovered' % hostid,
                    'fm_severity': fm_constants.FM_ALARM_SEVERITY_CLEAR,
                    'fm_event_type': fm_constants.FM_ALARM_TYPE_4,
                    'reason_text': reason_text,
                    }
        self.fm_log.customer_log(log_data)

    def _update_alarm_status(self, context, ihost_obj):
        self._do_update_alarm_status(
            context,
            ihost_obj,
            constants.CONFIG_STATUS_OUT_OF_DATE
        )

    def _do_update_alarm_status(self, context, ihost_obj, status):
        """Check config and update FM alarm"""

        # Get new reference to avoid stale values.
        # We can't refresh because that's in-place and
        # ihost_obj is not ours.
        ihost_obj = self.dbapi.ihost_get(ihost_obj.uuid)
        entity_instance_id = self._get_fm_entity_instance_id(ihost_obj)

        save_required = False
        if self._config_out_of_date(context, ihost_obj) or \
                status == constants.CONFIG_STATUS_REINSTALL:
            LOG.warn("SYS_I Raise system config alarm: host %s "
                     "config applied: %s  vs. target: %s." %
                     (ihost_obj.hostname,
                      ihost_obj.config_applied,
                      ihost_obj.config_target))

            fault = fm_api.Fault(
                alarm_id=fm_constants.FM_ALARM_ID_SYSCONFIG_OUT_OF_DATE,
                alarm_state=fm_constants.FM_ALARM_STATE_SET,
                entity_type_id=fm_constants.FM_ENTITY_TYPE_HOST,
                entity_instance_id=entity_instance_id,
                severity=fm_constants.FM_ALARM_SEVERITY_MAJOR,
                reason_text=(_("%s Configuration is out-of-date. (applied: %s target: %s)") %
                             (ihost_obj.hostname, ihost_obj.config_applied, ihost_obj.config_target)),
                alarm_type=fm_constants.FM_ALARM_TYPE_7,  # operational
                probable_cause=fm_constants.ALARM_PROBABLE_CAUSE_75,
                proposed_repair_action=_(
                    "Lock and unlock host %s to update config." %
                    ihost_obj.hostname),
                service_affecting=True)

            self.fm_api.set_fault(fault)

            if not ihost_obj.config_status:
                ihost_obj.config_status = status
                save_required = True
            elif (status != ihost_obj.config_status and
               status == constants.CONFIG_STATUS_REINSTALL):
                ihost_obj.config_status = status
                save_required = True

            if save_required:
                ihost_obj.save(context)

        else:
            # better to clear since a GET may block
            LOG.info("SYS_I Clear system config alarm: %s target config %s" %
                     (ihost_obj.hostname, ihost_obj.config_target))

            self.fm_api.clear_fault(
                fm_constants.FM_ALARM_ID_SYSCONFIG_OUT_OF_DATE,
                entity_instance_id)

            self._clear_runtime_class_apply_in_progress(host_uuids=[ihost_obj.uuid])

            # Do not clear the config status if there is a reinstall pending.
            if (ihost_obj.config_status != constants.CONFIG_STATUS_REINSTALL):
                ihost_obj.config_status = None
                ihost_obj.save(context)

    @staticmethod
    def _config_set_reboot_required(config_uuid):
        """Set the reboot required flag for the supplied UUID

        :param config_uuid UUID object or UUID string
        :return The modified UUID as a string
        :rtype str
        """
        uuid_str = str(config_uuid)
        uuid_int = int(uuid.UUID(uuid_str)) | constants.CONFIG_REBOOT_REQUIRED
        return str(uuid.UUID(int=uuid_int))

    @staticmethod
    def _config_clear_reboot_required(config_uuid):
        """Clear the reboot required flag for the supplied UUID

        :param config_uuid UUID object or UUID string
        :return The modified UUID as a string
        :rtype str
        """
        uuid_str = str(config_uuid)
        uuid_int = int(uuid.UUID(uuid_str)) & ~constants.CONFIG_REBOOT_REQUIRED
        return str(uuid.UUID(int=uuid_int))

    def _update_host_config_reinstall(self, context, ihost_obj):
        """ update the host to be 'reinstall required'
        """
        self._do_update_alarm_status(
            context,
            ihost_obj,
            constants.CONFIG_STATUS_REINSTALL
        )

    def _update_host_config_target(self, context, ihost_obj, config_uuid):
        """Based upon config update, update config status."""

        lock_name = LOCK_NAME_UPDATE_CONFIG + ihost_obj.uuid

        @cutils.synchronized(lock_name, external=False)
        def _sync_update_host_config_target(self,
                                            context, ihost_obj, config_uuid):
            if ihost_obj.config_target != config_uuid:
                # promote the current config to reboot required if a pending
                # reboot required is still present
                if (ihost_obj.config_target and
                        ihost_obj.config_applied != ihost_obj.config_target):
                    if utils.config_is_reboot_required(ihost_obj.config_target):
                        config_uuid = self._config_set_reboot_required(config_uuid)
                LOG.info("Setting config target of "
                         "host '%s' to '%s'." % (ihost_obj.hostname, config_uuid))
                ihost_obj.config_target = config_uuid
                ihost_obj.save(context)
            if cutils.is_initial_config_complete():
                self._update_alarm_status(context, ihost_obj)

        _sync_update_host_config_target(self, context, ihost_obj, config_uuid)

    def _update_host_config_applied(self, context, ihost_obj, config_uuid):
        """Based upon agent update, update config status."""

        lock_name = LOCK_NAME_UPDATE_CONFIG + ihost_obj.uuid

        @cutils.synchronized(lock_name, external=False)
        def _sync_update_host_config_applied(self,
                                             context, ihost_obj, config_uuid):
            self._remove_config_from_reboot_config_list(ihost_obj.uuid,
                    config_uuid)
            if ihost_obj.config_applied != config_uuid:
                ihost_obj.config_applied = config_uuid
                ihost_obj.save(context)
            if cutils.is_initial_config_complete():
                self._update_alarm_status(context, ihost_obj)

        _sync_update_host_config_applied(self, context, ihost_obj, config_uuid)

    def _config_reinstall_hosts(self, context, personalities):
        """ update the hosts configuration status for all host to be "
            reinstall is required.
        """
        hosts = self.dbapi.ihost_get_list()
        for host in hosts:
            if host.personality and host.personality in personalities:
                self._update_host_config_reinstall(context, host)

    def _config_update_hosts(self, context, personalities, host_uuids=None,
                             reboot=False):
        """"Update the hosts configuration status for all hosts affected
        :param context: request context.
        :param personalities: list of affected host personalities
        :parm host_uuids (optional): hosts whose config_target will be updated
        :param reboot (optional): indicates if a reboot is required to apply
        :                         update
        :return The UUID of the configuration generation
        """
        def _trace_caller(personalities, host_uuids, reboot, config_uuid):
            tb = traceback.format_stack()
            LOG.info("_config_update_hosts personalities=%s host_uuids=%s reboot=%s "
                     "config_uuid=%s tb=%s" %
                     (personalities, host_uuids, reboot, config_uuid, tb[-3]))

        # generate a new configuration identifier for this update
        config_uuid = uuid.uuid4()

        # Scope the UUID according to the reboot requirement of the update.
        # This is done to prevent dynamic updates from overriding the reboot
        # requirement of a previous update that required the host to be locked
        # and unlocked in order to apply the full set of updates.
        if reboot:
            config_uuid = self._config_set_reboot_required(config_uuid)
        else:
            config_uuid = self._config_clear_reboot_required(config_uuid)

        _trace_caller(personalities, host_uuids, reboot, config_uuid)

        if not host_uuids:
            hosts = self.dbapi.ihost_get_list()
        else:
            hosts = [self.dbapi.ihost_get(host_uuid) for host_uuid in host_uuids]

        for host in hosts:
            if host.personality and host.personality in personalities:
                if reboot:
                    if host.uuid in self._host_reboot_config_uuid:
                        self._host_reboot_config_uuid[host.uuid].append(config_uuid)
                    else:
                        self._host_reboot_config_uuid[host.uuid] = []
                        self._host_reboot_config_uuid[host.uuid].append(config_uuid)
                    if host.uuid == self.host_uuid:
                        # This ensures that the host_reboot_config_uuid tracking
                        # on this controller is aware that a reboot is required
                        cutils.touch(ACTIVE_CONFIG_REBOOT_REQUIRED)
                self._update_host_config_target(context, host, config_uuid)

        LOG.info("_config_update_hosts config_uuid=%s" % config_uuid)
        return config_uuid

    def _config_update_puppet(self, config_uuid, config_dict, force=False,
                              host_uuids=None):
        """Regenerate puppet hiera data files for each affected host that is
           provisioned. If host_uuid is provided, only that host's puppet
           hiera data file will be regenerated.
        """
        host_updated = False

        personalities = config_dict['personalities']
        if not host_uuids:
            hosts = self.dbapi.ihost_get_list()
        else:
            hosts = [self.dbapi.ihost_get(host_uuid) for host_uuid in host_uuids]

        for host in hosts:
            if host.personality in personalities:
                # Never generate hieradata for uninventoried hosts, as their
                # interface config will be incomplete.
                valid_inventory_states = [
                    constants.INV_STATE_INITIAL_INVENTORIED,
                    constants.INV_STATE_REINSTALLING
                ]
                if host.inv_state not in valid_inventory_states:
                    LOG.info(
                        "Cannot generate the configuration for %s, "
                        "the host is not inventoried yet." % host.hostname)
                # We will allow controller nodes to re-generate manifests
                # when in an "provisioning" state. This will allow for
                # example the ntp configuration to be changed on an CPE
                # node before the "worker_config_complete" has been
                # executed.
                elif (force or
                    host.invprovision in [constants.PROVISIONED, constants.UPGRADING] or
                    (host.invprovision == constants.PROVISIONING and
                     host.personality == constants.CONTROLLER)):
                    if host.software_load == tsc.SW_VERSION:
                        # We will not generate the hieradata in runtime here if the
                        # software load of the host is different from the active
                        # controller. The Hieradata of a host during an upgrade/rollback
                        # will be saved by update_host_config_upgrade() to the
                        # directory of the host's software load.
                        self._puppet.update_host_config(host, config_uuid)
                        host_updated = True
                else:
                    LOG.info(
                        "Cannot regenerate the configuration for %s, "
                        "the node is not ready. invprovision=%s" %
                        (host.hostname, host.invprovision))

        # ensure the system configuration is also updated if hosts require
        # a reconfiguration
        if host_updated:
            self._puppet.update_system_config()
            self._puppet.update_secure_system_config()

    def _config_update_file(self,
                            context,
                            config_uuid,
                            config_dict,
                            filter_files=None):
        """Apply the file on all hosts affected by supplied personalities.

        :param context: request context.
        :param config_uuid: configuration uuid
        :param config_dict: dictionary of attributes, such as:
        :          {personalities: list of host personalities
        :           file_names: list of full path file names
        :           file_content: file contents
        :           action: put(full replacement), patch
        :           action_key: match key (for patch only)
        :          }
        """

        if filter_files is None:
            filter_files = []

        # try to get the config from deferred list
        deferred_config = self._get_from_host_deferred_runtime_config(config_uuid)

        if not self._ready_to_apply_runtime_config(
                context,
                config_dict.get('personalities'),
                config_dict.get('host_uuids'),
                filter_files=filter_files):
            if deferred_config is None:
                # append to deferred for audit
                self._host_deferred_runtime_config.append(
                    {'config_type': CONFIG_UPDATE_FILE,
                     'config_uuid': config_uuid,
                     'config_dict': config_dict,
                     })
            LOG.info("defer update file to _host_deferred_runtime_config %s" %
                     self._host_deferred_runtime_config)
            return False

        if not self._try_config_update_puppet(
                config_uuid, config_dict, deferred_config):
            return False

        rpcapi = agent_rpcapi.AgentAPI()
        try:
            rpcapi.iconfig_update_file(context,
                                       iconfig_uuid=config_uuid,
                                       iconfig_dict=config_dict)
        except Exception as e:
            LOG.info("Error: %s" % str(e))
            return False

        return True

    @cutils.synchronized(LOCK_RUNTIME_CONFIG_CHECK)
    def _clear_runtime_class_apply_in_progress(self, classes_list=None, host_uuids=None):
        if classes_list is None:
            classes_list = []
        if host_uuids is None:
            host_uuids = []
        else:
            host_uuids = [host_uuids] if isinstance(host_uuids, str) else host_uuids

        for c, h in self._runtime_class_apply_in_progress:
            host_intersection = [i for i in host_uuids if i in h]
            LOG.info("config runtime c=%s, h=%s host_uuids=%s host_intersection=%s" %
                     (c, h, host_uuids, host_intersection))
            if c in classes_list:
                if host_intersection:
                    LOG.info("config runtime removing host_uuids=%s from %s" %
                             (host_uuids, self._runtime_class_apply_in_progress))
                    self._runtime_class_apply_in_progress.remove((c, h))
            elif not classes_list and host_intersection:
                LOG.info("config runtime removing host_uuids=%s from %s" %
                         (host_uuids, self._runtime_class_apply_in_progress))
                self._runtime_class_apply_in_progress.remove((c, h))
            elif not classes_list and not host_uuids:
                LOG.info("config runtime in classes_list c=%s, classes_list=%s" % (c, classes_list))
                self._runtime_class_apply_in_progress = list()

            LOG.info("config runtime end of _clear_runtime_class_apply_in_progress=%s" %
                     self._runtime_class_apply_in_progress)

    @cutils.synchronized(LOCK_RUNTIME_CONFIG_CHECK)
    def _add_runtime_class_apply_in_progress(self, classes_list, host_uuids=None):
        if host_uuids is None:
            host_uuids = []
        else:
            host_uuids = [host_uuids] if isinstance(host_uuids, str) else host_uuids

        for c in classes_list:
            self._runtime_class_apply_in_progress.append((c, host_uuids))

    def _check_runtime_class_apply_in_progress(self, classes_list, host_uuids=None):
        if host_uuids is None:
            host_uuids = []
        else:
            host_uuids = [host_uuids] if isinstance(host_uuids, str) else host_uuids

        for c, h in self._runtime_class_apply_in_progress:
            if c in classes_list:
                if host_uuids and host_uuids in h:
                    LOG.info("config runtime  host_uuids=%s from %s" %
                             (host_uuids, h))
                    return True
                else:
                    return True
        return False

    @cutils.synchronized(LOCK_RUNTIME_CONFIG_CHECK)
    def _update_host_deferred_runtime_config(
            self, config_type, config_uuid, config_dict, force=None):
        # check if already in deferred list, and if so, replace duplicate with latest config
        for drc in self._host_deferred_runtime_config:
            if (drc['config_type'] == config_type and
                    drc['config_dict'].get('classes') == config_dict.get('classes') and
                    drc['config_dict'].get('personalities') == config_dict.get('personalities') and
                    drc['config_dict'].get('host_uuids') == config_dict.get('host_uuids') and
                    drc.get('force') == force):
                LOG.info("config runtime replacing entry duplicate config %s with config_uuid=%s" %
                         (drc, config_uuid))
                drc['config_uuid'] = config_uuid
                break
        else:
            self._host_deferred_runtime_config.append(
                {'config_type': CONFIG_APPLY_RUNTIME_MANIFEST,
                 'config_uuid': config_uuid,
                 'config_dict': config_dict,
                 'force': force,
                 })

    def _get_from_host_deferred_runtime_config(self, config_uuid):
        # get the config from the deferred config list
        config = None
        for drc in self._host_deferred_runtime_config:
            if (drc['config_uuid'] == config_uuid):
                config = drc
                break
        return config

    def _try_config_update_puppet(
            self, config_uuid, config_dict,
            deferred_config=None, host_uuids=None, force=False):
        """Attempt the config puppet hierdata update.

           In the case of a deferred config, the puppet update can be
           asynchronously retried on exception.
           In the case of synchronous (non-deferred) config, exceptions
           are raised.
        """

        # the config will be processed so remove from deferred list if it is a
        # deferred one.
        if deferred_config:
            self._host_deferred_runtime_config.remove(deferred_config)

        # Update hiera data for all hosts prior to runtime apply if host_uuid
        # is not set. If host_uuids is set only update hiera data for those hosts.
        try:
            self._config_update_puppet(config_uuid,
                                       config_dict,
                                       host_uuids=host_uuids,
                                       force=force)
        except Exception as e:
            LOG.exception("_config_update_puppet %s" % e)
            if deferred_config:
                self._host_deferred_runtime_config.append(deferred_config)
                LOG.warn("deferred update runtime config %s exception. Retry." %
                         deferred_config)
                return False
            else:
                raise

        return True

    def _config_apply_runtime_manifest(self,
                                       context,
                                       config_uuid,
                                       config_dict,
                                       force=False,
                                       filter_classes=None):
        """Apply manifests on all hosts affected by the supplied personalities.
           If host_uuids is set in config_dict, only update hiera data and apply
           manifests for these hosts.
        """
        if filter_classes is None:
            filter_classes = []

        host_uuids = config_dict.get('host_uuids')

        try:
            self.dbapi.software_upgrade_get_one()
        except exception.NotFound:
            # No upgrade in progress
            pass
        else:
            # Limit host_uuids to those matching the active software version
            if not host_uuids:
                hosts = self.dbapi.ihost_get_list()
            else:
                hosts = [self.dbapi.ihost_get(host_uuid) for host_uuid in host_uuids]

            host_uuids = []
            personalities = config_dict.get('personalities')
            for host in hosts:
                if host.personality in personalities:
                    if host.software_load == tsc.SW_VERSION:
                        host_uuids.append(host.uuid)
                    else:
                        LOG.info("Skip applying manifest for host: %s. Version %s mismatch." %
                                 (host.hostname, host.software_load))
                        self._update_host_config_applied(context, host, config_uuid)

            if not host_uuids:
                LOG.info("No hosts with matching software_version found, skipping apply_runtime_manifest")
                return
            config_dict.update({'host_uuids': host_uuids})

        if "classes" in config_dict:
            LOG.info("applying runtime manifest config_uuid=%s, classes: %s" % (
                config_uuid, config_dict["classes"]))
        else:
            LOG.info("applying runtime manifest config_uuid=%s" % config_uuid)

        # try to get the config from deferred list
        deferred_config = self._get_from_host_deferred_runtime_config(config_uuid)

        # only apply runtime manifests to active controller if ready,
        # otherwise will append to the list of outstanding runtime manifests
        if not self._ready_to_apply_runtime_config(
                context,
                config_dict.get('personalities'),
                config_dict.get('host_uuids'),
                filter_classes=filter_classes):
            if deferred_config is None:
                self._update_host_deferred_runtime_config(
                    CONFIG_APPLY_RUNTIME_MANIFEST,
                    config_uuid,
                    config_dict,
                    force)
            LOG.info("defer apply runtime manifest %s" %
                     self._host_deferred_runtime_config)
            return

        if not self._try_config_update_puppet(
                config_uuid, config_dict, deferred_config, host_uuids, force):
            return

        self.evaluate_apps_reapply(context, trigger={'type': constants.APP_EVALUATE_REAPPLY_TYPE_RUNTIME_APPLY_PUPPET})

        # Remove reboot required flag in case it's present. Runtime manifests
        # are no supposed to clear this flag. A host lock/unlock cycle (or similar)
        # should do it.
        config_uuid = self._config_clear_reboot_required(config_uuid)

        config_dict.update({'force': force})
        rpcapi = agent_rpcapi.AgentAPI()
        rpcapi.config_apply_runtime_manifest(context,
                                             config_uuid=config_uuid,
                                             config_dict=config_dict)

        if filter_classes and config_dict['classes'] in filter_classes:
            LOG.info("config runtime filter_classes add %s %s" %
                     (filter_classes, config_dict))
            self._add_runtime_class_apply_in_progress(filter_classes,
                                                      host_uuids=config_dict.get('host_uuids', None))

    def _update_ipv_device_path(self, idisk, ipv):
        if not idisk.device_path:
            return
        pv_dict = {'disk_or_part_device_path': idisk.device_path}
        self.dbapi.ipv_update(ipv['uuid'], pv_dict)

    def iinterfaces_get_by_ihost_nettype(self,
                                         context,
                                         ihost_uuid,
                                         nettype=None):
        """
        Gets iinterfaces list by ihost and network type.

        If param 'nettype' is provided, returns list for
        only specified nettype, else: returns all
        iinterfaces in the host.

        """
        try:
            iinterfaces = self.dbapi.iinterface_get_by_ihost(ihost_uuid,
                                                             expunge=True)
        except exc.DetachedInstanceError:
            # A rare DetachedInstanceError exception may occur, retry
            LOG.warn("Detached Instance Error,  retry "
                     "iinterface_get_by_ihost %s" % ihost_uuid)
            iinterfaces = self.dbapi.iinterface_get_by_ihost(ihost_uuid,
                                                             expunge=True)

        if nettype:
            iinterfaces[:] = [i for i in iinterfaces if
                              nettype in i.networktypelist]

        return iinterfaces

    def mgmt_ip_set_by_ihost(self,
                             context,
                             ihost_uuid,
                             interface_id,
                             mgmt_ip):
        """Call sysinv to update host mgmt_ip
           (removes previous entry if necessary)

        :param context: an admin context
        :param ihost_uuid: ihost uuid
        :param interface_id: interface id value
        :param mgmt_ip: mgmt_ip to set, None for removal
        :returns: Address
        """

        LOG.debug("Calling mgmt ip set for ihost %s, ip %s" % (ihost_uuid,
            mgmt_ip))

        # Check for and remove existing addrs on mgmt subnet & host
        ihost = self.dbapi.ihost_get(ihost_uuid)

        for address in self.dbapi.addresses_get_by_interface(interface_id):
            if address['address'] == mgmt_ip:
                # Address already exists, can return early
                return address
            if not address['name']:
                self.dbapi.address_destroy(address['uuid'])

        try:
            if ihost.get('hostname'):
                self._generate_dnsmasq_hosts_file()
        except Exception:
            LOG.warning("Failed to remove mgmt ip from dnsmasq.hosts")

        if mgmt_ip is None:
            # Remove DHCP lease when removing mgmt interface
            self._unallocate_address(ihost.hostname,
                                     constants.NETWORK_TYPE_MGMT)
            self._generate_dnsmasq_hosts_file()
            # Just doing a remove, return early
            return

        # Check for IPv4 or IPv6
        if not cutils.is_valid_ipv4(mgmt_ip):
            if not cutils.is_valid_ipv6(mgmt_ip):
                LOG.error("Invalid mgmt_ip=%s" % mgmt_ip)
                return False
        address = self._create_or_update_address(context, ihost.hostname,
                                                 mgmt_ip,
                                                 constants.NETWORK_TYPE_MGMT,
                                                 interface_id)
        return address

    def vim_host_add(self, context, api_token, ihost_uuid,
                     hostname, subfunctions, administrative,
                     operational, availability,
                     subfunction_oper, subfunction_avail,
                     timeout_in_secs):
        """
        Asynchronously, notify VIM of host add
        """

        vim_resp = vim_api.vim_host_add(api_token,
                                        ihost_uuid,
                                        hostname,
                                        subfunctions,
                                        administrative,
                                        operational,
                                        availability,
                                        subfunction_oper,
                                        subfunction_avail,
                                        timeout_in_secs)
        LOG.info("vim_host_add resp=%s" % vim_resp)
        return vim_resp

    def mtc_host_add(self, context, mtc_address, mtc_port, ihost_mtc_dict):
        """
        Asynchronously, notify mtc of host add
        """
        mtc_response_dict = cutils.notify_mtc_and_recv(mtc_address,
                                                       mtc_port,
                                                       ihost_mtc_dict)

        if (mtc_response_dict['status'] != 'pass'):
            LOG.error("Failed mtc_host_add=%s" % ihost_mtc_dict)

        return

    def is_virtual_system_config(self, context):
        """
        Gets the virtual system config from service parameter
        """
        virtual_system = cutils.is_virtual_system_config(self.dbapi)
        return virtual_system

    def ilvg_get_nova_ilvg_by_ihost(self,
                                    context,
                                    ihost_uuid):
        """
        Gets the nova ilvg by ihost.

        returns the nova ilvg if added to the host else returns empty
        list

        """
        ilvgs = self.dbapi.ilvg_get_by_ihost(ihost_uuid)

        ilvgs[:] = [i for i in ilvgs if
                    (i.lvm_vg_name == constants.LVG_NOVA_LOCAL)]

        return ilvgs

    def _add_port_to_list(self, interface_id, port_list):
        info = {}
        ports = self.dbapi.port_get_all(interfaceid=interface_id)
        if ports:
            info['name'] = ports[0]['name']
            info['numa_node'] = ports[0]['numa_node']
            if info not in port_list:
                port_list.append(info)
        return port_list

    def platform_interfaces(self, context, ihost_id):
        """
        Gets the platform interfaces and associated numa nodes
        """
        info_list = []
        interface_list = self.dbapi.iinterface_get_all(ihost_id, expunge=True)
        for interface in interface_list:
            if interface['ifclass'] == constants.INTERFACE_CLASS_PLATFORM:
                if interface['iftype'] == constants.INTERFACE_TYPE_VLAN or \
                        interface['iftype'] == constants.INTERFACE_TYPE_AE:
                    for uses_if in interface['uses']:
                        lower_iface = self.dbapi.iinterface_get(uses_if, ihost_id)
                        if lower_iface['iftype'] == constants.INTERFACE_TYPE_ETHERNET:
                            info_list = self._add_port_to_list(lower_iface['id'],
                                                               info_list)
                        elif lower_iface['iftype'] == constants.INTERFACE_TYPE_AE:
                            for lower_uses_if in lower_iface['uses']:
                                ll_iface = self.dbapi.iinterface_get(lower_uses_if, ihost_id)
                                if ll_iface['iftype'] == constants.INTERFACE_TYPE_ETHERNET:
                                    info_list = self._add_port_to_list(ll_iface['id'],
                                                                       info_list)
                elif interface['iftype'] == constants.INTERFACE_TYPE_ETHERNET:
                    info_list = self._add_port_to_list(interface['id'],
                                                       info_list)

        LOG.info("platform_interfaces host_id=%s info_list=%s" %
                 (ihost_id, info_list))
        return info_list

    def ibm_deprovision_by_ihost(self, context, ihost_uuid, ibm_msg_dict):
        """Update ihost upon notification of board management controller
           deprovisioning.

        This method also allows a dictionary of values to be passed in to
        affort additional controls, if and as needed.

        :param context: an admin context
        :param ihost_uuid: ihost uuid unique id
        :param ibm_msg_dict: values for additional controls or changes
        :returns: pass or fail
        """
        LOG.info("ibm_deprovision_by_ihost=%s msg=%s" %
                 (ihost_uuid, ibm_msg_dict))

        isensorgroups = self.dbapi.isensorgroup_get_by_ihost(ihost_uuid)

        for isensorgroup in isensorgroups:
            isensors = self.dbapi.isensor_get_by_sensorgroup(isensorgroup.uuid)
            for isensor in isensors:
                self.dbapi.isensor_destroy(isensor.uuid)

            self.dbapi.isensorgroup_destroy(isensorgroup.uuid)

        isensors = self.dbapi.isensor_get_by_ihost(ihost_uuid)
        if isensors:
            LOG.info("ibm_deprovision_by_ihost=%s Non-group sensors=%s" %
                     (ihost_uuid, isensors))
            for isensor in isensors:
                self.dbapi.isensor_destroy(isensor.uuid)

        isensors = self.dbapi.isensor_get_by_ihost(ihost_uuid)

        return True

    def configure_ttys_dcd(self, context, uuid, ttys_dcd):
        """
        (TODO) Deprecate when supported from upgrade releases for tty_dcd
        have all been migrated to puppet.

        Reason: moving serial console configuration from agent audit
        to puppet discards the necessity of polling the host tty_dcd
        attribute in sysinv database through conductor API. (LP-1978009)

        Notify agent to configure the dcd with the supplied data.

        :param context: an admin context.
        :param uuid: the host uuid
        :param ttys_dcd: the flag to enable/disable dcd
        """

        LOG.debug("ConductorManager.configure_ttys_dcd: sending dcd update %s "
                  "%s to agents" % (ttys_dcd, uuid))
        rpcapi = agent_rpcapi.AgentAPI()
        rpcapi.configure_ttys_dcd(context, uuid=uuid, ttys_dcd=ttys_dcd)

    def get_host_ttys_dcd(self, context, ihost_id):
        """
        (TODO) Deprecate when supported from upgrade releases for tty_dcd
        have all been migrated to puppet.

        Reason: moving serial console configuration from agent audit
        to puppet discards the necessity of polling the host tty_dcd
        attribute in sysinv database through conductor API. (LP-1978009)

        Retrieve the serial line carrier detect state for a given host
        """
        ihost = self.dbapi.ihost_get(ihost_id)
        if ihost:
            return ihost.ttys_dcd
        else:
            LOG.error("Host: %s not found in database" % ihost_id)
            return None

    def _get_current_supported_upgrade_versions(self):
        supported_versions = []

        try:
            metadata_file = open(constants.CURRENT_METADATA_FILE_PATH, 'r')
            root = ElementTree.fromstring(metadata_file.read())
            metadata_file.close()
        except Exception:
            raise exception.SysinvException(_(
                "Unable to read metadata file from current version"))

        supported_upgrades_elm = root.find('supported_upgrades')

        if not supported_upgrades_elm:
            raise exception.SysinvException(
                _("Invalid Metadata XML from current version"))

        upgrade_paths = supported_upgrades_elm.findall('upgrade')

        for upgrade_element in upgrade_paths:
            valid_from_version = upgrade_element.findtext('version')
            versions = valid_from_version.split(",")
            supported_versions.extend(versions)

        return supported_versions

    def _create_symlink_install_uuid(self, current_version):
        """
        If the current version is Debian and the imported load
        is Centos, the install_uuid path is different. It's
        necessary to create a symlink for import.sh to find it.
        """
        centos_feed_path = '/www/pages/feed/rel-%s' % current_version

        os.makedirs(centos_feed_path, exist_ok=True)

        src = '/var/www/pages/feed/rel-%s/install_uuid' % current_version
        dst = '%s/install_uuid' % centos_feed_path

        if os.path.isfile(dst):
            return None

        os.symlink(src, dst)

    def _import_load_error(self, new_load):
        """
        Update the load state to 'error' in the database
        """
        patch = {'state': constants.ERROR_LOAD_STATE}
        try:
            self.dbapi.load_update(new_load['id'], patch)

        except exception.SysinvException as e:
            LOG.exception(e)
            raise exception.SysinvException(_("Error updating load in "
                                              "database for load id: %s")
                                            % new_load['id'])

    @staticmethod
    def _unmount_iso(mounted_iso, mntdir):
        # We need to sleep here because the mount/umount is happening too
        # fast and cause the following kernel logs
        #   Buffer I/O error on device loopxxx, logical block x
        # We sleep 1 sec to give time for the mount to finish processing
        # properly.
        time.sleep(1)
        mounted_iso._umount_iso()
        shutil.rmtree(mntdir)

    def start_import_load(self, context, path_to_iso, path_to_sig,
                          import_type=None):
        """
        Mount the ISO and validate the load for import
        """
        loads = self.dbapi.load_get_list()

        active_load = cutils.get_active_load(loads)

        if import_type != constants.ACTIVE_LOAD_IMPORT:
            cutils.validate_loads_for_import(loads)

        current_version = active_load.software_version

        if not os.path.exists(path_to_iso):
            raise exception.SysinvException(_("Specified path not found %s") %
                                            path_to_iso)
        if not os.path.exists(path_to_sig):
            raise exception.SysinvException(_("Specified path not found %s") %
                                            path_to_sig)

        if not verify_files([path_to_iso], path_to_sig):
            raise exception.SysinvException(_("Signature %s could not be verified") %
                                            path_to_sig)

        mounted_iso = None
        mntdir = tempfile.mkdtemp(dir='/tmp')
        # Attempt to mount iso
        try:
            mounted_iso = cutils.ISO(path_to_iso, mntdir)
            # Note: iso will be unmounted when object goes out of scope

        except subprocess.CalledProcessError:
            raise exception.SysinvException(_(
                "Unable to mount iso"))

        metadata_file_path = mntdir + '/upgrades/metadata.xml'

        if not os.path.exists(metadata_file_path):
            self._unmount_iso(mounted_iso, mntdir)
            raise exception.SysinvException(_("Metadata file not found"))

        # Read in the metadata file
        try:
            metadata_file = open(metadata_file_path, 'r')
            root = ElementTree.fromstring(metadata_file.read())
            metadata_file.close()

        except Exception:
            self._unmount_iso(mounted_iso, mntdir)
            raise exception.SysinvException(_(
                "Unable to read metadata file"))

        # unmount iso
        self._unmount_iso(mounted_iso, mntdir)

        new_version = root.findtext('version')

        if import_type == constants.ACTIVE_LOAD_IMPORT:
            if new_version != current_version:
                raise exception.SysinvException(
                    _("Active version and import version must match (%s)")
                    % current_version)

            # return the matching (active) load in the database
            loads = self.dbapi.load_get_list()

            for load in loads:
                if load.software_version == new_version:
                    break
            else:
                raise exception.SysinvException(
                    _("Active load not found (%s)") % current_version)

            return load

        if import_type == constants.INACTIVE_LOAD_IMPORT:
            if LooseVersion(new_version) >= LooseVersion(current_version):
                raise exception.SysinvException(
                    _("Inactive version must be less than the current version (%s)")
                    % current_version)

            supported_versions = self._get_current_supported_upgrade_versions()

            if new_version not in supported_versions:
                raise exception.SysinvException(
                    _("Inactive version must be upgradable to the current version (%s)")
                    % current_version)

        if new_version == current_version:
            raise exception.SysinvException(
                _("Active version and import version match (%s)")
                % current_version)

        supported_upgrades_elm = root.find('supported_upgrades')
        if not supported_upgrades_elm:
            raise exception.SysinvException(
                _("Invalid Metadata XML"))

        path_found = False
        upgrade_path = None
        upgrade_paths = supported_upgrades_elm.findall('upgrade')

        for upgrade_element in upgrade_paths:
            valid_from_version = upgrade_element.findtext('version')
            valid_from_versions = valid_from_version.split(",")
            if current_version in valid_from_versions:
                path_found = True
                upgrade_path = upgrade_element
                break

        if not path_found and import_type != constants.INACTIVE_LOAD_IMPORT:
            raise exception.SysinvException(
                _("No valid upgrade path found"))

        # Create a patch with the values from the metadata
        patch = dict()

        patch['state'] = constants.IMPORTING_LOAD_STATE
        patch['software_version'] = new_version
        patch['compatible_version'] = current_version

        required_patches = []

        if upgrade_path:
            patch_elements = upgrade_path.findall('required_patch')
            for patch_element in patch_elements:
                required_patches.append(patch_element.text)

        patch['required_patches'] = "\n".join(required_patches)

        # create the new imported load in the database
        new_load = self.dbapi.load_create(patch)

        return new_load

    def import_load(self, context, path_to_iso, new_load,
                    import_type=None):
        """
        Run the import script and add the load to the database
        """
        loads = self.dbapi.load_get_list()

        cutils.validate_loads_for_import(loads)

        if new_load is None:
            raise exception.SysinvException(
                _("Error importing load. Load not found"))

        if not os.path.exists(path_to_iso):
            self._import_load_error(new_load)
            raise exception.SysinvException(_("Specified path not found: %s") %
                                            path_to_iso)

        mounted_iso = None

        mntdir = tempfile.mkdtemp(dir='/tmp')
        # Attempt to mount iso
        try:
            mounted_iso = cutils.ISO(path_to_iso, mntdir)
            # Note: iso will be unmounted when object goes out of scope

        except subprocess.CalledProcessError:
            self._import_load_error(new_load)
            raise exception.SysinvException(_("Unable to mount iso"))

        if import_type == constants.INACTIVE_LOAD_IMPORT:
            active_load = cutils.get_active_load(loads)
            self._create_symlink_install_uuid(active_load.software_version)

        # Run the upgrade script
        with open(os.devnull, "w") as fnull:
            try:
                subprocess.check_call(mntdir +  # pylint: disable=not-callable
                                      '/upgrades/import.sh',
                                      stdout=fnull, stderr=fnull)
            except subprocess.CalledProcessError:
                self._import_load_error(new_load)
                raise exception.SysinvException(_(
                    "Failure during import script"))

        mounted_iso._umount_iso()
        shutil.rmtree(mntdir)

        state = constants.IMPORTED_LOAD_STATE

        if import_type == constants.INACTIVE_LOAD_IMPORT:
            state = constants.INACTIVE_LOAD_STATE

            try:
                LoadImport.extract_files(new_load['software_version'])
            except exception.SysinvException as error:
                self._import_load_error(new_load)
                raise exception.SysinvException(
                    "Failure during load extract_files: %s" % (error)
                )

        # Update the load status in the database
        try:
            self.dbapi.load_update(new_load['id'], {'state': state})

        except exception.SysinvException as e:
            LOG.exception(e)
            raise exception.SysinvException(_("Error updating load in "
                                              "database for load id: %s")
                                            % new_load['id'])

        # Run the sw-patch init-release commands
        with open(os.devnull, "w") as fnull:
            try:
                subprocess.check_call(["/usr/sbin/sw-patch",  # pylint: disable=not-callable
                                       "init-release",
                                       new_load['software_version']],
                                      stdout=fnull, stderr=fnull)
            except subprocess.CalledProcessError:
                self._import_load_error(new_load)
                raise exception.SysinvException(_(
                    "Failure during sw-patch init-release"))

        if os.path.exists(constants.LOAD_FILES_STAGING_DIR):
            shutil.rmtree(constants.LOAD_FILES_STAGING_DIR)

        LOG.info("Load import completed.")
        return True

    def delete_load(self, context, load_id):
        """
        Cleanup a load and remove it from the database
        """
        load = self.dbapi.load_get(load_id)

        cutils.validate_load_for_delete(load)

        # We allow this command to be run again if the delete fails
        if load.state != constants.DELETING_LOAD_STATE:
            # Here we run the cleanup script locally
            self._cleanup_load(load)
            self.dbapi.load_update(
                load_id, {'state': constants.DELETING_LOAD_STATE})

        mate_hostname = cutils.get_mate_controller_hostname()

        try:
            standby_controller = self.dbapi.ihost_get_by_hostname(
                mate_hostname)
            rpcapi = agent_rpcapi.AgentAPI()
            rpcapi.delete_load(
                context, standby_controller['uuid'], load.software_version)
        except exception.NodeNotFound:
            # The mate controller has not been configured so complete the
            # deletion of the load now.
            self.finalize_delete_load(context, load.software_version)

        LOG.info("Load (%s) deleted." % load.software_version)

    def _cleanup_load(self, load):
        # Run the sw-patch del-release commands
        with open(os.devnull, "w") as fnull:
            try:
                subprocess.check_call(["/usr/sbin/sw-patch",  # pylint: disable=not-callable
                                       "del-release",
                                       load.software_version],
                                      stdout=fnull, stderr=fnull)
            except subprocess.CalledProcessError:
                raise exception.SysinvException(_(
                    "Failure during sw-patch del-release"))

        cleanup_script = constants.DELETE_LOAD_SCRIPT
        if os.path.isfile(cleanup_script):
            with open(os.devnull, "w") as fnull:
                try:
                    subprocess.check_call(  # pylint: disable=not-callable
                        [cleanup_script, load.software_version],
                        stdout=fnull, stderr=fnull)
                except subprocess.CalledProcessError:
                    raise exception.SysinvException(_(
                        "Failure during cleanup script"))
        else:
            raise exception.SysinvException(_(
                "Cleanup script %s does not exist.") % cleanup_script)

    def finalize_delete_load(self, context, sw_version):
        # Clean up the staging directory in case an error occur during the
        # import and this directory did not get cleaned up.
        if os.path.exists(constants.LOAD_FILES_STAGING_DIR):
            shutil.rmtree(constants.LOAD_FILES_STAGING_DIR)

        loads = self.dbapi.load_get_list()
        for load in loads:
            if load.software_version == sw_version:
                self.dbapi.load_destroy(load.id)

    def upgrade_ihost_pxe_config(self, context, host, load):
        """Upgrade a host.

        Does the following tasks:
        - Updates the host's pxelinux.cfg file to the specified load

        :param host: a host object.
        :param load: a load object.
        """
        self._update_pxe_config(host, load)

    def load_update_by_host(self, context, ihost_id, sw_version):
        """Update the host_upgrade table with the running SW_VERSION

        Does the following:
           - Raises an alarm if host_upgrade software and target do not match
           - Clears an alarm if host_upgrade software and target do match
           - Updates upgrade state once data migration is complete
           - Clears VIM upgrade flag once controller-0 has been upgraded

        :param ihost_id: the host id
        :param sw_version: the SW_VERSION from the host
        """
        host_load = self.dbapi.load_get_by_version(sw_version)

        host = self.dbapi.ihost_get(ihost_id)

        host_upgrade = self.dbapi.host_upgrade_get_by_host(host.id)

        check_for_alarm = host_upgrade.software_load != host_upgrade.target_load

        if host_upgrade.software_load != host_load.id:
            host_upgrade.software_load = host_load.id
            host_upgrade.save(context)

        if host_upgrade.software_load != host_upgrade.target_load:
            entity_instance_id = self._get_fm_entity_instance_id(host)

            fault = fm_api.Fault(
                alarm_id=fm_constants.FM_ALARM_ID_HOST_VERSION_MISMATCH,
                alarm_state=fm_constants.FM_ALARM_STATE_SET,
                entity_type_id=fm_constants.FM_ENTITY_TYPE_HOST,
                entity_instance_id=entity_instance_id,
                severity=fm_constants.FM_ALARM_SEVERITY_MAJOR,
                reason_text=(_("Incorrect software load on %s.") %
                             host.hostname),
                alarm_type=fm_constants.FM_ALARM_TYPE_7,  # operational
                probable_cause=fm_constants.ALARM_PROBABLE_CAUSE_7,
                # configuration error
                proposed_repair_action=_(
                    "Reinstall %s to update applied load." %
                    host.hostname),
                service_affecting=True)

            self.fm_api.set_fault(fault)
        elif check_for_alarm:
            entity_instance_id = self._get_fm_entity_instance_id(host)
            self.fm_api.clear_fault(
                fm_constants.FM_ALARM_ID_HOST_VERSION_MISMATCH,
                entity_instance_id)

        # Check if there is an upgrade in progress
        try:
            upgrade = self.dbapi.software_upgrade_get_one()
        except exception.NotFound:
            # No upgrade in progress
            pass
        else:
            # Check if controller-1 has finished its data migration
            if (host.hostname == constants.CONTROLLER_1_HOSTNAME and
                    host_upgrade.software_load == upgrade.to_load and
                    upgrade.state == constants.UPGRADE_DATA_MIGRATION_COMPLETE):
                LOG.info("Finished upgrade of %s" %
                         constants.CONTROLLER_1_HOSTNAME)
                # Update upgrade state
                upgrade_update = {
                    'state': constants.UPGRADE_UPGRADING_CONTROLLERS}
                self.dbapi.software_upgrade_update(upgrade.uuid,
                                                   upgrade_update)

            if (host.hostname == constants.CONTROLLER_0_HOSTNAME and
                    host_upgrade.software_load == upgrade.to_load):
                # Clear VIM upgrade flag once controller_0 has been upgraded
                # This allows VM management
                try:
                    vim_api.set_vim_upgrade_state(host, False)
                except Exception as e:
                    LOG.exception(e)
                    raise exception.SysinvException(_(
                        "Failure clearing VIM host upgrade state"))

                # If we are in the upgrading controllers state and controller-0
                # is running the new release, update the upgrade state
                if upgrade.state == constants.UPGRADE_UPGRADING_CONTROLLERS:
                    upgrade_update = {
                        'state': constants.UPGRADE_UPGRADING_HOSTS}
                    self.dbapi.software_upgrade_update(upgrade.uuid,
                                                       upgrade_update)

                    LOG.info("Prepare for swact to controller-0")
                    # As a temporary solution we only migrate the etcd database
                    # when we swact to controller-0. This solution will present
                    # some problems when we do upgrade etcd, so further
                    # development will be required at that time.
                    try:
                        with open(os.devnull, "w") as devnull:
                            call_args = [
                                '/usr/bin/upgrade_swact_migration.py',
                                'prepare_swact',
                                upgrade.from_release,
                                upgrade.to_release
                            ]
                            subprocess.check_call(call_args, stdout=devnull)  # pylint: disable=not-callable
                    except subprocess.CalledProcessError as e:
                        LOG.exception(e)
                        raise exception.SysinvException(
                            "Failed upgrade_swact_migration prepare_swact")

    def start_upgrade(self, context, upgrade):
        """ Start the upgrade"""

        from_load = self.dbapi.load_get(upgrade.from_load)
        from_version = from_load.software_version
        to_load = self.dbapi.load_get(upgrade.to_load)
        to_version = to_load.software_version

        controller_0 = self.dbapi.ihost_get_by_hostname(
            constants.CONTROLLER_0_HOSTNAME)

        # Prepare for upgrade
        LOG.info("Preparing for upgrade from release: %s to release: %s" %
                 (from_version, to_version))

        try:
            if tsc.system_mode == constants.SYSTEM_MODE_SIMPLEX:
                LOG.info("Generating agent request to create simplex upgrade "
                         "data")
                software_upgrade = self.dbapi.software_upgrade_get_one()
                rpcapi = agent_rpcapi.AgentAPI()
                # In cases where there is no backup in progress alarm but the flag exists,
                # it must be removed. So upgrade-start is not blocked.
                if os.path.isfile(tsc.BACKUP_IN_PROGRESS_FLAG):
                    LOG.info("Backup in Progress flag was found, cleaning it.")
                    os.remove(tsc.BACKUP_IN_PROGRESS_FLAG)
                    LOG.info("Backup in Progress flag was cleaned.")
                rpcapi.create_simplex_backup(context, software_upgrade)
                return
            else:
                # Extract N+1 packages necessary for installation of controller-1
                # (ie. installer images, kickstarts)
                subprocess.check_call(['/usr/sbin/upgrade-start-pkg-extract',  # pylint: disable=not-callable
                                       '-r', to_version])
                # get the floating management IP
                mgmt_address = self.dbapi.address_get_by_name(
                    cutils.format_address_name(constants.CONTROLLER_HOSTNAME,
                                              constants.NETWORK_TYPE_MGMT)
                )
                i_system = self.dbapi.isystem_get_one()
                upgrades_management.prepare_upgrade(
                    from_version, to_version, i_system, mgmt_address.address)

            LOG.info("Finished upgrade preparation")
        except Exception:
            LOG.exception("Upgrade preparation failed")
            with excutils.save_and_reraise_exception():
                if tsc.system_mode != constants.SYSTEM_MODE_SIMPLEX:
                    vim_api.set_vim_upgrade_state(controller_0, False)
                upgrades_management.abort_upgrade(from_version, to_version,
                                                  upgrade)
                # Delete upgrade record
                self.dbapi.software_upgrade_destroy(upgrade.uuid)

        # Raise alarm to show an upgrade is in progress
        entity_instance_id = "%s=%s" % (fm_constants.FM_ENTITY_TYPE_HOST,
                                        constants.CONTROLLER_HOSTNAME)
        fault = fm_api.Fault(
            alarm_id=fm_constants.FM_ALARM_ID_UPGRADE_IN_PROGRESS,
            alarm_state=fm_constants.FM_ALARM_STATE_SET,
            entity_type_id=fm_constants.FM_ENTITY_TYPE_HOST,
            entity_instance_id=entity_instance_id,
            severity=fm_constants.FM_ALARM_SEVERITY_MINOR,
            reason_text="System Upgrade in progress.",
            # operational
            alarm_type=fm_constants.FM_ALARM_TYPE_7,
            # congestion
            probable_cause=fm_constants.ALARM_PROBABLE_CAUSE_8,
            proposed_repair_action="No action required.",
            service_affecting=False)
        fm_api.FaultAPIs().set_fault(fault)

        self.dbapi.software_upgrade_update(
            upgrade.uuid, {'state': constants.UPGRADE_STARTED})

    @cutils.synchronized(LOCK_IMAGE_PULL)
    def activate_upgrade(self, context, upgrade):
        """Activate the upgrade. Generate and apply new manifests.

        """
        # TODO Move upgrade methods to another file
        from_load = self.dbapi.load_get(upgrade.from_load)
        from_version = from_load.software_version
        to_load = self.dbapi.load_get(upgrade.to_load)
        to_version = to_load.software_version

        self.dbapi.software_upgrade_update(
            upgrade.uuid, {'state': constants.UPGRADE_ACTIVATING})

        # Ask upgrade management to activate the upgrade
        try:
            i_system = self.dbapi.isystem_get_one()
            upgrades_management.activate_upgrade(from_version,
                                                 to_version, i_system)
            LOG.info("Finished upgrade activation")
        except Exception:
            LOG.exception("Upgrade activation failed")
            with excutils.save_and_reraise_exception():
                # mark the activation as failed. The intention
                # is for the user to retry activation once they
                # have resolved the cause for failure
                self.dbapi.software_upgrade_update(
                    upgrade.uuid,
                    {'state': constants.UPGRADE_ACTIVATION_FAILED})

        # Remove platform-nfs-ip references if it exists
        # TODO(fcorream): platform-nfs-ip is just necessary to allow an upgrade from
        # StarlingX releases 6 or 7 to new releases.
        # remove the plat_nfs_address_name and update_platform_nfs_ip_references when
        # StarlingX rel. 6 or 7 are not being used anymore
        plat_nfs_address_name = cutils.format_address_name("controller-platform-nfs",
                                                constants.NETWORK_TYPE_MGMT)
        try:
            self.dbapi.address_get_by_name(plat_nfs_address_name)
            LOG.info("platform-nfs-ip exists in the DB, updating all references")
            self.update_platform_nfs_ip_references(context)

        except exception.AddressNotFoundByName:
            LOG.debug("activate_upgrade: {} does not exist".format(plat_nfs_address_name))
        except Exception as e:
            LOG.exception(e)
            LOG.error("exception: update {} references could not be completed"
                      .format(plat_nfs_address_name))

        manifests_applied = False

        if manifests_applied:
            LOG.info("Running upgrade activation manifests")
            self.dbapi.software_upgrade_update(
                upgrade.uuid, {'state': constants.UPGRADE_ACTIVATING_HOSTS})
        else:
            LOG.info("Upgrade activation complete")
            self.dbapi.software_upgrade_update(
                upgrade.uuid, {'state': constants.UPGRADE_ACTIVATION_COMPLETE})

    def complete_upgrade(self, context, upgrade, state):
        """ Complete the upgrade"""

        from_load = self.dbapi.load_get(upgrade.from_load)
        from_version = from_load.software_version
        to_load = self.dbapi.load_get(upgrade.to_load)
        to_version = to_load.software_version

        controller_0 = self.dbapi.ihost_get_by_hostname(
            constants.CONTROLLER_0_HOSTNAME)

        if state in [constants.UPGRADE_ABORTING,
                constants.UPGRADE_ABORTING_ROLLBACK]:
            if upgrade.state != constants.UPGRADE_ABORT_COMPLETING:
                raise exception.SysinvException(
                    _("Unable to complete upgrade-abort: Upgrade not in %s "
                      "state.") % constants.UPGRADE_ABORT_COMPLETING)
            LOG.info(
                "Completing upgrade abort from release: %s to release: %s" %
                (from_version, to_version))
            upgrades_management.abort_upgrade(from_version, to_version, upgrade)

            if (tsc.system_type == constants.SYSTEM_MODE_DUPLEX and
                    tsc.system_type == constants.TIS_AIO_BUILD and
                        state == constants.UPGRADE_ABORTING_ROLLBACK):

                # For AIO Case, VM goes into no state when Controller-0 becomes active
                # after swact. nova clean up will fail the instance and restart
                # nova-compute service
                LOG.info("Calling nova cleanup")
                with open(os.devnull, "w") as fnull:
                    try:
                        subprocess.check_call(["systemctl", "start", "nova-cleanup"],  # pylint: disable=not-callable
                                              stdout=fnull,
                                              stderr=fnull)
                    except subprocess.CalledProcessError:
                        raise exception.SysinvException(_(
                            "Failed to call nova cleanup during AIO abort"))

            try:
                vim_api.set_vim_upgrade_state(controller_0, False)
            except Exception:
                LOG.exception()
                raise exception.SysinvException(_(
                    "upgrade-abort rejected: unable to reset VIM upgrade "
                    "state"))
            LOG.info("Finished upgrade abort")
        else:
            if upgrade.state != constants.UPGRADE_COMPLETING:
                raise exception.SysinvException(
                    _("Unable to complete upgrade: Upgrade not in %s state.")
                    % constants.UPGRADE_COMPLETING)

            # Complete the restore procedure
            if tsc.system_mode == constants.SYSTEM_MODE_SIMPLEX:
                self.complete_restore(context)

            # Force all host_upgrade entries to use the new load
            # In particular we may have host profiles created in the from load
            # that we need to update before we can delete the load.
            hosts = self.dbapi.host_upgrade_get_list()
            for host_upgrade in hosts:
                if (host_upgrade.target_load == from_load.id or
                        host_upgrade.software_load == from_load.id):
                    LOG.info(_("Updating host id: %s to use load id: %s")
                             % (host_upgrade.forihostid, upgrade.to_load))
                    self.dbapi.host_upgrade_update(
                        host_upgrade.id,
                        {"software_load": upgrade.to_load,
                         "target_load": upgrade.to_load})

            # Complete the upgrade
            LOG.info("Completing upgrade from release: %s to release: %s" %
                     (from_version, to_version))
            upgrades_management.complete_upgrade(from_version, to_version, upgrade)
            LOG.info("Finished completing upgrade")
            # If applicable, notify dcmanager upgrade is complete
            system = self.dbapi.isystem_get_one()
            role = system.get('distributed_cloud_role')
            if role == constants.DISTRIBUTED_CLOUD_ROLE_SYSTEMCONTROLLER:
                dc_api.notify_dcmanager_platform_upgrade_completed()

        # Delete upgrade record
        self.dbapi.software_upgrade_destroy(upgrade.uuid)

        # TODO(RPCHybridMode): This is only useful for 21.12 -> 22.12 upgrades.
        #  Remove this in new releases, when it's no longer necessary
        #  do the migration work through RabbitMQ and ZeroMQ
        if (tsc.system_mode != constants.SYSTEM_MODE_SIMPLEX):
            rpcapi = agent_rpcapi.AgentAPI()
            controller_1 = self.dbapi.ihost_get_by_hostname(
                constants.CONTROLLER_1_HOSTNAME)
            LOG.info("Deleting Sysinv Hybrid state")
            rpcapi.delete_sysinv_hybrid_state(context, controller_1['uuid'])

        # Clear upgrades alarm
        entity_instance_id = "%s=%s" % (fm_constants.FM_ENTITY_TYPE_HOST,
                                        constants.CONTROLLER_HOSTNAME)
        fm_api.FaultAPIs().clear_fault(
            fm_constants.FM_ALARM_ID_UPGRADE_IN_PROGRESS,
            entity_instance_id)

    def abort_upgrade(self, context, upgrade):
        """ Abort the upgrade"""
        from_load = self.dbapi.load_get(upgrade.from_load)
        from_version = from_load.software_version
        to_load = self.dbapi.load_get(upgrade.to_load)
        to_version = to_load.software_version
        LOG.info("Aborted upgrade from release: %s to release: %s" %
                 (from_version, to_version))

        updates = {'state': constants.UPGRADE_ABORTING}

        controller_0 = self.dbapi.ihost_get_by_hostname(
            constants.CONTROLLER_0_HOSTNAME)
        host_upgrade = self.dbapi.host_upgrade_get_by_host(
            controller_0.id)

        if host_upgrade.target_load == to_load.id:
            updates['state'] = constants.UPGRADE_ABORTING_ROLLBACK

        rpc_upgrade = self.dbapi.software_upgrade_update(
            upgrade.uuid, updates)
        # make sure the to/from loads are in the correct state
        self.dbapi.set_upgrade_loads_state(
            upgrade,
            constants.IMPORTED_LOAD_STATE,
            constants.ACTIVE_LOAD_STATE)

        self._puppet.update_system_config()
        self._puppet.update_secure_system_config()

        # There are upgrade flags that are written to controller-0 that need to
        # be removed before downgrading controller-1. As these flags reside on
        # controller-0, we restrict this to abort actions started on that
        # controller. When the abort is run on controller-1 the data-migration
        # must be complete, and only the CONTROLLER_UPGRADE_COMPLETE_FLAG would
        # remain. The CONTROLLER_UPGRADE_COMPLETE_FLAG does not interfere with
        # the host-downgrade. Any remaining flags will be removed during
        # upgrade-complete.
        if utils.is_host_active_controller(controller_0):
            upgrade_flag_files = [
                tsc.CONTROLLER_UPGRADE_FLAG,
                tsc.CONTROLLER_UPGRADE_COMPLETE_FLAG,
                tsc.CONTROLLER_UPGRADE_FAIL_FLAG,
                tsc.CONTROLLER_UPGRADE_STARTED_FLAG
            ]
            for file in upgrade_flag_files:
                try:
                    if os.path.isfile(file):
                        os.remove(file)
                except OSError:
                    LOG.exception("Failed to remove upgrade flag: %s" % file)

        # When we abort from controller-1 while controller-0 is running
        # the previous release, controller-0 will not be aware of the abort.
        # We set the following flag so controller-0 will know we're
        # aborting the upgrade and can set it's database accordingly
        if tsc.system_mode != constants.SYSTEM_MODE_SIMPLEX:
            if updates['state'] == constants.UPGRADE_ABORTING:
                controller_1 = self.dbapi.ihost_get_by_hostname(
                    constants.CONTROLLER_1_HOSTNAME)
                c1_host_upgrade = self.dbapi.host_upgrade_get_by_host(
                    controller_1.id)
                if utils.is_host_active_controller(controller_1) and \
                        c1_host_upgrade.target_load == to_load.id:
                    abort_flag = os.path.join(
                        tsc.PLATFORM_PATH, 'config', from_version,
                        tsc.UPGRADE_ABORT_FILE)
                    open(abort_flag, "w").close()

        return rpc_upgrade

    def complete_simplex_backup(self, context, success):
        """Complete the simplex upgrade start process

        :param context: request context.
        :param success: If the create_simplex_backup call completed
        """
        try:
            upgrade = self.dbapi.software_upgrade_get_one()
        except exception.NotFound:
            LOG.error("Software upgrade record not found")
            return

        from_version = upgrade.from_release
        to_version = upgrade.to_release

        if not success:
            # The upgrade start data collection failed, stop the upgrade
            upgrades_management.abort_upgrade(from_version, to_version,
                                              upgrade)
            # Delete upgrade record
            self.dbapi.software_upgrade_destroy(upgrade.uuid)
            LOG.info("Simplex upgrade start failed")
        else:
            LOG.info("Simplex upgrade start completed")
            # Raise alarm to show an upgrade is in progress
            entity_instance_id = "%s=%s" % (fm_constants.FM_ENTITY_TYPE_HOST,
                                            constants.CONTROLLER_HOSTNAME)
            fault = fm_api.Fault(
                alarm_id=fm_constants.FM_ALARM_ID_UPGRADE_IN_PROGRESS,
                alarm_state=fm_constants.FM_ALARM_STATE_SET,
                entity_type_id=fm_constants.FM_ENTITY_TYPE_HOST,
                entity_instance_id=entity_instance_id,
                severity=fm_constants.FM_ALARM_SEVERITY_MINOR,
                reason_text="System Upgrade in progress.",
                # operational
                alarm_type=fm_constants.FM_ALARM_TYPE_7,
                # congestion
                probable_cause=fm_constants.ALARM_PROBABLE_CAUSE_8,
                proposed_repair_action="No action required.",
                service_affecting=False)
            fm_api.FaultAPIs().set_fault(fault)

            self.dbapi.software_upgrade_update(
                upgrade.uuid, {'state': constants.UPGRADE_STARTED})

        return

    def get_system_health(self, context, force=False, upgrade=False,
                          kube_upgrade=False,
                          kube_rootca_update=False,
                          alarm_ignore_list=None):
        """
        Performs a system health check.

        :param context: request context.
        :param force: set to true to ignore minor and warning alarms
        :param upgrade: set to true to perform an upgrade health check
        :param kube_upgrade: set to true to perform a kubernetes upgrade health
                             check
        :param kube_rootca_update: set to true to perform a kubernetes root CA
                                   update health check
        :param alarm_ignore_list: list of alarm ids to ignore when performing
                                  a health check
        """
        health_util = health.Health(self.dbapi)

        if upgrade is True:
            return health_util.get_system_health_upgrade(
                context=context,
                force=force,
                alarm_ignore_list=alarm_ignore_list)
        elif kube_upgrade is True or kube_rootca_update is True:
            return health_util.get_system_health_kube_upgrade(
                context=context,
                force=force,
                alarm_ignore_list=alarm_ignore_list)
        else:
            return health_util.get_system_health(
                context=context,
                force=force,
                alarm_ignore_list=alarm_ignore_list)

    def _get_cinder_address_name(self, network_type):
        ADDRESS_FORMAT_ARGS = (constants.CONTROLLER_HOSTNAME,
                               network_type)
        return "%s-cinder-%s" % ADDRESS_FORMAT_ARGS

    def reserve_ip_for_third_monitor_node(self, context, hostname):
        """
        Reserve an IP address for a host that will run the third
        Ceph monitor when Ceph is installed as a storage backend.

        :param context: request context.
        :param hostname: hostname to reserve ip.
        """
        chost = self.dbapi.ihost_get_by_hostname(hostname)

        # check if hostname is storage-0 or any worker
        if (chost['personality'] == constants.STORAGE and hostname != constants.STORAGE_0_HOSTNAME) \
                or chost['personality'] == constants.CONTROLLER:
            raise exception.SysinvException(_(
                "Ceph monitor can only be added to storage-0 or any worker."))

        network = self.dbapi.network_get_by_type(constants.NETWORK_TYPE_MGMT)
        address_name = cutils.format_address_name(
            hostname, constants.NETWORK_TYPE_MGMT)

        try:
            self.dbapi.address_get_by_name(address_name)
            LOG.debug("Address %s already reserved, continuing." % address_name)
        except exception.AddressNotFoundByName:
            LOG.debug("Reserving address for %s." % address_name)
            self._allocate_pool_address(None, network.pool_uuid,
                                        address_name)
            self._generate_dnsmasq_hosts_file()

    def reserve_ip_for_cinder(self, context):
        """
        Reserve ip address for Cinder's services

        :param context: request context.
        """
        lvm_backend = StorageBackendConfig.has_backend(
            self.dbapi,
            constants.CINDER_BACKEND_LVM
        )
        if not lvm_backend:
            # Cinder's IP address is only valid if LVM backend exists
            return

        network = self.dbapi.network_get_by_type(constants.NETWORK_TYPE_MGMT)
        network_type = constants.NETWORK_TYPE_MGMT

        # Reserve new ip address, if not present
        try:
            self.dbapi.address_get_by_name(
                self._get_cinder_address_name(network_type)
            )
        except exception.NotFound:
            self._allocate_pool_address(None, network.pool_uuid,
                                        self._get_cinder_address_name(network_type))

        self._generate_dnsmasq_hosts_file()

    def host_load_matches_sw_version(self, host):
        """
        Checks if the host is running the same load as the active controller
        :param host: a host object
        :return: True if host target load matches active sw_version
        """
        host_upgrade = self.dbapi.host_upgrade_get_by_host(host.id)
        target_load = self.dbapi.load_get(host_upgrade.target_load)
        return target_load.software_version == tsc.SW_VERSION

    def create_barbican_secret(self, context, name, payload):
        """Calls Barbican API to create a secret

        :param context: request context.
        :param name: secret name
        :param payload: secret payload
        """
        return self._openstack.create_barbican_secret(context=context,
                                                      name=name, payload=payload)

    def delete_barbican_secret(self, context, name):
        """Calls Barbican API to delete a secret

        :param context: request context.
        :param name: secret name
        """
        self._openstack.delete_barbican_secret(context=context, name=name)

    def update_snmp_config(self, context):
        """Update the snmpd configuration"""
        personalities = [constants.CONTROLLER]
        config_uuid = self._config_update_hosts(context, personalities)
        config_dict = {
            "personalities": personalities,
            "classes": ['platform::fm::runtime'],
        }
        self._config_apply_runtime_manifest(context, config_uuid, config_dict)

    def update_dnsmasq_config(self, context):
        """Update the dnsmasq configuration"""
        personalities = [constants.CONTROLLER]
        config_uuid = self._config_update_hosts(context, personalities)
        config_dict = {
            "personalities": personalities,
            "classes": ['platform::dns::dnsmasq::runtime'],
        }
        self._config_apply_runtime_manifest(context, config_uuid, config_dict)

    def update_ldap_client_config(self, context):
        """Update the LDAP client configuration"""
        personalities = [constants.CONTROLLER]
        config_uuid = self._config_update_hosts(context, personalities)
        config_dict = {
            "personalities": personalities,
            "classes": ['platform::ldap::client::runtime',
                        'platform::sssd::domain::runtime']
        }
        self._config_apply_runtime_manifest(context, config_uuid, config_dict)

    def get_controllerfs_lv_sizes(self, context):
        system = self.dbapi.isystem_get_one()
        system_dc_role = system.get('distributed_cloud_role', None)

        lvdisplay_command = 'lvdisplay --columns --options lv_size,lv_name ' \
                            '--units g --noheading --nosuffix ' \
                            '/dev/cgts-vg/pgsql-lv /dev/cgts-vg/backup-lv ' \
                            '/dev/cgts-vg/platform-lv ' \
                            '/dev/cgts-vg/scratch-lv ' \
                            '/dev/cgts-vg/extension-lv ' \
                            '/dev/cgts-vg/docker-lv ' \
                            '/dev/cgts-vg/etcd-lv ' \
                            '/dev/cgts-vg/dockerdistribution-lv '

        if system_dc_role == constants.DISTRIBUTED_CLOUD_ROLE_SYSTEMCONTROLLER:
            lvdisplay_command = lvdisplay_command + '/dev/cgts-vg/dc-vault-lv '

        lvdisplay_dict = {}
        # Execute the command.
        try:
            lvdisplay_process = subprocess.Popen(lvdisplay_command,
                                                 stdout=subprocess.PIPE,
                                                 shell=True,
                                                 universal_newlines=True)
        except Exception as e:
            LOG.error("Could not retrieve lvdisplay information: %s" % e)
            return lvdisplay_dict

        lvdisplay_output = lvdisplay_process.communicate()[0]
        lvdisplay_dict = cutils.output_to_dict(lvdisplay_output)
        LOG.debug("get_controllerfs_lv_sizes lvdisplay_output %s" % lvdisplay_output)

        return lvdisplay_dict

    def get_ceph_object_pool_name(self, context):
        """
        Get Rados Gateway object data pool name
        """
        return self._ceph.get_ceph_object_pool_name()

    def get_partition_size(self, context, partition):
        # Use the 'blockdev' command for obtaining the size of the partition.
        get_size_command = '{0} {1}'.format('blockdev --getsize64',
                                            partition)

        partition_size = None
        try:
            get_size_process = subprocess.Popen(get_size_command,
                                                stdout=subprocess.PIPE,
                                                shell=True,
                                                universal_newlines=True)
        except Exception as e:
            LOG.error("Could not retrieve device information: %s" % e)
            return partition_size

        partition_size = get_size_process.communicate()[0]

        partition_size = partition_size if partition_size else None

        if partition_size:
            # We also need to add the size of the partition table.
            partition_size = int(partition_size) +\
                                 constants.PARTITION_TABLE_SIZE

            # Convert bytes to GiB and round to be sure.
            partition_size = int(round(  # pylint: disable=W1633
                                 cutils.bytes_to_GiB(partition_size)))

        return partition_size

    def region_has_ceph_backend(self, context):
        """
        Send a request to the primary region to see if ceph is configured
        """
        return self._openstack.region_has_ceph_backend()

    def cinder_prepare_db_for_volume_restore(self, context):
        """
        Send a request to cinder to remove all volume snapshots and set all
        volumes to error state in preparation for restoring all volumes.

        This is needed for cinder disk replacement.
        """
        response = self._openstack.cinder_prepare_db_for_volume_restore(context)
        return response

    def get_software_upgrade_status(self, context):
        """
        Software upgrade status is needed by ceph-manager to take ceph specific
        upgrade actions
        """
        upgrade = {
            'from_version': None,
            'to_version': None,
            'state': None}
        try:
            row = self.dbapi.software_upgrade_get_one()
            upgrade['from_version'] = row.from_release
            upgrade['to_version'] = row.to_release
            upgrade['state'] = row.state
        except exception.NotFound:
            # No upgrade in progress
            pass
        return upgrade

    def distribute_ceph_external_config(self, context, ceph_conf_filename):
        """Notify agent to distribute Ceph configuration file for external
           cluster.
        """
        LOG.debug("ceph_conf_file: %s" % ceph_conf_filename)

        # Retriving the ceph config file that is stored in the /opt/platform/config
        # during the file upload stage.
        opt_ceph_conf_file = os.path.join(tsc.PLATFORM_CEPH_CONF_PATH,
                                          ceph_conf_filename)
        if not os.path.exists(opt_ceph_conf_file):
            raise exception.SysinvException(
                _("Could not find the uploaded ceph config file %s in %s")
                % (ceph_conf_filename, tsc.PLATFORM_CEPH_CONF_PATH))

        try:
            f = open(opt_ceph_conf_file, "r")
            f.seek(0, os.SEEK_SET)
            contents = f.read()
        except IOError:
            msg = _("Failed to read ceph config file from %s " %
                    tsc.PLATFORM_CEPH_CONF_PATH)
            raise exception.SysinvException(msg)

        ceph_conf_file = os.path.join(constants.CEPH_CONF_PATH,
                                      ceph_conf_filename)

        personalities = [constants.CONTROLLER, constants.WORKER]
        config_uuid = self._config_update_hosts(context, personalities)
        config_dict = {
            'personalities': personalities,
            'file_names': [ceph_conf_file],
            'file_content': contents,
        }
        self._config_update_file(context, config_uuid, config_dict)

    def store_ceph_external_config(self, context, contents, ceph_conf_filename):
        """Store the uploaded external ceph config file in /opt/platform/config
        """
        # Once this directory is created at installation time, we can
        # remove this code.
        if not os.path.exists(tsc.PLATFORM_CEPH_CONF_PATH):
            os.makedirs(tsc.PLATFORM_CEPH_CONF_PATH)
        opt_ceph_conf_file = os.path.join(tsc.PLATFORM_CEPH_CONF_PATH,
                                          ceph_conf_filename)

        # Because user needs root permission to manually delete ceph config file
        # from /opt/platform/config/version/ceph-config directory if the file
        # already exists, we will allow ceph config file to be overwritten.
        # Thus, we won't raise an exception if the file already exists.
        if os.path.exists(opt_ceph_conf_file):
            LOG.info("Overwriting file %s in %s " %
                     (ceph_conf_filename, tsc.PLATFORM_CEPH_CONF_PATH))

        # contents might be bytes, make sure it is str
        contents = six.ensure_str(contents)

        try:
            with open(opt_ceph_conf_file, 'w+') as f:
                f.write(contents)
        except IOError:
            msg = _("Failed to write ceph config file in %s " %
                    tsc.PLATFORM_CEPH_CONF_PATH)
            raise exception.SysinvException(msg)

    def install_license_file(self, context, contents):
        """Notify agent to install license file with the supplied data.

        :param context: request context.
        :param contents: contents of license file.
        """

        LOG.info("Install license file.")

        # contents might be bytes, make sure it is str
        contents = six.ensure_str(contents)

        license_file = os.path.join(tsc.PLATFORM_CONF_PATH,
                                    constants.LICENSE_FILE)
        temp_license_file = license_file + '.temp'
        with open(temp_license_file, 'w') as f:
            f.write(contents)
            f.close()

        # Verify license
        try:
            license.verify_license(temp_license_file)
        except Exception as e:
            raise exception.SysinvException(str(e))

        os.rename(temp_license_file, license_file)

        try:
            subprocess.check_output(["cp", license_file,  # pylint: disable=not-callable
                os.path.join(tsc.CONFIG_PATH, constants.LICENSE_FILE)])
        except subprocess.CalledProcessError as e:
            LOG.error("Fail to install license to redundant "
                      "storage, output: %s" % e.output)
            os.remove(license_file)
            raise exception.SysinvException(_(
                "ERROR: Failed to install license to redundant storage."))

        hostname = subprocess.check_output(  # pylint: disable=not-callable
                ["hostname"], universal_newlines=True).rstrip()
        validHostnames = [constants.CONTROLLER_0_HOSTNAME,
                            constants.CONTROLLER_1_HOSTNAME]
        if hostname == 'localhost':
            raise exception.SysinvException(_(
                "ERROR: Host undefined. Unable to install license"))
        elif hostname not in validHostnames:
            raise exception.SysinvException(_(
                "ERROR: Invalid hostname for controller node: %s") % hostname)

        personalities = [constants.CONTROLLER]
        config_uuid = self._config_update_hosts(context, personalities)
        config_dict = {
            'personalities': personalities,
            'file_names': [license_file],
            'file_content': contents,
        }
        self._config_update_file(context, config_uuid, config_dict)

    def update_distributed_cloud_role(self, context):
        """Configure the distributed cloud role.

        :param context: an admin context.
        """

        # update manifest files and nofity agents to apply the change.
        # Should only be applicable to the single controller that is up
        # when the dc role is configured, but add personalities anyway.
        personalities = [constants.CONTROLLER,
                         constants.WORKER,
                         constants.STORAGE]
        config_uuid = self._config_update_hosts(context, personalities)

        # NOTE: no specific classes need to be specified since the default
        # platform::config will be applied that will configure the platform.conf
        config_dict = {"personalities": personalities}

        self._config_apply_runtime_manifest(context, config_uuid, config_dict)

    @staticmethod
    def _extract_keys_from_pem(mode, pem_contents, cert_format,
                               passphrase=None):
        """Extract keys from the pem contents

        :param mode: mode one of: ssl, docker_registry
        :param pem_contents: pem_contents in unicode
        :param cert_format: serialization.PrivateFormat
        :param passphrase: passphrase for PEM file

        :returns: A list of {cert, public_bytes, signature}, and private key.
        """

        if passphrase:
            passphrase = str(passphrase)

        private_bytes = None
        private_mode = False
        temp_pem_contents = pem_contents.encode("utf-8")
        if mode in [constants.CERT_MODE_SSL,
                    constants.CERT_MODE_DOCKER_REGISTRY,
                    constants.CERT_MODE_OPENSTACK,
                    constants.CERT_MODE_OPENLDAP,
                    ]:
            private_mode = True

        if private_mode:
            # extract private_key with passphrase
            try:
                private_key = serialization.load_pem_private_key(
                    temp_pem_contents,
                    password=passphrase,
                    backend=default_backend())
            except Exception as e:
                raise exception.SysinvException(_("Error loading private key "
                                                  "from PEM data: %s" % e))

            if not isinstance(private_key, rsa.RSAPrivateKey):
                raise exception.SysinvException(_(
                    "Only RSA encryption based Private Keys are supported."))

            try:
                private_bytes = private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=cert_format,
                    encryption_algorithm=serialization.NoEncryption())
            except Exception as e:
                raise exception.SysinvException(_("Error loading private "
                                                  "bytes from PEM data: %s"
                                                  % e))

        certs = cutils.extract_certs_from_pem(temp_pem_contents)
        cert_list = []
        for cert in certs:
            # format=serialization.PrivateFormat.TraditionalOpenSSL,
            try:
                public_bytes = cert.public_bytes(
                    encoding=serialization.Encoding.PEM)
            except Exception as e:
                raise exception.SysinvException(_("Error loading public "
                                                  "bytes from PEM data: %s"
                                                  % e))

            # check if the cert is a CA cert
            is_ca = cutils.is_ca_cert(cert)

            hash_subject = cutils.get_cert_subject_hash(cert)

            signature = mode + '_' + str(cert.serial_number)
            if len(signature) > 255:
                LOG.info("Truncating certificate serial no %s" % signature)
                signature = signature[:255]
            LOG.info("config_certificate signature=%s" % signature)

            cert_list.append({'cert': cert,
                             'is_ca': is_ca,
                             'public_bytes': public_bytes,
                             'signature': signature,
                             'hash_subject': hash_subject})

        return cert_list, private_bytes

    @staticmethod
    def _get_public_bytes(cert_list):
        """Get all public bytes from cert list"""

        if len(cert_list) < 1:
            msg = "There should be at least one certificate " \
                  "in the pem contents."
            LOG.error(msg)
            raise exception.SysinvException(_(msg))

        # Concatenate all the public bytes together, as the pem contents
        # may contain intermediate CA certs in it.
        public_bytes = b''
        for cert in cert_list:
            public_bytes += cert.get('public_bytes', b'')

        return public_bytes

    @staticmethod
    def _get_private_bytes_one(private_key):
        """Get exactly one private bytes entry from private key"""

        if not private_key:
            msg = "No private key found in the pem contents."
            LOG.error(msg)
            raise exception.SysinvException(_(msg))
        return private_key

    @staticmethod
    def _consolidate_cert_files():
        # Cat all the cert files into one CA cert file and store it in
        # the shared directory to update system CA certs
        try:
            new_cert_files = \
                os.listdir(constants.SSL_CERT_CA_LIST_SHARED_DIR)
            with os.fdopen(
                    os.open(constants.SSL_CERT_CA_FILE_SHARED,
                            os.O_CREAT | os.O_TRUNC | os.O_WRONLY,
                            constants.CONFIG_FILE_PERMISSION_DEFAULT),
                    'wb') as f:
                for fname in new_cert_files:
                    fname = \
                        os.path.join(constants.SSL_CERT_CA_LIST_SHARED_DIR,
                                     fname)
                    with open(fname, "r") as infile:
                        f.write(infile.read().encode())
        except Exception as e:
            msg = "Failed to consolidate cert files: %s" % str(e)
            LOG.warn(msg)
            raise exception.SysinvException(_(msg))

    def _get_registry_floating_address(self):
        """gets the registry floating address. Currently this is mgmt
        """
        registry_network = self.dbapi.network_get_by_type(
            constants.NETWORK_TYPE_MGMT)
        registry_network_addr_pool = self.dbapi.address_pool_get(
            registry_network.pool_uuid)
        addr = registry_network_addr_pool.floating_address
        return addr

    def config_certificate(self, context, pem_contents, config_dict):
        """Configure certificate with the supplied data.

        :param context: an admin context.
        :param pem_contents: contents of certificate in pem format.
        :param config_dict: dictionary of certificate config attributes.

        In regular mode, the SSL certificate is crafted from the
            isolated private and public keys.
        """

        passphrase = config_dict.get('passphrase', None)
        mode = config_dict.get('mode', None)

        LOG.info("config_certificate mode=%s" % mode)

        # pem_contents might be bytes, make sure it is str
        pem_contents = six.ensure_str(pem_contents)

        cert_list, private_key = \
            self._extract_keys_from_pem(mode, pem_contents,
                                        serialization.PrivateFormat.PKCS8,
                                        passphrase)

        personalities = [constants.CONTROLLER]

        if mode == constants.CERT_MODE_SSL:
            config_uuid = self._config_update_hosts(context, personalities)
            private_bytes = self._get_private_bytes_one(private_key)
            public_bytes = self._get_public_bytes(cert_list)
            file_content = private_bytes + public_bytes
            config_dict = {
                'personalities': personalities,
                'file_names': [constants.SSL_PEM_FILE],
                'file_content': file_content,
                'nobackup': True,
                'permissions': constants.CONFIG_FILE_PERMISSION_ROOT_READ_ONLY,
            }
            self._config_update_file(context, config_uuid, config_dict)

            # copy the certificate to shared directory
            with os.fdopen(os.open(constants.SSL_PEM_FILE_SHARED,
                                   os.O_CREAT | os.O_TRUNC | os.O_WRONLY,
                                   constants.CONFIG_FILE_PERMISSION_ROOT_READ_ONLY),
                                   'wb') as f:
                f.write(file_content)

            config_uuid = self._config_update_hosts(context, personalities)
            config_dict = {
                "personalities": personalities,
                "classes": ['platform::haproxy::runtime',
                            'openstack::horizon::runtime']
            }
            self._config_apply_runtime_manifest(context,
                                                config_uuid,
                                                config_dict)

        elif mode == constants.CERT_MODE_SSL_CA:
            # The list of the existing CA certs in sysinv DB.
            certificates = self.dbapi.certificate_get_list()
            certs_inv = [certificate.signature
                         for certificate in certificates
                         if certificate.certtype == mode]
            # The list of the actual CA certs as files in FS
            certs_file = os.listdir(constants.SSL_CERT_CA_LIST_SHARED_DIR)

            # Remove these already installed from the cert list
            cert_list_c = cert_list[:]
            for cert in cert_list_c:
                if cert.get('signature') in certs_inv \
                        and cert.get('signature') in certs_file:
                    cert_list.remove(cert)

            # Save certs in files and cat them into ca-cert.pem to apply to the
            # system.
            if cert_list:
                # Save each cert in a separate file with signature as its name
                try:
                    for cert in cert_list:
                        file_content = cert.get('public_bytes')
                        file_name = \
                            os.path.join(constants.SSL_CERT_CA_LIST_SHARED_DIR,
                                         cert.get('signature'))
                        with os.fdopen(
                                os.open(file_name,
                                        os.O_CREAT | os.O_TRUNC | os.O_WRONLY,
                                        constants.CONFIG_FILE_PERMISSION_DEFAULT),
                                'wb') as f:
                            f.write(file_content)
                except Exception as e:
                    msg = "Failed to save cert file: %s" % str(e)
                    LOG.warn(msg)
                    raise exception.SysinvException(msg)

                # consolidate the CA cert files into ca-cert.pem to update
                # system CA certs.
                self._consolidate_cert_files()

            personalities = [constants.CONTROLLER,
                             constants.WORKER,
                             constants.STORAGE]
            config_uuid = self._config_update_hosts(context, personalities)
            config_dict = {
                "personalities": personalities,
                "classes": ['platform::config::runtime']
            }
            self._config_apply_runtime_manifest(context,
                                                config_uuid,
                                                config_dict,
                                                force=True)
        # Special mode for openldap CA certificate.
        # This CA certificate will be stored in k8s as an opaque secret
        elif mode == constants.CERT_MODE_OPENLDAP_CA:
            kube_operator = kubernetes.KubeOperator()
            public_bytes = self._get_public_bytes(cert_list)
            cert_secret = base64.encode_as_text(public_bytes)

            body = {
                'apiVersion': 'v1',
                'type': 'Opaque',
                'kind': 'Secret',
                'metadata': {
                    'name': constants.OPENLDAP_CA_CERT_SECRET_NAME,
                    'namespace': constants.CERT_NAMESPACE_PLATFORM_CA_CERTS
                },
                'data': {
                    'ca.crt': cert_secret,
                }
            }

            try:
                secret = kube_operator.kube_get_secret(
                        constants.OPENLDAP_CA_CERT_SECRET_NAME,
                        constants.CERT_NAMESPACE_PLATFORM_CA_CERTS)
                if secret is not None:
                    kube_operator.kube_delete_secret(
                            constants.OPENLDAP_CA_CERT_SECRET_NAME,
                            constants.CERT_NAMESPACE_PLATFORM_CA_CERTS)
                kube_operator.kube_create_secret(
                        constants.CERT_NAMESPACE_PLATFORM_CA_CERTS, body)
            except Exception as e:
                msg = "Failed to store openldap CA in k8s secret: %s" % str(e)
                LOG.error(msg)
                return msg

        elif mode == constants.CERT_MODE_DOCKER_REGISTRY:
            LOG.info("Docker registry certificate install")
            # docker registry requires a PKCS1 key for the token server
            _, private_key_pkcs1 = \
                self._extract_keys_from_pem(mode, pem_contents,
                                            serialization.PrivateFormat
                                            .TraditionalOpenSSL, passphrase)
            pkcs1_private_bytes = \
                self._get_private_bytes_one(private_key_pkcs1)

            # install certificate, key, and pkcs1 key to controllers
            config_uuid = self._config_update_hosts(context, personalities)
            key_path = constants.DOCKER_REGISTRY_KEY_FILE
            cert_path = constants.DOCKER_REGISTRY_CERT_FILE
            pkcs1_key_path = constants.DOCKER_REGISTRY_PKCS1_KEY_FILE

            private_bytes = self._get_private_bytes_one(private_key)
            public_bytes = self._get_public_bytes(cert_list)

            config_dict = {
                'personalities': personalities,
                'file_names': [key_path, cert_path, pkcs1_key_path],
                'file_content': {key_path: private_bytes,
                                 cert_path: public_bytes,
                                 pkcs1_key_path: pkcs1_private_bytes},
                'nobackup': True,
                'permissions': constants.CONFIG_FILE_PERMISSION_ROOT_READ_ONLY,
            }
            self._config_update_file(context, config_uuid, config_dict,
                                     filter_files=[key_path, cert_path, pkcs1_key_path])

            # copy certificate to shared directory
            with os.fdopen(os.open(constants.DOCKER_REGISTRY_CERT_FILE_SHARED,
                                   os.O_CREAT | os.O_TRUNC | os.O_WRONLY,
                                   constants.CONFIG_FILE_PERMISSION_ROOT_READ_ONLY),
                                   'wb') as f:
                f.write(public_bytes)
            with os.fdopen(os.open(constants.DOCKER_REGISTRY_KEY_FILE_SHARED,
                                   os.O_CREAT | os.O_TRUNC | os.O_WRONLY,
                                   constants.CONFIG_FILE_PERMISSION_ROOT_READ_ONLY),
                                   'wb') as f:
                f.write(private_bytes)
            with os.fdopen(os.open(constants.DOCKER_REGISTRY_PKCS1_KEY_FILE_SHARED,
                                   os.O_CREAT | os.O_TRUNC | os.O_WRONLY,
                                   constants.CONFIG_FILE_PERMISSION_ROOT_READ_ONLY),
                                   'wb') as f:
                f.write(pkcs1_private_bytes)

            config_uuid = self._config_update_hosts(context, personalities)
            config_dict = {
                "personalities": personalities,
                "classes": ['platform::dockerdistribution::runtime']
            }
            self._config_apply_runtime_manifest(context,
                                                config_uuid,
                                                config_dict,
                                                filter_classes=[self.PUPPET_RUNTIME_CLASS_DOCKERDISTRIBUTION])

            # install docker certificate on controllers and workers
            docker_cert_path = constants.DOCKER_CERT_FILE

            personalities = [constants.CONTROLLER,
                             constants.WORKER]
            config_uuid = self._config_update_hosts(context,
                                                    personalities)
            config_dict = {
                'personalities': personalities,
                'file_names': [docker_cert_path],
                'file_content': public_bytes,
                'nobackup': True,
                'permissions': constants.CONFIG_FILE_PERMISSION_ROOT_READ_ONLY,
            }
            self._config_update_file(context, config_uuid, config_dict,
                                     filter_files=[docker_cert_path])
        elif mode == constants.CERT_MODE_OPENLDAP:
            LOG.info("OpenLDAP certificate install")
            # install certificate, key to controllers
            config_uuid = self._config_update_hosts(context, personalities)
            config_dict = {
                "personalities": personalities,
                "classes": ['platform::ldap::secure::runtime']
            }
            self._config_apply_runtime_manifest(context,
                                                config_uuid,
                                                config_dict)

        elif mode == constants.CERT_MODE_OPENSTACK:
            config_uuid = self._config_update_hosts(context, personalities)
            key_path = constants.OPENSTACK_CERT_KEY_FILE
            cert_path = constants.OPENSTACK_CERT_FILE
            private_bytes = self._get_private_bytes_one(private_key)
            public_bytes = self._get_public_bytes(cert_list)

            config_dict = {
                'personalities': personalities,
                'file_names': [key_path, cert_path],
                'file_content': {key_path: private_bytes,
                                 cert_path: public_bytes},
                'nobackup': True,
                'permissions': constants.CONFIG_FILE_PERMISSION_ROOT_READ_ONLY,
            }
            self._config_update_file(context, config_uuid, config_dict)

            if not os.path.exists(constants.CERT_OPENSTACK_SHARED_DIR):
                os.makedirs(constants.CERT_OPENSTACK_SHARED_DIR)
            # copy the certificate to shared directory
            with os.fdopen(os.open(constants.OPENSTACK_CERT_FILE_SHARED,
                                   os.O_CREAT | os.O_TRUNC | os.O_WRONLY,
                                   constants.CONFIG_FILE_PERMISSION_ROOT_READ_ONLY),
                                   'wb') as f:
                f.write(public_bytes)
            with os.fdopen(os.open(constants.OPENSTACK_CERT_KEY_FILE_SHARED,
                                   os.O_CREAT | os.O_TRUNC | os.O_WRONLY,
                                   constants.CONFIG_FILE_PERMISSION_ROOT_READ_ONLY),
                                   'wb') as f:
                f.write(private_bytes)

            config_uuid = self._config_update_hosts(context, personalities)
            config_dict = {
                "personalities": personalities,
                "classes": ['openstack::keystone::endpoint::runtime',
                            'openstack::horizon::runtime']
            }
            self._config_apply_runtime_manifest(context,
                                                config_uuid,
                                                config_dict)

        elif mode == constants.CERT_MODE_OPENSTACK_CA:
            config_uuid = self._config_update_hosts(context, personalities)
            file_content = self._get_public_bytes(cert_list)
            config_dict = {
                'personalities': personalities,
                'file_names': [constants.OPENSTACK_CERT_CA_FILE],
                'file_content': file_content,
                'permissions': constants.CONFIG_FILE_PERMISSION_DEFAULT,
            }
            self._config_update_file(context, config_uuid, config_dict)

            # copy the certificate to shared directory
            with os.fdopen(os.open(constants.OPENSTACK_CERT_CA_FILE_SHARED,
                                   os.O_CREAT | os.O_TRUNC | os.O_WRONLY,
                                   constants.CONFIG_FILE_PERMISSION_DEFAULT),
                                   'wb') as f:
                f.write(file_content)

            config_uuid = self._config_update_hosts(context, personalities)
            config_dict = {
                "personalities": personalities,
                "classes": ['openstack::keystone::endpoint::runtime',
                            'openstack::horizon::runtime']
            }
            self._config_apply_runtime_manifest(context,
                                                config_uuid,
                                                config_dict)
        else:
            msg = "config_certificate unexpected mode=%s" % mode
            LOG.warn(msg)
            raise exception.SysinvException(_(msg))

        inv_certs = []
        for cert in cert_list:
            inv_cert = {'signature': cert.get('signature'),
                        'is_ca': cert.get('is_ca'),
                        'not_valid_before': cert.get('cert').not_valid_before,
                        'not_valid_after': cert.get('cert').not_valid_after,
                        'hash_subject': cert.get('hash_subject'),
                        'subject': cert.get('cert').subject.rfc4514_string()
                        }
            inv_certs.append(inv_cert)

        return inv_certs

    def _config_selfsigned_certificate(self, context):
        """
        This code is invoked when https is enabled
        to install a self signed certificate to get started

        :param context: an admin context.

        """

        mode = constants.CERT_MODE_SSL
        passphrase = None
        certificate_file = constants.SSL_PEM_SS_FILE

        # Generate a self-signed server certificate to enable https
        csr_config = """
            [ req ]
            default_bits           = 2048
            distinguished_name     = req_distinguished_name
            prompt                 = no
            [ req_distinguished_name ]
            CN                     = StarlingX
            """

        try:
            with open(os.devnull, "w") as fnull:
                openssl_cmd = "(openssl req -new -x509 -sha256 \
                        -keyout {file} -out {file} -days 365 -nodes \
                        -config <(echo \"{config}\")) && sync" \
                        .format(file=certificate_file, config=csr_config)
                subprocess.check_call(openssl_cmd,  # pylint: disable=not-callable
                                      stdout=fnull, stderr=fnull,
                                      shell=True, executable='/usr/bin/bash')
        except subprocess.CalledProcessError as e:
            LOG.exception(e)
            msg = "Fail to generate self-signed certificate to enable https."
            raise exception.SysinvException(_(msg))

        with open(certificate_file) as pemfile:
            pem_contents = pemfile.read()

        LOG.info("_config_selfsigned_certificate mode=%s file=%s" % (mode, certificate_file))

        cert_list, private_key = \
            self._extract_keys_from_pem(mode, pem_contents,
                                        serialization.PrivateFormat.PKCS8,
                                        passphrase)

        personalities = [constants.CONTROLLER]

        config_uuid = self._config_update_hosts(context, personalities)
        private_bytes = self._get_private_bytes_one(private_key)
        public_bytes = self._get_public_bytes(cert_list)
        file_content = private_bytes + public_bytes
        config_dict = {
            'personalities': personalities,
            'file_names': [constants.SSL_PEM_FILE],
            'file_content': file_content,
            'permissions': constants.CONFIG_FILE_PERMISSION_ROOT_READ_ONLY,
            'nobackup': True,
        }
        self._config_update_file(context, config_uuid, config_dict)

        # copy the certificate to shared directory
        with os.fdopen(os.open(constants.SSL_PEM_FILE_SHARED,
                               os.O_CREAT | os.O_TRUNC | os.O_WRONLY,
                               constants.CONFIG_FILE_PERMISSION_ROOT_READ_ONLY),
                               'wb') as f:
            f.write(file_content)

        # Inventory the self signed certificate.
        # In case the self signed cert is ICA signed,
        # skip these intermediate CA certs.
        for cert in cert_list:
            if not cert.get('is_ca', False):
                values = {
                    'certtype': mode,
                    'signature': cert.get('signature'),
                    'start_date': cert.get('cert').not_valid_before,
                    'expiry_date': cert.get('cert').not_valid_after,
                }
                self.dbapi.certificate_create(values)
                break
        else:
            msg = "Fail to inventory the self signed certificate, \
                   no leaf cert found."
            raise exception.SysinvException(_(msg))

    def delete_certificate(self, context, mode, signature):
        """Delete a certificate by its mode and signature.

        :param context: an admin context.
        :param mode: the mode of the certificate
        :param signature: the signature of the certificate.

        Currently only ssl_ca cert can be deleted.
        """
        LOG.info("delete_certificate mode=%s, signature=%s" %
                 (mode, signature))

        if mode == constants.CERT_MODE_SSL_CA:
            try:
                cert_file = \
                    os.path.join(constants.SSL_CERT_CA_LIST_SHARED_DIR,
                                 signature)
                os.remove(cert_file)
            except Exception as e:
                msg = "Failed to delete cert file: %s" % str(e)
                LOG.warn(msg)
                raise exception.SysinvException(_(msg))

            self._consolidate_cert_files()

            personalities = [constants.CONTROLLER,
                             constants.WORKER,
                             constants.STORAGE]
            config_uuid = self._config_update_hosts(context, personalities)
            config_dict = {
                "personalities": personalities,
                "classes": ['platform::config::runtime']
            }
            self._config_apply_runtime_manifest(context,
                                                config_uuid,
                                                config_dict,
                                                force=True)
        else:
            msg = "delete_certificate unsupported mode=%s" % mode
            LOG.error(msg)
            raise exception.SysinvException(_(msg))

    def update_host_max_cpu_mhz_configured(self, context, host):
        personalities = [constants.WORKER]

        config_uuid = self._config_update_hosts(context,
                                                personalities,
                                                [host['uuid']])
        config_dict = {
            "personalities": personalities,
            "host_uuids": [host['uuid']],
            "classes": ['platform::compute::config::runtime']
        }
        self._config_apply_runtime_manifest(context,
                                            config_uuid,
                                            config_dict)

    def update_admin_ep_certificate(self, context):
        """
        Update admin endpoint certificate
        :param context: an admin context.
        :return: true if certificate is renewed
        """
        update_required = False
        system = self.dbapi.isystem_get_one()
        system_dc_role = system.get('distributed_cloud_role', None)
        cert_data = cutils.get_admin_ep_cert(system_dc_role)

        if cert_data is None:
            return False

        ca_crt = cert_data['dc_root_ca_crt']
        admin_ep_cert = cert_data['admin_ep_crt']
        if os.path.isfile(constants.ADMIN_EP_CERT_FILENAME):
            with open(constants.ADMIN_EP_CERT_FILENAME, mode='r') as f:
                endpoint_cert = f.read()
            if admin_ep_cert not in endpoint_cert:
                update_required = True
        else:
            update_required = True

        if ca_crt is not None:
            if os.path.isfile(constants.DC_ROOT_CA_CERT_PATH):
                with open(constants.DC_ROOT_CA_CERT_PATH, mode='r') as f:
                    dc_root_ca_cert = f.read()
                if ca_crt not in dc_root_ca_cert:
                    update_required = True
            else:
                update_required = True

        if update_required:
            m = hashlib.md5()
            if ca_crt is not None:
                m.update(encodeutils.safe_encode(ca_crt))
            m.update(encodeutils.safe_encode(admin_ep_cert))
            md5sum = m.hexdigest()

            LOG.info('Updating admin endpoint cert, md5sum %s' % md5sum)

            personalities = [constants.CONTROLLER]
            config_uuid = self._config_update_hosts(context, personalities)
            config_dict = {
                "personalities": personalities,
                "classes": ['platform::config::dc_root_ca::runtime',
                            'platform::haproxy::restart::runtime']
            }

            self._config_apply_runtime_manifest(context,
                                                config_uuid,
                                                config_dict,
                                                force=True)

        return update_required

    def update_intermediate_ca_certificate(self, context,
                                    root_ca_crt, sc_ca_cert, sc_ca_key):
        """
        Update intermediate CA certificate
        """
        sc_endpoint_cert_secret_ns = 'sc-cert'
        sc_intermediate_ca_secret_name = 'sc-adminep-ca-certificate'
        sc_admin_endpoint_secret_name = constants.SC_ADMIN_ENDPOINT_SECRET_NAME
        if root_ca_crt is None:
            LOG.error('Root CA cert is not provided')
            raise exception.SysinvException(_(
                "Root CA certificate is not provided"))

        kube_operator = kubernetes.KubeOperator()
        secret = kube_operator.kube_get_secret(sc_intermediate_ca_secret_name,
                                               sc_endpoint_cert_secret_ns)
        if not hasattr(secret, 'data'):
            raise Exception('Invalid secret %s\\%s' % (
                sc_endpoint_cert_secret_ns, sc_intermediate_ca_secret_name
            ))

        tls_key = base64.encode_as_text(sc_ca_key)
        tls_crt = base64.encode_as_text(sc_ca_cert)
        if tls_key == secret.data['tls.key'] and tls_crt == secret.data['tls.crt']:
            LOG.info('Intermediate CA cert is not changed')
            return

        secret.data['tls.key'] = tls_key
        secret.data['tls.crt'] = tls_crt

        new = kube_operator.kube_patch_secret(sc_intermediate_ca_secret_name,
                                              sc_endpoint_cert_secret_ns,
                                              secret)
        if new.data['tls.key'] == tls_key and new.data['tls.crt'] == tls_crt:
            with open(constants.DC_ROOT_CA_CONFIG_PATH, 'w') as f:
                f.write(root_ca_crt)
            res = kube_operator.kube_delete_secret(sc_admin_endpoint_secret_name,
                                             sc_endpoint_cert_secret_ns)

            LOG.info('Deleting %s:%s, result %s, msg %s' %
                     (sc_endpoint_cert_secret_ns,
                      sc_admin_endpoint_secret_name,
                      res.status, res.message))
        else:
            raise Exception("Unexpected result updating %s\\%s. tls.crt "
                            "and/or tls.key don't match"
                            % (sc_endpoint_cert_secret_ns, sc_endpoint_cert_secret_ns))

    def update_ttys_dcd(self, context, ihost_uuid):
        """Apply runtime manifest to configure the dcd with the supplied data.

        :param context: an admin context.
        :param ihost_uuid: the host uuid.
        """
        host = self.dbapi.ihost_get(ihost_uuid)
        LOG.debug("ConductorManager.update_ttys_dcd: running manifest "
                  "dcd update %s %s" % (host.ttys_dcd, host['uuid']))
        personalities = [constants.WORKER,
                         constants.CONTROLLER,
                         constants.STORAGE]

        config_uuid = self._config_update_hosts(context,
                                                personalities,
                                                [host['uuid']])
        config_dict = {
            "personalities": personalities,
            "host_uuids": [host['uuid']],
            "classes": ['platform::tty::runtime']
        }
        self._config_apply_runtime_manifest(context,
                                            config_uuid,
                                            config_dict)

    def get_helm_chart_overrides(self, context, app_name, chart_name,
                                 cnamespace=None):
        """Get the overrides for a supported chart.

        This method retrieves overrides for a supported chart. Overrides for
        all supported namespaces will be returned unless a specific namespace
        is requested.

        :param context: request context.
        :param app_name: name of a supported application
        :param chart_name: name of a supported chart
        :param cnamespace: (optional) namespace
        :returns: dict of overrides.

        Example Without a cnamespace parameter:
        {
            'kube-system': {
                'deployment': {
                    'mode': 'cluster',
                    'type': 'DaemonSet'
                },
            },
            'openstack': {
                'pod': {
                    'replicas': {
                        'server': 1
                    }
                }
            }
        }

        Example with a cnamespace parameter: cnamespace='kube-system'
        {
            'deployment': {
                'mode': 'cluster',
                'type': 'DaemonSet'
            }
        }
        """

        app = kubeapp_obj.get_by_name(context, app_name)
        if app.status in [constants.APP_APPLY_IN_PROGRESS,
                          constants.APP_APPLY_SUCCESS,
                          constants.APP_APPLY_FAILURE]:
            overrides = self._helm.get_helm_chart_overrides(chart_name,
                                                            cnamespace)
        else:
            self._app.activate_app_plugins(app)
            overrides = self._helm.get_helm_chart_overrides(chart_name,
                                                            cnamespace)
            self._app.deactivate_app_plugins(app)

        return overrides

    def app_has_system_plugins(self, context, app_name):
        """Determine if the application has system plugin support.

        :returns: True if the application has system plugins and can generate
                  system overrides.
        """
        app = kubeapp_obj.get_by_name(context, app_name)
        return self._app.app_has_system_plugins(app)

    def get_helm_application_namespaces(self, context, app_name):
        """Get supported application namespaces.

        This method retrieves a dict of charts and their supported namespaces
        for an application.

        :param app_name: name of the bundle of charts required to support an
                         application
        :returns: dict of charts and supported namespaces that associated
                  overrides may be provided.
        """
        return self._helm.get_helm_application_namespaces(app_name)

    def get_helm_application_overrides(self, context, app_name, cnamespace):
        """Get the overrides for a supported set of charts.

        This method retrieves overrides for a set of supported charts that
        comprise an application. Overrides for all charts and all supported
        namespaces will be returned unless a specific namespace is requested.

        If a specific namespace is requested, then only charts that support
        that specified namespace will be returned.

        :param context: request context.
        :param app_name: name of a supported application (set of charts)
        :param cnamespace: (optional) namespace
        :returns: dict of overrides.

        Example:
        {
            'ingress': {
                'kube-system': {
                    'deployment': {
                        'mode': 'cluster',
                        'type': 'DaemonSet'
                    },
                },
                'openstack': {
                    'pod': {
                        'replicas': {
                            'server': 1
                        }
                    }
                }
            },
            'glance': {
                'openstack': {
                    'pod': {
                        'replicas': {
                            'server': 1
                        }
                    }
                }
             }
        }
        """
        return self._helm.get_helm_application_overrides(app_name, cnamespace)

    def merge_overrides(self, context, file_overrides=None, set_overrides=None):
        """Merge the file and set overrides into a single chart overrides.

        :param context: request context.
        :param file_overrides: (optional) list of overrides from files
        :param set_overrides: (optional) list of parameter overrides
        :returns: merged overrides string

        """
        return self._helm.merge_overrides(file_overrides, set_overrides)

    def update_kubernetes_label(self, context,
                                host_uuid, label_dict):
        """Synchronously, have the conductor update kubernetes label
        per host.

        :param context: request context.
        :param host_uuid: uuid or id of the host
        :param label_dict: a dictionary of host label attributes

        """
        LOG.info("update_kubernetes_label: label_dict=%s" % label_dict)
        try:
            host = self.dbapi.ihost_get(host_uuid)
        except exception.ServerNotFound:
            LOG.error("Cannot find host by id %s" % host_uuid)
            return
        body = {
            'metadata': {
                'labels': {}
            }
        }
        body['metadata']['labels'].update(label_dict)
        try:
            self._kube.kube_patch_node(host.hostname, body)
        except exception.KubeNodeNotFound:
            LOG.info("Host %s does not exist in kubernetes yet, label will "
                     "be added after node's unlock by audit" % host.hostname)

    def update_host_memory(self, context, host_uuid):
        try:
            host = self.dbapi.ihost_get(host_uuid)
        except exception.ServerNotFound:
            LOG.error("Cannot find host by id %s" % host_uuid)
            return

        rpcapi = agent_rpcapi.AgentAPI()
        rpcapi.update_host_memory(context, host.uuid)

    def update_fernet_repo(self, context, keys=None):
        """Update the fernet repo with the new keys.

          :param context: request context.
          :param keys: a list of keys
          :returns: nothing
          """

        if keys:
            self._fernet.update_fernet_keys(keys)
        else:
            self._fernet.reset_fernet_keys()

    def get_fernet_keys(self, context, key_id=None):
        """Get the keys from the fernet repo.

          :param context: request context.
          :param key_id: Optionally, it can be used to retrieve a specified key
          :returns: a list of keys
          """
        return self._fernet.get_fernet_keys(key_id)

    def determine_apps_reapply_order(self, name_only, filter_active=True):
        """ Order the apps for reapply

        :param name_only: return list of app names if name_only is True
                          return list of apps if name_only is False
        :param filter_active: When true keep only applied apps in the list

        :returns: list of apps or app names
        """
        try:
            # Cached entry: precomputed order of reapply evaluation
            if name_only and not filter_active:
                return self.apps_metadata[constants.APP_METADATA_ORDERED_APPS]

            ordered_apps = []
            # Start from already ordered list
            for app_name in self.apps_metadata[constants.APP_METADATA_ORDERED_APPS]:
                try:
                    app = self.dbapi.kube_app_get(app_name)
                except exception.KubeAppNotFound:
                    continue

                if filter_active and app.active:
                    ordered_apps.append(app)
                elif not filter_active:
                    ordered_apps.append(app)

            LOG.info("Apps reapply order: {}".format(
                [app_.name for app_ in ordered_apps]))

            if name_only:
                ordered_apps = [app_.name for app_ in ordered_apps]
        except Exception as e:
            LOG.error("Error while ordering apps for reapply {}".format(str(e)))
            ordered_apps = []

        return ordered_apps

    def evaluate_apps_reapply(self, context, trigger):
        """Synchronously, determine whether an application
        re-apply is needed, and if so, raise the re-apply flag.

        Run 3 checks before doing an app evaluation.
        First check is to verify whether Kubernetes upgrades are not in progress.
        Second check is a semantic check calling a lifecycle hook which can
        implement complex logic.
        Third check is specified in metadata which allows faster development
        time, doing simple key:value comparisons. Check that the 'trigger'
        parameter of the function contains a list of key:value pairs at a
        specified location. Default location for searching is root of 'trigger'
        dictionary. If the keys are absent or the values do not match, then the
        check is considered failed and the evaluation skipped.

        :param context: request context.
        :param trigger: dictionary containing at least the 'type' field

        """

        # Defer apps reapply evaluation if Kubernetes upgrades are in progress
        try:
            self.verify_k8s_upgrade_not_in_progress()
        except Exception as e:
            LOG.info("Deferring apps reapply evaluation. {}".format(str(e)))
            return

        LOG.info("Evaluating apps reapply {} ".format(trigger))
        apps = self.determine_apps_reapply_order(name_only=False, filter_active=True)

        metadata_map = constants.APP_EVALUATE_REAPPLY_TRIGGER_TO_METADATA_MAP

        for app in apps:

            app_metadata = self.apps_metadata[constants.APP_METADATA_APPS].get(app.name, {})
            try:
                app_triggers = app_metadata[constants.APP_METADATA_BEHAVIOR][
                    constants.APP_METADATA_EVALUATE_REAPPLY][
                    constants.APP_METADATA_TRIGGERS]
            except KeyError:
                continue

            try:
                hook_info = LifecycleHookInfo()
                hook_info.mode = constants.APP_LIFECYCLE_MODE_AUTO
                hook_info.operation = constants.APP_EVALUATE_REAPPLY_OP
                hook_info.lifecycle_type = constants.APP_LIFECYCLE_TYPE_SEMANTIC_CHECK
                hook_info.extra[LifecycleConstants.EVALUATE_REAPPLY_TRIGGER] = trigger
                self.app_lifecycle_actions(context=context, rpc_app=app, hook_info=hook_info)
            except exception.LifecycleSemanticCheckException as e:
                LOG.info("Evaluate reapply for {} rejected: {}".format(app.name, e))
                continue
            except exception.LifecycleMissingInfo as e:
                LOG.error("Evaluate reapply for {} error: {}".format(app.name, e))
                continue
            except Exception as e:
                LOG.error("Unexpected error during hook for app {}, error: {}"
                          "".format(app.name, e))
                continue

            if trigger['type'] in metadata_map.keys():
                # Check if the app subscribes to this trigger type
                if [t for t in app_triggers if t.get('type', None) ==
                                    metadata_map[trigger['type']]]:
                    # Get the first trigger with a specific type in the metadata
                    app_trigger = [x for x in app_triggers if
                                   x.get(constants.APP_METADATA_TYPE, None) == metadata_map[trigger['type']]][0]

                    # Get the filters for the trigger
                    trigger_filters = app_trigger.get(constants.APP_METADATA_FILTERS, [])

                    # Get which field inside the trigger should have the filters applied on
                    # Default is the trigger dictionary itself, but can be redirected to
                    # a sub-dictionary
                    target_for_filters_field = app_trigger.get(constants.APP_METADATA_FILTER_FIELD, None)
                    if target_for_filters_field is None:
                        target_for_filters = trigger
                    else:
                        if target_for_filters_field not in trigger:
                            LOG.error("Trigger {} does not have field {}"
                                      "".format(trigger, target_for_filters_field))
                            continue
                        target_for_filters = trigger[target_for_filters_field]

                    allow = True
                    # All filters must match, if any doesn't match then reject
                    # the evaluation
                    for filter_ in trigger_filters:
                        # Each filter is a single entry dict
                        k = list(filter_.keys())[0]
                        if k not in target_for_filters:
                            LOG.info("Evaluate reapply for {} rejected: "
                                     "trigger field {} absent".format(app.name, k))
                            allow = False
                            break
                        elif str(target_for_filters[k]) != str(filter_[k]):
                            LOG.info("Evaluate reapply for {} rejected: "
                                     "trigger field {} expected {} but got {} "
                                     "".format(app.name, k, filter_[k], target_for_filters[k]))
                            allow = False
                            break

                    if allow:
                        self.evaluate_app_reapply(context, app.name)

    def evaluate_app_reapply(self, context, app_name):
        """Synchronously, determine whether an application
        re-apply is needed, and if so, raise the re-apply flag.

          :param context: request context.
          :param app_name: application to be checked
          """
        try:
            app = kubeapp_obj.get_by_name(context, app_name)
            app = self._app.Application(app)

        except exception.KubeAppNotFound:
            return

        LOG.info("Evaluating app reapply of %s" % app.name)
        if app.active and app.status == constants.APP_APPLY_SUCCESS:
            # Hash the existing overrides
            # TODO these hashes can be stored in the db to reduce overhead,
            # as well as removing the writing to disk of the new overrides
            old_hash = {}
            app.charts = self._app._get_list_of_charts(app)
            helm_files = self._app._get_overrides_files(app)
            for f in helm_files:
                with open(f, 'rb') as file:
                    old_hash[f] = hashlib.md5(file.read()).hexdigest()

            # Regenerate overrides and compute new hash
            try:
                new_hash = {}
                app.charts = self._app._get_list_of_charts(app)
                self._helm.generate_helm_application_overrides(
                    app.sync_overrides_dir, app.name, app.mode, cnamespace=None,
                    chart_info=app.charts, combined=True)
                helm_files = self._app._get_overrides_files(app)
                for f in helm_files:
                    with open(f, 'rb') as file:
                        new_hash[f] = hashlib.md5(file.read()).hexdigest()

                if old_hash != new_hash:
                    LOG.info("There has been an overrides change, setting up "
                             "reapply of %s", app.name)
                    self._app.set_reapply(app.name)
                else:
                    LOG.info("No override change after configuration action, "
                             "skipping re-apply of %s", app.name)
            except Exception as e:
                LOG.exception("Failed to regenerate the overrides for app %s. %s" %
                              (app.name, e))
        else:
            LOG.info("{} app active:{} status:{} does not warrant re-apply"
                     "".format(app.name, app.active, app.status))

    def app_lifecycle_actions(self, context, rpc_app, hook_info):
        """Perform any lifecycle actions for the operation and timing supplied.

        :param context: request context.
        :param rpc_app: application to be checked
        :param hook_info: LifecycleHookInfo object

        """

        LOG.debug("app_lifecycle_actions for app "
                  "{}, {}".format(rpc_app.name, hook_info))

        try:
            self._app.app_lifecycle_actions(context, self, rpc_app, hook_info)
        except exception.LifecycleSemanticCheckOpererationBlocked as e:
            LOG.info("Metadata-evaluation: {}".format(e))
            raise

    def _log_applications_not_reverted(self, operation):
        try:
            operation_log = self._backup_actions_log[operation]
            if len(operation_log):
                LOG.error("{} : {} applications:\n{}".
                          format(operation,
                                 len(operation_log),
                                 '\n'.join(['\t- {}'.format(_) for _ in operation_log.keys()])
                                 ))
        except KeyError:
            LOG.error("Internal error, no such revert operation '{}'".format(operation))

    def _initialize_backup_actions_log(self, report_operation=None):

        if report_operation is not None:
            LOG.error("Failed to revert backup from {}.\n"
                      "The following applications were left in an undeterminate state:".
                      format(report_operation))

            self._log_applications_not_reverted(constants.BACKUP_ACTION_PRE_ETCD_BACKUP)
            self._log_applications_not_reverted(constants.BACKUP_ACTION_PRE_BACKUP)

        actions_list = list(self._backup_action_map.keys())
        self._backup_actions_log = dict(zip(actions_list, [OrderedDict()] * len(actions_list)))

    def _revert_backup_operation(self, operation):
        if operation not in self._backup_actions_log:
            raise exception.BackupRestoreInvalidRevertOperation(operation=operation)
        current_app = None
        completed_apps = []
        operation_log = self._backup_actions_log[operation]
        for app_name, callback in operation_log.items():
            current_app = app_name
            LOG.info("Reverting backup of app {} : {}".format(current_app, operation))
            try:
                callback()
            except Exception as ex:
                # we must swallow any exceptions and keep reverting all apps:
                LOG.exception("Unhandled exception {} from app {} while reverting backup.".
                              format(str(ex), current_app))
                continue
            completed_apps.append(current_app)
        # remove all apps that had their callback() finish successfully:
        for app in completed_apps:
            del operation_log[app]

    def _make_backup_hook_info(self, operation, success):
        try:
            hook_parameters = constants.HOOK_PARAMETERS_MAP[operation]
            hook_info = LifecycleHookInfo()
            hook_info.init(*hook_parameters)
            hook_info.extra[constants.BACKUP_ACTION_NOTIFY_SUCCESS] = success
            return hook_info
        except KeyError:
            LOG.error("Unexpected action '{}' (success={})".format(operation, success))
            raise
        except Exception as ex:
            LOG.exception("Failed to create a backup/restore hook for operation '{}': {}".
                          format(operation, ex))
            raise

    def _get_kube_apps_list(self, context):
        try:
            return [kubeapp_obj.get_by_name(context, k.name) for k in self.dbapi.kube_app_get_all()]
        except Exception as ex:
            LOG.exception("Failed to to get list of kube applications: {}".format(ex))
            raise

    def _do_backup_semantic_check(self, context, success):
        hook_info = self._make_backup_hook_info(constants.BACKUP_ACTION_SEMANTIC_CHECK, success)
        try:
            for app in self._get_kube_apps_list(context):
                self._app.app_lifecycle_actions(context, self, app, deepcopy(hook_info))
        except Exception as ex:
            app_name = app.name if app is not None else None
            raise exception.ApplicationLifecycleNotificationException(app_name, str(ex))

    def _do_pre_action(self, context, operation, revert_operation, success,
                       continue_on_exception=False):
        hook_info = self._make_backup_hook_info(operation, success)
        revert_hook_info = self._make_backup_hook_info(revert_operation,
                                                       constants.BACKUP_ACTION_NOTIFY_FAILURE)

        operation_log = self._backup_actions_log[operation]
        try:
            for app in self._get_kube_apps_list(context):
                # log the 'revert' operation for this app so we can call it in case something fails:
                operation_log[app.name] = lambda app=app: \
                            self._app.app_lifecycle_actions(context, self, app,
                                                            deepcopy(revert_hook_info))

                try:
                    self._app.app_lifecycle_actions(context, self, app, deepcopy(hook_info))
                except Exception as ex:
                    if continue_on_exception:
                        LOG.exception("Application {} raised '{}', ignoring.".
                                      format(app.name, str(ex)))
                        continue
                    else:
                        raise
        except Exception as ex:
            # we always revert in the correct order for the backup state machine:
            self._revert_backup_operation(constants.BACKUP_ACTION_PRE_ETCD_BACKUP)
            self._revert_backup_operation(constants.BACKUP_ACTION_PRE_BACKUP)
            # report error and clean all pending reverts
            self._initialize_backup_actions_log(operation)
            app_name = app.name if app is not None else None
            raise exception.ApplicationLifecycleNotificationException(app_name, str(ex))

    def _do_post_action(self, context, operation, success,
                        remove_revert_operations=None):  # noqa 0102
        hook_info = self._make_backup_hook_info(operation, success)

        try:
            for app in self._get_kube_apps_list(context):
                self._app.app_lifecycle_actions(context, self, app, deepcopy(hook_info))
            # if we notified all apps successfully of this POST action, then we need to
            # remove any 'revert' actions from its associated PRE action:
            for op in remove_revert_operations if remove_revert_operations is not None else []:
                self._backup_actions_log[op] = OrderedDict()
        except Exception as ex:
            app_name = app.name if app is not None else None
            raise exception.ApplicationLifecycleNotificationException(app_name, str(ex))

    def _do_pre_backup_action(self, context, success):
        operation = constants.BACKUP_ACTION_PRE_BACKUP
        revert_operation = constants.BACKUP_ACTION_POST_BACKUP
        self._do_pre_action(context, operation, revert_operation, success)

    def _do_post_backup_action(self, context, success):
        operation = constants.BACKUP_ACTION_POST_BACKUP
        self._do_post_action(context=context,
                             operation=operation,
                             success=success,
                             remove_revert_operations=[constants.BACKUP_ACTION_PRE_BACKUP])

    def _do_pre_etcd_backup_action(self, context, success):
        operation = constants.BACKUP_ACTION_PRE_ETCD_BACKUP
        revert_operation = constants.BACKUP_ACTION_POST_ETCD_BACKUP
        self._do_pre_action(context, operation, revert_operation, success)

    def _do_post_etcd_backup_action(self, context, success):
        operation = constants.BACKUP_ACTION_POST_ETCD_BACKUP
        self._do_post_action(context=context,
                             operation=operation,
                             success=success,
                             remove_revert_operations=[constants.BACKUP_ACTION_PRE_ETCD_BACKUP])

    def _do_pre_restore_action(self, context, success):
        operation = constants.BACKUP_ACTION_PRE_RESTORE
        raise NotImplementedError("{} action not implemented.".format(operation))

    def _do_post_restore_action(self, context, success):
        operation = constants.BACKUP_ACTION_POST_RESTORE
        hook_info = self._make_backup_hook_info(operation, success)

        for app in self._get_kube_apps_list(context):
            try:
                self._app.app_lifecycle_actions(context, self, app, deepcopy(hook_info))
            except Exception as ex:
                LOG.exception("Application {} raised '{}' during {}, ignoring.".
                              format(app.name, str(ex), operation))
                app.status = constants.APP_APPLY_FAILURE
                app.save()
                continue

    def backup_restore_lifecycle_actions(self, context, operation, success):
        """Perform any lifecycle actions for backup and restore operations.
        :param context: request context
        :param operation: operation we are notified about
        :param success: true if the operation was successful, false if it fails.
                        used in post-*-action to indicate that an operation in progress failed.
        """

        # TODO (agrosu): if this blocks for too long, it might trigger a RPC timeout.
        #                maybe parallelize the calls to pre/post hooks.
        try:
            self._backup_action_map[operation](context, success)
            return (True, None)
        except exception.ApplicationLifecycleNotificationException as ex:
            LOG.exception(ex)
            return (False, ex.application_name)
        except Exception as ex:
            LOG.exception(ex)
            return (False, None)

    def perform_app_upload(self, context, rpc_app, tarfile,
                           lifecycle_hook_info_app_upload, images=False):
        """Handling of application upload request (via AppOperator)

        :param context: request context.
        :param rpc_app: data object provided in the rpc request
        :param tarfile: location of the application tarfile to be exracted
        :param lifecycle_hook_info_app_upload: LifecycleHookInfo object
        :param images: save application images in the registry as part of app upload

        """
        lifecycle_hook_info_app_upload.operation = constants.APP_UPLOAD_OP

        self._app.perform_app_upload(rpc_app, tarfile, lifecycle_hook_info_app_upload, images)
        self._app.load_application_metadata_from_file(rpc_app)

        # Perform post upload operation actions
        try:
            lifecycle_hook_info_app_upload.lifecycle_type = constants.APP_LIFECYCLE_TYPE_OPERATION
            lifecycle_hook_info_app_upload.relative_timing = constants.APP_LIFECYCLE_TIMING_POST
            self.app_lifecycle_actions(context, rpc_app,
                                       lifecycle_hook_info_app_upload)
        except Exception as e:
            LOG.error("Error performing app_lifecycle_actions %s" % str(e))

    def perform_app_apply(self, context, rpc_app, mode, lifecycle_hook_info_app_apply):
        """Handling of application install request (via AppOperator)

        :param context: request context.
        :param rpc_app: data object provided in the rpc request
        :param mode: mode to control how to apply application manifest
        :param lifecycle_hook_info_app_apply: LifecycleHookInfo object

        """
        lifecycle_hook_info_app_apply.operation = constants.APP_APPLY_OP

        # Perform pre apply operation actions
        try:
            lifecycle_hook_info_app_apply.lifecycle_type = constants.APP_LIFECYCLE_TYPE_OPERATION
            lifecycle_hook_info_app_apply.relative_timing = constants.APP_LIFECYCLE_TIMING_PRE
            self.app_lifecycle_actions(context, rpc_app,
                                       lifecycle_hook_info_app_apply)
        except Exception as e:
            LOG.error("Error performing app_lifecycle_actions %s" % str(e))

        # TODO pass context and move hooks inside?
        app_applied = self._app.perform_app_apply(rpc_app, mode, lifecycle_hook_info_app_apply)
        lifecycle_hook_info_app_apply[LifecycleConstants.EXTRA][LifecycleConstants.APP_APPLIED] = app_applied

        # Perform post apply operation actions
        try:
            lifecycle_hook_info_app_apply.lifecycle_type = constants.APP_LIFECYCLE_TYPE_OPERATION
            lifecycle_hook_info_app_apply.relative_timing = constants.APP_LIFECYCLE_TIMING_POST
            self.app_lifecycle_actions(context, rpc_app,
                                       lifecycle_hook_info_app_apply)
        except Exception as e:
            LOG.error("Error performing app_lifecycle_actions %s" % str(e))

        return app_applied

    def perform_app_update(self, context, from_rpc_app, to_rpc_app, tarfile,
                           operation, lifecycle_hook_info_app_update, reuse_user_overrides=None,
                           reuse_attributes=None):
        """Handling of application update request (via AppOperator)

        :param context: request context.
        :param from_rpc_app: data object provided in the rpc request that
                             application update from
        :param to_rpc_app: data object provided in the rpc request that
                           application update to
        :param tarfile: location of the application tarfile to be extracted
        :param operation: apply or rollback
        :param lifecycle_hook_info_app_update: LifecycleHookInfo object
        :param reuse_user_overrides: (optional) True or False
        :param reuse_attributes: (optional) True or False

        """
        lifecycle_hook_info_app_update.operation = constants.APP_UPDATE_OP

        self._app.perform_app_update(from_rpc_app, to_rpc_app, tarfile,
                                     operation, lifecycle_hook_info_app_update, reuse_user_overrides,
                                     reuse_attributes)

    def perform_app_remove(self, context, rpc_app, lifecycle_hook_info_app_remove, force=False):
        """Handling of application removal request (via AppOperator)

        :param context: request context.
        :param rpc_app: data object provided in the rpc request
        :param lifecycle_hook_info_app_remove: LifecycleHookInfo object
        :param force: If set to True, will set the app state to 'uploaded'
            instead of 'remove-failed' in case of an error

        """
        lifecycle_hook_info_app_remove.operation = constants.APP_REMOVE_OP

        # deactivate the app
        self._app.deactivate(rpc_app)

        # Perform pre remove operation actions
        try:
            lifecycle_hook_info_app_remove.relative_timing = constants.APP_LIFECYCLE_TIMING_PRE
            lifecycle_hook_info_app_remove.lifecycle_type = constants.APP_LIFECYCLE_TYPE_OPERATION
            self.app_lifecycle_actions(context, rpc_app,
                                       lifecycle_hook_info_app_remove)
        except Exception as e:
            LOG.error("Error performing app_lifecycle_actions %s" % str(e))

        app_removed = self._app.perform_app_remove(
            rpc_app, lifecycle_hook_info_app_remove, force)
        lifecycle_hook_info_app_remove[LifecycleConstants.EXTRA][LifecycleConstants.APP_REMOVED] = app_removed

        # Perform post remove operation actions
        try:
            lifecycle_hook_info_app_remove.relative_timing = constants.APP_LIFECYCLE_TIMING_POST
            lifecycle_hook_info_app_remove.lifecycle_type = constants.APP_LIFECYCLE_TYPE_OPERATION
            self.app_lifecycle_actions(context, rpc_app,
                                       lifecycle_hook_info_app_remove)
        except Exception as e:
            LOG.error("Error performing app_lifecycle_actions %s" % str(e))

        return app_removed

    def perform_app_abort(self, context, rpc_app, lifecycle_hook_info_app_abort):
        """Handling of application abort request (via AppOperator)

        :param context: request context.
        :param rpc_app: data object provided in the rpc request
        :param lifecycle_hook_info_app_abort: LifecycleHookInfo object

        """
        lifecycle_hook_info_app_abort.operation = constants.APP_ABORT_OP

        return self._app.perform_app_abort(rpc_app, lifecycle_hook_info_app_abort)

    def perform_app_delete(self, context, rpc_app, lifecycle_hook_info_app_delete):
        """Handling of application delete request (via AppOperator)

        :param context: request context.
        :param rpc_app: data object provided in the rpc request
        :param lifecycle_hook_info_app_delete: LifecycleHookInfo object

        """
        lifecycle_hook_info_app_delete.operation = constants.APP_DELETE_OP

        # Perform pre delete operation actions
        try:
            lifecycle_hook_info_app_delete.relative_timing = constants.APP_LIFECYCLE_TIMING_PRE
            lifecycle_hook_info_app_delete.lifecycle_type = constants.APP_LIFECYCLE_TYPE_OPERATION
            self.app_lifecycle_actions(context, rpc_app,
                                       lifecycle_hook_info_app_delete)
        except Exception as e:
            LOG.error("Error performing app_lifecycle_actions %s" % str(e))

        return self._app.perform_app_delete(rpc_app, lifecycle_hook_info_app_delete)

    def reconfigure_service_endpoints(self, context, host):
        """Reconfigure the service endpoints upon the creation of initial
        controller host and management/oam network change during bootstrap
        playbook play and replay.

        :param context: request context.
        :param host: an ihost object

        """
        if (os.path.isfile(constants.ANSIBLE_BOOTSTRAP_FLAG) and
                host.hostname == constants.CONTROLLER_0_HOSTNAME):

            inventory_completed = True

            # This could be called as part of host creation, wait for
            # inventory to complete
            for i in range(constants.INVENTORY_WAIT_TIMEOUT_IN_SECS):
                if cutils.is_inventory_config_complete(self.dbapi, host.uuid):
                    break
                LOG.info('Inventory incomplete, will try again in 1 second.')
                greenthread.sleep(1)
            else:
                inventory_completed = False

            if inventory_completed:
                controller_0_address = self.dbapi.address_get_by_name(
                    constants.CONTROLLER_0_MGMT)
                if controller_0_address.address != host.mgmt_ip:
                    self.dbapi.ihost_update(
                        host.uuid, {'mgmt_ip': controller_0_address.address})

                personalities = [constants.CONTROLLER]
                config_uuid = self._config_update_hosts(context, personalities)
                config_dict = {
                    "personalities": personalities,
                    "host_uuids": [host.uuid],
                    "classes": ['openstack::keystone::endpoint::runtime',
                                'openstack::barbican::runtime']
                }
                self._config_apply_runtime_manifest(
                    context, config_uuid, config_dict, force=True)
            else:
                LOG.error("Unable to reconfigure service endpoints. Timed out "
                          "waiting for inventory to complete.")
        else:
            LOG.error("Received a request to reconfigure service endpoints "
                      "for host %s under the wrong condition." % host.hostname)

    def mgmt_mac_set_by_ihost(self, context, host, mgmt_mac):
        """Update the management mac address upon management interface
        during bootstrap.

        :param context: request context
        :param host: an ihost object
        :param mgmt_mac: mac address of management interface
        """
        if (os.path.isfile(constants.ANSIBLE_BOOTSTRAP_FLAG) and
                host.hostname == constants.CONTROLLER_0_HOSTNAME):

            self.dbapi.ihost_update(host.uuid,
                                    {'mgmt_mac': mgmt_mac})
        else:
            LOG.error("Received a request to update management mac for host "
                      "%s under the wrong condition." % host.hostname)

    def configure_system_controller(self, context, host):
        """Configure the system controller database and file system upon the
        creation of initial controller host and distributed_cloud_role change
        from 'none' to 'systemcontroller' during bootstrap playbook play and
        replay.

        :param context: request context.
        :param host: an ihost object

        """
        if (os.path.isfile(constants.ANSIBLE_BOOTSTRAP_FLAG) and
                host.hostname == constants.CONTROLLER_0_HOSTNAME):

            inventory_completed = True

            # This could be called as part of host creation, wait for
            # inventory to complete
            for i in range(constants.INVENTORY_WAIT_TIMEOUT_IN_SECS):
                if cutils.is_inventory_config_complete(self.dbapi, host.uuid):
                    break
                LOG.info('Inventory incomplete, will try again in 1 second.')
                greenthread.sleep(1)
            else:
                inventory_completed = False

            if inventory_completed:
                personalities = [constants.CONTROLLER]
                config_uuid = self._config_update_hosts(context, personalities)
                config_dict = {
                    "personalities": personalities,
                    "host_uuids": [host.uuid],
                    "classes": ['platform::postgresql::sc::runtime',
                                'platform::dcmanager::fs::runtime']
                }
                self._config_apply_runtime_manifest(
                    context, config_uuid, config_dict, force=True)
            else:
                LOG.error("Unable to configure the sc database or file system. "
                          "Timed out waiting for inventory to complete.")
        else:
            LOG.error("Received a request to configure the sc database and "
                      "filesystem for host %s under the wrong condition."
                      % host.hostname)

    def store_default_config(self, context):
        """ copy sysinv.conf to drbd storage """
        try:
            os.makedirs(constants.SYSINV_CONFIG_PATH)
        except OSError as oe:
            if (oe.errno != errno.EEXIST or
                    not os.path.isdir(constants.SYSINV_CONFIG_PATH)):
                LOG.error("Failed to create dir %s" % constants.SYSINV_CONFIG_PATH)
                raise

        shutil.copyfile(constants.SYSINV_CONFIG_FILE_LOCAL,
                        constants.SYSINV_CONF_DEFAULT_PATH)
        LOG.info("copied %s to %s" % (constants.SYSINV_CONFIG_FILE_LOCAL,
                                      constants.SYSINV_CONF_DEFAULT_PATH))

        os.chmod(constants.SYSINV_CONF_DEFAULT_PATH, 0o400)

    def _kube_upgrade_init_actions(self):
        """ Perform any kubernetes upgrade related startup actions"""
        try:
            kube_upgrade = self.dbapi.kube_upgrade_get_one()
        except exception.NotFound:
            # Not upgrading kubernetes
            return

        # Fail any upgrade operation that is in a transitory state. This
        # service is responsible for monitoring these operations and since
        # we were just restarted, the operation will never progress.
        fail_state = None
        if kube_upgrade.state == kubernetes.KUBE_UPGRADE_DOWNLOADING_IMAGES:
            fail_state = kubernetes.KUBE_UPGRADE_DOWNLOADING_IMAGES_FAILED
        elif kube_upgrade.state == kubernetes.KUBE_UPGRADING_FIRST_MASTER:
            fail_state = kubernetes.KUBE_UPGRADING_FIRST_MASTER_FAILED
        elif kube_upgrade.state == kubernetes.KUBE_UPGRADING_NETWORKING:
            fail_state = kubernetes.KUBE_UPGRADING_NETWORKING_FAILED
        elif kube_upgrade.state == kubernetes.KUBE_UPGRADING_SECOND_MASTER:
            fail_state = kubernetes.KUBE_UPGRADING_SECOND_MASTER_FAILED

        if fail_state is not None:
            LOG.warning("Failing upgrade in %s state due to service restart" %
                        kube_upgrade.state)
            self.dbapi.kube_upgrade_update(kube_upgrade.id,
                                           {'state': fail_state})

        # Fail any host upgrade operation that is in a transitory state.
        kube_host_upgrades = self.dbapi.kube_host_upgrade_get_list()
        for kube_host_upgrade in kube_host_upgrades:
            fail_status = None
            if kube_host_upgrade.status == \
                    kubernetes.KUBE_HOST_UPGRADING_CONTROL_PLANE:
                fail_status = \
                    kubernetes.KUBE_HOST_UPGRADING_CONTROL_PLANE_FAILED
            elif kube_host_upgrade.status == \
                    kubernetes.KUBE_HOST_UPGRADING_KUBELET:
                fail_status = kubernetes.KUBE_HOST_UPGRADING_KUBELET_FAILED

            if fail_status is not None:
                LOG.warning("Failing host upgrade with %s status due to "
                            "service restart" % kube_host_upgrade.status)
                self.dbapi.kube_host_upgrade_update(kube_host_upgrade.id,
                                                    {'status': fail_status})

    def kube_download_images(self, context, kube_version):
        """Download the kubernetes images for this version"""

        kube_operator = kubernetes.KubeOperator()
        kube_upgrade_obj = objects.kube_upgrade.get_one(context)
        system = self.dbapi.isystem_get_one()
        if system.system_mode == constants.SYSTEM_MODE_SIMPLEX:
            next_versions = kube_operator.kube_get_higher_patch_version(kube_upgrade_obj.from_version,
                                                                        kube_version)
        else:
            next_versions = [kube_version]

        for k8s_version in next_versions:
            LOG.info("executing playbook: %s for version %s" %
                (constants.ANSIBLE_KUBE_PUSH_IMAGES_PLAYBOOK, k8s_version))
            # Execute the playbook to download the images from the external
            # registry to registry.local.
            playbook_cmd = ['ansible-playbook', '-e', 'kubernetes_version=%s' % k8s_version,
                            constants.ANSIBLE_KUBE_PUSH_IMAGES_PLAYBOOK]
            returncode = cutils.run_playbook(playbook_cmd)

            if returncode:
                LOG.warning("ansible-playbook returned an error: %s" %
                            returncode)
                # Update the upgrade state
                kube_upgrade_obj = objects.kube_upgrade.get_one(context)
                kube_upgrade_obj.state = \
                    kubernetes.KUBE_UPGRADE_DOWNLOADING_IMAGES_FAILED
                kube_upgrade_obj.save()
                return

        if system.system_mode == constants.SYSTEM_MODE_DUPLEX:
            # Update the config for the controller host(s)
            personalities = [constants.CONTROLLER]
            config_uuid = self._config_update_hosts(context, personalities)

            # Apply the runtime manifest to have docker download the images on
            # each controller.
            config_dict = {
                "personalities": personalities,
                "classes": 'platform::kubernetes::pre_pull_control_plane_images'
            }
            self._config_apply_runtime_manifest(context, config_uuid, config_dict)

            # Wait for the manifest(s) to be applied
            elapsed = 0
            while elapsed < kubernetes.MANIFEST_APPLY_TIMEOUT:
                elapsed += kubernetes.MANIFEST_APPLY_INTERVAL
                greenthread.sleep(kubernetes.MANIFEST_APPLY_INTERVAL)
                controller_hosts = self.dbapi.ihost_get_by_personality(
                    constants.CONTROLLER)
                for host_obj in controller_hosts:
                    if host_obj.config_target != host_obj.config_applied:
                        # At least one controller has not been updated yet
                        LOG.debug("Waiting for config apply on host %s" %
                                host_obj.hostname)
                        break
                else:
                    LOG.info("Config was applied for all controller hosts")
                    break
            else:
                LOG.warning("Manifest apply failed for a controller host")
                kube_upgrade_obj = objects.kube_upgrade.get_one(context)
                kube_upgrade_obj.state = \
                    kubernetes.KUBE_UPGRADE_DOWNLOADING_IMAGES_FAILED
                kube_upgrade_obj.save()
                return

        # Update the upgrade state
        kube_upgrade_obj = objects.kube_upgrade.get_one(context)
        kube_upgrade_obj.state = kubernetes.KUBE_UPGRADE_DOWNLOADED_IMAGES
        kube_upgrade_obj.save()

    def kube_upgrade_control_plane(self, context, host_uuid):
        """Upgrade the kubernetes control plane on this host"""

        host_obj = objects.host.get_by_uuid(context, host_uuid)
        host_name = host_obj.hostname
        kube_host_upgrade_obj = objects.kube_host_upgrade.get_by_host_id(
            context, host_obj.id)
        target_version = kube_host_upgrade_obj.target_version
        kube_upgrade_obj = objects.kube_upgrade.get_one(context)

        if kube_upgrade_obj.state == kubernetes.KUBE_UPGRADING_FIRST_MASTER:
            puppet_class = 'platform::kubernetes::upgrade_first_control_plane'
            new_state = kubernetes.KUBE_UPGRADED_FIRST_MASTER
            fail_state = kubernetes.KUBE_UPGRADING_FIRST_MASTER_FAILED

            # Drop any removed/unsupported feature gates before we upgrade to a
            # newer Kubernetes.  If we leave them in we can prevent K8s services
            # from starting up.  If we hit any problems we'll still try and
            # convert what we can.
            rc = 0

            # The bootstrap config file is used by backup/restore.
            if self.sanitize_feature_gates_bootstrap_config_file(target_version) == 1:
                LOG.error("Problem sanitizing bootstrap config file.")
                rc = 1

            # The service parameters are used by backup/restore and the custom
            # K8s configuration functionality.
            if self.sanitize_feature_gates_service_parameters(target_version) == 1:
                LOG.error("Problem sanitizing feature gates service parameter.")
                rc = 1

            if self.sanitize_feature_gates_kubeadm_configmap(target_version) == 1:
                LOG.error("Problem sanitizing kubeadm configmap feature gates.")
                rc = 1

            if self.sanitize_image_repository_kubeadm_configmap(target_version) == 1:
                LOG.error("Problem updating kubeadm configmap image repository.")
                rc = 1

            # The kubelet configmap is used by the K8s upgrade itself.
            if self.sanitize_feature_gates_kubelet_configmap(target_version) == 1:
                LOG.error("Problem sanitizing kubelet configmap feature gates.")
                rc = 1

            if rc == 1:
                kube_upgrade_obj.state = fail_state
                kube_upgrade_obj.save()
                return

        elif kube_upgrade_obj.state == kubernetes.KUBE_UPGRADING_SECOND_MASTER:
            puppet_class = 'platform::kubernetes::upgrade_control_plane'
            new_state = kubernetes.KUBE_UPGRADED_SECOND_MASTER
            fail_state = kubernetes.KUBE_UPGRADING_SECOND_MASTER_FAILED
        else:
            raise exception.SysinvException(_(
                "Invalid state %s to upgrade control plane." %
                kube_upgrade_obj.state))

        # Update the config for this host
        personalities = [host_obj.personality]
        config_uuid = self._config_update_hosts(context, personalities,
            [host_uuid])

        # Apply the runtime manifest to upgrade the control plane
        config_dict = {
            "personalities": personalities,
            "host_uuids": [host_uuid],
            "classes": [puppet_class]
        }
        self._config_apply_runtime_manifest(context, config_uuid, config_dict)

        # Wait for the manifest to be applied
        elapsed = 0
        while elapsed < kubernetes.MANIFEST_APPLY_TIMEOUT:
            elapsed += kubernetes.MANIFEST_APPLY_INTERVAL
            greenthread.sleep(kubernetes.MANIFEST_APPLY_INTERVAL)
            host_obj = objects.host.get_by_uuid(context, host_uuid)
            if host_obj.config_target == host_obj.config_applied:
                LOG.info("Config was applied for host %s" % host_name)
                break
            LOG.debug("Waiting for config apply on host %s" % host_name)
        else:
            LOG.warning("Manifest apply failed for host %s" % host_name)
            kube_host_upgrade_obj = objects.kube_host_upgrade.get_by_host_id(
                context, host_obj.id)
            kube_host_upgrade_obj.status = \
                kubernetes.KUBE_HOST_UPGRADING_CONTROL_PLANE_FAILED
            kube_host_upgrade_obj.save()
            kube_upgrade_obj = objects.kube_upgrade.get_one(context)
            kube_upgrade_obj.state = fail_state
            kube_upgrade_obj.save()
            return

        # Wait for the control plane pods to start with the new version
        kube_operator = kubernetes.KubeOperator()
        elapsed = 0
        while elapsed < kubernetes.POD_START_TIMEOUT:
            elapsed += kubernetes.POD_START_INTERVAL
            greenthread.sleep(kubernetes.POD_START_INTERVAL)
            cp_versions = kube_operator.kube_get_control_plane_versions()
            if cp_versions.get(host_name, None) == target_version:
                LOG.info("Control plane was updated for host %s" % host_name)
                break
            LOG.debug("Waiting for control plane update on host %s" % host_name)
        else:
            LOG.warning("Control plane upgrade failed for host %s" %
                        host_name)
            kube_host_upgrade_obj = objects.kube_host_upgrade.get_by_host_id(
                context, host_obj.id)
            kube_host_upgrade_obj.status = \
                kubernetes.KUBE_HOST_UPGRADING_CONTROL_PLANE_FAILED
            kube_host_upgrade_obj.save()
            kube_upgrade_obj = objects.kube_upgrade.get_one(context)
            kube_upgrade_obj.state = fail_state
            kube_upgrade_obj.save()
            return

        # The control plane update was successful
        kube_host_upgrade_obj = objects.kube_host_upgrade.get_by_host_id(
            context, host_obj.id)
        kube_host_upgrade_obj.status = None
        kube_host_upgrade_obj.save()
        kube_upgrade_obj = objects.kube_upgrade.get_one(context)
        kube_upgrade_obj.state = new_state
        kube_upgrade_obj.save()

    def kube_upgrade_kubelet(self, context, host_uuid):
        """Upgrade the kubernetes kubelet on this host"""

        host_obj = objects.host.get_by_uuid(context, host_uuid)
        host_name = host_obj.hostname
        kube_host_upgrade_obj = objects.kube_host_upgrade.get_by_host_id(
            context, host_obj.id)
        target_version = kube_host_upgrade_obj.target_version

        if host_obj.personality == constants.CONTROLLER:
            puppet_class = 'platform::kubernetes::master::upgrade_kubelet'
        elif host_obj.personality == constants.WORKER:
            puppet_class = 'platform::kubernetes::worker::upgrade_kubelet'
        else:
            raise exception.SysinvException(_(
                "Invalid personality %s to upgrade kubelet." %
                host_obj.personality))

        # Update the config for this host
        personalities = [host_obj.personality]
        config_uuid = self._config_update_hosts(context, personalities,
            [host_uuid])

        # Apply the runtime manifest to upgrade the kubelet
        config_dict = {
            "personalities": personalities,
            "host_uuids": [host_uuid],
            "classes": [puppet_class]
        }
        self._config_apply_runtime_manifest(context, config_uuid, config_dict)

        # Wait for the manifest to be applied
        LOG.debug("Waiting for config apply on host %s" % host_name)
        starttime = datetime.utcnow()
        while ((datetime.utcnow() - starttime).total_seconds() <
                kubernetes.MANIFEST_APPLY_TIMEOUT):
            greenthread.sleep(kubernetes.MANIFEST_APPLY_INTERVAL)
            try:
                host_obj = objects.host.get_by_uuid(context, host_uuid)
                if host_obj.config_target == host_obj.config_applied:
                    LOG.info("Config was applied for host %s" % host_name)
                    break
            except Exception:
                LOG.exception("Problem getting host info.")
            LOG.debug("Waiting for config apply on host %s" % host_name)
        else:
            LOG.warning("Manifest apply failed for host %s" % host_name)
            kube_host_upgrade_obj = objects.kube_host_upgrade.get_by_host_id(
                context, host_obj.id)
            kube_host_upgrade_obj.status = \
                kubernetes.KUBE_HOST_UPGRADING_KUBELET_FAILED
            kube_host_upgrade_obj.save()
            return

        # Wait for the kubelet to start with the new version
        kube_operator = kubernetes.KubeOperator()
        LOG.debug("Waiting for kubelet update on host %s" % host_name)
        starttime = datetime.utcnow()
        while ((datetime.utcnow() - starttime).total_seconds() <
                kubernetes.POD_START_TIMEOUT):
            greenthread.sleep(kubernetes.POD_START_INTERVAL)
            try:
                # If we can't talk to the Kubernetes API we still want to
                # hit the else clause below on timeout.
                kubelet_versions = kube_operator.kube_get_kubelet_versions()
                if kubelet_versions.get(host_name, None) == target_version:
                    LOG.info("Kubelet was updated for host %s" % host_name)
                    break
            except Exception:
                LOG.exception("Problem getting kubelet versions.")
            LOG.debug("Waiting for kubelet update on host %s" % host_name)
        else:
            LOG.warning("Kubelet upgrade failed for host %s" % host_name)
            kube_host_upgrade_obj = objects.kube_host_upgrade.get_by_host_id(
                context, host_obj.id)
            kube_host_upgrade_obj.status = \
                kubernetes.KUBE_HOST_UPGRADING_KUBELET_FAILED
            kube_host_upgrade_obj.save()
            return

        # The kubelet update was successful
        kube_host_upgrade_obj = objects.kube_host_upgrade.get_by_host_id(
            context, host_obj.id)
        kube_host_upgrade_obj.status = kubernetes.KUBE_HOST_UPGRADED_KUBELET
        kube_host_upgrade_obj.save()

    def kube_upgrade_networking(self, context, kube_version):
        """Upgrade kubernetes networking for this kubernetes version"""

        LOG.info("executing playbook: %s for version %s" %
                 (constants.ANSIBLE_KUBE_NETWORKING_PLAYBOOK, kube_version))

        playbook_cmd = ['ansible-playbook', '-e', 'kubernetes_version=%s' % kube_version,
                        constants.ANSIBLE_KUBE_NETWORKING_PLAYBOOK]
        returncode = cutils.run_playbook(playbook_cmd)

        if returncode:
            LOG.warning("ansible-playbook returned an error: %s" %
                        returncode)
            # Update the upgrade state
            kube_upgrade_obj = objects.kube_upgrade.get_one(context)
            kube_upgrade_obj.state = \
                kubernetes.KUBE_UPGRADING_NETWORKING_FAILED
            kube_upgrade_obj.save()
            return

        # Indicate that networking upgrade is complete
        kube_upgrade_obj = objects.kube_upgrade.get_one(context)
        kube_upgrade_obj.state = kubernetes.KUBE_UPGRADED_NETWORKING
        kube_upgrade_obj.save()

    def store_bitstream_file(self, context, filename):
        """Store FPGA bitstream file """
        image_file_path = os.path.join(dconstants.DEVICE_IMAGE_PATH, filename)
        image_tmp_path = os.path.join(dconstants.DEVICE_IMAGE_TMP_PATH, filename)
        try:
            os.makedirs(dconstants.DEVICE_IMAGE_PATH)
        except OSError as oe:
            if (oe.errno != errno.EEXIST or
                    not os.path.isdir(dconstants.DEVICE_IMAGE_PATH)):
                LOG.error("Failed to create dir %s" % dconstants.DEVICE_IMAGE_PATH)
                raise
        shutil.copyfile(image_tmp_path, image_file_path)
        LOG.info("copied %s to %s" % (image_tmp_path, image_file_path))
        os.remove(image_tmp_path)

    def delete_bitstream_file(self, context, filename):
        """Delete FPGA bitstream file"""
        image_file_path = os.path.join(dconstants.DEVICE_IMAGE_PATH, filename)
        try:
            os.remove(image_file_path)
        except OSError:
            LOG.exception("Failed to delete bitstream file %s" % image_file_path)
        # If no device image is uploaded, clear the in-progress alarm.
        images = self.dbapi.deviceimages_get_all()
        if not images:
            system_uuid = self.dbapi.isystem_get_one().uuid
            entity_instance_id = "%s=%s" % (fm_constants.FM_ENTITY_TYPE_SYSTEM, system_uuid)
            self.fm_api.clear_fault(fm_constants.FM_ALARM_ID_DEVICE_IMAGE_UPDATE_IN_PROGRESS,
                                    entity_instance_id)

    def apply_device_image(self, context):
        """Apply device image"""
        # Raise device image update alarm if not already exists
        alarm_id = fm_constants.FM_ALARM_ID_DEVICE_IMAGE_UPDATE_IN_PROGRESS
        system_uuid = self.dbapi.isystem_get_one().uuid
        entity_instance_id = "%s=%s" % (fm_constants.FM_ENTITY_TYPE_SYSTEM, system_uuid)
        if not self.fm_api.get_fault(alarm_id, entity_instance_id):
            fault = fm_api.Fault(
                alarm_id=alarm_id,
                alarm_state=fm_constants.FM_ALARM_STATE_SET,
                entity_type_id=fm_constants.FM_ENTITY_TYPE_SYSTEM,
                entity_instance_id=entity_instance_id,
                severity=fm_constants.FM_ALARM_SEVERITY_MINOR,
                reason_text="Device image update operation in progress ",
                alarm_type=fm_constants.FM_ALARM_TYPE_5,
                probable_cause=fm_constants.ALARM_PROBABLE_CAUSE_65,
                proposed_repair_action="Complete reboots of affected hosts",
                suppression=False,
                service_affecting=False)
            self.fm_api.set_fault(fault)

    def clear_device_image_alarm(self, context):
        self._clear_device_image_alarm(context)

    def host_device_image_update_next(self, context, host_uuid):
        # Find the first device on this host that needs updating,
        # and trigger an update of it.
        try:
            host = self.dbapi.ihost_get(host_uuid)
        except exception.ServerNotFound:
            # This really shouldn't happen.
            LOG.exception("Unable to update device images, invalid host_uuid %s" % host_uuid)
            return

        device_image_states = self.dbapi.device_image_state_get_all(
            host_id=host.id,
            status=dconstants.DEVICE_IMAGE_UPDATE_PENDING)

        # At this point we expect host.device_image_update to be either
        # "in-progress" or "in-progress-aborted".
        # If we've aborted the device update operation and there are device
        # image updates left to do on this host, then set the host status
        # back to "pending" and return.  If there are no device image updates
        # left, then fall through to setting the host status to null below.
        if (host.device_image_update == dconstants.DEVICE_IMAGE_UPDATE_IN_PROGRESS_ABORTED and
                device_image_states):
            host.device_image_update = dconstants.DEVICE_IMAGE_UPDATE_PENDING
            host.save(context)
            return

        # TODO: the code below needs to be updated to order the device images
        # for a given device to handle simultaneous update of multiple devices.
        # For the N3000 we want to apply any root-key image first, then
        # any key-revocation images, then any functional images.

        for device_image_state in sorted(device_image_states,
                                         key=device_image_state_sort_key):
            # get the PCI device for the pending device image update
            pci_device = objects.pci_device.get_by_uuid(context, device_image_state.pcidevice_id)
            # figure out the filename for the device image
            device_image = objects.device_image.get_by_uuid(context, device_image_state.image_id)
            filename = cutils.format_image_filename(device_image)
            LOG.info("sending rpc req to update image for host %s, pciaddr: %s, filename: %s, id: %s" %
                     (host.hostname, pci_device.pciaddr, filename, device_image_state.id))
            fpga_rpcapi = agent_rpcapi.AgentAPI()
            fpga_rpcapi.host_device_update_image(
                context, host_uuid, host.hostname, pci_device.pciaddr, filename,
                device_image_state.id, device_image.retimer_included)
            # We've kicked off a device image update, so exit the function.
            return
        LOG.info("no more device images to process")

        # If one or more of the device image updates failed, set
        # host.device_image_update to pending because we are going to retry
        # writing them next time we run host_device_image_update().
        failed_device_image_states = self.dbapi.device_image_state_get_all(
            host_id=host.id,
            status=dconstants.DEVICE_IMAGE_UPDATE_FAILED)
        if len(failed_device_image_states) >= 1:
            host.device_image_update = dconstants.DEVICE_IMAGE_UPDATE_PENDING
        else:
            # Getting here should mean that we're done processing so we can
            # clear the "this host is currently updating device images" flag.
            host.device_image_update = dconstants.DEVICE_IMAGE_UPDATE_NULL
        host.save(context)

    def host_device_image_update(self, context, host_uuid):
        """Update any applied device images for devices on this host"""

        host = objects.host.get_by_uuid(context, host_uuid)
        LOG.info("Updating device image on %s" % host.hostname)

        # Set any previously "failed" updates back to "pending" to retry them.
        device_image_states = self.dbapi.device_image_state_get_all(
            host_id=host.id,
            status=dconstants.DEVICE_IMAGE_UPDATE_FAILED)
        for device_image_state in device_image_states:
            device_image_state.status = dconstants.DEVICE_IMAGE_UPDATE_PENDING
            device_image_state.update_start_time = None
            device_image_state.save(context)

        # Update the host status.
        host.device_image_update = dconstants.DEVICE_IMAGE_UPDATE_IN_PROGRESS
        host.save()

        # Find the first device on this host that needs updating,
        # and trigger an update of it.
        self.host_device_image_update_next(context, host_uuid)

    def host_device_image_update_abort(self, context, host_uuid):
        """Abort device image update on this host"""

        host = objects.host.get_by_uuid(context, host_uuid)
        LOG.info("Aborting device image update on %s" % host.hostname)

        # If the host status is currently pending or blank or already aborted
        # then just leave it as-is.
        if host.device_image_update == dconstants.DEVICE_IMAGE_UPDATE_IN_PROGRESS:
            host.device_image_update = dconstants.DEVICE_IMAGE_UPDATE_IN_PROGRESS_ABORTED
            host.save(context)

    @periodic_task.periodic_task(spacing=CONF.conductor_periodic_task_intervals.device_image_update)
    def _audit_device_image_update(self, context):
        """Check if device image update is stuck in 'in-progress'"""
        dev_img_list = self.dbapi.device_image_state_get_all(
            status=dconstants.DEVICE_IMAGE_UPDATE_IN_PROGRESS)
        for img in dev_img_list:
            if img['bitstream_type'] == dconstants.BITSTREAM_TYPE_FUNCTIONAL:
                timeout = CONF.conductor.fw_update_large_timeout
            else:
                timeout = CONF.conductor.fw_update_small_timeout
            tz = img.update_start_time.tzinfo
            if ((datetime.now(tz) - img.update_start_time).total_seconds() >=
                    timeout):
                # Mark the status as failed
                img.status = dconstants.DEVICE_IMAGE_UPDATE_FAILED
                img.save(context)
                host = objects.host.get_by_uuid(context, img.host_uuid)
                pci = objects.pci_device.get_by_uuid(context, img.pcidevice_uuid)
                LOG.error("Device image update timed out host={} "
                            "device={} image={}".format(host.hostname,
                                                        pci.pciaddr,
                                                        img.image_uuid))

    def _clear_device_image_alarm(self, context):
        # If there are no more pending, failed or in-progress device image
        # update in the DB for any host, and if no host has the "reboot needed"
        # DB entry set, then the "Device image update in progress" alarm is cleared.
        dev_img_list = self.dbapi.device_image_state_get_all(
            status=[dconstants.DEVICE_IMAGE_UPDATE_PENDING,
                    dconstants.DEVICE_IMAGE_UPDATE_FAILED,
                    dconstants.DEVICE_IMAGE_UPDATE_IN_PROGRESS])
        if not dev_img_list:
            if self.dbapi.count_hosts_matching_criteria(reboot_needed=True) > 0:
                return
            system_uuid = self.dbapi.isystem_get_one().uuid
            entity_instance_id = "%s=%s" % (fm_constants.FM_ENTITY_TYPE_SYSTEM, system_uuid)
            self.fm_api.clear_fault(fm_constants.FM_ALARM_ID_DEVICE_IMAGE_UPDATE_IN_PROGRESS,
                                    entity_instance_id)

    def fpga_device_update_by_host(self, context,
                                  host_uuid, fpga_device_dict_array):
        """Create FPGA devices for an ihost with the supplied data.

        This method allows records for FPGA devices for ihost to be created.

        :param context: an admin context
        :param host_uuid: host uuid
        :param fpga_device_dict_array: initial values for device objects
        :returns: either returns nothing or raises exception
        """
        LOG.info("Entering device_update_by_host %s %s" %
                  (host_uuid, fpga_device_dict_array))
        host_uuid.strip()
        try:
            host = self.dbapi.ihost_get(host_uuid)
        except exception.ServerNotFound:
            # This really shouldn't happen.
            LOG.exception("Invalid host_uuid %s" % host_uuid)
            return

        for fpga_dev in fpga_device_dict_array:
            LOG.info("Processing dev %s" % fpga_dev)
            try:
                dev_found = None
                try:
                    dev = self.dbapi.fpga_device_get(fpga_dev['pciaddr'],
                                                    hostid=host['id'])
                    dev_found = dev
                except Exception:
                    LOG.info("Attempting to create new device "
                             "%s on host %s" % (fpga_dev, host['id']))

                    # Look up the PCI device in the DB, we need the id.
                    try:
                        pci_dev = self.dbapi.pci_device_get(
                            fpga_dev['pciaddr'], hostid=host['id'])
                        fpga_dev['pci_id'] = pci_dev.id
                    except Exception as ex:
                        LOG.info("Unable to find pci device entry for "
                                 "address %s on host id %s, can't create "
                                 "fpga_device entry, ex: %s" %
                                 (fpga_dev['pciaddr'], host['id'], str(ex)))
                        return

                    # Save the FPGA device to the DB.
                    try:
                        dev = self.dbapi.fpga_device_create(host['id'],
                                                            fpga_dev)
                    except Exception as ex:
                        LOG.info("Unable to create fpga_device entry for "
                                 "address %s on host id %s, ex: %s" %
                                 (fpga_dev['pciaddr'], host['id'], str(ex)))
                        return

                # If the device existed already, update some of the fields
                if dev_found:
                    try:
                        attr = {
                            'bmc_build_version': fpga_dev['bmc_build_version'],
                            'bmc_fw_version': fpga_dev['bmc_fw_version'],
                            'retimer_a_version': fpga_dev.get('retimer_a_version', None),
                            'retimer_b_version': fpga_dev.get('retimer_b_version', None),
                            'root_key': fpga_dev['root_key'],
                            'revoked_key_ids': fpga_dev['revoked_key_ids'],
                            'boot_page': fpga_dev['boot_page'],
                            'bitstream_id': fpga_dev['bitstream_id'],
                        }
                        LOG.info("attr: %s" % attr)
                        dev = self.dbapi.fpga_device_update(dev['uuid'], attr)
                    except Exception as ex:
                        LOG.exception("Failed to update fpga fields for "
                                      "address %s on host id %s, ex: %s" %
                                      (dev['pciaddr'], host['id'], str(ex)))
                        pass

            except exception.NodeNotFound:
                raise exception.SysinvException(_(
                    "Invalid host_uuid: host not found: %s") %
                    host_uuid)
            except Exception:
                pass

    def device_update_image_status(self, context, host_uuid, transaction_id,
                                   status, progress=None, err=None):
        """Update the status of an image-update operation.

        This is a status update from the agent on the node regarding a
        previously-triggered firmware update operation.

        :param context: an admin context
        :param host_uuid: the uuid of the host calling this function
        :param transaction_id: uuid to allow us to find the transaction
        :param status: status of the operation
        :param progress: optional progress value if status is in-progress
        :param err: error string (only set if status is failure)
        :returns: either returns nothing or raises exception
        """

        LOG.info("device_update_image_status: transaction_id: %s, status: %s, "
                 "progress: %s, err: %s" %
                 (transaction_id, status, progress, err))

        # Save the status of the completed device image update in the db.
        # The status should be one of dconstants.DEVICE_IMAGE_UPDATE_*
        device_image_state = objects.device_image_state.get_by_uuid(
            context, transaction_id)
        device_image_state.status = status
        if status == dconstants.DEVICE_IMAGE_UPDATE_IN_PROGRESS:
            device_image_state.update_start_time = timeutils.utcnow()
        device_image_state.save()

        # If the device image update completed, someone will need to reboot
        # the host for it to take effect.
        if status == dconstants.DEVICE_IMAGE_UPDATE_COMPLETED:
            host = objects.host.get_by_uuid(context, host_uuid)
            host.reboot_needed = True
            host.save()

        if status in [dconstants.DEVICE_IMAGE_UPDATE_COMPLETED,
                      dconstants.DEVICE_IMAGE_UPDATE_FAILED]:
            # Find the next device on the same host that needs updating,
            # and trigger an update of it.
            self.host_device_image_update_next(context, host_uuid)

    def start_restore(self, context):
        """Start the restore

        :param context: request context.
        """

        LOG.info("Preparing for restore procedure.")
        try:
            self.dbapi.restore_get_one(
                filters={'state': constants.RESTORE_STATE_IN_PROGRESS})
        except exception.NotFound:
            self.dbapi.restore_create(
                values={'state': constants.RESTORE_STATE_IN_PROGRESS})
        else:
            return constants.RESTORE_PROGRESS_ALREADY_IN_PROGRESS

        # TODO (agrosu): no use case at this point for sending a BACKUP_ACTION_PRE_RESTORE notification.
        return constants.RESTORE_PROGRESS_STARTED

    def complete_restore(self, context):
        """Complete the restore

        :param context: request context.
        """

        try:
            controllers = self.dbapi.ihost_get_by_personality(
                constants.CONTROLLER)
            invalid_controllers = [
                controller for controller in controllers if
                controller.administrative != constants.ADMIN_UNLOCKED or
                controller.operational != constants.OPERATIONAL_ENABLED or
                (controller.availability != constants.AVAILABILITY_AVAILABLE and
                 controller.availability != constants.AVAILABILITY_DEGRADED)]

            if invalid_controllers:
                message = "Cannot complete the restore procedure. " \
                          "One of the controllers is not unlocked enabled available/degraded"
                LOG.info(message)
                return message
        except Exception as e:
            message = "Cannot complete the restore procedure. " \
                      "Cannot query controllers state."
            LOG.info(message)
            LOG.error(e)
            return message

        try:
            restore = self.dbapi.restore_get_one(
                filters={'state': constants.RESTORE_STATE_IN_PROGRESS})
        except exception.NotFound:
            return constants.RESTORE_PROGRESS_ALREADY_COMPLETED
        else:
            ok, app = self.backup_restore_lifecycle_actions(context,
                                                  constants.BACKUP_ACTION_POST_RESTORE,
                                                  constants.BACKUP_ACTION_NOTIFY_SUCCESS)
            state = constants.RESTORE_STATE_COMPLETED
            if not ok:
                if app is None:
                    app = 'unknown'
                LOG.error("Restore action failed because of application '{}'".format(app))

            self.dbapi.restore_update(restore.uuid,
                                      values={'state': state})

        LOG.info("Complete the restore procedure.")

        return constants.RESTORE_PROGRESS_COMPLETED

    def get_restore_state(self, context):
        """Get the restore state

        :param context: request context.
        """

        if self._verify_restore_in_progress():
            output = constants.RESTORE_PROGRESS_IN_PROGRESS
        else:
            output = constants.RESTORE_PROGRESS_NOT_IN_PROGRESS

        LOG.info(output)
        return output

    def _create_kube_rootca_resources(self, certificate, key):
        """ A method to create new resources to store new kubernetes
        rootca data.

        :param certificate: the certificate to be stored in TLS secret
        :param key: the certificate key to be stored in TLS secret
        :return: An error message if method is not successful, otherwhise None
        """
        kube_operator = kubernetes.KubeOperator()

        body = {
            'apiVersion': 'v1',
            'type': 'kubernetes.io/tls',
            'kind': 'Secret',
            'metadata': {
                'name': constants.KUBE_ROOTCA_SECRET,
                'namespace': kubernetes.NAMESPACE_DEPLOYMENT
            },
            'data': {
                'tls.crt': certificate,
                'tls.key': key
            }
        }

        try:
            secret = kube_operator.kube_get_secret(constants.KUBE_ROOTCA_SECRET,
                                                    kubernetes.NAMESPACE_DEPLOYMENT)
            if secret is not None:
                kube_operator.kube_delete_secret(constants.KUBE_ROOTCA_SECRET,
                                                    kubernetes.NAMESPACE_DEPLOYMENT)
            kube_operator.kube_create_secret(kubernetes.NAMESPACE_DEPLOYMENT, body)
        except Exception as e:
            msg = "Creation of kube-rootca secret failed: %s" % str(e)
            LOG.error(msg)
            return msg

        api_version = "%s/%s" % (kubernetes.CERT_MANAGER_GROUP,
                                 kubernetes.CERT_MANAGER_VERSION)
        body = {
            'apiVersion': api_version,
            'kind': 'Issuer',
            'metadata': {
                'name': constants.KUBE_ROOTCA_ISSUER,
                'namespace': kubernetes.NAMESPACE_DEPLOYMENT
            },
            'spec': {
                'ca': {
                    'secretName': constants.KUBE_ROOTCA_SECRET
                }
            }
        }

        try:
            kube_operator.apply_custom_resource(kubernetes.CERT_MANAGER_GROUP,
                                                     kubernetes.CERT_MANAGER_VERSION,
                                                     kubernetes.NAMESPACE_DEPLOYMENT,
                                                     'issuers',
                                                     constants.KUBE_ROOTCA_ISSUER,
                                                     body)
        except Exception as e:
            msg = "Not successfull applying issuer: %s" % str(e)
            return msg

    def _precheck_save_kubernetes_rootca_cert(self, update, temp_pem_contents):
        """ This method intends to do a series of validations to allow the
            upload of a new rootca for kubernetes. These validations are
            respective to the procedure itself or the new ca file that is
            being uploaded.

        :param update: actual entry of kube rootca update procedure from DB
        :param temp_pem_contents: content of the file uploaded
        to update kube rootca
        :return: A dictionary with a new_cert if successful and eventual
        error message
        """

        if update.state != kubernetes.KUBE_ROOTCA_UPDATE_STARTED:
            msg = "A new root CA certificate already exists"
            return dict(success="", error=msg)

        if update.to_rootca_cert:
            LOG.info("root CA target with serial number %s will be overwritten"
                     % update.to_rootca_cert)

        # extract the certificate contained in PEM file
        try:
            cert = cutils.extract_certs_from_pem(temp_pem_contents)[0]
        except Exception as e:
            msg = "Failed to extract certificate from file: %s" % str(e)
            return dict(success="", error=msg)

        if not cert:
            msg = "No certificate have been added, " \
                  "no valid certificate found in file."
            LOG.info(msg)
            return dict(success="", error=msg)

        # extract current k8s rootca
        current_cert = \
            cutils.get_certificate_from_file(kubernetes.KUBERNETES_ROOTCA_CERT)
        if not current_cert:
            msg = "Not able to get the current kube rootca"
            return dict(success="", error=msg)

        # validate certificate
        msg = cutils.check_cert_validity(cert)

        if msg is not None:
            return dict(success="", error=msg)

        is_ca = cutils.is_ca_cert(cert)
        if not is_ca:
            msg = "The certificate in the file is not a CA certificate"
            LOG.error(msg)
            return dict(success="", error=msg)

        # extract information regarding the new rootca
        try:
            new_cert_id = cutils.build_cert_identifier(cert)
        except Exception:
            msg = "Failed to extract subject and serial number " \
                  "from new root CA"
            LOG.error(msg)
            return dict(success="", error=msg)

        return dict(success=new_cert_id, error="")

    def save_kubernetes_rootca_cert(self, context, ca_file):
        """
        Save a new uploaded kubernetes rootca for update procedure
        :param context: request context
        :param ca_file: a stream representing the PEM file uploaded
        """

        # ca_file has to be in bytes format for extract information
        if not isinstance(ca_file, bytes):
            temp_pem_contents = ca_file.encode("utf-8")
        else:
            temp_pem_contents = ca_file

        try:
            update = self.dbapi.kube_rootca_update_get_one()
        except exception.NotFound:
            msg = "Kubernetes root CA update not started"
            LOG.error(msg)
            return dict(success="", error=msg)

        result = \
            self._precheck_save_kubernetes_rootca_cert(update,
                                                       temp_pem_contents)
        if result.get("error"):
            msg = result.get("error")
            return dict(success="", error=msg)
        else:
            new_cert = result.get("success")

        try:
            certificate = cutils.extract_ca_crt_bytes_from_pem(temp_pem_contents)
        except exception.InvalidKubernetesCA:
            msg = "Invalid certificate format"
            return dict(success="", error=msg)

        try:
            key = cutils.extract_ca_private_key_bytes_from_pem(temp_pem_contents)
        except exception.InvalidKubernetesCA:
            msg = "Failed to extract key from certificate file"
            return dict(success="", error=msg)

        msg = self._create_kube_rootca_resources(certificate, key)
        if msg is not None:
            return dict(success="", error=msg)

        # update db
        update_obj = {'state': kubernetes.KUBE_ROOTCA_UPDATE_CERT_UPLOADED,
                      'to_rootca_cert': new_cert}

        r = self.dbapi.kube_rootca_update_update(update.id, update_obj)
        return dict(success=r.to_rootca_cert, error="")

    def generate_kubernetes_rootca_cert(self, context, subject, duration=None):
        """ Generate a new k8s root CA
            this will consist on 5 steps:
                1. Pre-check to assure all conditions are OK for the cert generation
                2. Generate a self-signed issuer
                3. Generate a Certificate (root CA) from this issuer
                4. Generate an issuer from this newly self-signed root CA
                5. Extract info from new and current root CA and save it on DB

        :param context: request context.
        :returns: the identifier for the new root CA
        """

        # Step 1: Pre-checking
        # check actual procedure entry
        try:
            update = self.dbapi.kube_rootca_update_get_one()
        except exception.NotFound:
            msg = "Kubernetes root CA update not started"
            LOG.error(msg)
            return dict(success="", error=msg)

        # check if procedure is in a state that allow us to generate new cert
        if update.state != kubernetes.KUBE_ROOTCA_UPDATE_STARTED:
            msg = "A new root CA certificate already exists"
            LOG.error(msg)
            return dict(success="", error=msg)

        if update.to_rootca_cert:
            LOG.info("root CA target with serial number %s "
                     "will be overwritten" % update.to_rootca_cert)

        # extract current k8s rootca identifier
        current_cert = \
            cutils.get_certificate_from_file(kubernetes.KUBERNETES_ROOTCA_CERT)
        if not current_cert:
            msg = "Not able to get the current kube rootca"
            return dict(success="", error=msg)

        if duration is None:
            # extract validation period from current cert
            # the generated one will have the same period of validity
            validation_period = current_cert.not_valid_after - \
                                current_cert.not_valid_before

            # convert duration into hours to apply in resource spec
            duration = validation_period.days * 24

        # Step 2: Generating a self-signed issuer
        kube_operator = kubernetes.KubeOperator()
        selfsigned_issuer_name = constants.KUBE_SELFSIGNED_ISSUER
        api_version = "%s/%s" % (kubernetes.CERT_MANAGER_GROUP,
                                 kubernetes.CERT_MANAGER_VERSION)
        selfsigned_issuer = {
            'apiVersion': api_version,
            'kind': 'Issuer',
            'metadata': {
                'name': selfsigned_issuer_name,
                'namespace': kubernetes.NAMESPACE_DEPLOYMENT
            },
            'spec': {
                'selfSigned': {}
            }
        }

        try:
            kube_operator.apply_custom_resource(kubernetes.CERT_MANAGER_GROUP,
                                                     kubernetes.CERT_MANAGER_VERSION,
                                                     kubernetes.NAMESPACE_DEPLOYMENT,
                                                     'issuers',
                                                     selfsigned_issuer_name,
                                                     selfsigned_issuer)
        except Exception:
            msg = "Failed to generate self-signed issuer in cert-manager"
            LOG.error(msg)
            return dict(success="", error=msg)

        # Step 3: Generating a self-signed CA from issuer
        rootca_certificate_name = constants.KUBE_ROOTCA_SECRET
        spec = {
            'isCA': True,
            'duration': str(duration) + 'h',
            'renewBefore': constants.K8S_CERTIFICATE_MINIMAL_DURATION,
            'commonName': 'kubernetes',
            'secretName': rootca_certificate_name,
            'issuerRef': {
                'name': selfsigned_issuer_name,
                'kind': 'Issuer'
            },
            'keyEncoding': 'pkcs8'
        }

        spec = cutils.add_certificate_subject(subject, spec)

        rootca_certificate = {
            'apiVersion': api_version,
            'kind': 'Certificate',
            'metadata': {
                'name': rootca_certificate_name,
                'namespace': kubernetes.NAMESPACE_DEPLOYMENT
            },
            'spec': spec
        }

        try:
            kube_operator.apply_custom_resource(kubernetes.CERT_MANAGER_GROUP,
                                                     kubernetes.CERT_MANAGER_VERSION,
                                                     kubernetes.NAMESPACE_DEPLOYMENT,
                                                     'certificates',
                                                     rootca_certificate_name,
                                                     rootca_certificate)
        except Exception:
            msg = ("Failed to generate root CA certificate in cert-manager")
            LOG.error(msg)
            return dict(success="", error=msg)

        # Step 4: Generating issuer to sign certificates within newly
        # root CA certificate
        certificate_issuer_name = constants.KUBE_ROOTCA_ISSUER

        certificate_issuer = {
            'apiVersion': api_version,
            'kind': 'Issuer',
            'metadata': {
                'name': certificate_issuer_name,
                'namespace': kubernetes.NAMESPACE_DEPLOYMENT
            },
            'spec': {
                'ca': {
                    'secretName': rootca_certificate_name
                }
            }
        }

        try:
            kube_operator.apply_custom_resource(kubernetes.CERT_MANAGER_GROUP,
                                                     kubernetes.CERT_MANAGER_VERSION,
                                                     kubernetes.NAMESPACE_DEPLOYMENT,
                                                     'issuers',
                                                     certificate_issuer_name,
                                                     certificate_issuer)
        except Exception as e:
            msg = ("Failed to create root CA issuer in cert-manager: %s" % e)
            LOG.error(msg)
            return dict(success="", error=msg)

        # Step 5: Extracting information from current and new root CA
        # The new root CA will be stored in the secret
        # system-kube-rootca-certificate as indicated in Certificate
        # resource above
        secret = kube_operator.get_cert_secret(rootca_certificate_name,
                                               kubernetes.NAMESPACE_DEPLOYMENT)
        if secret is None:
            msg = ("TLS Secret creation timeout")
            LOG.error(msg)
            return dict(success="", error=msg)

        data = secret.data
        tls_crt = base64.decode_as_bytes(data['tls.crt'])
        certs = cutils.extract_certs_from_pem(tls_crt)

        # extract information regarding the new rootca
        try:
            new_cert = cutils.build_cert_identifier(certs[0])
        except Exception:
            msg = "Failed to extract issuer and serial number from new root CA"
            LOG.error(msg)
            return dict(success="", error=msg)

        # update db
        update_obj = {'state': kubernetes.KUBE_ROOTCA_UPDATE_CERT_GENERATED,
                      'to_rootca_cert': new_cert}

        r = self.dbapi.kube_rootca_update_update(update.id, update_obj)
        return dict(success=r.to_rootca_cert, error="")

    def get_current_kube_rootca_cert_id(self, context):
        # extract current k8s rootca
        cert = cutils.get_certificate_from_file(kubernetes.KUBERNETES_ROOTCA_CERT)
        if not cert:
            LOG.error("Failed to get current kube root CA cert")
            raise exception.SysinvException(_("Failed to get current kube root CA cert"))

        # build the identifier of the current root CA cert
        try:
            cert_id = cutils.build_cert_identifier(cert)
        except Exception:
            LOG.error("Failed to calculate the ID of current kube root CA cert")
            raise exception.SysinvException(_(
                "Failed to calculate the ID of current kube root CA cert"))
        return cert_id

    def mtc_action_apps_semantic_checks(self, context, action):
        """Call semantic check for maintenance actions of each app.
        Fail if at least one app rejects the action.

        :param context: request context.
        :param action: maintenance action
        """
        apps = self.dbapi.kube_app_get_all()

        for app in apps:
            try:
                semantic_check_hook_info = LifecycleHookInfo()
                semantic_check_hook_info.init(
                    constants.APP_LIFECYCLE_MODE_MANUAL,
                    constants.APP_LIFECYCLE_TYPE_SEMANTIC_CHECK,
                    constants.APP_LIFECYCLE_TIMING_PRE,
                    constants.APP_LIFECYCLE_OPERATION_MTC_ACTION)
                semantic_check_hook_info.extra[
                    LifecycleConstants.APP_STATUS] = app.status
                semantic_check_hook_info.extra[
                    LifecycleConstants.ACTION] = action

                self._app.app_lifecycle_actions(context, self, app, semantic_check_hook_info)
            except exception.LifecycleSemanticCheckException as e:
                LOG.info("App {} rejected maintance action {} for reason: {}"
                         "".format(app.name, action, str(e)))
                raise
            except Exception as e:
                LOG.error("App {} maintance action {} semantic check error: {}"
                          "".format(app.name, action, str(e)))
                raise

    def _wait_secret_creation(self, secret_name):
        """ Wait for secret to be created and information regarding crt/key to be stored

        It will wait until tls.crt and tls.key contents are available to read
        In case this wait timeouts it will save the update state on db and
        raise a SysinvException

        :param secret_name: the name of the secret to wait
        """
        kube_operator = kubernetes.KubeOperator()
        secret = kube_operator.get_cert_secret(secret_name, kubernetes.NAMESPACE_DEPLOYMENT)
        if secret is None:
            msg = "Secret %s creation timeout" % secret_name
            LOG.error(msg)
            raise exception.SysinvException(_(msg))

    def _build_k8s_controller_certificates(self, host, api_version, issuer_reference, usages):
        """ Build k8s resources to get certificates for the control plane components
            to be updated

            - admin Certificate
            - apiserver Certificate
            - apiserver kubelet client Certificate
            - kube scheduler Certificate
            - controller manager Certificate
            - kubelet Certificate
        """

        kube_operator = kubernetes.KubeOperator()

        # Set the validity duration for each certificate that's going
        # to be created in this method
        duration = cutils.calculate_k8s_component_certificate_duration()

        # placeholder to set a time for the renewBefore
        # Certificate.spec parameter
        renew_before = constants.K8S_CERTIFICATE_MINIMAL_DURATION

        LOG.info("Creating secrets for %s kubernetes control plane components "
                 "due to rootCA update" % host.hostname)

        # Create admin.conf cert/key.
        # the admin cert/key will be the same for all controller hosts.
        # This way we need to check if it is already created
        # or if we'll have to generate a new Certificate resource
        # to issue a new pair cert/key

        admin_certificate_name = constants.KUBE_ADMIN_CERT
        admin_secret = kube_operator.get_cert_secret(admin_certificate_name, kubernetes.NAMESPACE_DEPLOYMENT)
        if admin_secret is None:
            # Create k8s admin certificate/key
            admin_certificate = {
                'apiVersion': api_version,
                'kind': 'Certificate',
                'metadata': {
                    'name': admin_certificate_name,
                    'namespace': kubernetes.NAMESPACE_DEPLOYMENT
                },
                'spec': {
                    'secretName': admin_certificate_name,
                    'commonName': 'kubernetes-admin',
                    'duration': str(duration) + 'h',
                    'renewBefore': renew_before,
                    'subject': {
                        'organizations': ['system:masters']
                    },
                    'usages': usages,
                    'issuerRef': issuer_reference
                }
            }

            try:
                kube_operator.apply_custom_resource(kubernetes.CERT_MANAGER_GROUP,
                                                    kubernetes.CERT_MANAGER_VERSION,
                                                    kubernetes.NAMESPACE_DEPLOYMENT,
                                                    'certificates',
                                                    admin_certificate_name,
                                                    admin_certificate)
            except Exception:
                LOG.error("Failed to create %s resource" % admin_certificate_name)
                raise

            self._wait_secret_creation(admin_certificate_name)

            LOG.info("%s Secret successfully created and populated with cert/key data" % admin_certificate_name)

        # Create apiserver server certificate/key
        # for this one the SAN should maintain the same addresses
        # as the apiserver actually running
        apiserver_cert = cutils.get_certificate_from_file(kubernetes.KUBERNETES_APISERVER_CERT)
        dns_names = cutils.get_cert_DNSNames(apiserver_cert)
        ip_addresses = cutils.get_cert_IPAddresses(apiserver_cert)

        apiserver_certificate_name = constants.KUBE_APISERVER_CERT.format(host.hostname)
        apiserver_certificate = {
            'apiVersion': api_version,
            'kind': 'Certificate',
            'metadata': {
                'name': apiserver_certificate_name,
                'namespace': kubernetes.NAMESPACE_DEPLOYMENT
            },
            'spec': {
                'secretName': apiserver_certificate_name,
                'commonName': 'kube-apiserver',
                'duration': str(duration) + 'h',
                'renewBefore': renew_before,
                'dnsNames': dns_names,
                'ipAddresses': ip_addresses,
                'usages': ['digital signature', 'key encipherment', 'server auth'],
                'issuerRef': issuer_reference
            }
        }

        try:
            kube_operator.apply_custom_resource(kubernetes.CERT_MANAGER_GROUP,
                                                    kubernetes.CERT_MANAGER_VERSION,
                                                    kubernetes.NAMESPACE_DEPLOYMENT,
                                                    'certificates',
                                                    apiserver_certificate_name,
                                                    apiserver_certificate)
        except Exception:
            LOG.error("Failed to create %s resource" % apiserver_certificate_name)
            raise

        self._wait_secret_creation(apiserver_certificate_name)

        LOG.info("%s Secret successfully created and populated with cert/key data" % apiserver_certificate_name)

        # Create apiserver server kubelet client certificate/key
        apiserver_kubelet_client_certificate_name = constants.KUBE_APISERVER_KUBELET_CERT.format(host.hostname)
        apiserver_kubelet_client_certificate = {
            'apiVersion': api_version,
            'kind': 'Certificate',
            'metadata': {
                'name': apiserver_kubelet_client_certificate_name,
                'namespace': kubernetes.NAMESPACE_DEPLOYMENT
            },
            'spec': {
                'secretName': apiserver_kubelet_client_certificate_name,
                'commonName': 'kube-apiserver-kubelet-client',
                'duration': str(duration) + 'h',
                'renewBefore': renew_before,
                'usages': usages,
                'issuerRef': issuer_reference
            }
        }

        try:
            kube_operator.apply_custom_resource(kubernetes.CERT_MANAGER_GROUP,
                                                    kubernetes.CERT_MANAGER_VERSION,
                                                    kubernetes.NAMESPACE_DEPLOYMENT,
                                                    'certificates',
                                                    apiserver_kubelet_client_certificate_name,
                                                    apiserver_kubelet_client_certificate)
        except Exception:
            LOG.error("Failed to create %s resource" % apiserver_kubelet_client_certificate_name)
            raise

        self._wait_secret_creation(apiserver_kubelet_client_certificate_name)

        LOG.info("%s Secret successfully created and populated with cert/key data" %
        apiserver_kubelet_client_certificate_name)

        # Create scheduler certificate/key
        kube_scheduler_certificate_name = constants.KUBE_SCHEDULER_CERT.format(host.hostname)

        kube_scheduler_certificate = {
            'apiVersion': api_version,
            'kind': 'Certificate',
            'metadata': {
                'name': kube_scheduler_certificate_name,
                'namespace': kubernetes.NAMESPACE_DEPLOYMENT
            },
            'spec': {
                'secretName': kube_scheduler_certificate_name,
                'commonName': 'system:kube-scheduler',
                'duration': str(duration) + 'h',
                'renewBefore': renew_before,
                'usages': usages,
                'issuerRef': issuer_reference
            }
        }

        try:
            kube_operator.apply_custom_resource(kubernetes.CERT_MANAGER_GROUP,
                                                    kubernetes.CERT_MANAGER_VERSION,
                                                    kubernetes.NAMESPACE_DEPLOYMENT,
                                                    'certificates',
                                                    kube_scheduler_certificate_name,
                                                    kube_scheduler_certificate)
        except Exception:
            LOG.error("Failed to create %s resource" % kube_scheduler_certificate_name)
            raise

        self._wait_secret_creation(kube_scheduler_certificate_name)

        LOG.info("%s Secret successfully created and populated with cert/key data" %
        kube_scheduler_certificate_name)

        # Create controller manager certificate/key
        controller_manager_certificate_name = constants.KUBE_CONTROLLER_MANAGER_CERT.format(host.hostname)
        controller_manager_certificate = {
            'apiVersion': api_version,
            'kind': 'Certificate',
            'metadata': {
                'name': controller_manager_certificate_name,
                'namespace': kubernetes.NAMESPACE_DEPLOYMENT
            },
            'spec': {
                'secretName': controller_manager_certificate_name,
                'commonName': 'system:kube-controller-manager',
                'duration': str(duration) + 'h',
                'renewBefore': renew_before,
                'usages': usages,
                'issuerRef': issuer_reference
            }
        }

        try:
            kube_operator.apply_custom_resource(kubernetes.CERT_MANAGER_GROUP,
                                                    kubernetes.CERT_MANAGER_VERSION,
                                                    kubernetes.NAMESPACE_DEPLOYMENT,
                                                    'certificates',
                                                    controller_manager_certificate_name,
                                                    controller_manager_certificate)
        except Exception:
            LOG.error("Failed to create %s resource" % controller_manager_certificate_name)
            raise

        self._wait_secret_creation(controller_manager_certificate_name)

        LOG.info("%s Secret successfully created and populated with cert/key data" %
        controller_manager_certificate_name)

        # Create kubelet client certificate/key
        kubelet_certificate_name = constants.KUBE_KUBELET_CERT.format(host.hostname)
        kubelet_certificate = {
            'apiVersion': api_version,
            'kind': 'Certificate',
            'metadata': {
                'name': kubelet_certificate_name,
                'namespace': kubernetes.NAMESPACE_DEPLOYMENT
            },
            'spec': {
                'secretName': kubelet_certificate_name,
                'commonName': 'system:node:' + host.hostname,
                'duration': str(duration) + 'h',
                'renewBefore': renew_before,
                'subject': {
                    'organizations': ['system:nodes']
                },
                'usages': usages,
                'issuerRef': issuer_reference
            }
        }

        try:
            kube_operator.apply_custom_resource(kubernetes.CERT_MANAGER_GROUP,
                                                    kubernetes.CERT_MANAGER_VERSION,
                                                    kubernetes.NAMESPACE_DEPLOYMENT,
                                                    'certificates',
                                                    kubelet_certificate_name,
                                                    kubelet_certificate)
        except Exception:
            LOG.error("Failed to create %s resource" % kubelet_certificate_name)
            raise

        self._wait_secret_creation(kubelet_certificate_name)

        LOG.info("%s Secret successfully created and populated with cert/key data" %
        kubelet_certificate_name)

    def _build_k8s_worker_certificates(self, host, api_version, issuer_reference, usages):
        kube_operator = kubernetes.KubeOperator()

        # Read apiserver cert duration information as a standard. For this
        # procedure we're going to set the same duration for all certificates
        # created.
        duration = cutils.calculate_k8s_component_certificate_duration()

        # placeholder to set a time for the renewBefore
        # Certificate.spec parameter
        renew_before = constants.K8S_CERTIFICATE_MINIMAL_DURATION

        LOG.info("Creating secrets for %s kubernetes control plane components "
                 "due to rootCA update" % host.hostname)

        # Create kubelet client certificate/key
        kubelet_certificate_name = constants.KUBE_KUBELET_CERT.format(host.hostname)
        kubelet_certificate = {
            'apiVersion': api_version,
            'kind': 'Certificate',
            'metadata': {
                'name': kubelet_certificate_name,
                'namespace': kubernetes.NAMESPACE_DEPLOYMENT
            },
            'spec': {
                'secretName': kubelet_certificate_name,
                'commonName': 'system:node:' + host.hostname,
                'duration': str(duration) + 'h',
                'renewBefore': renew_before,
                'subject': {
                    'organizations': ['system:nodes']
                },
                'usages': usages,
                'issuerRef': issuer_reference
            }
        }

        try:
            kube_operator.apply_custom_resource(kubernetes.CERT_MANAGER_GROUP,
                                                    kubernetes.CERT_MANAGER_VERSION,
                                                    kubernetes.NAMESPACE_DEPLOYMENT,
                                                    'certificates',
                                                    kubelet_certificate_name,
                                                    kubelet_certificate)
        except Exception:
            LOG.error("Failed to create %s resource" % kubelet_certificate)
            raise

        self._wait_secret_creation(kubelet_certificate_name)

    def _failed_update_certs(self, host):
        # Change host table entry
        # for KUBE_ROOTCA_UPDATING_HOST_UPDATECERTS_FAILED state
        h_update = self.dbapi.kube_rootca_host_update_get_by_host(host.id)
        self.dbapi.kube_rootca_host_update_update(h_update.id,
                                                {'state':
                                                kubernetes.KUBE_ROOTCA_UPDATING_HOST_UPDATECERTS_FAILED})
        cluster_rootca_procedure = self.dbapi.kube_rootca_update_get_one()
        # Change cluster table entry
        # for KUBE_ROOTCA_UPDATING_HOST_UPDATECERTS_FAILED state
        self.dbapi.kube_rootca_update_update(cluster_rootca_procedure.id,
                                                {'state':
                                                kubernetes.KUBE_ROOTCA_UPDATING_HOST_UPDATECERTS_FAILED})

    def kube_certificate_update_by_host(self, context, host, phase):
        """Update the kube certificate for a host"""
        phase = phase.lower()
        update_certs = False
        if phase == constants.KUBE_CERT_UPDATE_UPDATECERTS:
            kube_operator = kubernetes.KubeOperator()
            api_version = "%s/%s" % (kubernetes.CERT_MANAGER_GROUP,
                                    kubernetes.CERT_MANAGER_VERSION)
            try:
                issuer = kube_operator.get_custom_resource(kubernetes.CERT_MANAGER_GROUP,
                                                        kubernetes.CERT_MANAGER_VERSION,
                                                        kubernetes.NAMESPACE_DEPLOYMENT,
                                                        'issuers',
                                                        constants.KUBE_ROOTCA_ISSUER)
            except Exception as e:
                LOG.error("root CA issuer could not be found: %s" % e)

            if not issuer:
                self._failed_update_certs(host)
                raise exception.SysinvException(_("CA issuer not found"))

            issuer_reference = {'name': constants.KUBE_ROOTCA_ISSUER, 'kind': 'Issuer'}
            usages = ['digital signature', 'key encipherment', 'client auth']
            update_certs = True

        if phase not in [constants.KUBE_CERT_UPDATE_TRUSTBOTHCAS,
                         constants.KUBE_CERT_UPDATE_UPDATECERTS,
                         constants.KUBE_CERT_UPDATE_TRUSTNEWCA]:
            raise exception.SysinvException(_(
                "Invalid phase %s to update kube certificate." %
                phase))

        if host.personality == constants.CONTROLLER:
            if update_certs:
                try:
                    self._build_k8s_controller_certificates(host, api_version, issuer_reference, usages)
                except Exception:
                    self._failed_update_certs(host)
                    raise exception.SysinvException(_(
                        "resource creation for update kubernetes components in phase %s failed" %
                        phase))

            puppet_class = [
                'platform::kubernetes::master::rootca::' + phase.replace('-', '') + '::runtime',
            ]
        else:
            if update_certs:
                try:
                    self._build_k8s_worker_certificates(host, api_version, issuer_reference, usages)
                except Exception:
                    self._failed_update_certs(host)
                    raise exception.SysinvException(_(
                        "resource creation for update kubernetes worker "
                        "components in phase %s failed" % phase))

            puppet_class = [
                'platform::kubernetes::worker::rootca::' + phase.replace('-', '') + '::runtime',
            ]

        config_dict = {
            "personalities": host.personality,
            "classes": puppet_class,
            "host_uuids": [host.uuid],
            puppet_common.REPORT_STATUS_CFG: phase,
        }

        config_uuid = self._config_update_hosts(context,
                                        personalities=host.personality,
                                        host_uuids=[host.uuid])

        LOG.info("kube_certificate_update_by_host config_uuid=%s"
                 % config_uuid)

        self._config_apply_runtime_manifest(context,
                                            config_uuid,
                                            config_dict)

    def kube_certificate_update_for_pods(self, context, phase):
        """Update the kube certificate for pods"""

        # Updating pods' certificates is only needed to run once on active
        # controller
        host = self.dbapi.ihost_get(self.host_uuid)
        config_uuid = self._config_update_hosts(context,
                                                personalities=host.personality,
                                                host_uuids=[host.uuid])

        LOG.info("kube_certificate_update_for_pods config_uuid=%s"
                 % config_uuid)

        phase = phase.lower()
        if phase not in [constants.KUBE_CERT_UPDATE_TRUSTBOTHCAS,
                         constants.KUBE_CERT_UPDATE_TRUSTNEWCA]:
            raise exception.SysinvException(_(
                "Invalid phase %s to update kube certificate for pods." %
                phase))

        puppet_class = [
            'platform::kubernetes::master::rootca::pods::' + phase.replace('-', '') + '::runtime',
        ]

        config_dict = {
            "personalities": host.personality,
            "classes": puppet_class,
            "host_uuids": [host.uuid],
            puppet_common.REPORT_STATUS_CFG: 'pods_' + phase,
        }

        self._config_apply_runtime_manifest(context,
                                            config_uuid,
                                            config_dict)

    def clear_kubernetes_rootca_update_resources(self, context, certificate_list,
                                                 issuers_list, secret_list):

        kube_operator = kubernetes.KubeOperator()
        namespace = kubernetes.NAMESPACE_DEPLOYMENT
        group = kubernetes.CERT_MANAGER_GROUP
        version = kubernetes.CERT_MANAGER_VERSION

        deleted_resources = []
        for certificate_name in certificate_list:
            try:
                kube_operator.delete_custom_resource(group, version, namespace,
                                                     'certificates', certificate_name)
                deleted_resources.append(certificate_name)
            except Exception:
                pass

        LOG.info('Deleted k8s certificates:\n %s' % deleted_resources)

        deleted_resources = []
        for issuer_name in issuers_list:
            try:
                kube_operator.delete_custom_resource(group, version, namespace,
                                                     'issuers', issuer_name)
                deleted_resources.append(certificate_name)
            except Exception:
                pass

        LOG.info('Deleted k8s issuers:\n %s' % deleted_resources)

        deleted_resources = []
        for secret_name in secret_list:
            try:
                kube_operator.kube_delete_secret(secret_name, namespace)
                deleted_resources.append(secret_name)
            except Exception:
                pass

        LOG.info('Deleted k8s secrets:\n %s' % deleted_resources)

    def sanitize_feature_gates_bootstrap_config_file(self, target_version):
        """
        Remove the "RemoveSelfLink=false" kube-apiserver feature gate from the
        last_kube_extra_config_bootstrap.yaml file when doing an upgrade from
        K8s 1.23 to 1.24.

        The yaml file contains information that is used during backup and restore.
        We want to remove the "RemoveSelfLink=false" kube-apiserver feature gate
        if it's present so that if we do a backup and restore after the upgrade
        to K8s 1.24 we won't try to use this feature gate any more.  Any other feature
        gates should be left alone, and if there aren't any other feature gates
        we want to delete the entire "feature-gates" line.

        Once we no longer need to worry about upgrading from 1.23 we can remove
        this function.

        HugePageStorageMedium feature gate could only have been true
        starting from 1.22 and it removed entirely in 1.24.

        TTLAfterFinished feature gate could only have been true starting
        from 1.23 and it removed entirely in 1.25.
        """
        FILENAME = tsc.CONFIG_PATH + "last_kube_extra_config_bootstrap.yaml"
        newyaml = yaml.YAML()
        newyaml.default_flow_style = False

        try:
            with open(FILENAME, "r") as stream:
                info = newyaml.load(stream)
        except FileNotFoundError:
            # For "skip version" upgrades this is normal.
            LOG.info("File %s not found, ignoring." % FILENAME)
            return 0
        except Exception as ex:
            LOG.error("Problem reading from %s" % FILENAME)
            LOG.error(str(ex))
            return 1

        rc = 0
        try:
            if target_version == 'v1.24.4':
                # RemoveSelfLink can only be true as of 1.24
                info, tmp = sanitize_feature_gates_bootstrap(
                    info, 'RemoveSelfLink=false')
                rc |= tmp
                # HugePageStorageMedium removed entirely in 1.24
                # but could only have been true starting with 1.22
                info, tmp = sanitize_feature_gates_bootstrap(
                    info, 'HugePageStorageMediumSize=true')
                rc |= tmp

            if target_version == 'v1.25.3':
                info, tmp = sanitize_feature_gates_bootstrap(
                    info, 'TTLAfterFinished=true')
                rc |= tmp

        except exception.Exception as ex:
            # Unexpected problem
            LOG.error('Problem sanitizing bootstrap feature gates %s' % ex)
            return 1

        # Write out the new file.
        try:
            with open(FILENAME, 'w') as outfile:
                newyaml.dump(info, outfile)
        except Exception as ex:
            LOG.error("Problem writing to %s" % FILENAME)
            LOG.error(str(ex))
            return 1
        LOG.info('Successfully updated feature gates in bootstrap file.')
        return rc

    def sanitize_feature_gates_kubelet_configmap(self, target_version):
        """
        Edit the kubelet configmap and remove stale feature gates that
        are no longer applicable for the version of K8s that we are upgrading to.
        """
        newyaml = yaml.YAML()

        # Get the configmap name based on target version
        if target_version == 'v1.24.4':
            configmap_name = 'kubelet-config-1.23'
        else:
            LOG.error("Unsupported target version %s, can't edit kubelet cm.",
                target_version)
            return 0

        try:
            configmap = self._kube.kube_read_config_map(
                configmap_name, 'kube-system')

            # Parse the configmap to get the feature gates
            stream = StringIO(configmap.data['kubelet'])
            kubelet_config = newyaml.load(stream)
            feature_gates = kubelet_config.get('featureGates', {})

            # Edit the feature gates
            if target_version == 'v1.24.4':
                # RemoveSelfLink can only be true as of 1.24
                if feature_gates.get('RemoveSelfLink') is False:
                    feature_gates.pop('RemoveSelfLink', None)
                # HugePageStorageMedium removed entirely in 1.24
                # but could only have been true starting with 1.22
                if feature_gates.get('HugePageStorageMediumSize') is True:
                    feature_gates.pop('HugePageStorageMediumSize', None)

            if target_version == 'v1.25.3':
                if feature_gates.get('TTLAfterFinished') is True:
                    feature_gates.pop('TTLAfterFinished', None)

            # If there aren't any feature gates left, remove the whole thing
            if not feature_gates:
                kubelet_config.pop('featureGates', {})

            # Re-format the embedded entry.
            outstream = StringIO()
            newyaml.dump(kubelet_config, outstream)

            # Create partial configmap for patching
            configmap = {'data': {'kubelet': outstream.getvalue()}}

            self._kube.kube_patch_config_map(configmap_name, 'kube-system', configmap)
        except Exception as e:
            LOG.exception("Unable to patch kubelet config_map: %s" % e)
            return 1

        LOG.info('Successfully updated feature gates in kubelet cm.')
        return 0

    def sanitize_feature_gates_kubeadm_configmap(self, target_version):
        """
        Edit the kubeadm configmap and remove stale feature gates that
        are no longer applicable for the version of K8s that we are upgrading to.
        """
        configmap_name = 'kubeadm-config'

        try:
            configmap = self._kube.kube_read_config_map(configmap_name, 'kube-system')

            # Parse the configmap to get the feature gates
            stream = StringIO(configmap.data['ClusterConfiguration'])
            kubeadm_config = yaml.safe_load(stream)
            for component in ['apiServer', 'controllerManager', 'scheduler']:
                k8s_component = kubeadm_config.get(component, {})
                extra_args = k8s_component.get('extraArgs', {})
                feature_gates = extra_args.get('feature-gates', None)
                if not feature_gates:
                    continue

                try:
                    feature_gates = sanitize_feature_gates(feature_gates,
                                'RemoveSelfLink=false')
                    if target_version == 'v1.25.3':
                        feature_gates = sanitize_feature_gates(feature_gates,
                                    'TTLAfterFinished=true')
                    if not feature_gates:
                        # No feature gates left, so delete the entry
                        LOG.info('Deleting %s feature gates in Kubeadm_config.'
                                    % extra_args)
                        extra_args.pop('feature-gates')
                    else:
                        # Update the feature gates with the new value
                        LOG.info('Modifying %s feature gates in Kubeadm_config.'
                                    % extra_args)
                        extra_args['feature-gates'] = feature_gates
                except Exception as ex:
                    LOG.error("Problem sanitizing %s feature Kubeadm_config."
                                % extra_args)
                    LOG.error(str(ex))
                    raise
            outstream = StringIO()
            yaml.dump(kubeadm_config, outstream)
            configmap = {'data': {'ClusterConfiguration': outstream.getvalue()}}

            self._kube.kube_patch_config_map(configmap_name, 'kube-system', configmap)
        except Exception as e:
            LOG.exception("Unable to patch kubeadm config_map: %s" % e)
            return 1

        LOG.info('Successfully updated feature gates in kubeadm cm.')
        return 0

    def sanitize_feature_gates_service_parameters(self, target_version):
        """
        Loop over all the service parameter sections for Kubernetes, and
        remove stale feature gates that are no longer applicable for the
        version of K8s that we are upgrading to.
        """
        k8s_sections = [
            constants.SERVICE_PARAM_SECTION_KUBERNETES_APISERVER,
            constants.SERVICE_PARAM_SECTION_KUBERNETES_CONTROLLER_MANAGER,
            constants.SERVICE_PARAM_SECTION_KUBERNETES_SCHEDULER,
            constants.SERVICE_PARAM_SECTION_KUBERNETES_KUBELET,
        ]

        rc = 0
        try:
            for section in k8s_sections:
                if target_version == 'v1.24.4':
                    # This could be optimized to pass down a list of
                    # feature gates to remove.  Future optimization maybe.

                    # RemoveSelfLink can only be true as of 1.24
                    rc |= self.sanitize_feature_gates_service_parameter_section(
                        section, 'RemoveSelfLink=false')
                    # HugePageStorageMedium removed entirely in 1.24
                    # but could only have been true starting with 1.22
                    rc |= self.sanitize_feature_gates_service_parameter_section(
                        section, 'HugePageStorageMediumSize=true')

                if target_version == 'v1.25.3':
                    rc |= self.sanitize_feature_gates_service_parameter_section(
                        section, 'TTLAfterFinished=true')

        except exception.Exception as ex:
            # No apiserver feature gates, nothing to do
            LOG.info('Problems sanitizing feature gate service params: %s' % ex)
            return 1

        if rc == 0:
            LOG.info('Successfully updated feature gates in service parameters.')
        return rc

    def sanitize_feature_gates_service_parameter_section(self, section, feature):
            """
            Remove the "feature" feature gate from the "feature_gates" service
            parameter name for the "section" section.

            This is used to ensure that feature gates that have been removed upstream
            do not get mistakenly used.
            """
            try:
                service_param = self.dbapi.service_parameter_get_one(
                        constants.SERVICE_TYPE_KUBERNETES,
                        section,
                        constants.SERVICE_PARAM_NAME_KUBERNETES_FEATURE_GATES)
            except exception.NotFound:
                # No feature gates for this section, nothing to do
                return 0
            except exception.MultipleResults:
                # Unexpected, should only have one.
                LOG.error('Unexpected multiple %s feature-gate service params.' % section)
                return 1

            feature_gates = service_param.value
            if feature not in feature_gates:
                # Nothing to do
                return 0

            # Remove "feature" from the feature gates.
            feature_gates = sanitize_feature_gates(feature_gates, feature)
            try:
                if not feature_gates:
                    # No feature gates left, so delete the service parameter
                    self.dbapi.service_parameter_destroy_uuid(service_param.uuid)
                else:
                    # Update the feature gates with the new value
                    self.dbapi.service_parameter_update(service_param.uuid, {'value': feature_gates})
            except exception.NotFound:
                LOG.error("Problem updating %s feature-gate service param." % section)
                return 1
            LOG.info('Successfully updated %s feature-gates service param.' % section)
            return 0

    def sanitize_image_repository_kubeadm_configmap(self, target_version):
        """
        Update the imageRepository field of kubeadm configmap if it contains
        an incompatible  value for a given version of k8s.
        """

        configmap_name = 'kubeadm-config'
        OLD_IMAGE_REPOSITORY = "registry.local:9001/k8s.gcr.io"
        NEW_IMAGE_REPOSITORY = "registry.local:9001/registry.k8s.io"

        try:
            configmap = self._kube.kube_read_config_map(configmap_name, 'kube-system')
            # Parse the configmap to get the imageRepository
            stream = StringIO(configmap.data['ClusterConfiguration'])
            kubeadm_config = yaml.safe_load(stream)
            image_repository = kubeadm_config.get('imageRepository', None)

            if image_repository:
                minor_k8s_version = int(target_version.split('.')[1])
                if minor_k8s_version >= 25 and image_repository == OLD_IMAGE_REPOSITORY:
                    # Update the imageRepository with the new value
                    image_repository = NEW_IMAGE_REPOSITORY
                    kubeadm_config['imageRepository'] = image_repository
                    LOG.info('Setting imageRepository to %s in kubeadm-config.' % image_repository)
                    outstream = StringIO()
                    yaml.dump(kubeadm_config, outstream)
                    configmap = {'data': {'ClusterConfiguration': outstream.getvalue()}}
                    self._kube.kube_patch_config_map(configmap_name, 'kube-system', configmap)

        except Exception:
            LOG.exception("Error updating imageRepository in kubeadm configmap")
            return 1

        LOG.info('Successfully updated imageRepository in kubeadm configmap.')
        return 0

    @periodic_task.periodic_task(spacing=CONF.conductor_periodic_task_intervals.kube_upgrade_states)
    def _audit_kube_upgrade_states(self, context):
        # A Kubernetes upgrade state can be stuck in upgrading-* state.
        # To avoid this situation we audit the sanity of the states,
        # after 2 audit cycles if the states are not changed then set
        # the kube_state to *-failed.

        kube_upgrade_state_map = dict()
        kube_upgrade_state_map["downloading-images"] = "downloading-images-failed"
        kube_upgrade_state_map["upgrading-networking"] = "upgrading-networking-failed"
        kube_upgrade_state_map["upgrading-first-master"] = "upgrading-first-master-failed"
        kube_upgrade_state_map["upgrading-second-master"] = "upgrading-second-master-failed"

        try:
            kube_upgrade = self.dbapi.kube_upgrade_get_one()
            current_state = getattr(kube_upgrade, 'state', '')
            if kube_upgrade_state_map.get(current_state):
                kube_upgrade_time_stamp = getattr(kube_upgrade, 'updated_at')
                if timeutils.is_older_than(
                    kube_upgrade_time_stamp,
                    CONF.conductor_periodic_task_intervals.kube_upgrade_states * 2
                ):
                    self.dbapi.kube_upgrade_update(kube_upgrade.uuid,
                                        {'state': kube_upgrade_state_map[current_state]})
                    LOG.info(
                        "kube_upgrade state changed from "
                        "'%s' to '%s'", current_state,
                        kube_upgrade_state_map[current_state])
        except exception.NotFound:
            LOG.debug("A kubernetes upgrade is not in progress")


def device_image_state_sort_key(dev_img_state):
    if dev_img_state.bitstream_type == dconstants.BITSTREAM_TYPE_ROOT_KEY:
        return 0
    elif dev_img_state.bitstream_type == dconstants.BITSTREAM_TYPE_KEY_REVOCATION:
        return 1
    else:  # if dev_img_state.bitstream_type == dconstants.BITSTREAM_TYPE_FUNCTIONAL:
        return 2


def sanitize_feature_gates(feature_gates, feature):
    """
    Remove feature contained in the "feature" string arg from the feature_gates
    string arg which contains a comma-separated list of features.
    We need to handle the case where it could be at the beginning of the string
    with other entries after it, or at the end of the string with other entries
    before it, in the middle of the string, or by itself.
    """
    feature_gates = feature_gates.replace(feature + ',', '')
    feature_gates = feature_gates.replace(',' + feature, '')
    feature_gates = feature_gates.replace(feature, '')
    return feature_gates


def sanitize_feature_gates_bootstrap(info, feature):
    """
    This is a helper function for sanitize_feature_gates_bootstrap_config_file().

    "info" is the data structure from last_kube_extra_config_bootstrap.yaml

    It looks something like this:
    apiserver_extra_args:
      audit-log-maxsize: '100'
      audit-log-path: /var/log/kubernetes/audit/audit.log
      event-ttl: 24h
      feature-gates: TTLAfterFinished=true,RemoveSelfLink=false

    kubelet_configurations:
      failSwapOn: false
      featureGates:
        HugePageStorageMediumSize: true
        TTLAfterFinished: true

    We need to remove "feature" from the feature-gates field for the three
    sections corresponding to kube-apiserver, kube-controller-manager, and
    kube-scheduler.  We also need to remove it from the featureGates field
    for kubelet, which just to make things interesting uses a different
    representation of the data.
    """
    extra_args_sections = [
        'apiserver_extra_args',
        'controllermanager_extra_args',
        'scheduler_extra_args',
    ]

    rc = 0
    # Remove the feature from apiserver/controllermanager/scheduler extra args:
    for section in extra_args_sections:
        featuregates_string = 'feature-gates'

        feature_gates = info.get(section, {}).get(featuregates_string, '')
        if feature not in feature_gates:
            # Nothing to do
            continue

        # feature is in feature gates, remove it.
        try:
            feature_gates = sanitize_feature_gates(feature_gates, feature)
            if not feature_gates:
                # No feature gates left, so delete the entry
                LOG.info('Deleting %s feature gates in bootstrap.' % section)
                info[section].pop(featuregates_string, None)
            else:
                # Update the feature gates with the new value
                LOG.info('Modifying %s feature gates in bootstrap.' % section)
                info[section][featuregates_string] = feature_gates
        except Exception as ex:
            LOG.error("Problem sanitizing %s feature gates in bootstrap." % section)
            LOG.error(str(ex))
            rc = 1

    # Now we need to remove the feature from kubelet_configurations
    section = 'kubelet_configurations'
    featuregates_string = 'featureGates'

    # The 'feature' parameter is a string of the form 'Foo=false', while the
    # corresponding featureGates entry is a dict of the form
    # {'Foo': False}.  We only want to get rid of the entry if both key
    # and value match.
    tmp = feature.split('=', 1)
    key = tmp[0]
    val = tmp[1]
    if val == 'true':
        val = True
    elif val == 'false':
        val = False
    else:
        LOG.error("Unexpected value in %s kubelet feature gate in bootstrap." % tmp[0])
        rc = 1
        return info, rc

    feature_gates = info.get(section, {}).get(featuregates_string, {})
    # If the specified feature gate key/value is present, remove it.
    if feature_gates.get(key, None) == val:
        feature_gates.pop(key, None)
    # If there are no feature gates left, remove it.
    if not feature_gates:
        info.get(section, {}).pop(featuregates_string, {})

    return info, rc
