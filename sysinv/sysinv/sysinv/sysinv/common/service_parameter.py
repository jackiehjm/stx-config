# Copyright (c) 2017-2022 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# vim: tabstop=4 shiftwidth=4 softtabstop=4
# coding=utf-8
#

import netaddr
import pecan
import re
import wsme

from oslo_log import log
from six.moves.urllib.parse import urlparse
from sysinv._i18n import _
from sysinv.common import constants
from sysinv.common import exception
from sysinv.common import utils as cutils
from sysinv.common.storage_backend_conf import StorageBackendConfig

LOG = log.getLogger(__name__)

SERVICE_PARAMETER_DATA_FORMAT_ARRAY = 'array'
SERVICE_PARAMETER_DATA_FORMAT_BOOLEAN = 'boolean'
SERVICE_PARAMETER_DATA_FORMAT_DICT = 'dict'
SERVICE_PARAMETER_DATA_FORMAT_SKIP = 'skip'

IDENTITY_CONFIG_TOKEN_EXPIRATION_MIN = 3600
IDENTITY_CONFIG_TOKEN_EXPIRATION_MAX = 14400


def _validate_boolean(name, value):
    if value.lower() not in ['true', 'false']:
        raise wsme.exc.ClientSideError(_(
            "Parameter '%s' must be a boolean value." % name))


def _validate_no_update(name, value):
    msg = _(
        "Unable to configure service parameter,"
        " %s is disabled." % name)
    raise wsme.exc.ClientSideError(msg)


def _validate_yes_no(name, value):
    if value.lower() not in ['y', 'n']:
        raise wsme.exc.ClientSideError(_(
            "Parameter '%s' must be a yes/no value." % name))


def _validate_integer(name, value):
    try:
        int(value)
    except ValueError:
        raise wsme.exc.ClientSideError(_(
            "Parameter '%s' must be an integer value." % name))


def _validate_zero_or_positive_integer(name, value):
    _validate_integer(name, value)

    if int(value) < 0:
        raise wsme.exc.ClientSideError(_(
            "Parameter '%s' must be positive integer or zero.") % name)


def _validate_float(name, value):
    try:
        float(value)
    except ValueError:
        raise wsme.exc.ClientSideError(_(
            "Parameter '%s' must be a float value." % name))


def _validate_not_empty(name, value):
    if not value or value == '':
        raise wsme.exc.ClientSideError(_(
            "Parameter '%s' must not be an empty value." % name))


def _validate_range(name, value, min, max):
    try:
        if int(value) < min or int(value) > max:
            raise wsme.exc.ClientSideError(_(
                "Parameter '%s' must be between %d and %d.")
                % (name, min, max))
    except ValueError:
        raise wsme.exc.ClientSideError(_(
            "Parameter '%s' must be an integer value." % name))


def _validate_zero_or_range(name, value, min, max):
    try:
        if int(value) != 0:
            if int(value) < min or int(value) > max:
                raise wsme.exc.ClientSideError(_(
                    "Parameter '%s' must be zero or between %d and %d.")
                    % (name, min, max))
    except ValueError:
        raise wsme.exc.ClientSideError(_(
            "Parameter '%s' must be an integer value." % name))


def _validate_value_in_set(name, value, _set):
    if value not in _set:
        raise wsme.exc.ClientSideError(_(
            "Parameter '{}' must be{}: {}".format(
                name,
                " one of" if (len(_set) > 1) else "",
                ", ".join(_set))))


def _validate_token_expiry_time(name, value):
    """Check if timeout value is valid"""
    try:
        if int(value) < IDENTITY_CONFIG_TOKEN_EXPIRATION_MIN \
                or int(value) > IDENTITY_CONFIG_TOKEN_EXPIRATION_MAX:
            raise wsme.exc.ClientSideError(_(
                "Parameter '%s' must be between %d and %d seconds.")
                % (name, IDENTITY_CONFIG_TOKEN_EXPIRATION_MIN,
                   IDENTITY_CONFIG_TOKEN_EXPIRATION_MAX))
    except ValueError:
        raise wsme.exc.ClientSideError(_(
            "Parameter '%s' must be an integer value." % name))


def _validate_ip_address(name, value):
    """Check if ip value is valid"""
    if not cutils.is_valid_ip(value):
        raise wsme.exc.ClientSideError(_(
            "Parameter '%s' must be an IP address." % name))


def _validate_read_only(name, value):
    raise wsme.exc.ClientSideError(_(
        "Parameter '%s' is readonly" % name))


def _validate_SAN_list(name, value):
    """
    Validate list of Subject Alternative Name for x509 certificates. Each entry
    must be an IP address or domain name
    For example:
      "localhost.localdomain,192.168.204.2,controller"
    """
    san_entries = value.split(',')
    if len(san_entries) == 0:
        raise wsme.exc.ClientSideError(_(
            "No values provided for '%s'" % name))

    for entry in san_entries:
        if not cutils.is_valid_domain_or_ip(entry):
            raise wsme.exc.ClientSideError(_(
                "The value provided is not a domain name or IP address. (%s)"
                % entry))


def _validate_oidc_issuer_url(name, value):
    """Check if oidc issuer address is valid"""

    # is_valid_domain_or_ip does not work with entire urls
    # for example, the 'https://' needs to be removed
    parsed_value = urlparse(value)
    if not parsed_value.netloc or not cutils.is_valid_domain_or_ip(parsed_value.netloc):
        raise wsme.exc.ClientSideError(_(
            "Parameter '%s' must be a valid address or domain." % name))


def _deprecated_oidc_params(name, value):
    """Check oidc deprecated parameters"""
    msg = "This parameter '{}' is deprecated you must use a valid parameter like " \
          "(oidc-issuer-url, oidc-client-id, oidc-username-claim, oidc-groups-claim).".format(name)
    LOG.warning(msg)


def _validate_cri_class_format(name, value):
    """
    Validate string into cri runtimeClassName:runtimeBinary format,
    criHandler format: Alphanumeric plus underscore,
    criBinary format: Portable filename plus '/'.
    For example:
      "my_runtimeClassName:/usr/bin/my-runtimeBinary"
    """

    msg_example = "Example: my_runtimeClassName:/usr/bin/my-runtimeBinary\n"
    msg_format = " format: runtimeClassName:runtimeBinaryName\n"
    msg_runtimeBinaryName = "runtimeBinary: Portable filename plus \'/\'\n"
    msg_runtimeClassName = "runtimeClassName: Alphanumeric and underscore\n"

    if len(value) == 0:
        raise wsme.exc.ClientSideError(_(
            "syntax: custom_container_runtime=runtimeClassName:runtimeBinary"))
    for cri in value.split(','):
        try:
            criHandler, criBinary = cri.split(':')
        except ValueError:
            raise wsme.exc.ClientSideError(_(
                 "Parameter ValueError in %s"
                 % (name + msg_format + msg_runtimeClassName +
                     msg_runtimeBinaryName + msg_example)))

        if (len(criHandler) == 0 or
               (len(criBinary) == 0 or len(criBinary) > 4095)):
                    raise wsme.exc.ClientSideError(_(
                        "Parameter %s"
                        % (name + msg_format + msg_runtimeClassName +
                           msg_runtimeBinaryName + msg_example)))

        # criHandler format: Alphanumeric and underscore
        if len(re.findall(r"[^\w+]", criHandler)):
            raise wsme.exc.ClientSideError(_(
                "Parameter %s "
                % (name + msg_format + msg_runtimeClassName +
                   "Invalid Characters in runtimeClassName: " + criHandler +
                   "\n" + msg_example)))

        # criBinary format: Absolute path, portable filename
        if len(re.findall(r"^[^/]|[^a-zA-Z0-9-_./]|\/\.|\/$", criBinary)):
            raise wsme.exc.ClientSideError(_(
                "Parameter %s "
                % (name + msg_format + msg_runtimeBinaryName +
                   "Invalid Characters in runtimeBinaryName: " + criBinary +
                   "\n" + msg_example)))


def _get_network_pool_from_ip_address(ip, networks):
    for name in networks:
        try:
            network = pecan.request.dbapi.network_get_by_type(name)
        except exception.NetworkTypeNotFound:
            continue
        pool = pecan.request.dbapi.address_pool_get(network.pool_uuid)
        #
        # IP address in the pool's network?  If so, return the pool.
        #
        ipnet = netaddr.IPNetwork("%s/%u" % (pool["network"], pool["prefix"]))
        if ip in ipnet:
            return pool
    #
    # Pool not found.
    #
    return None


def _validate_worker_boot_timeout(name, value):
    _validate_range(name, value,
                    SERVICE_PARAM_PLAT_MTCE_WORKER_BOOT_TIMEOUT_MIN,
                    SERVICE_PARAM_PLAT_MTCE_WORKER_BOOT_TIMEOUT_MAX)


def _validate_controller_boot_timeout(name, value):
    _validate_range(name, value,
                    SERVICE_PARAM_PLAT_MTCE_CONTROLLER_BOOT_TIMEOUT_MIN,
                    SERVICE_PARAM_PLAT_MTCE_CONTROLLER_BOOT_TIMEOUT_MAX)


def _validate_hbs_period(name, value):
    _validate_range(name, value,
                    SERVICE_PARAM_PLAT_MTCE_HBS_PERIOD_MIN,
                    SERVICE_PARAM_PLAT_MTCE_HBS_PERIOD_MAX)


def _validate_hbs_failure_action(name, value):
    error = False
    try:
        if str(value) != SERVICE_PARAM_PLAT_MTCE_HBS_FAILURE_ACTION_FAIL and \
                str(value) != SERVICE_PARAM_PLAT_MTCE_HBS_FAILURE_ACTION_DEGRADE and \
                str(value) != SERVICE_PARAM_PLAT_MTCE_HBS_FAILURE_ACTION_ALARM and \
                str(value) != SERVICE_PARAM_PLAT_MTCE_HBS_FAILURE_ACTION_NONE:
            error = True

    except ValueError:
        error = True

    if error is True:
        raise wsme.exc.ClientSideError(_(
            "Action must be one of '%s', '%s', '%s' or '%s'" %
            (SERVICE_PARAM_PLAT_MTCE_HBS_FAILURE_ACTION_FAIL,
             SERVICE_PARAM_PLAT_MTCE_HBS_FAILURE_ACTION_DEGRADE,
             SERVICE_PARAM_PLAT_MTCE_HBS_FAILURE_ACTION_ALARM,
             SERVICE_PARAM_PLAT_MTCE_HBS_FAILURE_ACTION_NONE)))


def _validate_hbs_failure_threshold(name, value):
    _validate_range(name, value,
                    SERVICE_PARAM_PLAT_MTCE_HBS_FAILURE_THRESHOLD_MIN,
                    SERVICE_PARAM_PLAT_MTCE_HBS_FAILURE_THRESHOLD_MAX)


def _validate_hbs_degrade_threshold(name, value):
    _validate_range(name, value,
                    SERVICE_PARAM_PLAT_MTCE_HBS_DEGRADE_THRESHOLD_MIN,
                    SERVICE_PARAM_PLAT_MTCE_HBS_DEGRADE_THRESHOLD_MAX)


def _validate_mnfa_threshold(name, value):
    _validate_range(name, value,
                    SERVICE_PARAM_PLAT_MTCE_MNFA_THRESHOLD_MIN,
                    SERVICE_PARAM_PLAT_MTCE_MNFA_THRESHOLD_MAX)


def _validate_mnfa_timeout(name, value):
    # accept zero (no timeout) or a reasonable/tested specific range
    _validate_zero_or_range(name, value,
                    SERVICE_PARAM_PLAT_MTCE_MNFA_TIMEOUT_MIN,
                    SERVICE_PARAM_PLAT_MTCE_MNFA_TIMEOUT_MAX)


def _validate_ipv4(name, value):
    """Check if router_id value is valid"""
    if not netaddr.valid_ipv4(value):
        raise wsme.exc.ClientSideError(_(
            "Parameter '%s' must be a valid router_id." % name))


def _validate_mac_address(name, value):
    """Check if a given value is a valid MAC address."""
    try:
        if not netaddr.valid_mac(value):
            raise wsme.exc.ClientSideError(_(
                "Parameter '%s' must be a valid MAC address" % name))
        if not int(netaddr.EUI(value).oui):
            raise wsme.exc.ClientSideError(_(
                "Parameter '%s' must be a MAC address with a non-zero OUI" %
                name))
    except netaddr.core.NotRegisteredError:
        pass  # allow any OUI value regardless of registration


def _validate_radosgw_enabled(name, value):
    if not cutils.is_valid_boolstr(value):
        raise wsme.exc.ClientSideError(_(
            "Parameter '%s' must be a valid bool string." % name))


def _validate_docker_proxy_address(name, value):
    """Check if proxy value is valid"""
    if not cutils.is_url(value):
        raise wsme.exc.ClientSideError(_(
            "Parameter '%s' must be a valid address." % name))


def _validate_docker_no_proxy_address(name, value):
    """Check if no proxy value is valid"""
    values = value.split(',')
    for item in values:
        # will extend to more cases if CIDR notation is supported
        if not cutils.is_valid_domain_or_ip(item):
            raise wsme.exc.ClientSideError(_(
                "Parameter '%s' includes an invalid address '%s'." %
                (name, item)))


def _validate_docker_registry_address(name, value):
    """Check if registry address is valid"""
    if not cutils.is_valid_domain_or_ip(value):
        raise wsme.exc.ClientSideError(_(
            "Parameter '%s' must be a valid address." % name))


def _validate_docker_registry_auth_secret(name, value):
    """Check if registry auth secret is a valid UUID"""
    if not cutils.is_uuid_like(value):
        raise wsme.exc.ClientSideError(_(
            "Parameter '%s' must be a valid UUID." % name))


def _validate_docker_registry_type(name, value):
    """Check if registry type is supported or not"""
    if value not in [constants.DOCKER_REGISTRY_TYPE_DOCKER,
                     constants.DOCKER_REGISTRY_TYPE_AWS_ECR]:
        raise wsme.exc.ClientSideError(_(
            "%s is not supported. Parameter %s must be one of %s or %s") %
            (value, constants.DOCKER_REGISTRY_TYPE_DOCKER,
             constants.DOCKER_REGISTRY_TYPE_AWS_ECR))


def _validate_docker_insecure_registry_bool(name, value):
    """Check if insecure registry is a valid bool"""
    if not cutils.is_valid_boolstr(value):
        raise wsme.exc.ClientSideError(_(
            "Parameter '%s' must be a valid bool string." % name))


def _validate_domain(name, value):
    """Check if domain name is valid"""
    if not cutils.is_valid_domain_name(value):
        raise wsme.exc.ClientSideError(_(
            "Parameter '%s' includes an invalid domain name '%s'." %
            (name, value)))


def _validate_pod_max_pids(name, value):
    """Check if specified value is supported"""
    _validate_range(name, value,
                    constants.SERVICE_PARAM_KUBERNETES_POD_MAX_PIDS_MIN,
                    constants.SERVICE_PARAM_KUBERNETES_POD_MAX_PIDS_MAX)


def _validate_kernel_audit(name, value):
    """Check if specified value is supported"""
    try:
        if str(value) in [constants.SERVICE_PARAM_PLATFORM_AUDITD_DISABLED,
                          constants.SERVICE_PARAM_PLATFORM_AUDITD_ENABLED]:
            return
    except ValueError:
        pass

    raise wsme.exc.ClientSideError(_(
        "Parameter '%s' value must be either '%s' or '%s'" %
        (name, constants.SERVICE_PARAM_PLATFORM_AUDITD_DISABLED,
         constants.SERVICE_PARAM_PLATFORM_AUDITD_ENABLED)))


def _byte_transform(param_value, param_name):
    format1 = re.search(r"^(-*[0-9]+([\.][0-9]+)*)([B|K|M|G|T|P|E])$", str(param_value))
    format2 = re.search(r"^(0)$", str(param_value))

    if not (format1 or format2):
        raise wsme.exc.ClientSideError("Parameter '%s' has invalid value format." % param_name)

    if format1:
        size_greatness = format1.group(3)
        if format1.group(2):
            size_value = float(format1.group(1))
        else:
            size_value = int(format1.group(1))
        greatness_list = ['B', 'K', 'M', 'G', 'T', 'P', 'E']
        if size_greatness in greatness_list:
            index = greatness_list.index(size_greatness)
            size_in_bytes = (1024**index) * size_value
    else:
        size_in_bytes = int(format2.group(1))

    return size_in_bytes


def _validate_minimum_value(name, value, min_value):
    min_value_in_bytes = _byte_transform(min_value, name)
    if value < min_value_in_bytes:
        raise wsme.exc.ClientSideError(_(
            "Parameter '%s' must be greater than or equal to %s.") % (name, min_value))


def _validate_process_size_max(name, value):
    _validate_not_empty(name, value)
    size_in_bytes = _byte_transform(value, name)
    _validate_minimum_value(name, size_in_bytes,
                            constants.SERVICE_PARAM_PLAT_PROCESS_SIZE_MAX_MINSIZE)


def _validate_external_size_max(name, value):
    _validate_not_empty(name, value)
    size_in_bytes = _byte_transform(value, name)
    _validate_minimum_value(name, size_in_bytes,
                            constants.SERVICE_PARAM_PLAT_EXTERNAL_SIZE_MAX_MINSIZE)


def _validate_max_use(name, value):
    _validate_not_empty(name, value)
    size_in_bytes = _byte_transform(value, name)
    _validate_minimum_value(name, size_in_bytes,
                            constants.SERVICE_PARAM_PLAT_MAX_USE_MINSIZE)


def _validate_keep_free(name, value):
    _validate_not_empty(name, value)
    size_in_bytes = _byte_transform(value, name)
    _validate_minimum_value(name, size_in_bytes,
                            constants.SERVICE_PARAM_PLAT_KEEP_FREE_MINSIZE)


def _validate_regex(name, value):
    """Check if specified regex is valid"""
    try:
        re.compile(value)
    except re.error:
        raise wsme.exc.ClientSideError(_(
            "Parameter %s must be a valid regex" % name))


def _validate_auth_id_reclaim_enabled(name, value):
    if not StorageBackendConfig.has_backend_configured(
            pecan.request.dbapi,
            constants.CINDER_BACKEND_CEPH):
        raise wsme.exc.ClientSideError(_(
            "A Ceph backend must be configured before trying to set '%s' parameter." %
            name))
    if not cutils.is_valid_boolstr(value):
        raise wsme.exc.ClientSideError(_(
            "Parameter '%s' must be a valid bool string." % name))


def _validate_max_cpu_min_percentage(name, value):
    return _validate_range(name, value, 60, 100)


PLATFORM_CONFIG_PARAMETER_OPTIONAL = [
    constants.SERVICE_PARAM_NAME_PLAT_CONFIG_VIRTUAL,
    constants.SERVICE_PARAM_NAME_PLATFORM_MAX_CPU_PERCENTAGE,
]

PLATFORM_CONFIG_PARAMETER_READONLY = [
    constants.SERVICE_PARAM_NAME_PLAT_CONFIG_VIRTUAL,
]

PLATFORM_CONFIG_PARAMETER_VALIDATOR = {
    constants.SERVICE_PARAM_NAME_PLAT_CONFIG_VIRTUAL:
        _validate_boolean,
    constants.SERVICE_PARAM_NAME_PLATFORM_MAX_CPU_PERCENTAGE:
        _validate_max_cpu_min_percentage
}

PLATFORM_CONFIG_PARAMETER_RESOURCE = {
    constants.SERVICE_PARAM_NAME_PLAT_CONFIG_VIRTUAL: 'platform::params::virtual_system',
}

IDENTITY_CONFIG_PARAMETER_OPTIONAL = [
    constants.SERVICE_PARAM_IDENTITY_CONFIG_TOKEN_EXPIRATION,
]

IDENTITY_CONFIG_PARAMETER_VALIDATOR = {
    constants.SERVICE_PARAM_IDENTITY_CONFIG_TOKEN_EXPIRATION:
        _validate_token_expiry_time,
}

IDENTITY_CONFIG_PARAMETER_RESOURCE = {
    constants.SERVICE_PARAM_IDENTITY_CONFIG_TOKEN_EXPIRATION: 'openstack::keystone::params::token_expiration',
}

# Maintenance Service Parameters
PLATFORM_MTCE_PARAMETER_MANDATORY = [
    constants.SERVICE_PARAM_PLAT_MTCE_WORKER_BOOT_TIMEOUT,
    constants.SERVICE_PARAM_PLAT_MTCE_CONTROLLER_BOOT_TIMEOUT,
    constants.SERVICE_PARAM_PLAT_MTCE_HBS_PERIOD,
    constants.SERVICE_PARAM_PLAT_MTCE_HBS_FAILURE_ACTION,
    constants.SERVICE_PARAM_PLAT_MTCE_HBS_FAILURE_THRESHOLD,
    constants.SERVICE_PARAM_PLAT_MTCE_HBS_DEGRADE_THRESHOLD,
    constants.SERVICE_PARAM_PLAT_MTCE_MNFA_THRESHOLD,
    constants.SERVICE_PARAM_PLAT_MTCE_MNFA_TIMEOUT,
]

PLATFORM_SYSINV_PARAMETER_PROTECTED = ['firewall_rules_id']

PLATFORM_CRI_PARAMETER_OPTIONAL = [
    constants.SERVICE_PARAM_NAME_PLATFORM_CRI_RUNTIME_CLASS,
]

PLATFORM_CRI_PARAMETER_VALIDATOR = {
    constants.SERVICE_PARAM_NAME_PLATFORM_CRI_RUNTIME_CLASS:
        _validate_cri_class_format,
}

PLATFORM_CRI_PARAMETER_RESOURCE = {
    constants.SERVICE_PARAM_NAME_PLATFORM_CRI_RUNTIME_CLASS:
        'platform::containerd::params::custom_container_runtime',
}

PLATFORM_CRI_PARAMETER_DATA_FORMAT = {
    constants.SERVICE_PARAM_NAME_PLATFORM_CRI_RUNTIME_CLASS:
        SERVICE_PARAMETER_DATA_FORMAT_DICT,
}

SERVICE_PARAM_PLAT_MTCE_WORKER_BOOT_TIMEOUT_MIN = 720
SERVICE_PARAM_PLAT_MTCE_WORKER_BOOT_TIMEOUT_MAX = 1800
SERVICE_PARAM_PLAT_MTCE_CONTROLLER_BOOT_TIMEOUT_MIN = 1200
SERVICE_PARAM_PLAT_MTCE_CONTROLLER_BOOT_TIMEOUT_MAX = 1800
SERVICE_PARAM_PLAT_MTCE_HBS_PERIOD_MIN = 100
SERVICE_PARAM_PLAT_MTCE_HBS_PERIOD_MAX = 1000
SERVICE_PARAM_PLAT_MTCE_HBS_FAILURE_THRESHOLD_MIN = 10
SERVICE_PARAM_PLAT_MTCE_HBS_FAILURE_THRESHOLD_MAX = 100
SERVICE_PARAM_PLAT_MTCE_HBS_DEGRADE_THRESHOLD_MIN = 4
SERVICE_PARAM_PLAT_MTCE_HBS_DEGRADE_THRESHOLD_MAX = 100
SERVICE_PARAM_PLAT_MTCE_HBS_FAILURE_ACTION_FAIL = 'fail'
SERVICE_PARAM_PLAT_MTCE_HBS_FAILURE_ACTION_DEGRADE = 'degrade'
SERVICE_PARAM_PLAT_MTCE_HBS_FAILURE_ACTION_ALARM = 'alarm'
SERVICE_PARAM_PLAT_MTCE_HBS_FAILURE_ACTION_NONE = 'none'
SERVICE_PARAM_PLAT_MTCE_MNFA_THRESHOLD_MIN = 2
SERVICE_PARAM_PLAT_MTCE_MNFA_THRESHOLD_MAX = 100
SERVICE_PARAM_PLAT_MTCE_MNFA_TIMEOUT_MIN = 100
SERVICE_PARAM_PLAT_MTCE_MNFA_TIMEOUT_MAX = 86400


PLATFORM_MTCE_PARAMETER_VALIDATOR = {
    constants.SERVICE_PARAM_PLAT_MTCE_WORKER_BOOT_TIMEOUT:
        _validate_worker_boot_timeout,
    constants.SERVICE_PARAM_PLAT_MTCE_CONTROLLER_BOOT_TIMEOUT:
        _validate_controller_boot_timeout,
    constants.SERVICE_PARAM_PLAT_MTCE_HBS_PERIOD:
        _validate_hbs_period,
    constants.SERVICE_PARAM_PLAT_MTCE_HBS_FAILURE_ACTION:
        _validate_hbs_failure_action,
    constants.SERVICE_PARAM_PLAT_MTCE_HBS_FAILURE_THRESHOLD:
        _validate_hbs_failure_threshold,
    constants.SERVICE_PARAM_PLAT_MTCE_HBS_DEGRADE_THRESHOLD:
        _validate_hbs_degrade_threshold,
    constants.SERVICE_PARAM_PLAT_MTCE_MNFA_THRESHOLD:
        _validate_mnfa_threshold,
    constants.SERVICE_PARAM_PLAT_MTCE_MNFA_TIMEOUT:
        _validate_mnfa_timeout,
}

PLATFORM_MTCE_PARAMETER_RESOURCE = {
    constants.SERVICE_PARAM_PLAT_MTCE_WORKER_BOOT_TIMEOUT: 'platform::mtce::params::worker_boot_timeout',
    constants.SERVICE_PARAM_PLAT_MTCE_CONTROLLER_BOOT_TIMEOUT: 'platform::mtce::params::controller_boot_timeout',
    constants.SERVICE_PARAM_PLAT_MTCE_HBS_PERIOD: 'platform::mtce::params::heartbeat_period',
    constants.SERVICE_PARAM_PLAT_MTCE_HBS_FAILURE_ACTION: 'platform::mtce::params::heartbeat_failure_action',
    constants.SERVICE_PARAM_PLAT_MTCE_HBS_FAILURE_THRESHOLD: 'platform::mtce::params::heartbeat_failure_threshold',
    constants.SERVICE_PARAM_PLAT_MTCE_HBS_DEGRADE_THRESHOLD: 'platform::mtce::params::heartbeat_degrade_threshold',
    constants.SERVICE_PARAM_PLAT_MTCE_MNFA_THRESHOLD: 'platform::mtce::params::mnfa_threshold',
    constants.SERVICE_PARAM_PLAT_MTCE_MNFA_TIMEOUT: 'platform::mtce::params::mnfa_timeout',
}

PLATFORM_KERNEL_PARAMETER_OPTIONAL = [
    constants.SERVICE_PARAM_NAME_PLATFORM_AUDITD,
]

PLATFORM_KEYSTONE_PARAMETER_OPTIONAL = [
    constants.SERVICE_PARAM_NAME_SECURITY_COMPLIANCE_UNIQUE_LAST_PASSWORD_COUNT,
    constants.SERVICE_PARAM_NAME_SECURITY_COMPLIANCE_PASSWORD_REGEX,
    constants.SERVICE_PARAM_NAME_SECURITY_COMPLIANCE_PASSWORD_REGEX_DESCRIPTION,
    constants.SERVICE_PARAM_NAME_SECURITY_COMPLIANCE_LOCKOUT_DURATION,
    constants.SERVICE_PARAM_NAME_SECURITY_COMPLIANCE_LOCKOUT_FAILURE_ATTEMPTS,
]

PLATFORM_COREDUMP_PARAMETER_OPTIONAL = [
    constants.SERVICE_PARAM_NAME_PLATFORM_PROCESS_SIZE_MAX,
    constants.SERVICE_PARAM_NAME_PLATFORM_EXTERNAL_SIZE_MAX,
    constants.SERVICE_PARAM_NAME_PLATFORM_MAX_USE,
    constants.SERVICE_PARAM_NAME_PLATFORM_KEEP_FREE
]

PLATFORM_KERNEL_PARAMETER_VALIDATOR = {
    constants.SERVICE_PARAM_NAME_PLATFORM_AUDITD: _validate_kernel_audit,
}

PLATFORM_KEYSTONE_PARAMETER_VALIDATOR = {
    constants.SERVICE_PARAM_NAME_SECURITY_COMPLIANCE_UNIQUE_LAST_PASSWORD_COUNT:
        _validate_zero_or_positive_integer,
    constants.SERVICE_PARAM_NAME_SECURITY_COMPLIANCE_PASSWORD_REGEX:
        _validate_regex,
    constants.SERVICE_PARAM_NAME_SECURITY_COMPLIANCE_PASSWORD_REGEX_DESCRIPTION:
        _validate_not_empty,
    constants.SERVICE_PARAM_NAME_SECURITY_COMPLIANCE_LOCKOUT_DURATION:
        _validate_integer,
    constants.SERVICE_PARAM_NAME_SECURITY_COMPLIANCE_LOCKOUT_FAILURE_ATTEMPTS:
        _validate_integer,
}

PLATFORM_COREDUMP_PARAMETER_VALIDATOR = {
    constants.SERVICE_PARAM_NAME_PLATFORM_PROCESS_SIZE_MAX: _validate_process_size_max,
    constants.SERVICE_PARAM_NAME_PLATFORM_EXTERNAL_SIZE_MAX: _validate_external_size_max,
    constants.SERVICE_PARAM_NAME_PLATFORM_MAX_USE: _validate_max_use,
    constants.SERVICE_PARAM_NAME_PLATFORM_KEEP_FREE: _validate_keep_free,
}

PLATFORM_KERNEL_PARAMETER_RESOURCE = {
    constants.SERVICE_PARAM_NAME_PLATFORM_AUDITD:
        'platform::compute::grub::params::g_audit',
}

PLATFORM_KEYSTONE_PARAMETER_RESOURCE = {
    constants.SERVICE_PARAM_NAME_SECURITY_COMPLIANCE_UNIQUE_LAST_PASSWORD_COUNT:
        'keystone::security_compliance::unique_last_password_count',
    constants.SERVICE_PARAM_NAME_SECURITY_COMPLIANCE_PASSWORD_REGEX:
        'keystone::security_compliance::password_regex',
    constants.SERVICE_PARAM_NAME_SECURITY_COMPLIANCE_PASSWORD_REGEX_DESCRIPTION:
        'keystone::security_compliance::password_regex_description',
    constants.SERVICE_PARAM_NAME_SECURITY_COMPLIANCE_LOCKOUT_DURATION:
        'openstack::keystone::params::lockout_period',
    constants.SERVICE_PARAM_NAME_SECURITY_COMPLIANCE_LOCKOUT_FAILURE_ATTEMPTS:
        'openstack::keystone::params::lockout_retries',
}

PLATFORM_COREDUMP_PARAMETER_RESOURCE = {
    constants.SERVICE_PARAM_NAME_PLATFORM_PROCESS_SIZE_MAX:
        'platform::coredump::params::process_size_max',
    constants.SERVICE_PARAM_NAME_PLATFORM_EXTERNAL_SIZE_MAX:
        'platform::coredump::params::external_size_max',
    constants.SERVICE_PARAM_NAME_PLATFORM_MAX_USE:
        'platform::coredump::params::max_use',
    constants.SERVICE_PARAM_NAME_PLATFORM_KEEP_FREE:
        'platform::coredump::params::keep_free',
}

RADOSGW_CONFIG_PARAMETER_MANDATORY = [
    constants.SERVICE_PARAM_NAME_RADOSGW_SERVICE_ENABLED,
]

RADOSGW_CONFIG_PARAMETER_OPTIONAL = [
    constants.SERVICE_PARAM_NAME_RADOSGW_FS_SIZE_MB,
]

RADOSGW_CONFIG_PARAMETER_VALIDATOR = {
    constants.SERVICE_PARAM_NAME_RADOSGW_SERVICE_ENABLED: _validate_radosgw_enabled,
    constants.SERVICE_PARAM_NAME_RADOSGW_FS_SIZE_MB: _validate_integer,
}

RADOSGW_CONFIG_PARAMETER_RESOURCE = {
    constants.SERVICE_PARAM_NAME_RADOSGW_SERVICE_ENABLED:
        'openstack::radosgw::params::service_enabled',
    constants.SERVICE_PARAM_NAME_RADOSGW_FS_SIZE_MB:
        'openstack::radosgw::params::fs_size_mb',
}

RADOSGW_CONFIG_PARAMETER_DATA_FORMAT = {
    constants.SERVICE_PARAM_NAME_RADOSGW_SERVICE_ENABLED: SERVICE_PARAMETER_DATA_FORMAT_BOOLEAN,
}

DOCKER_PROXY_PARAMETER_OPTIONAL = [
    constants.SERVICE_PARAM_NAME_DOCKER_HTTP_PROXY,
    constants.SERVICE_PARAM_NAME_DOCKER_HTTPS_PROXY,
    constants.SERVICE_PARAM_NAME_DOCKER_NO_PROXY,
]

DOCKER_PROXY_PARAMETER_VALIDATOR = {
    constants.SERVICE_PARAM_NAME_DOCKER_HTTP_PROXY: _validate_docker_proxy_address,
    constants.SERVICE_PARAM_NAME_DOCKER_HTTPS_PROXY: _validate_docker_proxy_address,
    constants.SERVICE_PARAM_NAME_DOCKER_NO_PROXY: _validate_docker_no_proxy_address,
}

DOCKER_PROXY_PARAMETER_RESOURCE = {
    constants.SERVICE_PARAM_NAME_DOCKER_HTTP_PROXY:
        'platform::docker::params::http_proxy',
    constants.SERVICE_PARAM_NAME_DOCKER_HTTPS_PROXY:
        'platform::docker::params::https_proxy',
    constants.SERVICE_PARAM_NAME_DOCKER_NO_PROXY:
        'platform::docker::params::no_proxy',
}

DOCKER_REGISTRIES_PARAMETER_OPTIONAL = [
    constants.SERVICE_PARAM_NAME_DOCKER_URL,
    constants.SERVICE_PARAM_NAME_DOCKER_AUTH_SECRET,
    constants.SERVICE_PARAM_NAME_DOCKER_TYPE,
    constants.SERVICE_PARAM_NAME_DOCKER_ADDITIONAL_OVERRIDES,
    constants.SERVICE_PARAM_NAME_DOCKER_SECURE_REGISTRY
]

DOCKER_REGISTRIES_PARAMETER_VALIDATOR = {
    constants.SERVICE_PARAM_NAME_DOCKER_URL: _validate_docker_registry_address,
    constants.SERVICE_PARAM_NAME_DOCKER_AUTH_SECRET: _validate_docker_registry_auth_secret,
    constants.SERVICE_PARAM_NAME_DOCKER_TYPE: _validate_docker_registry_type,
    constants.SERVICE_PARAM_NAME_DOCKER_ADDITIONAL_OVERRIDES: _validate_docker_registry_address,
    constants.SERVICE_PARAM_NAME_DOCKER_SECURE_REGISTRY: _validate_docker_insecure_registry_bool
}

DOCKER_DOCKER_REGISTRY_PARAMETER_RESOURCE = {
    constants.SERVICE_PARAM_NAME_DOCKER_URL:
        'platform::docker::params::docker_registry',
    constants.SERVICE_PARAM_NAME_DOCKER_SECURE_REGISTRY:
        'platform::docker::params::docker_registry_secure',
}

DOCKER_GCR_REGISTRY_PARAMETER_RESOURCE = {
    constants.SERVICE_PARAM_NAME_DOCKER_URL:
        'platform::docker::params::gcr_registry',
    constants.SERVICE_PARAM_NAME_DOCKER_SECURE_REGISTRY:
        'platform::docker::params::gcr_registry_secure',
}

DOCKER_K8S_REGISTRY_PARAMETER_RESOURCE = {
    constants.SERVICE_PARAM_NAME_DOCKER_URL:
        'platform::docker::params::k8s_registry',
    constants.SERVICE_PARAM_NAME_DOCKER_SECURE_REGISTRY:
        'platform::docker::params::k8s_registry_secure',
}

DOCKER_QUAY_REGISTRY_PARAMETER_RESOURCE = {
    constants.SERVICE_PARAM_NAME_DOCKER_URL:
        'platform::docker::params::quay_registry',
    constants.SERVICE_PARAM_NAME_DOCKER_SECURE_REGISTRY:
        'platform::docker::params::quay_registry_secure',
}

DOCKER_ELASTIC_REGISTRY_PARAMETER_RESOURCE = {
    constants.SERVICE_PARAM_NAME_DOCKER_URL:
        'platform::docker::params::elastic_registry',
    constants.SERVICE_PARAM_NAME_DOCKER_SECURE_REGISTRY:
        'platform::docker::params::elastic_registry_secure',
}

DOCKER_GHCR_REGISTRY_PARAMETER_RESOURCE = {
    constants.SERVICE_PARAM_NAME_DOCKER_URL:
        'platform::docker::params::ghcr_registry',
    constants.SERVICE_PARAM_NAME_DOCKER_SECURE_REGISTRY:
        'platform::docker::params::ghcr_registry_secure',
}

KUBERNETES_CERTIFICATES_PARAMETER_OPTIONAL = [
    constants.SERVICE_PARAM_NAME_KUBERNETES_API_SAN_LIST,
]

KUBERNETES_CERTIFICATES_PARAMETER_VALIDATOR = {
    constants.SERVICE_PARAM_NAME_KUBERNETES_API_SAN_LIST: _validate_SAN_list,
}

KUBERNETES_CERTIFICATES_PARAMETER_RESOURCE = {
    constants.SERVICE_PARAM_NAME_KUBERNETES_API_SAN_LIST:
        'platform::kubernetes::params::apiserver_cert_san',
}

KUBERNETES_CERTIFICATES_PARAMETER_DATA_FORMAT = {
    constants.SERVICE_PARAM_NAME_KUBERNETES_API_SAN_LIST: SERVICE_PARAMETER_DATA_FORMAT_ARRAY,
}

KUBERNETES_CONFIG_PARAMETER_OPTIONAL = [
    constants.SERVICE_PARAM_NAME_KUBERNETES_POD_MAX_PIDS,
    constants.SERVICE_PARAM_NAME_KUBERNETES_AUTOMATIC_RECOVERY
]

KUBERNETES_CONFIG_PARAMETER_VALIDATOR = {
    constants.SERVICE_PARAM_NAME_KUBERNETES_POD_MAX_PIDS: _validate_pod_max_pids,
    constants.SERVICE_PARAM_NAME_KUBERNETES_AUTOMATIC_RECOVERY: _validate_boolean
}

KUBERNETES_CONFIG_PARAMETER_RESOURCE = {
    constants.SERVICE_PARAM_NAME_KUBERNETES_POD_MAX_PIDS:
        'platform::kubernetes::params::k8s_pod_max_pids',
    constants.SERVICE_PARAM_NAME_KUBERNETES_AUTOMATIC_RECOVERY:
        'platform::kubernetes::config::params::automatic_recovery',
}

KUBERNETES_APISERVER_PARAMETER_OPTIONAL = [
    constants.SERVICE_PARAM_NAME_OIDC_ISSUER_URL,
    constants.SERVICE_PARAM_NAME_OIDC_CLIENT_ID,
    constants.SERVICE_PARAM_NAME_OIDC_USERNAME_CLAIM,
    constants.SERVICE_PARAM_NAME_OIDC_GROUPS_CLAIM,
    constants.SERVICE_PARAM_NAME_AUDIT_POLICY_FILE,
    constants.SERVICE_PARAM_NAME_WILDCARD,
]

KUBERNETES_APISERVER_PARAMETER_VALIDATOR = {
    constants.SERVICE_PARAM_NAME_OIDC_ISSUER_URL: _validate_oidc_issuer_url,
    constants.SERVICE_PARAM_DEPRECATED_NAME_OIDC_ISSUER_URL: _deprecated_oidc_params,
    constants.SERVICE_PARAM_DEPRECATED_NAME_OIDC_CLIENT_ID: _deprecated_oidc_params,
    constants.SERVICE_PARAM_DEPRECATED_NAME_OIDC_USERNAME_CLAIM: _deprecated_oidc_params,
    constants.SERVICE_PARAM_DEPRECATED_NAME_OIDC_GROUPS_CLAIM: _deprecated_oidc_params,
    constants.SERVICE_PARAM_NAME_WILDCARD: _validate_not_empty,
    constants.SERVICE_PARAM_NAME_AUDIT_POLICY_FILE: _validate_not_empty
}

KUBERNETES_APISERVER_PARAMETER_RESOURCE = {
    constants.SERVICE_PARAM_NAME_OIDC_ISSUER_URL:
        'platform::kubernetes::kube_apiserver::params::oidc_issuer_url',
    constants.SERVICE_PARAM_NAME_OIDC_CLIENT_ID:
        'platform::kubernetes::kube_apiserver::params::oidc_client_id',
    constants.SERVICE_PARAM_NAME_OIDC_USERNAME_CLAIM:
        'platform::kubernetes::kube_apiserver::params::oidc_username_claim',
    constants.SERVICE_PARAM_NAME_OIDC_GROUPS_CLAIM:
        'platform::kubernetes::kube_apiserver::params::oidc_groups_claim',
    constants.SERVICE_PARAM_NAME_WILDCARD:
        'platform::kubernetes::kube_apiserver::params',
    constants.SERVICE_PARAM_NAME_AUDIT_POLICY_FILE:
        'platform::kubernetes::params::audit_policy_file'
}

KUBERNETES_CONTROLLER_MANAGER_PARAMETER_OPTIONAL = [
    constants.SERVICE_PARAM_NAME_OIDC_ISSUER_URL,
    constants.SERVICE_PARAM_NAME_OIDC_CLIENT_ID,
    constants.SERVICE_PARAM_NAME_OIDC_USERNAME_CLAIM,
    constants.SERVICE_PARAM_NAME_OIDC_GROUPS_CLAIM,
    constants.SERVICE_PARAM_NAME_WILDCARD
]

KUBERNETES_CONTROLLER_MANAGER_PARAMETER_VALIDATOR = {
    constants.SERVICE_PARAM_NAME_WILDCARD: _validate_not_empty
}

KUBERNETES_CONTROLLER_MANAGER_PARAMETER_RESOURCE = {
    constants.SERVICE_PARAM_NAME_WILDCARD:
        'platform::kubernetes::kube_controller_manager::params',
}

KUBERNETES_SCHEDULER_PARAMETER_OPTIONAL = [
    constants.SERVICE_PARAM_NAME_WILDCARD
]

KUBERNETES_SCHEDULER_PARAMETER_VALIDATOR = {
    constants.SERVICE_PARAM_NAME_WILDCARD: _validate_not_empty
}

KUBERNETES_SCHEDULER_PARAMETER_RESOURCE = {
    constants.SERVICE_PARAM_NAME_WILDCARD:
        'platform::kubernetes::kube_scheduler::params',
}

KUBERNETES_KUBELET_PARAMETER_OPTIONAL = [
    constants.SERVICE_PARAM_NAME_WILDCARD
]

KUBERNETES_KUBELET_PARAMETER_VALIDATOR = {
    constants.SERVICE_PARAM_NAME_WILDCARD: _validate_not_empty
}

KUBERNETES_KUBELET_PARAMETER_RESOURCE = {
    constants.SERVICE_PARAM_NAME_WILDCARD:
        'platform::kubernetes::kubelet::params',
}

HTTPD_PORT_PARAMETER_OPTIONAL = [
    constants.SERVICE_PARAM_HTTP_PORT_HTTP,
    constants.SERVICE_PARAM_HTTP_PORT_HTTPS,
]

HTTPD_PORT_PARAMETER_VALIDATOR = {
    constants.SERVICE_PARAM_HTTP_PORT_HTTP: _validate_integer,
    constants.SERVICE_PARAM_HTTP_PORT_HTTPS: _validate_integer,
}

HTTPD_PORT_PARAMETER_RESOURCE = {
    constants.SERVICE_PARAM_HTTP_PORT_HTTP:
        'openstack::horizon::params::http_port',
    constants.SERVICE_PARAM_HTTP_PORT_HTTPS:
        'openstack::horizon::params::https_port',
}

OPENSTACK_HELM_PARAMETER_OPTIONAL = [
    constants.SERVICE_PARAM_NAME_ENDPOINT_DOMAIN,
]
OPENSTACK_HELM_PARAMETER_VALIDATOR = {
    constants.SERVICE_PARAM_NAME_ENDPOINT_DOMAIN: _validate_domain,
}
OPENSTACK_HELM_PARAMETER_RESOURCE = {
    constants.SERVICE_PARAM_NAME_ENDPOINT_DOMAIN:
        'openstack::helm::params::endpoint_domain',
}


COLLECTD_NETWORK_SERVERS_PARAMETER_DATA_FORMAT = {
    constants.SERVICE_PARAM_COLLECTD_NETWORK_SERVERS:
        SERVICE_PARAMETER_DATA_FORMAT_ARRAY,
}

COLLECTD_PARAMETER_OPTIONAL = [
    constants.SERVICE_PARAM_COLLECTD_NETWORK_SERVERS,
]

COLLECTD_PARAMETER_VALIDATOR = {
    constants.SERVICE_PARAM_COLLECTD_NETWORK_SERVERS:
        _validate_SAN_list,
}

COLLECTD_PARAMETER_RESOURCE = {
    constants.SERVICE_PARAM_COLLECTD_NETWORK_SERVERS:
        'platform::collectd::params::network_servers',
}

PTP_GLOBAL_PARAMETER_OPTIONAL = [
    constants.SERVICE_PARAM_NAME_WILDCARD
]

PTP_GLOBAL_PARAMETER_VALIDATOR = {
    constants.SERVICE_PARAM_NAME_WILDCARD: _validate_not_empty
}

PTP_PHC2SYS_PARAMETER_OPTIONAL = [
    constants.SERVICE_PARAM_NAME_PTP_UPDATE_RATE,
    constants.SERVICE_PARAM_NAME_PTP_SUMMARY_UPDATES
]

PTP_PHC2SYS_PARAMETER_VALIDATOR = {
    constants.SERVICE_PARAM_NAME_PTP_UPDATE_RATE: _validate_float,
    # phc2sys summary-updates accepts a range of 0 to UNIT_MAX (ie 2^32 - 1)
    constants.SERVICE_PARAM_NAME_PTP_SUMMARY_UPDATES: lambda name, value: _validate_range(name, value, 0, 2 ** 32 - 1)
}

CEPH_MONITOR_PARAMETER_OPTIONAL = [
    constants.SERVICE_PARAM_NAME_CEPH_MONITOR_AUTH_ID_RECLAIM
]

CEPH_MONITOR_PARAMETER_VALIDATOR = {
    constants.SERVICE_PARAM_NAME_CEPH_MONITOR_AUTH_ID_RECLAIM: _validate_auth_id_reclaim_enabled,
}

CEPH_MONITOR_PARAMETER_RESOURCE = {
    constants.SERVICE_PARAM_NAME_CEPH_MONITOR_AUTH_ID_RECLAIM:
        'platform::ceph::params::auth_id_reclaim',
}

CEPH_MONITOR_PARAMETER_DATA_FORMAT = {
    constants.SERVICE_PARAM_NAME_CEPH_MONITOR_AUTH_ID_RECLAIM: SERVICE_PARAMETER_DATA_FORMAT_BOOLEAN,
}

# Service Parameter Schema
SERVICE_PARAM_MANDATORY = 'mandatory'
SERVICE_PARAM_OPTIONAL = 'optional'
SERVICE_PARAM_VALIDATOR = 'validator'
SERVICE_PARAM_RESOURCE = 'resource'
SERVICE_PARAM_DATA_FORMAT = 'format'
SERVICE_PARAM_READONLY = 'readonly'

SERVICE_PARAM_PROTECTED = 'protected'
SERVICE_VALUE_PROTECTION_MASK = "****"


SERVICE_PARAMETER_SCHEMA = {
    constants.SERVICE_TYPE_IDENTITY: {
        constants.SERVICE_PARAM_SECTION_IDENTITY_CONFIG: {
            SERVICE_PARAM_OPTIONAL: IDENTITY_CONFIG_PARAMETER_OPTIONAL,
            SERVICE_PARAM_VALIDATOR: IDENTITY_CONFIG_PARAMETER_VALIDATOR,
            SERVICE_PARAM_RESOURCE: IDENTITY_CONFIG_PARAMETER_RESOURCE,
        },
        constants.SERVICE_PARAM_SECTION_SECURITY_COMPLIANCE: {
            SERVICE_PARAM_OPTIONAL: PLATFORM_KEYSTONE_PARAMETER_OPTIONAL,
            SERVICE_PARAM_VALIDATOR: PLATFORM_KEYSTONE_PARAMETER_VALIDATOR,
            SERVICE_PARAM_RESOURCE: PLATFORM_KEYSTONE_PARAMETER_RESOURCE,
        }
    },
    constants.SERVICE_TYPE_PLATFORM: {
        constants.SERVICE_PARAM_SECTION_PLATFORM_CONFIG: {
            SERVICE_PARAM_OPTIONAL: PLATFORM_CONFIG_PARAMETER_OPTIONAL,
            SERVICE_PARAM_VALIDATOR: PLATFORM_CONFIG_PARAMETER_VALIDATOR,
            SERVICE_PARAM_RESOURCE: PLATFORM_CONFIG_PARAMETER_RESOURCE,
            SERVICE_PARAM_READONLY: PLATFORM_CONFIG_PARAMETER_READONLY,
        },
        constants.SERVICE_PARAM_SECTION_PLATFORM_MAINTENANCE: {
            SERVICE_PARAM_MANDATORY: PLATFORM_MTCE_PARAMETER_MANDATORY,
            SERVICE_PARAM_VALIDATOR: PLATFORM_MTCE_PARAMETER_VALIDATOR,
            SERVICE_PARAM_RESOURCE: PLATFORM_MTCE_PARAMETER_RESOURCE,
        },
        constants.SERVICE_PARAM_SECTION_PLATFORM_SYSINV: {
            SERVICE_PARAM_PROTECTED: PLATFORM_SYSINV_PARAMETER_PROTECTED,
        },
        constants.SERVICE_PARAM_SECTION_PLATFORM_CRI_RUNTIME_CLASS: {
            SERVICE_PARAM_OPTIONAL: PLATFORM_CRI_PARAMETER_OPTIONAL,
            SERVICE_PARAM_VALIDATOR: PLATFORM_CRI_PARAMETER_VALIDATOR,
            SERVICE_PARAM_DATA_FORMAT: PLATFORM_CRI_PARAMETER_DATA_FORMAT,
            SERVICE_PARAM_RESOURCE: PLATFORM_CRI_PARAMETER_RESOURCE,
        },
        constants.SERVICE_PARAM_SECTION_COLLECTD: {
            SERVICE_PARAM_OPTIONAL: COLLECTD_PARAMETER_OPTIONAL,
            SERVICE_PARAM_VALIDATOR: COLLECTD_PARAMETER_VALIDATOR,
            SERVICE_PARAM_RESOURCE: COLLECTD_PARAMETER_RESOURCE,
            SERVICE_PARAM_DATA_FORMAT: COLLECTD_NETWORK_SERVERS_PARAMETER_DATA_FORMAT,
        },
        constants.SERVICE_PARAM_SECTION_PLATFORM_KERNEL: {
            SERVICE_PARAM_OPTIONAL: PLATFORM_KERNEL_PARAMETER_OPTIONAL,
            SERVICE_PARAM_VALIDATOR: PLATFORM_KERNEL_PARAMETER_VALIDATOR,
            SERVICE_PARAM_RESOURCE: PLATFORM_KERNEL_PARAMETER_RESOURCE,
        },
        constants.SERVICE_PARAM_SECTION_PLATFORM_COREDUMP: {
            SERVICE_PARAM_OPTIONAL: PLATFORM_COREDUMP_PARAMETER_OPTIONAL,
            SERVICE_PARAM_VALIDATOR: PLATFORM_COREDUMP_PARAMETER_VALIDATOR,
            SERVICE_PARAM_RESOURCE: PLATFORM_COREDUMP_PARAMETER_RESOURCE,
        },
    },
    constants.SERVICE_TYPE_RADOSGW: {
        constants.SERVICE_PARAM_SECTION_RADOSGW_CONFIG: {
            SERVICE_PARAM_MANDATORY: RADOSGW_CONFIG_PARAMETER_MANDATORY,
            SERVICE_PARAM_OPTIONAL: RADOSGW_CONFIG_PARAMETER_OPTIONAL,
            SERVICE_PARAM_VALIDATOR: RADOSGW_CONFIG_PARAMETER_VALIDATOR,
            SERVICE_PARAM_RESOURCE: RADOSGW_CONFIG_PARAMETER_RESOURCE,
            SERVICE_PARAM_DATA_FORMAT: RADOSGW_CONFIG_PARAMETER_DATA_FORMAT,
        },
    },
    constants.SERVICE_TYPE_DOCKER: {
        constants.SERVICE_PARAM_SECTION_DOCKER_PROXY: {
            SERVICE_PARAM_OPTIONAL: DOCKER_PROXY_PARAMETER_OPTIONAL,
            SERVICE_PARAM_VALIDATOR: DOCKER_PROXY_PARAMETER_VALIDATOR,
            SERVICE_PARAM_RESOURCE: DOCKER_PROXY_PARAMETER_RESOURCE,
        },
        constants.SERVICE_PARAM_SECTION_DOCKER_DOCKER_REGISTRY: {
            SERVICE_PARAM_OPTIONAL: DOCKER_REGISTRIES_PARAMETER_OPTIONAL,
            SERVICE_PARAM_VALIDATOR: DOCKER_REGISTRIES_PARAMETER_VALIDATOR,
            SERVICE_PARAM_RESOURCE: DOCKER_DOCKER_REGISTRY_PARAMETER_RESOURCE
        },
        constants.SERVICE_PARAM_SECTION_DOCKER_GCR_REGISTRY: {
            SERVICE_PARAM_OPTIONAL: DOCKER_REGISTRIES_PARAMETER_OPTIONAL,
            SERVICE_PARAM_VALIDATOR: DOCKER_REGISTRIES_PARAMETER_VALIDATOR,
            SERVICE_PARAM_RESOURCE: DOCKER_GCR_REGISTRY_PARAMETER_RESOURCE
        },
        constants.SERVICE_PARAM_SECTION_DOCKER_K8S_REGISTRY: {
            SERVICE_PARAM_OPTIONAL: DOCKER_REGISTRIES_PARAMETER_OPTIONAL,
            SERVICE_PARAM_VALIDATOR: DOCKER_REGISTRIES_PARAMETER_VALIDATOR,
            SERVICE_PARAM_RESOURCE: DOCKER_K8S_REGISTRY_PARAMETER_RESOURCE
        },
        constants.SERVICE_PARAM_SECTION_DOCKER_QUAY_REGISTRY: {
            SERVICE_PARAM_OPTIONAL: DOCKER_REGISTRIES_PARAMETER_OPTIONAL,
            SERVICE_PARAM_VALIDATOR: DOCKER_REGISTRIES_PARAMETER_VALIDATOR,
            SERVICE_PARAM_RESOURCE: DOCKER_QUAY_REGISTRY_PARAMETER_RESOURCE
        },
        constants.SERVICE_PARAM_SECTION_DOCKER_ELASTIC_REGISTRY: {
            SERVICE_PARAM_OPTIONAL: DOCKER_REGISTRIES_PARAMETER_OPTIONAL,
            SERVICE_PARAM_VALIDATOR: DOCKER_REGISTRIES_PARAMETER_VALIDATOR,
            SERVICE_PARAM_RESOURCE: DOCKER_ELASTIC_REGISTRY_PARAMETER_RESOURCE
        },
        constants.SERVICE_PARAM_SECTION_DOCKER_GHCR_REGISTRY: {
            SERVICE_PARAM_OPTIONAL: DOCKER_REGISTRIES_PARAMETER_OPTIONAL,
            SERVICE_PARAM_VALIDATOR: DOCKER_REGISTRIES_PARAMETER_VALIDATOR,
            SERVICE_PARAM_RESOURCE: DOCKER_GHCR_REGISTRY_PARAMETER_RESOURCE
        }
    },
    constants.SERVICE_TYPE_KUBERNETES: {
        constants.SERVICE_PARAM_SECTION_KUBERNETES_CERTIFICATES: {
            SERVICE_PARAM_OPTIONAL: KUBERNETES_CERTIFICATES_PARAMETER_OPTIONAL,
            SERVICE_PARAM_VALIDATOR: KUBERNETES_CERTIFICATES_PARAMETER_VALIDATOR,
            SERVICE_PARAM_RESOURCE: KUBERNETES_CERTIFICATES_PARAMETER_RESOURCE,
            SERVICE_PARAM_DATA_FORMAT: KUBERNETES_CERTIFICATES_PARAMETER_DATA_FORMAT,
        },
        constants.SERVICE_PARAM_SECTION_KUBERNETES_APISERVER: {
            SERVICE_PARAM_OPTIONAL: KUBERNETES_APISERVER_PARAMETER_OPTIONAL,
            SERVICE_PARAM_VALIDATOR: KUBERNETES_APISERVER_PARAMETER_VALIDATOR,
            SERVICE_PARAM_RESOURCE: KUBERNETES_APISERVER_PARAMETER_RESOURCE,
        },
        constants.SERVICE_PARAM_SECTION_KUBERNETES_CONFIG: {
            SERVICE_PARAM_OPTIONAL: KUBERNETES_CONFIG_PARAMETER_OPTIONAL,
            SERVICE_PARAM_VALIDATOR: KUBERNETES_CONFIG_PARAMETER_VALIDATOR,
            SERVICE_PARAM_RESOURCE: KUBERNETES_CONFIG_PARAMETER_RESOURCE,
        },
        constants.SERVICE_PARAM_SECTION_KUBERNETES_CONTROLLER_MANAGER: {
            SERVICE_PARAM_OPTIONAL: KUBERNETES_CONTROLLER_MANAGER_PARAMETER_OPTIONAL,
            SERVICE_PARAM_VALIDATOR: KUBERNETES_CONTROLLER_MANAGER_PARAMETER_VALIDATOR,
            SERVICE_PARAM_RESOURCE: KUBERNETES_CONTROLLER_MANAGER_PARAMETER_RESOURCE
        },
        constants.SERVICE_PARAM_SECTION_KUBERNETES_SCHEDULER: {
            SERVICE_PARAM_OPTIONAL: KUBERNETES_SCHEDULER_PARAMETER_OPTIONAL,
            SERVICE_PARAM_VALIDATOR: KUBERNETES_SCHEDULER_PARAMETER_VALIDATOR,
            SERVICE_PARAM_RESOURCE: KUBERNETES_SCHEDULER_PARAMETER_RESOURCE,
        },
        constants.SERVICE_PARAM_SECTION_KUBERNETES_KUBELET: {
            SERVICE_PARAM_OPTIONAL: KUBERNETES_KUBELET_PARAMETER_OPTIONAL,
            SERVICE_PARAM_VALIDATOR: KUBERNETES_KUBELET_PARAMETER_VALIDATOR,
            SERVICE_PARAM_RESOURCE: KUBERNETES_KUBELET_PARAMETER_RESOURCE,
        },
    },
    constants.SERVICE_TYPE_PTP: {
        constants.SERVICE_PARAM_SECTION_PTP_GLOBAL: {
            SERVICE_PARAM_OPTIONAL: PTP_GLOBAL_PARAMETER_OPTIONAL,
            SERVICE_PARAM_VALIDATOR: PTP_GLOBAL_PARAMETER_VALIDATOR
        },
        constants.SERVICE_PARAM_SECTION_PTP_PHC2SYS: {
            SERVICE_PARAM_OPTIONAL: PTP_PHC2SYS_PARAMETER_OPTIONAL,
            SERVICE_PARAM_VALIDATOR: PTP_PHC2SYS_PARAMETER_VALIDATOR
        },
    },
    constants.SERVICE_TYPE_HTTP: {
        constants.SERVICE_PARAM_SECTION_HTTP_CONFIG: {
            SERVICE_PARAM_OPTIONAL: HTTPD_PORT_PARAMETER_OPTIONAL,
            SERVICE_PARAM_VALIDATOR: HTTPD_PORT_PARAMETER_VALIDATOR,
            SERVICE_PARAM_RESOURCE: HTTPD_PORT_PARAMETER_RESOURCE,
        },
    },
    constants.SERVICE_TYPE_OPENSTACK: {
        constants.SERVICE_PARAM_SECTION_OPENSTACK_HELM: {
            SERVICE_PARAM_OPTIONAL: OPENSTACK_HELM_PARAMETER_OPTIONAL,
            SERVICE_PARAM_VALIDATOR: OPENSTACK_HELM_PARAMETER_VALIDATOR,
            SERVICE_PARAM_RESOURCE: OPENSTACK_HELM_PARAMETER_RESOURCE,
        },
    },
    constants.SERVICE_TYPE_CEPH: {
        constants.SERVICE_PARAM_SECTION_CEPH_MONITOR: {
            SERVICE_PARAM_OPTIONAL: CEPH_MONITOR_PARAMETER_OPTIONAL,
            SERVICE_PARAM_VALIDATOR: CEPH_MONITOR_PARAMETER_VALIDATOR,
            SERVICE_PARAM_RESOURCE: CEPH_MONITOR_PARAMETER_RESOURCE,
            SERVICE_PARAM_DATA_FORMAT: CEPH_MONITOR_PARAMETER_DATA_FORMAT,
        },
    },
}

SERVICE_PARAMETER_MAX_LENGTH = 4096

DB_ONLY_SERVICE_PARAMETERS = [
    constants.SERVICE_PARAM_NAME_PLATFORM_MAX_CPU_PERCENTAGE
]


MANAGED_RESOURCES_MAP = None


def map_resource(resource_query):
    global MANAGED_RESOURCES_MAP

    if MANAGED_RESOURCES_MAP is None:
        MANAGED_RESOURCES_MAP = {}
        # Populate the map once and cache it
        for service in SERVICE_PARAMETER_SCHEMA.keys():
            for section, schema in SERVICE_PARAMETER_SCHEMA[service].items():
                for name, resource in schema.get(SERVICE_PARAM_RESOURCE, {}).items():
                    if resource is not None:
                        MANAGED_RESOURCES_MAP[resource] = {
                            'service': service,
                            'section': section,
                            'name': name,
                        }

    return MANAGED_RESOURCES_MAP.get(resource_query)
