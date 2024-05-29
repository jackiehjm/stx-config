#
# Copyright (c) 2016-2023 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

#
# This file contains common upgrades functions that can be used by both sysinv
# and during the upgrade of controller-1.
#

import keyring
import os
import psycopg2
from psycopg2.extras import RealDictCursor
import six
import subprocess
import tempfile
import yaml
import netaddr

# WARNING: The controller-1 upgrade is done before any puppet manifests
# have been applied, so only the static entries from tsconfig can be used.
# (the platform.conf file will not have been updated with dynamic values).
from tsconfig.tsconfig import SW_VERSION
from tsconfig.tsconfig import PLATFORM_PATH

from controllerconfig import utils as cutils
from controllerconfig.common import constants
from sysinv.common import constants as sysinv_constants
from sysinv.common import utils as sysinv_utils

from oslo_log import log

LOG = log.getLogger(__name__)

POSTGRES_PATH = '/var/lib/postgresql'
POSTGRES_DATA_DIR = os.path.join(POSTGRES_PATH, SW_VERSION)
RABBIT_PATH = '/var/lib/rabbitmq'
CONTROLLER_1_HOSTNAME = "controller-1"
DB_CONNECTION = "postgresql://%s:%s@127.0.0.1/%s\n"
KUBERNETES_CONF_PATH = "/etc/kubernetes"
KUBERNETES_ADMIN_CONF_FILE = "admin.conf"
PLATFORM_LOG = '/var/log/platform.log'
ERROR_FILE = '/tmp/upgrade_fail_msg'

# well-known default domain name
DEFAULT_DOMAIN_NAME = 'Default'

# Migration script actions
ACTION_START = "start"
ACTION_MIGRATE = "migrate"
ACTION_ACTIVATE = "activate"


def execute_migration_scripts(from_release, to_release, action,
                              migration_script_dir="/etc/upgrade.d"):
    """ Execute migration scripts with an action:
          start: Prepare for upgrade on release N side. Called during
                 "system upgrade-start".
          migrate: Perform data migration on release N+1 side. Called while
                   controller-1 is performing its upgrade.
    """

    LOG.info("Executing migration scripts with from_release: %s, "
             "to_release: %s, action: %s" % (from_release, to_release, action))

    # Get a sorted list of all the migration scripts
    # Exclude any files that can not be executed, including .pyc and .pyo files
    files = [f for f in os.listdir(migration_script_dir)
             if os.path.isfile(os.path.join(migration_script_dir, f)) and
             os.access(os.path.join(migration_script_dir, f), os.X_OK)]
    # From file name, get the number to sort the calling sequence,
    # abort when the file name format does not follow the pattern
    # "nnn-*.*", where "nnn" string shall contain only digits, corresponding
    # to a valid unsigned integer (first sequence of characters before "-")
    try:
        files.sort(key=lambda x: int(x.split("-")[0]))
    except Exception:
        LOG.exception("Migration script sequence validation failed, invalid "
                      "file name format")
        raise

    MSG_SCRIPT_FAILURE = "Migration script %s failed with returncode %d" \
                         "Script output:\n%s"
    # Execute each migration script
    for f in files:
        migration_script = os.path.join(migration_script_dir, f)
        try:
            # needed to flag each execution in case of error
            start_script_exec = "Executing migration script"
            LOG.info("%s %s" % (start_script_exec, migration_script))
            # TODO(heitormatsui): remove py2 code when
            # CentOS and zuul py2.7 are deprecated
            if six.PY2:
                subprocess.check_output([migration_script,
                                         from_release,
                                         to_release,
                                         action],
                                        stderr=subprocess.STDOUT,
                                        universal_newlines=True)
            else:
                ret = subprocess.run([migration_script,
                                      from_release,
                                      to_release,
                                      action],
                                     stderr=subprocess.STDOUT,
                                     stdout=subprocess.PIPE,
                                     text=True)
                if ret.returncode != 0:
                    script_output = ret.stdout.splitlines()
                    output_list = []
                    for item in script_output:
                        if item not in output_list:
                            output_list.append(item)
                    output_script = "\n".join(output_list)
                    msg = MSG_SCRIPT_FAILURE % (migration_script,
                                                ret.returncode,
                                                output_script)
                    LOG.error(msg)
                    start_script_line = get_exec_start_line(
                        start_script_exec, PLATFORM_LOG)
                    error_message = search_script_output(
                        start_script_line, PLATFORM_LOG, f)
                    save_temp_file(msg, error_message)
                    raise Exception(msg)

        except subprocess.CalledProcessError as e:
            # log script output if script executed but failed.
            LOG.error(MSG_SCRIPT_FAILURE %
                      (migration_script, e.returncode, e.output))
            # Abort when a migration script fails
            raise
        except Exception as e:
            # log exception if script not executed.
            LOG.exception(e)
            raise


def get_exec_start_line(start_script_exec, file_name):
    """ Search the last ocurrence of the start of the script.
    Get the line number and use it to find the last start
    of script execution in logs.

    Used to prevent reading an outdated error log.
    """
    cmd = [
        "awk",
        '/{pattern_to_find}/ {{last_match = $0; start_line = NR}}'
        'END {{if (last_match) print start_line, last_match}}'
        .format(pattern_to_find=start_script_exec),
        file_name
    ]
    start_line = None

    try:
        process = subprocess.Popen(cmd,
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE)
        output, error = process.communicate()
        last_match = output.decode().strip().splitlines()
        start_line, last_match = last_match[0].split(' ', 1)
        start_line = int(start_line)
    except Exception:
        LOG.error("Failed to exec cmd. \n %s" % error)
        return None
    return start_line


def search_script_output(start_script_line, file_name, script):
    """Search error lines for this script.

    Then, compare the line number and just add the
    lines after the start of the last execution.
    """
    cmd = [
        "awk",
        '/{script}/ && /error|ERROR/ {{print NR, $0}}'.format(script=script),
        file_name
    ]
    error_list = []
    error_string = ""

    try:
        process = subprocess.Popen(cmd,
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE)
        output, error = process.communicate()
        error_lines = output.decode().strip().splitlines()
        # Compare the line numbers of each occurrence.
        # If the line number is greater than 'start_script_line', then
        # add this line to the output string
        for i, current_line in enumerate(error_lines):
            if i < (len(error_lines) - 1):
                current_line, error_line = error_lines[i + 1].split(' ', 1)
                current_line = int(current_line)
                if current_line > start_script_line:
                    error_list.append(error_line)
        error_string = '\n'.join(error_list)
    except Exception:
        LOG.error("Failed to exec cmd. \n %s" % error)
        return None
    return error_string


def save_temp_file(msg, error=None):
    if os.path.isfile(ERROR_FILE):
        os.remove(ERROR_FILE)

    MSG_FAILURE = '%s \n\n'\
                  '%s \n\n'\
                  'Check specific service log or search for ' \
                  'this app in sysinv.log for details\n'
    msg = MSG_FAILURE % (msg,
                         error)
    try:
        with open(ERROR_FILE, 'w+') as error_file:
            error_file.write(msg)
    except Exception:
        LOG.warning("Error opening file %s" % ERROR_FILE)
        return None


def get_db_connection(hiera_db_records, database):
    username = hiera_db_records[database]['username']
    password = hiera_db_records[database]['password']
    return "postgresql://%s:%s@%s/%s" % (
        username, password, 'localhost', database)


def get_password_from_keyring(service, username):
    """Retrieve password from keyring"""
    password = ""
    os.environ["XDG_DATA_HOME"] = constants.KEYRING_PERMDIR
    try:
        password = keyring.get_password(service, username)
    except Exception as e:
        LOG.exception("Received exception when attempting to get password "
                      "for service %s, username %s: %s" %
                      (service, username, e))
        raise
    finally:
        del os.environ["XDG_DATA_HOME"]
    return password


def set_password_in_keyring(service, username):
    """Generate random password and store in keyring"""
    os.environ["XDG_DATA_HOME"] = constants.KEYRING_PERMDIR
    try:
        password = sysinv_utils.generate_random_password(length=16)
        keyring.set_password(service, username, password)
    except Exception as e:
        LOG.exception("Received exception when attempting to generate "
                      "password for service %s, username %s: %s" %
                      (service, username, e))
        raise
    finally:
        del os.environ["XDG_DATA_HOME"]
    return password


def get_upgrade_token(from_release,
                      config,
                      secure_config):

    # Get the system hiera data from the from release
    from_hiera_path = os.path.join(PLATFORM_PATH, "puppet", from_release,
                                   "hieradata")
    system_file = os.path.join(from_hiera_path, "system.yaml")
    with open(system_file, 'r') as s_file:
        system_config = yaml.load(s_file, Loader=yaml.FullLoader)

    # during a controller-1 upgrade, keystone is running
    # on the controller UNIT IP, however the service catalog
    # that was migrated from controller-0 since lists the
    # floating controller IP. Keystone operations that use
    # the AUTH URL will hit this service URL and fail,
    # therefore we have to issue an Upgrade token for
    # all Keystone operations during an Upgrade. This token
    # will allow us to circumvent the service catalog entry, by
    # providing a bypass endpoint.
    keystone_upgrade_url = "http://{}:5000/{}".format(
        '127.0.0.1',
        system_config['openstack::keystone::params::api_version'])

    admin_user_domain = system_config.get(
        'platform::client::params::admin_user_domain')
    if admin_user_domain is None:
        # This value wasn't present in R2. So may be missing in upgrades from
        # that release
        LOG.info("platform::client::params::admin_user_domain key not found. "
                 "Using Default.")
        admin_user_domain = DEFAULT_DOMAIN_NAME

    admin_project_domain = system_config.get(
        'platform::client::params::admin_project_domain')
    if admin_project_domain is None:
        # This value wasn't present in R2. So may be missing in upgrades from
        # that release
        LOG.info("platform::client::params::admin_project_domain key not "
                 "found. Using Default.")
        admin_project_domain = DEFAULT_DOMAIN_NAME

    admin_password = get_password_from_keyring("CGCS", "admin")
    admin_username = system_config.get(
        'platform::client::params::admin_username')

    # the upgrade token command
    keystone_upgrade_token = (
        "openstack "
        "--os-username {} "
        "--os-password '{}' "
        "--os-auth-url {} "
        "--os-project-name admin "
        "--os-user-domain-name {} "
        "--os-project-domain-name {} "
        "--os-interface internal "
        "--os-identity-api-version 3 "
        "token issue -c id -f value".format(
            admin_username,
            admin_password,
            keystone_upgrade_url,
            admin_user_domain,
            admin_project_domain
        ))

    config.update({
        'openstack::keystone::upgrade::upgrade_token_file':
            '/etc/keystone/upgrade_token',
        'openstack::keystone::upgrade::url': keystone_upgrade_url
    })

    secure_config.update({
        'openstack::keystone::upgrade::upgrade_token_cmd':
            keystone_upgrade_token,
    })


def get_upgrade_data(from_release,
                     system_config,
                     secure_config):
    """ Retrieve required data from the from-release, update system_config
        and secure_config with them.
        This function is needed for adding new service account and endpoints
        during upgrade.
    """
    # Get the system hiera data from the from release
    from_hiera_path = os.path.join(PLATFORM_PATH, "puppet", from_release,
                                   "hieradata")
    system_file = os.path.join(from_hiera_path, "system.yaml")
    with open(system_file, 'r') as s_file:
        system_config_from_release = yaml.load(s_file, Loader=yaml.FullLoader)

    # Get keystone region
    keystone_region = system_config_from_release.get(
        'keystone::endpoint::region')

    system_config.update({
        'platform::client::params::identity_region': keystone_region,
        # Retrieve keystone::auth::region from the from-release for the new
        # service.
        # 'newservice::keystone::auth::region': keystone_region,
    })

    # Generate password for the new service
    # password = sysinv_utils.generate_random_password(16)

    secure_config.update({
        # Generate and set the keystone::auth::password for the new service.
        # 'newservice::keystone::auth::password': password,
    })


def add_upgrade_entries_to_hiera_data(from_release):
    """ Adds upgrade entries to the hiera data """

    filename = 'static.yaml'
    secure_filename = 'secure_static.yaml'
    path = constants.HIERADATA_PERMDIR

    # Get the hiera data for this release
    filepath = os.path.join(path, filename)
    with open(filepath, 'r') as c_file:
        config = yaml.load(c_file, Loader=yaml.FullLoader)
    secure_filepath = os.path.join(path, secure_filename)
    with open(secure_filepath, 'r') as s_file:
        secure_config = yaml.load(s_file, Loader=yaml.FullLoader)

    # File for system.yaml
    # This is needed for adding new service account and endpoints
    # during upgrade.
    system_filename = 'system.yaml'
    system_filepath = os.path.join(path, system_filename)

    # Get a token and update the config
    get_upgrade_token(from_release, config, secure_config)

    # Get required data from the from-release and add them in system.yaml.
    # We don't carry system.yaml from the from-release.
    # This is needed for adding new service account and endpoints
    # during upgrade.
    system_config = {}
    get_upgrade_data(from_release, system_config, secure_config)

    # Update the hiera data on disk
    try:
        fd, tmppath = tempfile.mkstemp(dir=path, prefix=filename,
                                       text=True)
        with open(tmppath, 'w') as f:
            yaml.dump(config, f, default_flow_style=False)
        os.close(fd)
        os.rename(tmppath, filepath)
    except Exception:
        LOG.exception("failed to write config file: %s" % filepath)
        raise

    try:
        fd, tmppath = tempfile.mkstemp(dir=path, prefix=secure_filename,
                                       text=True)
        with open(tmppath, 'w') as f:
            yaml.dump(secure_config, f, default_flow_style=False)
        os.close(fd)
        os.rename(tmppath, secure_filepath)
    except Exception:
        LOG.exception("failed to write secure config: %s" % secure_filepath)
        raise

    # Add required hiera data into system.yaml.
    # This is needed for adding new service account and endpoints
    # during upgrade.
    try:
        fd, tmppath = tempfile.mkstemp(dir=path, prefix=system_filename,
                                       text=True)
        with open(tmppath, 'w') as f:
            yaml.dump(system_config, f, default_flow_style=False)
        os.close(fd)
        os.rename(tmppath, system_filepath)
    except Exception:
        LOG.exception("failed to write system config: %s" % system_filepath)
        raise


def create_simplex_runtime_config(filename):
    """ Create any runtime parameters needed for simplex upgrades"""
    config = {}
    # Here is an example from a previous release...
    # config.update({'nova::db::sync_api::cellv2_setup': False})
    cutils.create_manifest_runtime_config(filename, config)


def apply_upgrade_manifest(controller_address):
    """Apply puppet upgrade manifest files."""

    cmd = [
        "/usr/local/bin/puppet-manifest-apply.sh",
        constants.HIERADATA_PERMDIR,
        str(controller_address),
        sysinv_constants.CONTROLLER,
        'upgrade'
    ]

    logfile = "/tmp/apply_manifest.log"
    try:
        with open(logfile, "w") as flog:
            subprocess.check_call(cmd, stdout=flog, stderr=flog)
    except subprocess.CalledProcessError:
        msg = "Failed to execute upgrade manifest"
        print(msg)
        raise Exception(msg)


def format_url_address(address):
    """Format the URL address according to RFC 2732"""
    try:
        addr = netaddr.IPAddress(address)
        if addr.version == sysinv_constants.IPV6_FAMILY:
            return "[%s]" % address
        else:
            return str(address)
    except netaddr.AddrFormatError:
        return address


def get_keystone_user_id(user_name):
    """ Get the a keystone user id by name"""

    conn = psycopg2.connect("dbname='keystone' user='postgres'")
    with conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT user_id FROM local_user WHERE name='%s'" %
                        user_name)
            user_id = cur.fetchone()
            if user_id is not None:
                return user_id['user_id']
            else:
                return user_id


def get_keystone_project_id(project_name):
    """ Get the a keystone project id by name"""

    conn = psycopg2.connect("dbname='keystone' user='postgres'")
    with conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT id FROM project WHERE name='%s'" %
                        project_name)
            project_id = cur.fetchone()
            if project_id is not None:
                return project_id['id']
            else:
                return project_id


def get_postgres_bin():
    """ Get the path to the postgres binaries"""

    try:
        return subprocess.check_output(
            ['pg_config', '--bindir']).decode().rstrip('\n')
    except subprocess.CalledProcessError:
        LOG.exception("Failed to get postgres bin directory.")
        raise
