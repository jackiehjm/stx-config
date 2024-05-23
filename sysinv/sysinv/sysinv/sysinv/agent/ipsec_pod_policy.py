# vim: tabstop=4 shiftwidth=4 softtabstop=4

#
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# All Rights Reserved.
#
import os
import glob
import shutil
import subprocess

from collections import defaultdict

from oslo_log import log

from sysinv.common import exception

LOG = log.getLogger(__name__)
CONFIG_PATH = "/etc/swanctl/conf.d/"


def _compare_dicts(dict1, dict2):
    '''Compare whether the elements in the two dict are consistent.
    :param    dict1: the first dict
    :param    dict2: the second dict
    :returns  True:  the elements in the two dict are consistent
              False: the elements in the two dict are not consistent
    '''
    if not dict1 and not dict2:
        # If both dicts are None, they are considered the same
        return True
    if not dict1 or not dict2:
        # If either dict is None, they are not the same
        return False
    # Compare the two dicts data to see if they are the same
    if set(dict1.keys()) != set(dict2.keys()):
        return False
    for key in dict1:
        value1 = dict1[key]
        value2 = dict2[key]
        if isinstance(value1, dict) and isinstance(value2, dict):
            if not _compare_dicts(value1, value2):
                return False
        elif isinstance(value1, (list, set, tuple)) and isinstance(value2, (list, set, tuple)):
            if set(value1) != set(value2):
                return False
        elif value1 != value2:
            return False
    return True


class IpsecPodPolicyAgentOperator(object):
    '''Class to encapsulate Ipsec Pod policy operations'''
    def __init__(self):
        self.swanctl_local_data = None

    def _convert_dict_to_swanctl_conf(self, data, indent=0):
        '''Recursively Convert the dict to valid swanctl conf using.
        :param    self
        :param    data: dict-formatted of the configuration data
        :returns  array of the swanctl configurations
        '''
        lines = []
        indent_str = ' ' * (indent * 4)

        for key, value in data.items():
            if isinstance(value, dict):
                lines.append(f"{indent_str}{key} {{")
                lines.extend(
                    self._convert_dict_to_swanctl_conf(value, indent + 1))
                lines.append(f"{indent_str}}}")
            else:
                lines.append(f"{indent_str}{key} = {value}")

        return lines

    def _clean_configs(self):
        '''Clear the swanctl configuration files and directories.
        :param    self
        :returns  None
        '''
        files = glob.glob(os.path.join(CONFIG_PATH, '*'))
        for file_path in files:
            if os.path.isfile(file_path) or os.path.islink(file_path):
                os.remove(file_path)
            elif os.path.isdir(file_path):
                shutil.rmtree(file_path)

    def _reload_policy(self):
        '''Use the swanctl command to reload the swanctl policy.
        :param    self
        :returns  None
        '''
        try:
            subprocess.run(['swanctl', '--load-all'],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           check=True)
        except subprocess.CalledProcessError as exc:
            msg = ("Failed to re-load swanctl."
                   "Command output: %s." % (exc.output))
            LOG.error(msg)
            raise exception.SysinvException(msg)

    def _terminate_all(self, swanctl_data):
        '''Use the swanctl command to terminate the swanctl policy of Specified ike.
        :param    self
        :param    swanctl_data: dict-formatted of the swanctl data
        :returns  None
        '''
        if not swanctl_data:
            return
        for _, conns in swanctl_data.items():
            for _, connection in conns.items():
                for ike_name, _ in connection.items():
                    try:
                        subprocess.run(
                            ['swanctl', '--terminate', '--ike', ike_name],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            check=True)
                    except subprocess.CalledProcessError as exc:
                        msg = ("Failed to terminate swanctl with ike name %s. "
                               "Command output: %s." % (ike_name, exc.output))
                        LOG.error(msg)
                        raise exception.SysinvException(msg)

    def _write_swanctl_config(self, data):
        '''Write the swanctl configuration data to the configuration file.
        :param    self
        :param    swanctl_data: dict-formatted of the swanctl data
        :returns  None
        '''
        self._terminate_all(self.swanctl_local_data)
        self._clean_configs()

        # reload for clean old connections
        self._reload_policy()

        if not data:
            return

        for k, v in data.items():
            full_path = CONFIG_PATH + k
            content = self._convert_dict_to_swanctl_conf(v)
            config_str = '\n'.join(content)
            with open(full_path, 'w', encoding='utf-8') as file:
                file.write(config_str)
            LOG.info(f"write {full_path} content:{config_str}")
        self._reload_policy()

    def _parse_conf_file(self, filepath):
        '''Convert swanctl config content into dict.
        :param    self
        :param    filepath: swanctl config file path
        :returns  dict of the configurations
        '''
        with open(filepath, 'r') as file:
            lines = file.readlines()

        conf_dict = defaultdict(dict)
        stack = []
        current_dict = conf_dict
        current_section = None

        for line in lines:
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            if line.endswith('{'):
                key = line[:-1].strip()
                stack.append((current_section, current_dict))
                current_dict[key] = {}
                current_section = key
                current_dict = current_dict[key]
            elif line == '}':
                current_section, current_dict = stack.pop()
            else:
                if '=' in line:
                    key, value = map(str.strip, line.split('=', 1))
                    current_dict[key] = value

        return dict(conf_dict)

    def _load_local_config(self):
        '''Load swanctl config from local file.
        :param    self
        :returns  dict of the configurations
        '''
        # Load config from local file
        conf_data = {}
        for filename in os.listdir(CONFIG_PATH):
            if filename.endswith('.conf'):
                filepath = os.path.join(CONFIG_PATH, filename)
                conf_data[filename] = self._parse_conf_file(filepath)
        return conf_data

    def _check_config_delta(self, swanctl_data):
        # compare swanctl data with local config file
        # if have delta return False
        self.swanctl_local_data = self._load_local_config()
        return _compare_dicts(swanctl_data, self.swanctl_local_data)

    def puppet_apply_manifest(self, swanctl_data):
        # Apply puppet manifest
        err_msg = None
        if self._check_config_delta(swanctl_data):
            LOG.info("IPsec pod policy data is same with local config, no"
                     " need to apply")
            return err_msg
        LOG.info("Apply manifest for:%s" % swanctl_data)
        self._write_swanctl_config(swanctl_data)
        # TODO(twang4): puppet call to apply changes
        LOG.warning("Puppet apply logic not yet implemented")
        return err_msg
