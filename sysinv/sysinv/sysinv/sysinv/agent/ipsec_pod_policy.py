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

from oslo_log import log

LOG = log.getLogger(__name__)


class IpsecPodPolicyAgentOperator(object):
    def __init__(self):
        pass

    def _debug_dict_to_swanctl_conf(self, data, indent=0):
        lines = []
        indent_str = ' ' * (indent * 4)

        for key, value in data.items():
            if isinstance(value, dict):
                lines.append(f"{indent_str}{key} {{")
                lines.extend(
                    self._debug_dict_to_swanctl_conf(value, indent + 1))
                lines.append(f"{indent_str}}}")
            else:
                lines.append(f"{indent_str}{key} = {value}")

        return lines

    def _debug_clean_configs(self):
        files = glob.glob(os.path.join("/etc/swanctl/conf.d/", '*'))
        for file_path in files:
            if os.path.isfile(file_path) or os.path.islink(file_path):
                os.remove(file_path)
            elif os.path.isdir(file_path):
                shutil.rmtree(file_path)

    def _repolad_policy(self):
        subprocess.run(['swanctl', '--load-all'],
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                       check=False)

    def _terminate_all(self, swanctl_data):
        if not swanctl_data:
            return
        for _, conns in swanctl_data.items():
            for _, connection in conns.items():
                for ike_name, _ in connection.items():
                    subprocess.run(
                        ['swanctl', '--terminate', '--ike', ike_name],
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                        check=False)

    def _write_swanctl_config(self, data):
        self._terminate_all(data)
        self._debug_clean_configs()

        # reload for clean old connections
        self._repolad_policy()

        if not data:
            return

        root_path = "/etc/swanctl/conf.d/"
        for k, v in data.items():
            full_path = root_path + k
            content = self._debug_dict_to_swanctl_conf(v)
            config_str = '\n'.join(content)
            with open(full_path, 'w', encoding='utf-8') as file:
                file.write(config_str)
            LOG.info(f"write {full_path} content:{config_str}")
        self._repolad_policy()

    def puppet_apply_manifest(self, k8s_net_data):
        err_msg = None
        LOG.info("Apply manifest for:%s" % k8s_net_data)
        self._write_swanctl_config(k8s_net_data)
        # TODO(twang4): puppet call to apply changes
        return err_msg
