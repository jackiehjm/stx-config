# vim: tabstop=4 shiftwidth=4 softtabstop=4

#
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# All Rights Reserved.
#

import copy
import threading
import time

from oslo_log import log
from sysinv.agent import rpcapiproxy as agent_rpcapi
from sysinv.common import constants
from sysinv.common import kubernetes
from sysinv.db import api as dbapi
from sysinv.ipsec_auth.common import constants as ipsec_constants

LOG = log.getLogger(__name__)

CONNECTION_PREFIX = "k8s-node-"

OFFLINE_STATS = [constants.AVAILABILITY_OFFLINE]


class IpsecPodPolicyOperator(object):
    def __init__(self):
        self.policy_apply_lock = threading.Lock()
        self.dbapi = dbapi.get_instance()
        self._kube_operator = kubernetes.KubeOperator()
        self.k8s_host_dict = dict()
        self.policy_list = list()
        self.rpcapi = agent_rpcapi.AgentAPI()

        # thread map data {"host_uuid": threading}
        self.wait_thread_map = dict()

    def _get_node_pod_cidr(self):
        try:
            blockaffinities_list = self._kube_operator.list_custom_resources(
                "crd.projectcalico.org",
                "v1",
                "blockaffinities")
            if len(blockaffinities_list) == 0:
                self.k8s_host_dict = None
                raise Exception("Error, get empty list of blockaffinities")
            for blockaffinities in blockaffinities_list:
                spec = blockaffinities['spec']
                host = dict()
                host[spec['node']] = {'pod_cidr': spec['cidr']}
                self.k8s_host_dict.update(host)
        except Exception as e:
            LOG.error("Error try to get blockaffinities from "
                      "kubernetes: %s" % e)
            raise e

    def _get_node_cluster_ip(self):
        try:
            nodes = self._kube_operator.kube_get_nodes()
            # error if node number not match from previous call
            if len(self.k8s_host_dict) != len(nodes):
                self.k8s_host_dict = None
                raise Exception("Error, node number not match with node pod "
                                "cidr number, host_dict:%s nodes:%s" %
                                (self.k8s_host_dict, nodes))
            for node in nodes:
                try:
                    host_cluter_ip = None
                    host_cluter_name = None
                    for addr in node.status.addresses:
                        if addr.type == 'InternalIP':
                            host_cluter_ip = addr.address
                            continue
                        if addr.type == 'Hostname':
                            host_cluter_name = addr.address
                            continue
                except Exception as e:
                    raise Exception("Error to get cluster address from "
                                    "node: %s, error: %s" % (node, e))
                self.k8s_host_dict[host_cluter_name].update(
                    {'cluster_ip': host_cluter_ip})
        except Exception:
            LOG.error("Error try to get nodes address from kubernetes")
            raise

    def _validate_host(self, host):
        # only apply policy on controller and worker host
        if host.personality not in [constants.WORKER,
                                    constants.CONTROLLER]:
            LOG.info("skip host %s for not controller or worker"
                     % (host.hostname))
            return False
        # only apply policy on 'unlocked' and 'available' host
        if host['availability'] in OFFLINE_STATS:
            LOG.info("skip host %s for in %s "
                     "status" % (host.hostname, OFFLINE_STATS))
            return False

        # only apply on mgmt IPsec enabled host
        capa = host.get('capabilities')
        mgmt_ipsec_enabled = capa.get(constants.MGMT_IPSEC_FLAG, None)
        if mgmt_ipsec_enabled != constants.MGMT_IPSEC_ENABLED:
            LOG.info("skip host %s for not enabled mgmt IPsec"
                     % (host.hostname))
            return False
        return True

    def _get_avaliable_hosts(self):
        hosts = self.dbapi.ihost_get_list()
        host_name_uuid_list = list()
        for host in hosts:
            if self._validate_host(host):
                host_name_uuid_list.append([host.hostname, host.uuid])
            else:
                if host.hostname in self.k8s_host_dict:
                    self.k8s_host_dict.pop(host.hostname)

        return host_name_uuid_list

    def _update_host_dict_from_kubernetes(self):
        self.k8s_host_dict = dict()
        self._get_node_pod_cidr()
        self._get_node_cluster_ip()

    def _update_policy_state(self, state):
        for p in self.policy_list:
            update = dict()
            update['policy_status'] = state
            self.dbapi.ipsec_pod_policy_update(p.uuid, update)

    def _generate_policy_dict(self, local_host, remote_host):
        policy_d = dict()
        for p in self.policy_list:
            proto_port_str = str(p.protocol)
            proto_port_rule_str = str(p.protocol)
            if p.port:
                proto_port_str = proto_port_str + '-' + str(p.port)
                proto_port_rule_str = proto_port_rule_str + '/' + str(p.port)

            proto_port_rule_str = "[%s]" % proto_port_rule_str

            remote_ts = self.k8s_host_dict[remote_host]['pod_cidr'] + \
                proto_port_rule_str
            local_ts = self.k8s_host_dict[local_host]['pod_cidr'] + \
                proto_port_rule_str

            if not p.port:
                # for ICMP protocol, only one rule, no egress or ingress
                # needed
                policy_d[proto_port_str] = {
                    'start_action': 'start',
                    'local_ts': local_ts,
                    'remote_ts': remote_ts,
                    'updown': '/usr/lib/ipsec/_updown iptables',
                    'mode': 'tunnel'
                }
                continue

            egress_p = proto_port_str + '-egress'
            ingress_p = proto_port_str + '-ingress'

            policy_d[egress_p] = {
                'start_action': 'start',
                'local_ts': self.k8s_host_dict[local_host]['pod_cidr'],
                'remote_ts': remote_ts,
                'updown': '/usr/lib/ipsec/_updown iptables',
                'mode': 'tunnel'
            }
            policy_d[ingress_p] = {
                'start_action': 'start',
                'local_ts': local_ts,
                'remote_ts': self.k8s_host_dict[remote_host]['pod_cidr'],
                'updown': '/usr/lib/ipsec/_updown iptables',
                'mode': 'tunnel'
            }
        return policy_d

    def _generate_bypass_dict(self, host_name):
        d = dict()
        d['connections'] = {
            'k8s-node-bypass':
            {
                'children': {
                    'k8s-bypass': {
                        'local_ts': self.k8s_host_dict[host_name]['pod_cidr'],
                        'remote_ts': self.k8s_host_dict[host_name]['pod_cidr'],
                        'mode': 'pass',
                        'start_action': 'trap'
                    }
                }
            }
        }
        return d

    def _build_swanctl_config_data(self, host_name):
        """
        :param host_name: config data for the host
        :return: swanctl config data for the host
        """
        remote_host_dict = copy.deepcopy(self.k8s_host_dict)
        # remove the host itself
        remote_host_dict.pop(host_name)

        LOG.info(f"build config for {host_name} tunnel to {remote_host_dict}")
        local_certs = ipsec_constants.CERT_NAME_PREFIX + host_name + '.crt'
        remote_ca = ipsec_constants.TRUSTED_CA_CERT_FILE_0 + \
            ',' + ipsec_constants.TRUSTED_CA_CERT_FILE_1
        config_dict = dict()

        for remote_host in remote_host_dict:
            connection_name = CONNECTION_PREFIX + remote_host
            file_name = connection_name + '.conf'
            content = dict()
            config_dict[file_name] = {"connections": content}

            connection = dict()
            content[connection_name] = connection
            connection['reauth_time'] = '14000'
            connection['rekey_time'] = '3600'
            connection['unique'] = 'never'
            connection['local_addrs'] = \
                self.k8s_host_dict[host_name]['cluster_ip']
            connection['remote_addrs'] = \
                self.k8s_host_dict[remote_host]['cluster_ip']
            connection['local'] = {
                'auth': 'pubkey',
                'certs': local_certs,
            }
            connection['remote'] = {
                'id': 'CN=*',
                'auth': 'pubkey',
                'cacerts': remote_ca,
            }
            policy_dict = self._generate_policy_dict(host_name, remote_host)
            connection['children'] = policy_dict
        config_dict['k8s-node-bypass.conf'] = self._generate_bypass_dict(
            host_name)
        LOG.debug(f"for host:{host_name} config_dict:{config_dict}")
        return config_dict

    def _rpc_call_agent(self, context, host_uuid, data, retry_times=2):
        for times in range(retry_times):
            try:
                ret = self.rpcapi.apply_ipsec_pod_policy_manifest(
                    context, host_uuid, data)
                return ret
            except Exception as e:
                if times == retry_times - 1:
                    err_msg = ("error in ipsec pod policy rpc call to %s: %s"
                               % (host_uuid, e))
                    LOG.error(err_msg)
                    return err_msg
                else:
                    err_msg = ("error in ipsec pod policy rpc call to %s: %s,"
                               "%d retry..." % (host_uuid, e, times + 1))
                    LOG.error(err_msg)
                    time.sleep(1)
                    continue

    def _apply_policy_on_hosts(self, context, hosts):
        err_list = list()
        for host_name, host_uuid in hosts:
            if host_name not in self.k8s_host_dict:
                err_msg = "host %s is not in kubernetes %s" % (
                    host_name, self.k8s_host_dict)
                LOG.error(err_msg)
                err_list.append(err_msg)
                return err_list

            LOG.info("%s cluster and pod data: %s" %
                     (host_name, self.k8s_host_dict[host_name]))
            data = self._build_swanctl_config_data(host_name)

            ret = self._rpc_call_agent(context, host_uuid, data)
            if ret:
                err_msg = "Failed to apply ipsec policy on host %s: %s" % \
                          (host_name, ret)
                LOG.error(err_msg)
                err_list.append(err_msg)
        if err_list:
            self._update_policy_state(constants.IPSEC_POD_POLICY_STATUS_ERROR)
            return err_list
        else:
            self._update_policy_state(
                constants.IPSEC_POD_POLICY_STATUS_APPLIED)

    def _remove_all_policy_on_hosts(self, context, host_name_uuids):
        err_list = list()
        for host_name, host_uuid in host_name_uuids:
            if host_name not in self.k8s_host_dict:
                err_msg = "host %s is not in kubernetes %s" % (
                    host_name, self.k8s_host_dict)
                LOG.error(err_msg)
                err_list.append(err_msg)
                return err_list

            LOG.info("remove all IPsec pod policy config data from %s" %
                     (host_name))

            ret = self._rpc_call_agent(context, host_uuid, None)
            if ret:
                err_msg = "Failed to remove ipsec policy on host %s: %s" % \
                          (host_name, ret)
                LOG.error(err_msg)
                err_list.append(err_msg)
        if err_list:
            self._update_policy_state(constants.IPSEC_POD_POLICY_STATUS_ERROR)
            return err_list
        else:
            self._update_policy_state(None)

    def _apply_condition(self, host_uuid):
        if self.policy_apply_lock.locked():
            return
        try:
            host = self.dbapi.ihost_get(host_uuid)
        except Exception:
            return 'host uuid %s not found' % host_uuid

        if (host['availability'] not in OFFLINE_STATS):
            return True
        else:
            return

    def _wait_host_ready_apply_pod_policy(self, context, host):
        times = 30
        while True:
            time.sleep(10)
            ret = self._apply_condition(host.uuid)
            if ret is True:
                break
            if ret is None:
                LOG.info("wait for host %s online to apply pod "
                         "policy" % host.hostname)
                times += 1
                if times >= 0:
                    LOG.warning("wait host %s online timeout, you may apply"
                                " policy by manual" % host.hostname)
                    break
            else:
                LOG.error("error on wait for host %s online: "
                          "%s" % (host.hostname, ret))
                break
        if ret is True:
            LOG.info("host %s online, ready to apply policy"
                     % (host.hostname))
            self.apply_ipsec_pod_policy_config(context)

        # remove host from wait thread map
        self.wait_thread_map.pop(host.uuid)

    def ipsec_pod_policy_applying_status(self, context):
        if self.policy_apply_lock.locked():
            return True
        return False

    def apply_ipsec_pod_policy_config(self, context):
        err_msg = None
        if self.policy_apply_lock.locked():
            err_msg = "IPsec pod policy is applying now"
            LOG.warning(err_msg)
            return err_msg
        # Add a lock when applying the IPsec pod policy to the cluster
        with self.policy_apply_lock:
            # Read cluster ip and pod CIDR from kubernetes
            self._update_host_dict_from_kubernetes()

            host_name_uuids = self._get_avaliable_hosts()
            LOG.info(f"apply ipsec pod policy on hosts: {host_name_uuids}")
            if not host_name_uuids:
                err_msg = "no available host to apply ipsec pod policy"
                LOG.error(err_msg)
                return err_msg

            system = self.dbapi.isystem_get_one()
            if system.capabilities.get('pod_to_pod_security_enabled',
                                       False) is False:
                LOG.info("pod to pod security is disabled, remove config "
                         "files from each hosts")
                self._remove_all_policy_on_hosts(context, host_name_uuids)
                return err_msg

            self.policy_list = self.dbapi.ipsec_pod_policy_get_all()
            if not self.policy_list:
                LOG.info("No pod to pod policy exist, remove config "
                         "files from each hosts")
                self._remove_all_policy_on_hosts(context, host_name_uuids)
                return err_msg

            err_list = self._apply_policy_on_hosts(context, host_name_uuids)
            if err_list:
                return str(err_list)
            return err_msg

    def wait_host_ready_apply_pod_policy(self, context, host):
        if host.uuid not in self.wait_thread_map:
            t = threading.Thread(
                target=self._wait_host_ready_apply_pod_policy,
                args=(context, host))
            t.start()
            self.wait_thread_map[host.uuid] = t
        else:
            LOG.warning("A waiting thread is already running for host %s" %
                        host.hostname)
