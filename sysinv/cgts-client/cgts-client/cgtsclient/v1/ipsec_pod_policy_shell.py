#
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# vim: tabstop=4 shiftwidth=4 softtabstop=4
# All Rights Reserved.
#

from cgtsclient.common import utils
from cgtsclient import exc


def _print_ipsec_pod_policy_show(obj):
    """Method to show the policy's key data"""
    fields = ['uuid', 'protocol', 'port', 'policy_status']
    data = [(fields[index], getattr(obj, f, ''))
            for index, f in enumerate(fields)]
    utils.print_tuple_list(data)


@utils.arg('--column',
           action='append',
           default=[],
           help="Specify the column(s) to include, can be repeated")
@utils.arg('--format',
           choices=['table', 'yaml', 'value'],
           help="specify the output format, defaults to table")
def do_ipsec_pod_policy_list(cc, args):
    """List IPsec Pod policies"""
    ipsec_pod_policy_list = cc.ipsec_pod_policy.list()
    fields = ['uuid', 'protocol', 'port', 'policy_status']
    utils.print_list(ipsec_pod_policy_list, fields, fields, sortby=1)


def do_ipsec_pod_policy_apply(cc, args):
    """Apply IPsec Pod policies"""
    ret = cc.ipsec_pod_policy.apply()
    if ret:
        print(ret)


@utils.arg('ipsec_pod_policy_uuid',
           metavar='<ipsec pod policy uuid>',
           help="UUID of ipsec pod policy entry")
def do_ipsec_pod_policy_show(cc, args):
    """Show ipsec pod policy attributes."""
    ipsec_pod_policy = cc.ipsec_pod_policy.get(args.ipsec_pod_policy_uuid)
    _print_ipsec_pod_policy_show(ipsec_pod_policy)


@utils.arg('ipsec_pod_policy_uuid',
           metavar='<ipsec pod policy uuid>',
           help="UUID of ipsec pod policy entry")
def do_ipsec_pod_policy_delete(cc, args):
    """Delete an IPsec pod policy."""
    cc.ipsec_pod_policy.delete(args.ipsec_pod_policy_uuid)
    print('Deleted IPsec pod policy: %s' % (args.ipsec_pod_policy_uuid))


@utils.arg('--protocol',
           metavar='<protocol>',
           help="protocol of policy "
           "avaliable are tcp,udp,icmp [REQUIRED]")
@utils.arg('--port',
           metavar='<port | <ranges>',
           help="port or <start_port-end_port>), only valid for tcp and udp "
           "protocol [REQUIRED for tcp,udp]")
def do_ipsec_pod_policy_add(cc, args):
    """Add an IPsec pod policy."""

    field_list = ['protocol', 'port']

    # Prune input fields down to required/expected values
    data = dict((k, v) for (k, v) in vars(args).items()
                if k in field_list and not (v is None))

    ipsec_pod_policy = cc.ipsec_pod_policy.create(**data)
    uuid = getattr(ipsec_pod_policy, 'uuid', '')
    try:
        new_policy = cc.ipsec_pod_policy.get(uuid)
    except exc.HTTPNotFound:
        raise exc.CommandError(
            'Created IPsec pod policy UUID not found: %s' % uuid)
    _print_ipsec_pod_policy_show(new_policy)


@utils.arg('ipsec_pod_policy_uuid',
           metavar='<ipsec pod policy uuid>',
           help="UUID of ipsec pod policy entry [REQUIRED]")
@utils.arg('--protocol',
           metavar='<protocol>',
           help="protocol of policy "
           "avaliable are tcp,udp,icmp")
@utils.arg('--port',
           metavar='<port | <ranges>',
           help="port or <start_port-end_port>), only valid for tcp and udp "
           "protocol [REQUIRED for tcp,udp]")
def do_ipsec_pod_policy_update(cc, args):
    """Modify IPsec pod policy attributes."""

    rwfields = ['protocol', 'port']

    # Prune input fields down to required/expected values
    data = dict((k, v) for (k, v) in vars(args).items()
                if k in rwfields and not (v is None))

    patch = []
    for (k, v) in data.items():
        patch.append({'op': 'replace', 'path': '/' + k, 'value': v})

    ipsec_pod_policy = cc.ipsec_pod_policy.update(
        args.ipsec_pod_policy_uuid, patch)
    _print_ipsec_pod_policy_show(ipsec_pod_policy)
