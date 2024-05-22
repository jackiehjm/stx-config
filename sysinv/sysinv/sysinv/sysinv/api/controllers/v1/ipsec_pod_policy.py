#
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import pecan
import wsme

from pecan import rest
from wsme import types as wtypes

from oslo_log import log
from oslo_utils import uuidutils
from sysinv._i18n import _

import wsmeext.pecan as wsme_pecan
from sysinv.api.controllers.v1 import base
from sysinv.api.controllers.v1 import types
from sysinv.api.controllers.v1 import collection
from sysinv.api.controllers.v1 import utils
from sysinv.common import utils as cutils
from sysinv import objects

LOG = log.getLogger(__name__)

VALID_PROTOCOL = ['tcp', 'udp', 'icmp']
PROTOCOL_WITHOUT_PORT = ['icmp']


class IpsecPodPolicyPatchType(types.JsonPatchType):
    """A complex type that represents a single json-patch operation."""

    value = types.MultiType([wtypes.text, [list]])

    @staticmethod
    def mandatory_attrs():
        """These attributes cannot be removed."""
        result = (super(IpsecPodPolicyPatchType, IpsecPodPolicyPatchType).
                  mandatory_attrs())
        result.append(['/protocol'])
        return result

    @staticmethod
    def validate(patch):
        result = (super(IpsecPodPolicyPatchType, IpsecPodPolicyPatchType).
                  validate(patch))
        if patch.op in ['add', 'remove']:
            msg = _("Attributes cannot be added or removed")
            raise wsme.exc.ClientSideError(msg % patch.path)
        return result


class IpsecPodPolicy(base.APIBase):
    """API of IPsec Pod policy
    """

    id = int
    "Unique ID for this policy"

    uuid = types.uuid
    "Unique UUID for this policy"

    protocol = wtypes.text
    "protocol of the policy"

    port = wtypes.text
    "port or port range of the policy"

    policy_status = wtypes.text
    "policy apply status of the policy"

    def __init__(self, **kwargs):
        self.fields = list(objects.ipsec_pod_policy.fields.keys())
        for k in self.fields:
            if not hasattr(self, k):
                continue
            setattr(self, k, kwargs.get(k, wtypes.Unset))

    def _validate_port(self):
        # Skip for protocols without port feature
        if self.protocol.lower() in PROTOCOL_WITHOUT_PORT:
            if self.port:
                raise ValueError(_("Port is not a valid option for "
                                   "protocol: %s" % self.protocol.lower()))
            return

        if isinstance(self.port, str) and self.port.isdigit():
            port_num = int(self.port)
            if 1 <= port_num <= 65535:
                return
            else:
                raise ValueError(_("Invalid port, port must in 1-65535"))
        elif isinstance(self.port, str) and '-' in self.port:
            start, end = self.port.split('-')
            if start.isdigit() and end.isdigit():
                start_num, end_num = int(start), int(end)
                if 1 <= start_num < end_num <= 65535:
                    return
        raise ValueError(_("Invalid port, port range must in 1-65535"))

    def _check_port_overlap(self, port_base):
        if self.port.isdigit():
            # new port is a single port
            port_num = int(self.port)
            # port_base range type
            if "-" in port_base:
                start, end = port_base.split('-')
                start_num, end_num = int(start), int(end)
                if start_num <= port_num <= end_num:
                    return True
            else:
                # port_base one port
                if int(port_base) == int(self.port):
                    return True
        elif '-' in self.port:
            # new port is a port range
            start_new, end_new = self.port.split('-')
            start_num_new, end_num_new = int(start_new), int(end_new)
            # port_base range type
            if "-" in port_base:
                start, end = port_base.split('-')
                start_num, end_num = int(start), int(end)
                if not (end_num_new < start_num or start_num_new > end_num):
                    return True
            else:
                # port_base one port
                if start_num_new <= int(port_base) <= end_num_new:
                    return True

    def _validate_duplicate(self, skip_uuid=None):
        policies = pecan.request.dbapi.ipsec_pod_policy_get_all()
        # Validate protocol without port
        if self.protocol.lower() in PROTOCOL_WITHOUT_PORT:
            for policy in policies:
                # Skip validate the policy we do not want to validate
                if policy.uuid == skip_uuid:
                    continue
                if self.protocol.lower() == policy.protocol:
                    raise ValueError(_("Duplicate with policy "
                                       "%s" % policy.uuid))
        # Validate duplicate tcp and udp policy
        elif self.protocol.lower() not in PROTOCOL_WITHOUT_PORT:
            for policy in policies:
                # Skip validate the policy we do not want to validate
                if policy.uuid == skip_uuid:
                    continue
                if self.protocol.lower() == policy.protocol:
                    if self._check_port_overlap(policy.port):
                        raise ValueError(_("Duplicate with policy "
                                           "%s" % policy.uuid))

    def validate_policy(self, skip_uuid=None):
        if not self.protocol:
            err_str = "Need provide a protocol from %s" % (VALID_PROTOCOL)
            raise ValueError(_(err_str))
        if self.protocol.lower() not in VALID_PROTOCOL:
            err_str = "Protocol %s must in %s" % \
                (self.protocol.lower(), VALID_PROTOCOL)
            raise ValueError(_(err_str))
        self._validate_port()
        self._validate_duplicate(skip_uuid)

    @classmethod
    def convert_with_links(cls, rpc_ipsec_pod_policy, expand=True):
        ipsec_pod_policy = IpsecPodPolicy(**rpc_ipsec_pod_policy.as_dict())
        if not expand:
            ipsec_pod_policy.unset_fields_except(['id', 'uuid',
                                                  'protocol',
                                                  'port',
                                                  'policy_status'])
        return ipsec_pod_policy


class IpsecPodPolicyCollection(collection.Collection):
    """API representation of a collection of IPsec pod policy."""

    ipsec_pod_policy = [IpsecPodPolicy]
    "A list containing IPsec pod policy objects"

    def __init__(self, **kwargs):
        self._type = 'ipsec_pod_policy'

    @classmethod
    def convert_with_links(cls, rpc_ipsec_pod_policy, limit, url=None,
                           expand=False, **kwargs):
        collection = IpsecPodPolicyCollection()
        collection.ipsec_pod_policy = [
            IpsecPodPolicy.convert_with_links(n, expand)
            for n in rpc_ipsec_pod_policy]
        collection.next = collection.get_next(limit, url=url, **kwargs)
        return collection


LOCK_NAME = 'IpsecPodPolicyController'


class IpsecPodPolicyController(rest.RestController):
    """REST controller for IpsecPodPolicy."""

    def __init__(self, parent=None, **kwargs):
        self._parent = parent

    def _get_one(self, ipsec_pod_policy_uuid):
        rpc_ipsec_pod_policy = objects.ipsec_pod_policy.get_by_uuid(
            pecan.request.context, ipsec_pod_policy_uuid)
        return IpsecPodPolicy.convert_with_links(rpc_ipsec_pod_policy)

    def _get_ipsec_pod_policy_collection(self, marker=None, limit=None,
                                         sort_key=None,
                                         sort_dir=None,
                                         expand=False,
                                         resource_url=None):
        limit = utils.validate_limit(limit)
        sort_dir = utils.validate_sort_dir(sort_dir)
        marker_obj = None

        if marker:
            marker_obj = objects.ipsec_pod_policy.get_by_uuid(
                pecan.request.context, marker)

        policies = pecan.request.dbapi.ipsec_pod_policy_get_all(
            limit, marker_obj, sort_key=sort_key, sort_dir=sort_dir)

        return IpsecPodPolicyCollection.convert_with_links(
            policies, limit, url=resource_url, expand=expand,
            sort_key=sort_key, sort_dir=sort_dir)

    def _create_ipsec_pod_policy(self, ipsec_pod_policy):
        ipsec_pod_policy.validate_policy()
        ipsec_pod_policy_dict = ipsec_pod_policy.as_dict()
        values = {
            'protocol': ipsec_pod_policy_dict['protocol'].lower(),
            'port': ipsec_pod_policy_dict.get('port', None),
            'policy_status': None,
        }
        LOG.info(f"Create IPsec pod policy in DB:{values}")
        policy_obj = pecan.request.dbapi.ipsec_pod_policy_create(values)

        return policy_obj

    def _get_updates(self, patch):
        """Retrieve the updated attributes from the patch request."""
        updates = {}
        for p in patch:
            attribute = p['path'] if p['path'][0] != '/' else p['path'][1:]
            updates[attribute] = p['value']
        return updates

    @wsme_pecan.wsexpose(IpsecPodPolicyCollection,
                         types.uuid, wtypes.text, wtypes.text, wtypes.text)
    def get_all(self, marker=None, limit=None, sort_key='uuid',
                sort_dir='asc'):
        """Retrieve a list of Ipsec pod policy objects."""
        return self._get_ipsec_pod_policy_collection(marker, limit,
                                                     sort_key=sort_key,
                                                     sort_dir=sort_dir)

    @wsme_pecan.wsexpose(IpsecPodPolicy, types.uuid)
    def get_one(self, ipsec_pod_policy_uuid):
        """Retrieve a single IPsec pod policy object."""
        return self._get_one(ipsec_pod_policy_uuid)

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(IpsecPodPolicy, body=IpsecPodPolicy)
    def post(self, ipsec_pod_policy):
        """Create a new IPsec pod policy."""
        if pecan.request.rpcapi.ipsec_pod_policy_applying_status(
                pecan.request.context):
            raise Exception("An IPsec pod policy is applying")
        policy = self._create_ipsec_pod_policy(ipsec_pod_policy)
        if utils.get_pod_to_pod_security_enabled() is False:
            return
        LOG.info("Call the conductor to create the policy")
        ret = pecan.request.rpcapi.apply_ipsec_pod_policy(
            pecan.request.context)
        if ret:
            LOG.error(f"apply_ipsec_pod_policy return with:{ret}")
            raise Exception("error in IPsec pod policy applying")
        return policy

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(None, types.uuid, status_code=204)
    def delete(self, ipsec_pod_policy_uuid):
        """Delete an IPsec pod policy."""
        if pecan.request.rpcapi.ipsec_pod_policy_applying_status(
                pecan.request.context):
            raise Exception("An IPsec pod policy is applying")
        policy_obj = objects.ipsec_pod_policy.get_by_uuid(
            pecan.request.context, ipsec_pod_policy_uuid)
        if policy_obj:
            pecan.request.dbapi.ipsec_pod_policy_destroy(
                ipsec_pod_policy_uuid)
            if utils.get_pod_to_pod_security_enabled() is False:
                return
            LOG.info("Call the conductor to remove the policy")
            ret = pecan.request.rpcapi.apply_ipsec_pod_policy(
                pecan.request.context)
            if ret:
                LOG.error(f"apply_ipsec_pod_policy return with:{ret}")
                raise Exception("error in IPsec pod policy applying")

    @cutils.synchronized(LOCK_NAME)
    # @wsme.validate(types.uuid, [IpsecPodPolicyPatchType])
    @wsme_pecan.wsexpose(IpsecPodPolicy, wtypes.text,
                         body=[IpsecPodPolicyPatchType])
    def patch(self, uuid_or_operation, patch):
        """Updates attributes of an IPsec pod policy or
           apply IPsec pod policies
        """
        if pecan.request.rpcapi.ipsec_pod_policy_applying_status(
                pecan.request.context):
            raise Exception("An IPsec pod policy is applying")

        if not uuidutils.is_uuid_like(uuid_or_operation):
            # handle IPsec pod policy apply operation
            if uuid_or_operation == 'apply':
                ret = pecan.request.rpcapi.apply_ipsec_pod_policy(
                    pecan.request.context)
                return ret
            else:
                err_str = "Invalid UUID: %s" % uuid_or_operation
                raise ValueError(_(err_str))

        ipsec_pod_policy_uuid = uuid_or_operation
        ipsec_pod_policy = self._get_one(ipsec_pod_policy_uuid)
        updates = self._get_updates(patch)
        LOG.debug("Updates attributes of policy "
                  f"{ipsec_pod_policy_uuid}:{updates}")

        if 'port' in updates:
            # Check if port same as old and raise errors
            if ipsec_pod_policy.port == updates.get('port'):
                err_str = "Error: port %s is not changed" % \
                    ipsec_pod_policy.port
                raise ValueError(_(err_str))
            ipsec_pod_policy.port = updates.get('port')
        if 'protocol' in updates:
            # Check if protocol same as old and raise error
            if ipsec_pod_policy.protocol == updates.get('protocol').lower():
                err_str = "Error: protocol %s is not changed" % \
                    ipsec_pod_policy.protocol
                raise ValueError(_(err_str))
            ipsec_pod_policy.protocol = updates.get('protocol').lower()

        ipsec_pod_policy.validate_policy(ipsec_pod_policy_uuid)
        if utils.get_pod_to_pod_security_enabled() is False:
            return
        LOG.info("Call the conductor to update the policy")
        policy = pecan.request.dbapi.ipsec_pod_policy_update(
            ipsec_pod_policy_uuid, updates)
        ret = pecan.request.rpcapi.apply_ipsec_pod_policy(
            pecan.request.context)
        policy = self._get_one(ipsec_pod_policy_uuid)
        if ret:
            LOG.error(f"apply_ipsec_pod_policy return with:{ret}")
            raise Exception("error in IPsec pod policy applying")
        return policy
