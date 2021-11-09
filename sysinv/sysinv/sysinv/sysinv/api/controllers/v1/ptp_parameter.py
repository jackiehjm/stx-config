#
# Copyright (c) 2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import jsonpatch
import pecan
from pecan import rest
import wsme
from wsme import types as wtypes
import wsmeext.pecan as wsme_pecan

from oslo_log import log
from sysinv._i18n import _
from sysinv.api.controllers.v1 import base
from sysinv.api.controllers.v1 import collection
from sysinv.api.controllers.v1 import types
from sysinv.api.controllers.v1 import utils
from sysinv.common import constants
from sysinv.common import exception
from sysinv.common import utils as cutils
from sysinv import objects

LOG = log.getLogger(__name__)


class PtpParameterPatchType(types.JsonPatchType):
    @staticmethod
    def mandatory_attrs():
        return []


class PtpParameter(base.APIBase):
    """API representation of a PTP parameter.

    This class enforces type checking and value constraints, and converts
    between the internal object model and the API representation of
    a PTP parameter.
    """

    created_at = wtypes.datetime.datetime
    "Timestamp of creation of this PTP parameter"

    updated_at = wtypes.datetime.datetime
    "Timestamp of update of this PTP parameter"

    id = int
    "Unique ID for this PTP parameter"

    uuid = types.uuid
    "Unique UUID for this PTP parameter"

    name = wtypes.text
    "Name of PTP parameter"

    value = wtypes.text
    "Value of PTP parameter"

    type = wtypes.Enum(str,
                       constants.PTP_PARAMETER_OWNER_INSTANCE,
                       constants.PTP_PARAMETER_OWNER_INTERFACE)
    "Type of owner of this PTP parameter"

    foreign_uuid = types.uuid
    "UUID of the owner of this PTP parameter"

    owner = types.MultiType([dict])
    "Owner information: name, type, hostname"

    def __init__(self, **kwargs):
        self.fields = list(objects.ptp_parameter.fields.keys())
        for k in self.fields:
            if not hasattr(self, k):
                continue
            setattr(self, k, kwargs.get(k))

    @classmethod
    def convert_with_links(cls, rpc_ptp_parameter, expand=True):
        ptp_parameter = PtpParameter(**rpc_ptp_parameter.as_dict())
        if not expand:
            ptp_parameter.unset_fields_except(['uuid',
                                               'name',
                                               'value',
                                               'type',
                                               'foreign_uuid',
                                               'owner',
                                               'created_at',
                                               'updated_at'])

        LOG.debug("PtpParameter.convert_with_links: converted %s" %
                  ptp_parameter.as_dict())
        return ptp_parameter


class PtpParameterCollection(collection.Collection):
    """API representation of a collection of PTP parameters."""

    ptp_parameters = [PtpParameter]
    "A list containing PTP parameter objects"

    def __init__(self, **kwargs):
        self._type = 'ptp_parameters'

    @classmethod
    def convert_with_links(cls, rpc_ptp_parameters, limit, url=None,
                           expand=False, **kwargs):
        collection = PtpParameterCollection()
        collection.ptp_parameters = [PtpParameter.convert_with_links(p, expand)
                                     for p in rpc_ptp_parameters]
        collection.next = collection.get_next(limit, url=url, **kwargs)
        return collection


LOCK_NAME = 'PtpParameterController'


class PtpParameterController(rest.RestController):
    """REST controller for PTP parameter."""

    def __init__(self, parent=None):
        self._parent = parent

    def _get_ptp_parameter_collection(
            self, parent_uuid=None, type=None, marker=None, limit=None,
            sort_key=None, sort_dir=None, expand=False, resource_url=None):
        LOG.debug("PtpParameterController._get_ptp_parameter_collection: "
                  "parent %s uuid %s type %s" %
                  (self._parent, parent_uuid, type))
        if self._parent and not parent_uuid:
            raise exception.InvalidParameterValue(_(
                  "Parent id not specified."))

        limit = utils.validate_limit(limit)
        sort_dir = utils.validate_sort_dir(sort_dir)

        LOG.debug("PtpParameterController._get_ptp_parameter_collection: "
                  "marker %s, limit %s, sort_dir %s" % (marker, limit,
                                                        sort_dir))

        marker_obj = None
        if marker:
            marker_obj = objects.ptp_parameter.get_by_uuid(
                pecan.request.context, marker)

        if parent_uuid:
            ptp_parameters = pecan.request.dbapi.ptp_parameters_get_by_owner(
                parent_uuid, limit, marker_obj, sort_key=sort_key,
                sort_dir=sort_dir)
        elif type is not None:
            ptp_parameters = pecan.request.dbapi.ptp_parameters_get_by_type(
                type, limit, marker_obj, sort_key=sort_key, sort_dir=sort_dir)
        else:
            ptp_parameters = pecan.request.dbapi.ptp_parameters_get_list(
                limit, marker_obj, sort_key=sort_key, sort_dir=sort_dir)

        return PtpParameterCollection.convert_with_links(
            ptp_parameters, limit, url=resource_url, expand=expand,
            sort_key=sort_key, sort_dir=sort_dir)

    @wsme_pecan.wsexpose(PtpParameterCollection, types.uuid, types.uuid,
                         int, wtypes.text, wtypes.text)
    def get_all(self, uuid=None, marker=None, limit=None,
                sort_key='id', sort_dir='asc'):
        """Retrieve a list of PTP parameters."""
        type = None
        LOG.debug("PtpParameterController.get_all: uuid=%s, type=%s" %
                  (uuid, type))
        return self._get_ptp_parameter_collection(uuid, type,
                                                  marker, limit,
                                                  sort_key=sort_key,
                                                  sort_dir=sort_dir)

    @wsme_pecan.wsexpose(PtpParameter, types.uuid)
    def get_one(self, ptp_parameter_uuid):
        """Retrieve a single PTP parameter."""
        LOG.debug("PtpParameterController.get_one: uuid=%s" %
                  ptp_parameter_uuid)
        try:
            ptp_parameter = objects.ptp_parameter.get_by_uuid(
                pecan.request.context,
                ptp_parameter_uuid)
        except exception.InvalidParameterValue:
            raise wsme.exc.ClientSideError(
                _("No PTP parameter found for %s" % ptp_parameter_uuid))

        return PtpParameter.convert_with_links(ptp_parameter)

    def _check_foreign_exists(self, type, uuid):
        LOG.debug("PtpParameterController._check_foreign_exists: "
                  "type %s uuid %s" % (type, uuid))
        try:
            if type == constants.PTP_PARAMETER_OWNER_INSTANCE:
                try:
                    pecan.request.dbapi.ptp_instance_get(uuid)
                except exception.PtpInstanceNotFound:
                    raise exception.NotFound
            elif type == constants.PTP_PARAMETER_OWNER_INTERFACE:
                try:
                    pecan.request.dbapi.ptp_interface_get(uuid)
                except exception.PtpInterfaceNotFound:
                    raise exception.NotFound
        except exception.NotFound:
            raise wsme.exc.ClientSideError(
                _("No foreign object found with id %s" % uuid))

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(PtpParameter, body=PtpParameter)
    def post(self, ptp_parameter):
        """Create a new PTP parameter."""
        ptp_parameter_dict = ptp_parameter.as_dict()
        LOG.debug("PtpParameterController.post: %s" % ptp_parameter_dict)

        self._check_foreign_exists(ptp_parameter_dict['type'],
                                   ptp_parameter_dict['foreign_uuid'])

        # Get rid of owner details to create the PTP parameter
        try:
            ptp_parameter_dict.pop('owner')
        except KeyError:
            LOG.debug("PtpParameterController.post: no owner data in %s" %
                      ptp_parameter_dict)

        result = pecan.request.dbapi.ptp_parameter_create(ptp_parameter_dict)
        return PtpParameter.convert_with_links(result)

    @cutils.synchronized(LOCK_NAME)
    @wsme.validate(types.uuid, [PtpParameterPatchType])
    @wsme_pecan.wsexpose(PtpParameter, types.uuid,
                         body=[PtpParameterPatchType])
    def patch(self, uuid, patch):
        """Update the value of an existing PTP parameter."""
        if self._parent:
            raise exception.OperationNotPermitted

        ptp_parameter = objects.ptp_parameter.get_by_uuid(
            pecan.request.context, uuid)

        patch_obj = jsonpatch.JsonPatch(patch)
        try:
            patched_parameter = PtpParameter(
                **jsonpatch.apply_patch(ptp_parameter.as_dict(), patch_obj))
        except utils.JSONPATCH_EXCEPTIONS as e:
            raise exception.PatchError(patch=patch, reason=e)

        # Update only the fields that have changed
        for field in objects.ptp_parameter.fields:
            if ptp_parameter[field] != getattr(patched_parameter, field):
                ptp_parameter[field] = getattr(patched_parameter, field)

        ptp_parameter.save()
        return PtpParameter.convert_with_links(ptp_parameter)

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(None, types.uuid, status_code=204)
    def delete(self, ptp_parameter_uuid):
        """Delete a PTP parameter."""
        LOG.debug("PtpParameterController.delete: %s" % ptp_parameter_uuid)
        if self._parent:
            raise exception.OperationNotPermitted

        pecan.request.dbapi.ptp_parameter_destroy(ptp_parameter_uuid)
