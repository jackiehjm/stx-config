#
# Copyright (c) 2020-2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from distutils.util import strtobool
import os
import pecan
from pecan import expose
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
from sysinv.common import device as dconstants
from sysinv.common import exception
from sysinv.common import utils as cutils
from sysinv.fpga_agent import constants as fpga_constants
from sysinv import objects

LOG = log.getLogger(__name__)

ALLOWED_BITSTREAM_TYPES = [
    dconstants.BITSTREAM_TYPE_ROOT_KEY,
    dconstants.BITSTREAM_TYPE_FUNCTIONAL,
    dconstants.BITSTREAM_TYPE_KEY_REVOCATION,
]


class DeviceImagePatchType(types.JsonPatchType):
    @staticmethod
    def mandatory_attrs():
        return []


class DeviceImage(base.APIBase):
    """API representation of a device_image.

    This class enforces type checking and value constraints, and converts
    between the internal object model and the API representation of
    a device image.
    """

    id = int
    "Unique ID for this device_image"

    uuid = types.uuid
    "Unique UUID for this device_image"

    bitstream_type = wtypes.text
    "The bitstream type of the device image"

    pci_vendor = wtypes.text
    "The vendor ID of the pci device"

    pci_device = wtypes.text
    "The device ID of the pci device"

    bitstream_id = wtypes.text
    "The bitstream id of the functional device image"

    key_signature = wtypes.text
    "The key signature of the root-key device image"

    revoke_key_id = int
    "The key revocation id of the key revocation device image"

    name = wtypes.text
    "The name of the device image"

    description = wtypes.text
    "The description of the device image"

    image_version = wtypes.text
    "The version of the device image"

    bmc = bool
    "Represent the functional image is a BMC image"

    retimer_included = bool
    "Retimer firmware included in BMC firmware binary"

    applied = bool
    "Represent current status: created or applied"

    applied_labels = types.MultiType([list])
    "Represent a list of key-value pair of labels"

    def __init__(self, **kwargs):
        self.fields = list(objects.device_image.fields.keys())
        for k in self.fields:
            setattr(self, k, kwargs.get(k))

        # API-only attribute
        self.fields.append('action')
        setattr(self, 'action', kwargs.get('action', None))

        # 'applied_labels' is not part of the object.device_image.fields
        # (it is an API-only attribute)
        self.fields.append('applied_labels')
        setattr(self, 'applied_labels', kwargs.get('applied_labels', None))

    @classmethod
    def convert_with_links(cls, rpc_device_image, expand=True):
        device_image = DeviceImage(**rpc_device_image.as_dict())
        if not expand:
            device_image.unset_fields_except(
                ['id', 'uuid', 'bitstream_type', 'pci_vendor', 'pci_device',
                 'bitstream_id', 'key_signature', 'revoke_key_id',
                 'name', 'description', 'image_version',
                 'applied', 'applied_labels', 'bmc', 'retimer_included'])

        # insert applied labels for this device image if they exist
        device_image = _get_applied_labels(device_image)

        # do not expose the id attribute
        device_image.id = wtypes.Unset

        return device_image

    def _validate_bitstream_type(self):
        if self.bitstream_type not in ALLOWED_BITSTREAM_TYPES:
            raise ValueError(_("Bitstream type %s not supported") %
                             self.bitstream_type)

    def validate_syntax(self):
        """
        Validates the syntax of each field.
        """
        self._validate_bitstream_type()


class DeviceImageCollection(collection.Collection):
    """API representation of a collection of device_image."""

    device_images = [DeviceImage]
    "A list containing device_image objects"

    def __init__(self, **kwargs):
        self._type = 'device_images'

    @classmethod
    def convert_with_links(cls, rpc_device_images, limit, url=None,
                           expand=False, **kwargs):
        collection = DeviceImageCollection()
        collection.device_images = [DeviceImage.convert_with_links(p, expand)
                              for p in rpc_device_images]
        collection.next = collection.get_next(limit, url=url, **kwargs)
        return collection


def _get_applied_labels(device_image):
    if not device_image:
        return device_image
    image_labels = pecan.request.dbapi.device_image_label_get_by_image(
        device_image.id)

    applied_labels = []
    if image_labels:
        for image_label in image_labels:
            label = pecan.request.dbapi.device_label_get(image_label.label_uuid)
            label_dict = {label.label_key: label.label_value}
            if label_dict not in applied_labels:
                applied_labels.append({label.label_key: label.label_value})
        device_image.applied_labels = applied_labels

    # In the database, 'applied' field is True if the image is applied without
    # labels and False if the image is not applied without labels.
    # In the api response, 'applied' field is True if the image is applied with
    # or without labels and False if the image is not applied
    if device_image.applied:
        # image is applied without labels, insert a null dict to applied-labels
        applied_labels.append({})
        device_image.applied_labels = applied_labels
    elif device_image.applied_labels is not None:
        # image is applied with labels, set the applied attribute to True
        device_image.applied = True
    return device_image


LOCK_NAME = 'DeviceImageController'


class DeviceImageController(rest.RestController):
    """REST controller for device_image."""

    def __init__(self, parent=None, **kwargs):
        self._parent = parent

    def _get_device_image_collection(
            self, marker=None, limit=None, sort_key=None,
            sort_dir=None, expand=False, resource_url=None):

        limit = utils.validate_limit(limit)
        sort_dir = utils.validate_sort_dir(sort_dir)
        marker_obj = None
        if marker:
            marker_obj = objects.device_image.get_by_uuid(
                pecan.request.context,
                marker)

        deviceimages = pecan.request.dbapi.deviceimages_get_all(
            limit=limit, marker=marker_obj,
            sort_key=sort_key, sort_dir=sort_dir)

        return DeviceImageCollection.convert_with_links(
            deviceimages, limit, url=resource_url, expand=expand,
            sort_key=sort_key, sort_dir=sort_dir)

    def _get_one(self, deviceimage_uuid):
        rpc_deviceimage = objects.device_image.get_by_uuid(
            pecan.request.context, deviceimage_uuid)
        return DeviceImage.convert_with_links(rpc_deviceimage)

    @wsme_pecan.wsexpose(DeviceImageCollection,
                         types.uuid, int, wtypes.text, wtypes.text)
    def get_all(self, marker=None, limit=None, sort_key='id', sort_dir='asc'):
        """Retrieve a list of device images."""

        return self._get_device_image_collection(marker, limit,
                                                 sort_key=sort_key,
                                                 sort_dir=sort_dir)

    @wsme_pecan.wsexpose(DeviceImage, wtypes.text)
    def get_one(self, deviceimage_uuid):
        """Retrieve a single device image."""

        return self._get_one(deviceimage_uuid)

    @expose('json')
    @cutils.synchronized(LOCK_NAME)
    def post(self):
        """Create a new device image."""

        fileitem = pecan.request.POST['file']
        if not fileitem.filename:
            return dict(success="", error="Error: No file uploaded")
        try:
            file_content = fileitem.file.read()
        except Exception as e:
            return dict(
                success="",
                error=("No bitstream file has been added, "
                       "invalid file: %s" % e))

        field_list = ['uuid', 'bitstream_type', 'pci_vendor', 'pci_device',
                      'bitstream_id', 'key_signature', 'revoke_key_id',
                      'name', 'description', 'image_version', 'bmc', 'retimer_included']
        data = dict((k, v) for (k, v) in pecan.request.POST.items()
                if k in field_list and not (v is None))
        msg = _validate_syntax(data)
        if msg:
            return dict(success="", error=msg)
        msg = _validate_pci_device(data)
        if msg:
            return dict(error=msg)

        for k, v in data.items():
            if k == 'bmc':
                data['bmc'] = bool(strtobool(v))
            if k == 'retimer_included':
                data['retimer_included'] = bool(strtobool(v))

        device_image = pecan.request.dbapi.deviceimage_create(data)
        device_image_dict = device_image.as_dict()

        # Save the file contents in a temporary location
        filename = cutils.format_image_filename(device_image)
        image_file_path = os.path.join(dconstants.DEVICE_IMAGE_TMP_PATH, filename)
        if not os.path.exists(dconstants.DEVICE_IMAGE_TMP_PATH):
            os.makedirs(dconstants.DEVICE_IMAGE_TMP_PATH)
        with os.fdopen(os.open(image_file_path,
                       os.O_CREAT | os.O_TRUNC | os.O_WRONLY,
                       constants.CONFIG_FILE_PERMISSION_DEFAULT),
                       'wb') as f:
            f.write(file_content)
        # Call rpc to move the bitstream file to the final destination
        pecan.request.rpcapi.store_bitstream_file(pecan.request.context, filename)
        return dict(success="", error="", device_image=device_image_dict)

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(DeviceImage, types.uuid, status_code=202)
    def delete(self, deviceimage_uuid):
        """Delete a device image."""
        device_image = objects.device_image.get_by_uuid(
            pecan.request.context, deviceimage_uuid)

        # Check if the image has been written or is being written to any of the devices
        if pecan.request.dbapi.device_image_state_get_all(
                image_id=device_image.id,
                status=[dconstants.DEVICE_IMAGE_UPDATE_COMPLETED,
                        dconstants.DEVICE_IMAGE_UPDATE_IN_PROGRESS]):
            raise wsme.exc.ClientSideError(_(
                "Delete failed: device image is being written to or has "
                "already been written to devices"))

        image_labels = pecan.request.dbapi.device_image_label_get_by_image(
            device_image.id)
        for lbl in image_labels:
            rec = pecan.request.dbapi.device_image_label_get_by_label(lbl.label_id)
            if len(rec) == 1:
                # Delete the device label that is not associated with a physical device
                label = pecan.request.dbapi.device_label_get(lbl.label_uuid)
                if label.pcidevice_id is None:
                    pecan.request.dbapi.device_label_destroy(lbl.label_id)

        pecan.request.dbapi.deviceimage_destroy(deviceimage_uuid)
        filename = cutils.format_image_filename(device_image)
        pecan.request.rpcapi.delete_bitstream_file(pecan.request.context,
                                                   filename)
        return DeviceImage.convert_with_links(device_image)

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(DeviceImage, types.uuid, wtypes.text, body=types.apidict)
    def patch(self, uuid, action, body):
        """Apply/Remove a device image to/from host ."""
        if action not in [dconstants.APPLY_ACTION, dconstants.REMOVE_ACTION]:
            raise exception.OperationNotPermitted

        try:
            device_image = objects.device_image.get_by_uuid(
                pecan.request.context, uuid)
        except exception.DeviceImageNotFound:
            LOG.error("Device image %s deos not exist." % uuid)
            raise wsme.exc.ClientSideError(_(
                "Device image {} failed: image does not exist".format(action)))

        # find device label with matching label key and value
        for lbl_dict in body:
            key, value = list(lbl_dict.items())[0]
            device_labels = pecan.request.dbapi.device_label_get_by_label(
                key, value, sort_key='host_id', sort_dir='asc')
            if not device_labels and action == dconstants.APPLY_ACTION:
                # Create device label without a local host device
                values = {
                    'host_id': None, 'pcidevice_id': None,
                    'label_key': key, 'label_value': value
                }
                pecan.request.dbapi.device_label_create(None, values)
                device_labels = pecan.request.dbapi.device_label_get_by_label(
                    key, value)
            elif not device_labels and action == dconstants.REMOVE_ACTION:
                raise wsme.exc.ClientSideError(_(
                    "Device image {} failed: label {}={} does not exist".format(
                        action, key, value)))
                break

            for device_label in device_labels:
                if action == dconstants.APPLY_ACTION:
                    if device_label.pcidevice_id is not None:
                        if process_device_image_apply(device_label.pcidevice_id,
                                device_image, device_label.id):
                            update_device_image_state(device_label.host_id,
                                device_label.pcidevice_id,
                                device_image.id, dconstants.DEVICE_IMAGE_UPDATE_PENDING)
                            set_host_device_image_update_pending(device_label.host_uuid)
                    try:
                        pecan.request.dbapi.device_image_label_get_by_image_label(
                            device_image.id, device_label.id)
                    except exception.DeviceImageLabelNotFoundByKey:
                        # Create an entry of image to label mapping
                        pecan.request.dbapi.device_image_label_create({
                            'image_id': device_image.id,
                            'label_id': device_label.id,
                        })

                elif action == dconstants.REMOVE_ACTION:
                    try:
                        img_lbl = pecan.request.dbapi.device_image_label_get_by_image_label(
                            device_image.id, device_label.id)
                        if img_lbl:
                            pecan.request.dbapi.device_image_label_destroy(img_lbl.id)
                    except exception.DeviceImageLabelNotFoundByKey:
                        # device image was applied with either the host device
                        # specific label or the non-hardware device label
                        pass
                    # If the label is not associated with a local device and
                    # no other image is applied with the label, then
                    # delete the device label.
                    if (not pecan.request.dbapi.device_image_label_get_by_label(device_label.id) and
                            device_label.pcidevice_id is None):
                        pecan.request.dbapi.device_label_destroy(device_label.uuid)
                    if device_label.pcidevice_id is not None:
                        delete_device_image_state(device_label.pcidevice_id, device_image)

        if not body:
            # No host device labels specified, apply to all hosts
            LOG.info("No host device labels specified")
            hosts = pecan.request.dbapi.ihost_get_list()
            for host in hosts:
                fpga_devices = pecan.request.dbapi.fpga_device_get_by_host(host.id)
                for dev in fpga_devices:
                    if action == dconstants.APPLY_ACTION:
                        if process_device_image_apply(dev.pci_id, device_image):
                            update_device_image_state(host.id,
                                dev.pci_id, device_image.id,
                                dconstants.DEVICE_IMAGE_UPDATE_PENDING)
                            set_host_device_image_update_pending(host.uuid)
                    elif action == dconstants.REMOVE_ACTION:
                        delete_device_image_state(dev.pci_id, device_image)

            if action == dconstants.APPLY_ACTION:
                # set applied flag to True to indicate the image is applied
                # without label
                pecan.request.dbapi.deviceimage_update(device_image.uuid,
                                                       {'applied': True})
            elif action == dconstants.REMOVE_ACTION:
                # set applied flag to False to indicate the image is not applied
                pecan.request.dbapi.deviceimage_update(device_image.uuid,
                                                       {'applied': False})

        if action == dconstants.APPLY_ACTION:
            # If any of the devices needs updating, call rpc to raise alarm
            if pecan.request.dbapi.device_image_state_get_all(
                    image_id=device_image.id,
                    status=[dconstants.DEVICE_IMAGE_UPDATE_PENDING,
                            dconstants.DEVICE_IMAGE_UPDATE_FAILED,
                            dconstants.DEVICE_IMAGE_UPDATE_IN_PROGRESS]):
                pecan.request.rpcapi.apply_device_image(pecan.request.context)
        elif action == dconstants.REMOVE_ACTION:
            pecan.request.rpcapi.clear_device_image_alarm(pecan.request.context)
        device_image = objects.device_image.get_by_uuid(pecan.request.context, uuid)
        return DeviceImage.convert_with_links(device_image)


def _validate_bitstream_type(dev_img):
    msg = None
    if dev_img['bitstream_type'] not in ALLOWED_BITSTREAM_TYPES:
        msg = _("Bitstream type %s not supported" % dev_img['bitstream_type'])
    elif (dev_img['bitstream_type'] == dconstants.BITSTREAM_TYPE_FUNCTIONAL and
            'bitstream_id' not in dev_img):
        msg = _("bitstream_id is required for functional bitstream type")
    elif (dev_img['bitstream_type'] == dconstants.BITSTREAM_TYPE_ROOT_KEY and
          'key_signature' not in dev_img):
        msg = _("key_signature is required for root key bitstream type")
    elif (dev_img['bitstream_type'] == dconstants.BITSTREAM_TYPE_KEY_REVOCATION and
          'revoke_key_id' not in dev_img):
        msg = _("revoke_key_id is required for key revocation bitstream type")
    elif (dev_img['bitstream_type'] != dconstants.BITSTREAM_TYPE_FUNCTIONAL and
          'bmc' in dev_img.keys()):
        msg = _("bmc option is only applicable to functional image")
    elif (dev_img['bitstream_type'] != dconstants.BITSTREAM_TYPE_FUNCTIONAL and
          'retimer_included' in dev_img.keys()):
        msg = _("retimer_included option is only applicable to functional BMC image")
    elif dev_img['bitstream_type'] == dconstants.BITSTREAM_TYPE_FUNCTIONAL:
        bmc = False
        retimer_included = False
        if 'bmc' in dev_img.keys():
            bmc = bool(strtobool(dev_img['bmc']))
        if 'retimer_included' in dev_img.keys():
            retimer_included = bool(strtobool(dev_img['retimer_included']))
        if not bmc and retimer_included:
            msg = _("retimer_included option is only applicable to functional BMC image")
    return msg


def _is_hex_string(s):
    try:
        int(s, 16)
        return True
    except ValueError:
        return False


def _validate_hexadecimal_fields(dev_img):
    msg = None
    if ('pci_vendor' in dev_img.keys() and
            not _is_hex_string(dev_img['pci_vendor'])):
        msg = _("pci_vendor must be hexadecimal")
    elif ('pci_device' in dev_img.keys() and
            not _is_hex_string(dev_img['pci_device'])):
        msg = _("pci_device must be hexadecimal")
    elif ('bitstream_id' in dev_img.keys() and
            not _is_hex_string(dev_img['bitstream_id'])):
        msg = _("bitstream_id must be hexadecimal")
    elif ('key_signature' in dev_img.keys() and
            not _is_hex_string(dev_img['key_signature'])):
        msg = _("key_signature must be hexadecimal")
    return msg


def _check_revoke_key(dev_img):
    msg = None
    if ('revoke_key_id' in dev_img.keys()):
        if str(dev_img['revoke_key_id']).isdigit():
            dev_img['revoke_key_id'] = int(dev_img['revoke_key_id'])
        else:
            msg = _("revoke_key_id must be an integer")
    return msg


def _validate_syntax(device_image):
    """
    Validates the syntax of each field.
    """
    if ('uuid' in device_image.keys() and
            not cutils.is_uuid_like(device_image['uuid'])):
        msg = _("uuid must be a valid UUID")
        return msg
    if ('bmc' in device_image.keys() and
            not cutils.is_valid_boolstr(device_image['bmc'])):
        msg = _("Parameter bmc must be a valid bool string")
        return msg
    if ('retimer_included' in device_image.keys() and
            not cutils.is_valid_boolstr(device_image['retimer_included'])):
        msg = _("Parameter retimer_included must be a valid bool string")
        return msg
    msg = _validate_hexadecimal_fields(device_image)
    if not msg:
        msg = _validate_bitstream_type(device_image)
        if not msg:
            msg = _check_revoke_key(device_image)
    return msg


def _validate_pci_device(device_image):
    msg = None
    if (device_image['pci_vendor'] != fpga_constants.N3000_VENDOR or
           device_image['pci_device'] != fpga_constants.N3000_DEVICE):
        msg = _("Invalid PCI vendor/device ID: %s %s. "
                "Supported vendor ID: %s and supported device ID: %s" %
                (device_image['pci_vendor'], device_image['pci_device'],
                 fpga_constants.N3000_VENDOR, fpga_constants.N3000_DEVICE))
    return msg


def set_host_device_image_update_pending(host_uuid):
    host = objects.host.get_by_uuid(pecan.request.context, host_uuid)
    if host.device_image_update != dconstants.DEVICE_IMAGE_UPDATE_IN_PROGRESS:
        host.device_image_update = dconstants.DEVICE_IMAGE_UPDATE_PENDING
        host.save()


def update_device_image_state(host_id, pcidevice_id, image_id, status):
    try:
        dev_img_state = pecan.request.dbapi.device_image_state_get_by_image_device(
            image_id, pcidevice_id)
        pecan.request.dbapi.device_image_state_update(dev_img_state.id,
                                                      {'status': status})
    except exception.DeviceImageStateNotFoundByKey:
        # Create an entry of image to device mapping
        state_values = {
            'host_id': host_id,
            'pcidevice_id': pcidevice_id,
            'image_id': image_id,
            'status': status,
        }
        pecan.request.dbapi.device_image_state_create(state_values)


def process_device_image_apply(pcidevice_id, device_image, label_id=None):
    pci_device = pecan.request.dbapi.pci_device_get(pcidevice_id)
    host = pecan.request.dbapi.ihost_get(pci_device.host_uuid)
    response = True
    # check if device image with type functional or root-key already applied
    # to the device
    records = pecan.request.dbapi.device_image_state_get_all(
         host_id=host.id, pcidevice_id=pcidevice_id)
    for r in records:
        img = pecan.request.dbapi.deviceimage_get(r.image_id)
        if img.bitstream_type == device_image.bitstream_type:
            if img.bitstream_type == dconstants.BITSTREAM_TYPE_ROOT_KEY:
                if img.id != device_image.id:
                    # Block applying root-key image if another one is already applied
                    msg = _("Root-key image {} is already applied to host {} device"
                            " {}".format(img.uuid, host.hostname, pci_device.pciaddr))
                    raise wsme.exc.ClientSideError(msg)
                else:
                    # reapplying the same image
                    if r.status in [dconstants.DEVICE_IMAGE_UPDATE_COMPLETED,
                                    dconstants.DEVICE_IMAGE_UPDATE_IN_PROGRESS,
                                    dconstants.DEVICE_IMAGE_UPDATE_PENDING]:
                        # return False for nothing to do
                        response = False
            elif img.bitstream_type == dconstants.BITSTREAM_TYPE_FUNCTIONAL:
                if r.status == dconstants.DEVICE_IMAGE_UPDATE_IN_PROGRESS:
                    msg = _("Applying image {} for host {} device {} not allowed "
                            "while device image update is in progress".format(
                                device_image.uuid, host.hostname, pci_device.pciaddr))
                    raise wsme.exc.ClientSideError(msg)
                if img.id == device_image.id:
                    if r.status in [dconstants.DEVICE_IMAGE_UPDATE_COMPLETED,
                                    dconstants.DEVICE_IMAGE_UPDATE_PENDING]:
                        # return False for nothing to do
                        response = False
                else:
                    do_remove = True
                    # If the new image and the applied image are of a different kind (user/bmc),
                    # do not remove the image.
                    # If the new BMC image does not have retimer and an applied BMC image
                    # does have retimer, keep that applied device image state.
                    if device_image.bmc != img.bmc:
                        do_remove = False
                    if (device_image.bmc and
                            (not device_image.retimer_included and img.retimer_included)):
                        do_remove = False
                    if do_remove:
                        # Remove the existing device_image_state record
                        pecan.request.dbapi.device_image_state_destroy(r.uuid)
                        # Remove the existing device image label if any
                        if label_id:
                            try:
                                img_lbl = pecan.request.dbapi.device_image_label_get_by_image_label(
                                    img.id, label_id)
                                pecan.request.dbapi.device_image_label_destroy(img_lbl.uuid)
                            except exception.DeviceImageLabelNotFoundByKey:
                                pass
            elif img.bitstream_type == dconstants.BITSTREAM_TYPE_KEY_REVOCATION:
                if img.id == device_image.id:
                    if r.status in [dconstants.DEVICE_IMAGE_UPDATE_COMPLETED,
                                    dconstants.DEVICE_IMAGE_UPDATE_IN_PROGRESS,
                                    dconstants.DEVICE_IMAGE_UPDATE_PENDING]:
                        # return False for nothing to do
                        response = False
    return response


def delete_device_image_state(pcidevice_id, device_image):
    try:
        dev_img = pecan.request.dbapi.device_image_state_get_by_image_device(
            device_image.id, pcidevice_id)
        pecan.request.dbapi.device_image_state_destroy(dev_img.uuid)
    except exception.DeviceImageStateNotFoundByKey:
        pass
