# vim: tabstop=4 shiftwidth=4 softtabstop=4
# -*- encoding: utf-8 -*-
#
#
# Copyright (c) 2020-2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""
Tests for the API /interfaces/ methods.
"""

import time
from six.moves import http_client

from sysinv.common import constants
from sysinv.common import device as dconstants
from sysinv.tests.api import base
from sysinv.tests.db import base as dbbase
from sysinv.tests.db import utils as dbutils


class TestDevice(base.FunctionalTest, dbbase.BaseHostTestCase):
    def _setup_configuration(self):
        pass

    def setUp(self):
        super(TestDevice, self).setUp()
        self._setup_context()

    def _get_path(self, device_uuid=None):
        if device_uuid:
            return '/pci_devices/' + device_uuid
        else:
            return '/pci_devices'

    def _post_get_test_device(self, **kw):
        device = dbutils.get_test_pci_device(**kw)

        # When invoking a POST the following fields should not be populated:
        del device['id']

        return device

    def _create_host(self, personality, subfunction=None,
                     mgmt_mac=None, mgmt_ip=None,
                     admin=None,
                     invprovision=constants.PROVISIONED, **kw):
        host = self._create_test_host(
            personality=personality,
            subfunction=subfunction,
            administrative=admin or constants.ADMIN_UNLOCKED,
            invprovision=invprovision,
            **kw)
        if personality == constants.CONTROLLER:
            self.controller = host
        else:
            self.worker = host
        return host

    def _create_device(self, **kw):
        device = dbutils.create_test_pci_device(**kw)
        return device

    def _post_and_check_success(self, ndict):
        response = self.post_json('%s' % self._get_path(), ndict)
        self.assertEqual(http_client.OK, response.status_int)
        return response

    def _post_and_check_not_allowed(self, ndict):
        response = self.post_json('%s' % self._get_path(), ndict,
                                  expect_errors=True)
        self.assertEqual(http_client.METHOD_NOT_ALLOWED, response.status_int)
        self.assertEqual('application/json', response.content_type)
        self.assertTrue(response.json['error_message'])
        return response

    def _post_and_check(self, ndict, expect_errors=False, error_message=None):
        response = self.post_json('%s' % self._get_path(), ndict,
                                  expect_errors)
        if expect_errors:
            self.assertEqual(http_client.BAD_REQUEST, response.status_int)
            self.assertEqual('application/json', response.content_type)
            self.assertTrue(response.json['error_message'])
            if error_message:
                self.assertIn(error_message, response.json['error_message'])
        else:
            self.assertEqual(http_client.OK, response.status_int)
        return response

    def _patch_and_check(self, data, path, expect_errors=False, error_message=None):
        response = self.patch_dict('%s' % path, expect_errors=expect_errors, data=data)
        if expect_errors:
            self.assertEqual(http_client.BAD_REQUEST, response.status_int)
            self.assertEqual('application/json', response.content_type)
            self.assertTrue(response.json['error_message'])
            if error_message:
                self.assertIn(error_message, response.json['error_message'])
        else:
            self.assertEqual(http_client.OK, response.status_int)
        return response

    def _setup_context(self):
        self.controller = None
        self.worker = None
        self._create_host(constants.WORKER, admin=constants.ADMIN_LOCKED)


class TestListDevice(TestDevice):
    def setUp(self):
        super(TestListDevice, self).setUp()

    def test_device_list_one(self):
        device = dbutils.create_test_pci_device(
            host_id=self.worker.id,
            pclass_id='030000',
            pvendor_id='80ee',
            pdevice_id='beef',
            sriov_totalvfs=64
        )

        result = self.get_json(self._get_path(device['uuid']))

        self.assertEqual(result['pclass_id'], '030000')
        self.assertEqual(result['pvendor_id'], '80ee')
        self.assertEqual(result['pdevice_id'], 'beef')
        self.assertEqual(result['sriov_totalvfs'], 64)

    def test_device_list_all(self):
        dbutils.create_test_pci_device(
            host_id=self.worker.id,
            pclass_id='030000',
            pvendor_id='80ee',
            pdevice_id='beef',
            sriov_totalvfs=64
        )
        data = self.get_json(self._get_path())
        self.assertEqual(1, len(data['pci_devices']))
        self.assertEqual(data['pci_devices'][0]['pclass_id'], '030000')
        self.assertEqual(data['pci_devices'][0]['pvendor_id'], '80ee')
        self.assertEqual(data['pci_devices'][0]['pdevice_id'], 'beef')
        self.assertEqual(data['pci_devices'][0]['sriov_totalvfs'], 64)


class TestPostDevice(TestDevice, dbbase.ControllerHostTestCase):

    def test_device_post_failure(self):
        # Test creation of a device

        ndict = self._post_get_test_device(
            host_uuid=self.worker.uuid,
            name='device0',
            pclass_id='030000',
            pvendor_id='80ee',
            pdevice_id='beef',
            sriov_totalvfs=64)
        self._post_and_check_not_allowed(ndict)


class TestPatchDevice(TestDevice):

    def setUp(self,
              pclass_id=dconstants.PCI_DEVICE_CLASS_FPGA.__str__().split(' '),
              pdev_id='0d8f'
              ):
        super(TestPatchDevice, self).setUp()

        # PCI_DEVICE_CLASS_FPGA is now a class that overloads euqality conditional.
        # This was needed to account for PCI devices with ProgIF other than 0x0.
        # First element in pclass_id is the default 0x120000 Classid + ProgIF.

        self.pclass_id = pclass_id[0]
        self.pdevice = 'Device [' + pdev_id + ']'

        # Create a pci_device
        self.pci_device = dbutils.create_test_pci_device(
            host_id=self.worker.id,
            pciaddr='0000:b7:00.0',
            name='pci_0000_b7_00_0',
            pclass='Processing accelerators',
            pclass_id=self.pclass_id,
            pvendor='Intel Corporation',
            pvendor_id='8086',
            pdevice='Device [0d8f]',
            pdevice_id=dconstants.PCI_DEVICE_ID_FPGA_INTEL_5GNR_FEC_PF,
            driver=None,
            enabled=False,
            sriov_totalvfs=8,
            sriov_numvfs=0,
            sriov_vf_driver=None)
        time.sleep(2)
        response = self.get_json(self._get_path(self.pci_device['uuid']))
        self.assertEqual('0000:b7:00.0', response['pciaddr'])
        self.assertEqual('pci_0000_b7_00_0', response['name'])
        self.assertEqual('Processing accelerators', response['pclass'])
        self.assertEqual(self.pclass_id, response['pclass_id'])
        self.assertEqual('Intel Corporation', response['pvendor'])
        self.assertEqual('8086', response['pvendor_id'])
        self.assertEqual(self.pdevice, response['pdevice'])
        self.assertEqual(dconstants.PCI_DEVICE_ID_FPGA_INTEL_5GNR_FEC_PF, response['pdevice_id'])
        self.assertEqual(None, response['driver'])
        self.assertEqual(False, response['enabled'])
        self.assertEqual(8, response['sriov_totalvfs'])
        self.assertEqual(0, response['sriov_numvfs'])
        self.assertEqual(None, response['sriov_vf_driver'])

    def test_device_modify_name(self):
        self.pci_device = dbutils.create_test_pci_device(
            host_id=self.worker.id,
            pdevice_id='FFFF')
        response = self.patch_dict_json(
            '%s' % self._get_path(self.pci_device['uuid']),
            name='new_name',
            expect_errors=False)
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(http_client.OK, response.status_code)
        self.assertEqual('new_name', response.json['name'])

    def test_device_modify_enabled(self):
        response = self.patch_dict_json(
            '%s' % self._get_path(self.pci_device['uuid']),
            enabled=True,
            expect_errors=False)
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(http_client.OK, response.status_code)
        self.assertEqual(True, response.json['enabled'])

    def test_device_modify_driver(self):
        response = self.patch_dict_json(
            '%s' % self._get_path(self.pci_device['uuid']),
            driver='igb_uio',
            expect_errors=False)
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(http_client.OK, response.status_code)
        self.assertEqual('igb_uio', response.json['driver'])

    def test_device_modify_sriov_numvfs(self):
        response = self.patch_dict_json(
            '%s' % self._get_path(self.pci_device['uuid']),
            driver='igb_uio',
            sriov_vf_driver='igb_uio',
            sriov_numvfs=2,
            expect_errors=False)
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(http_client.OK, response.status_code)
        self.assertEqual(2, response.json['sriov_numvfs'])

    def test_device_modify_sriov_numvfs_negative(self):
        response = self.patch_dict_json(
            '%s' % self._get_path(self.pci_device['uuid']),
            sriov_numvfs=-1,
            driver='igb_uio',
            sriov_vf_driver='igb_uio',
            expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, response.status_int)
        self.assertEqual('application/json', response.content_type)
        self.assertTrue(response.json['error_message'])
        self.assertIn('Value for number of SR-IOV VFs must be >= 0.',
                      response.json['error_message'])

    def test_device_modify_sriov_numvfs_none(self):
        response = self.patch_dict_json(
            '%s' % self._get_path(self.pci_device['uuid']),
            driver='igb_uio',
            sriov_vf_driver='igb_uio',
            expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, response.status_int)
        self.assertEqual('application/json', response.content_type)
        self.assertTrue(response.json['error_message'])
        self.assertIn('The value for number of SR-IOV VFs must be > 0 '
                      'when the VF driver is igb_uio',
                      response.json['error_message'])

    def test_device_modify_sriov_numvfs_zero(self):
        response = self.patch_dict_json(
            '%s' % self._get_path(self.pci_device['uuid']),
            driver='igb_uio',
            sriov_vf_driver='igb_uio',
            sriov_numvfs=0,
            expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, response.status_int)
        self.assertEqual('application/json', response.content_type)
        self.assertTrue(response.json['error_message'])
        self.assertIn('The value for number of SR-IOV VFs must be > 0 '
                      'when the VF driver is igb_uio',
                      response.json['error_message'])

    def test_device_modify_sriov_numvfs_badvalue(self):
        response = self.patch_dict_json(
            '%s' % self._get_path(self.pci_device['uuid']),
            driver='igb_uio',
            sriov_vf_driver='igb_uio',
            sriov_numvfs="bad",
            expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, response.status_int)
        self.assertEqual('application/json', response.content_type)
        self.assertTrue(response.json['error_message'])
        self.assertIn('Invalid input for field/attribute sriov_numvfs',
                      response.json['error_message'])

    def test_device_modify_sriov_numvfs_toohigh(self):
        response = self.patch_dict_json(
            '%s' % self._get_path(self.pci_device['uuid']),
            driver='igb_uio',
            sriov_vf_driver='igb_uio',
            sriov_numvfs=1000,
            expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, response.status_int)
        self.assertEqual('application/json', response.content_type)
        self.assertTrue(response.json['error_message'])
        self.assertIn('The device supports a maximum of',
                      response.json['error_message'])

    def test_device_modify_sriov_numvfs_unsupported_stx_device(self):
        self.pci_device = dbutils.create_test_pci_device(
            host_id=self.worker.id, device_id="FFFF")
        response = self.patch_dict_json(
            '%s' % self._get_path(self.pci_device['uuid']),
            driver='igb_uio',
            sriov_vf_driver='igb_uio',
            sriov_numvfs=2,
            expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, response.status_int)
        self.assertEqual('application/json', response.content_type)
        self.assertTrue(response.json['error_message'])
        self.assertIn('device is not supported for SR-IOV',
                      response.json['error_message'])

    def test_device_modify_sriov_numvfs_unsupported_hw_device(self):
        self.pci_device = dbutils.create_test_pci_device(
            host_id=self.worker.id,
            pclass_id=self.pclass_id,
            pdevice_id=dconstants.PCI_DEVICE_ID_FPGA_INTEL_5GNR_FEC_PF,
            sriov_totalvfs=None)
        response = self.patch_dict_json(
            '%s' % self._get_path(self.pci_device['uuid']),
            driver='igb_uio',
            sriov_vf_driver='igb_uio',
            sriov_numvfs=2,
            expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, response.status_int)
        self.assertEqual('application/json', response.content_type)
        self.assertTrue(response.json['error_message'])
        self.assertIn('SR-IOV cannot be configured on this interface',
                      response.json['error_message'])

    def test_device_modify_sriov_vf_driver_igb_uio(self):
        self.pci_device = dbutils.create_test_pci_device(
            host_id=self.worker.id,
            pclass_id=self.pclass_id,
            pdevice_id=dconstants.PCI_DEVICE_ID_FPGA_INTEL_5GNR_FEC_PF,
            driver='igb_uio',
            sriov_totalvfs=8,
            sriov_numvfs=2)
        response = self.patch_dict_json(
            '%s' % self._get_path(self.pci_device['uuid']),
            sriov_vf_driver='igb_uio',
            expect_errors=False)
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(http_client.OK, response.status_code)
        self.assertEqual('igb_uio', response.json['sriov_vf_driver'])

    def test_device_modify_sriov_vf_driver_vfio(self):
        self.pci_device = dbutils.create_test_pci_device(
            host_id=self.worker.id,
            pclass_id=self.pclass_id,
            pdevice_id=dconstants.PCI_DEVICE_ID_FPGA_INTEL_5GNR_FEC_PF,
            driver='igb_uio',
            sriov_vf_driver='igb_uio',
            sriov_totalvfs=8,
            sriov_numvfs=2)
        response = self.patch_dict_json(
            '%s' % self._get_path(self.pci_device['uuid']),
            sriov_vf_driver='vfio',
            expect_errors=False)
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(http_client.OK, response.status_code)
        self.assertEqual('vfio', response.json['sriov_vf_driver'])

    def test_device_modify_sriov_vf_driver_unsupported_device(self):
        self.pci_device = dbutils.create_test_pci_device(
            host_id=self.worker.id, device_id="FFFF")
        response = self.patch_dict_json(
            '%s' % self._get_path(self.pci_device['uuid']),
            driver='igb_uio',
            sriov_vf_driver='igb_uio',
            expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, response.status_int)
        self.assertEqual('application/json', response.content_type)
        self.assertTrue(response.json['error_message'])
        self.assertIn('device is not supported for SR-IOV',
                      response.json['error_message'])

    def test_device_modify_sriov_vf_driver_invalid(self):
        response = self.patch_dict_json(
            '%s' % self._get_path(self.pci_device['uuid']),
            driver='igb_uio',
            sriov_vf_driver='bad',
            sriov_numvfs=2,
            expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, response.status_int)
        self.assertEqual('application/json', response.content_type)
        self.assertTrue(response.json['error_message'])
        self.assertIn('Value for SR-IOV VF driver must be one of',
                      response.json['error_message'])

    def test_device_modify_sriov_pf_driver_invalid(self):
        response = self.patch_dict_json(
            '%s' % self._get_path(self.pci_device['uuid']),
            driver='bad',
            expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, response.status_int)
        self.assertEqual('application/json', response.content_type)
        self.assertTrue(response.json['error_message'])
        self.assertIn('Value for SR-IOV PF driver must be one of',
                      response.json['error_message'])

    def test_device_modify_restricted_field(self):
        response = self.patch_dict_json(
            '%s' % self._get_path(self.pci_device['uuid']),
            sriov_totalvfs=4,
            expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, response.status_int)
        self.assertEqual('application/json', response.content_type)
        self.assertTrue(response.json['error_message'])
        self.assertIn('attribute restricted', response.json['error_message'])

    def test_device_modify_fec_device_unprovisioned(self):
        host = self._create_host(constants.CONTROLLER,
                                 subfunction=constants.WORKER,
                                 admin=constants.ADMIN_LOCKED,
                                 invprovision="provisioning")
        self.pci_device = dbutils.create_test_pci_device(
            host_id=host.id,
            pclass_id=self.pclass_id,
            pdevice_id=dconstants.PCI_DEVICE_ID_FPGA_INTEL_5GNR_FEC_PF,
            sriov_totalvfs=8,
            sriov_numvfs=2)
        response = self.patch_dict_json(
            '%s' % self._get_path(self.pci_device['uuid']),
            sriov_numvfs=-1,
            expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, response.status_int)
        self.assertEqual('application/json', response.content_type)
        self.assertTrue(response.json['error_message'])
        self.assertIn('is unlocked for the first time', response.json['error_message'])

    def test_device_modify_sriov_reset_all(self):
        self.pci_device = dbutils.create_test_pci_device(
            host_id=self.worker.id,
            pclass_id=self.pclass_id,
            pdevice_id=dconstants.PCI_DEVICE_ID_FPGA_INTEL_5GNR_FEC_PF,
            driver='igb_uio',
            sriov_vf_driver='igb_uio',
            sriov_totalvfs=8,
            sriov_numvfs=2)
        response = self.patch_dict_json(
            '%s' % self._get_path(self.pci_device['uuid']),
            driver='none',
            sriov_vf_driver='none',
            sriov_numvfs=0,
            expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, response.status_int)
        self.assertEqual('application/json', response.content_type)
        self.assertTrue(response.json['error_message'])
        self.assertIn('The SR-IOV VF driver must first be set to none and the number '
                      'of VFs set to 0 before setting the PF driver to none.  '
                      'Current values: sriov_vf_driver: igb_uio, sriov_numvfs: 2',
                      response.json['error_message'])

    def test_device_modify_sriov_reset_vf_params(self):
        self.pci_device = dbutils.create_test_pci_device(
            host_id=self.worker.id,
            pclass_id=self.pclass_id,
            pdevice_id=dconstants.PCI_DEVICE_ID_FPGA_INTEL_5GNR_FEC_PF,
            driver='igb_uio',
            sriov_vf_driver='igb_uio',
            sriov_totalvfs=8,
            sriov_numvfs=2)
        response = self.patch_dict_json(
            '%s' % self._get_path(self.pci_device['uuid']),
            sriov_vf_driver='none',
            sriov_numvfs=0,
            expect_errors=True)
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(http_client.OK, response.status_code)
        self.assertEqual(None, response.json['sriov_vf_driver'])
        self.assertEqual(0, response.json['sriov_numvfs'])

    def test_device_modify_sriov_reset_driver(self):
        self.pci_device = dbutils.create_test_pci_device(
            host_id=self.worker.id,
            pclass_id=self.pclass_id,
            pdevice_id=dconstants.PCI_DEVICE_ID_FPGA_INTEL_5GNR_FEC_PF,
            driver='igb_uio',
            sriov_vf_driver=None,
            sriov_totalvfs=8,
            sriov_numvfs=0)
        response = self.patch_dict_json(
            '%s' % self._get_path(self.pci_device['uuid']),
            driver='none',
            expect_errors=True)
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(http_client.OK, response.status_code)
        self.assertEqual(None, response.json['sriov_vf_driver'])
        self.assertEqual(0, response.json['sriov_numvfs'])

    def test_device_modify_sriov_set_numvfs_no_pf_driver(self):
        self.pci_device = dbutils.create_test_pci_device(
            host_id=self.worker.id,
            pclass_id=self.pclass_id,
            pdevice_id=dconstants.PCI_DEVICE_ID_FPGA_INTEL_5GNR_FEC_PF,
            driver=None,
            sriov_vf_driver=None,
            sriov_totalvfs=8,
            sriov_numvfs=0)
        response = self.patch_dict_json(
            '%s' % self._get_path(self.pci_device['uuid']),
            sriov_numvfs=4,
            expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, response.status_int)
        self.assertEqual('application/json', response.content_type)
        self.assertTrue(response.json['error_message'])
        self.assertIn('The SR-IOV PF driver must not be None to set the number '
                      'of VFs.',
                      response.json['error_message'])

    def test_device_modify_sriov_set_vf_driver_no_pf_driver(self):
        self.pci_device = dbutils.create_test_pci_device(
            host_id=self.worker.id,
            pclass_id=self.pclass_id,
            pdevice_id=dconstants.PCI_DEVICE_ID_FPGA_INTEL_5GNR_FEC_PF,
            driver=None,
            sriov_vf_driver=None,
            sriov_totalvfs=8,
            sriov_numvfs=0)
        response = self.patch_dict_json(
            '%s' % self._get_path(self.pci_device['uuid']),
            sriov_vf_driver='igb_uio',
            expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, response.status_int)
        self.assertEqual('application/json', response.content_type)
        self.assertTrue(response.json['error_message'])
        self.assertIn('The value for number of SR-IOV VFs must be > 0 when the '
                      'VF driver is igb_uio',
                      response.json['error_message'])

    def test_device_modify_sriov_set_vf_params_no_pf_driver(self):
        self.pci_device = dbutils.create_test_pci_device(
            host_id=self.worker.id,
            pclass_id=self.pclass_id,
            pdevice_id=dconstants.PCI_DEVICE_ID_FPGA_INTEL_5GNR_FEC_PF,
            driver=None,
            sriov_vf_driver=None,
            sriov_totalvfs=8,
            sriov_numvfs=0)
        response = self.patch_dict_json(
            '%s' % self._get_path(self.pci_device['uuid']),
            sriov_numvfs=4,
            sriov_vf_driver='igb_uio',
            expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, response.status_int)
        self.assertEqual('application/json', response.content_type)
        self.assertTrue(response.json['error_message'])
        self.assertIn('The SR-IOV PF driver must not be None to set the number '
                      'of VFs.',
                      response.json['error_message'])

    def test_device_modify_sriov_reset_vf_driver(self):
        self.pci_device = dbutils.create_test_pci_device(
            host_id=self.worker.id,
            pclass_id=self.pclass_id,
            pdevice_id=dconstants.PCI_DEVICE_ID_FPGA_INTEL_5GNR_FEC_PF,
            driver='igb_uio',
            sriov_vf_driver='igb_uio',
            sriov_totalvfs=8,
            sriov_numvfs=4)
        response = self.patch_dict_json(
            '%s' % self._get_path(self.pci_device['uuid']),
            sriov_vf_driver='none',
            expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, response.status_int)
        self.assertEqual('application/json', response.content_type)
        self.assertTrue(response.json['error_message'])
        self.assertIn('The value for the SR-IOV number of VFs must be 0 when '
                      'the SR-IOV VF driver is none',
                      response.json['error_message'])

    def test_device_modify_sriov_reset_numvfs(self):
        self.pci_device = dbutils.create_test_pci_device(
            host_id=self.worker.id,
            pclass_id=self.pclass_id,
            pdevice_id=dconstants.PCI_DEVICE_ID_FPGA_INTEL_5GNR_FEC_PF,
            driver='igb_uio',
            sriov_vf_driver='igb_uio',
            sriov_totalvfs=8,
            sriov_numvfs=4)
        response = self.patch_dict_json(
            '%s' % self._get_path(self.pci_device['uuid']),
            sriov_numvfs=0,
            expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, response.status_int)
        self.assertEqual('application/json', response.content_type)
        self.assertTrue(response.json['error_message'])
        self.assertIn('The value for number of SR-IOV VFs must be > 0 when the '
                      'VF driver is igb_uio',
                      response.json['error_message'])

    def test_device_modify_sriov_qat_reset_all(self):
        self.pci_device = dbutils.create_test_pci_device(
            host_id=self.worker.id,
            pclass_id=self.pclass_id,
            pdevice_id=constants.PCI_ALIAS_QAT_401XX_PF_DEVICE,
            driver='4xxx',
            sriov_vf_driver='vfio',
            sriov_totalvfs=16,
            sriov_numvfs=16)
        response = self.patch_dict_json(
            '%s' % self._get_path(self.pci_device['uuid']),
            driver='none',
            sriov_vf_driver='none',
            sriov_numvfs=0,
            expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, response.status_int)
        self.assertEqual('application/json', response.content_type)
        self.assertTrue(response.json['error_message'])
        self.assertIn('QAT device is already initialized, further modification '
                      'not allowed. Details:- devicename: pci_0000_00_02_0 , '
                      'enabled status: True, driver: 4xxx, VF driver: vfio, '
                      'sriov numvfs: 16', response.json['error_message'])
