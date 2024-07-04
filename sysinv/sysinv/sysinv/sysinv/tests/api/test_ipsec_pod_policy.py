#
# Copyright (c) 2023-2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import uuid
from six.moves import http_client

from oslo_utils import uuidutils

from sysinv.tests.api import base
from sysinv.tests.db import base as dbbase
from sysinv.tests.db import utils as dbutils


class IpsecPodPolicyTestCase(base.FunctionalTest, dbbase.BaseHostTestCase):
    # API_HEADERS are a generic header passed to most API calls
    API_HEADERS = {'User-Agent': 'sysinv-test'}

    # API_PREFIX is the prefix for the URL
    API_PREFIX = '/ipsec_pod_policy'

    # expected_api_fields are attributes that should be populated by
    # an API query
    expected_api_fields = ['id',
                           'uuid',
                           'protocol',
                           'port',
                           'policy_status'
                           ]

    COMMON_FIELD = 'protocol'
    RESULT_KEY = 'ipsec_pod_policy'

    def setUp(self):
        super(IpsecPodPolicyTestCase, self).setUp()

    def get_single_url(self, uuid):
        return '%s/%s' % (self.API_PREFIX, uuid)

    def assert_fields(self, api_object):
        # check the uuid is a uuid
        assert (uuidutils.is_uuid_like(api_object['uuid']))

        # Verify that expected attributes are returned
        for field in self.expected_api_fields:
            self.assertIn(field, api_object)

    def get_post_object(self, protocol, port=None):

        policy_db = dbutils.get_test_ipsec_pod_policy(
            id=0,
            uuid=str(uuid.uuid4()),
            protocol=protocol,
            port=port
        )

        return policy_db

    def _create_db_object(self, protocol, port=None):
        return self._create_test_ipsec_pod_policy(
            protocol=protocol,
            port=port,
        )

    def _delete_ipsec_pod_policy(self):
        policy = self.get_json(self.API_PREFIX)
        self.delete(self.get_single_url(policy['uuid']),
                    headers=self.API_HEADERS)


class TestPostMixin(IpsecPodPolicyTestCase):

    def setUp(self):
        super(TestPostMixin, self).setUp()

    def test_create_ipsec_pod_policy_success(self):
        # Test creation of object
        ndict = self.get_post_object('tcp', '8080')
        response = self.post_json(self.API_PREFIX,
                                  ndict,
                                  headers=self.API_HEADERS)

        # Check HTTP response is successful
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(response.status_code, http_client.OK)

        # Check that an expected field matches.
        self.assertEqual(response.json[self.COMMON_FIELD],
                         ndict[self.COMMON_FIELD])

        uid = response.json['uuid']

        # Verify that the object was created and some basic attribute matches
        response = self.get_json(self.get_single_url(uid))
        self.assertEqual(response[self.COMMON_FIELD],
                         ndict[self.COMMON_FIELD])

    def test_create_ipsec_pod_policy_with_duplicate_protocol(self):
        # Test creation of object
        self._create_db_object('icmp')
        ndict = self.get_post_object('icmp')
        response = self.post_json(self.API_PREFIX,
                                  ndict,
                                  headers=self.API_HEADERS,
                                  expect_errors=True)

        # Check HTTP response is failed
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(response.status_code, 500)
        self.assertIn("Duplicate with policy",
                      response.json['error_message'])

    def test_create_ipsec_pod_policy_with_overlap_port(self):
        # Test creation of object
        self._create_db_object('tcp', '8000-9000')
        ndict = self.get_post_object('tcp', '8080')
        response = self.post_json(self.API_PREFIX,
                                  ndict,
                                  headers=self.API_HEADERS,
                                  expect_errors=True)

        # Check HTTP response is failed
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(response.status_code, 500)
        self.assertIn("Duplicate with policy",
                      response.json['error_message'])

    def test_create_ipsec_pod_policy_with_invalid_protocol(self):
        # Test creation of object
        ndict = self.get_post_object('not_a_valid_protocol', '8080')
        response = self.post_json(self.API_PREFIX,
                                  ndict,
                                  headers=self.API_HEADERS,
                                  expect_errors=True)

        # Check HTTP response is failed
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(response.status_code, 500)
        self.assertIn("must in ['tcp', 'udp', 'icmp']",
                      response.json['error_message'])

    def test_create_ipsec_pod_policy_with_invalid_port(self):
        # Test creation of object
        ndict = self.get_post_object('tcp', '666666')
        response = self.post_json(self.API_PREFIX,
                                  ndict,
                                  headers=self.API_HEADERS,
                                  expect_errors=True)

        # Check HTTP response is failed
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(response.status_code, 500)
        self.assertIn("Invalid port, port must in 1-65535",
                      response.json['error_message'])

    def test_create_ipsec_pod_policy_with_invalid_protocl_port(self):
        # Test creation of object
        ndict = self.get_post_object('icmp', '8080')
        response = self.post_json(self.API_PREFIX,
                                  ndict,
                                  headers=self.API_HEADERS,
                                  expect_errors=True)

        # Check HTTP response is failed
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(response.status_code, 500)
        self.assertIn("Port is not a valid option for protocol",
                      response.json['error_message'])

    def test_get_one_ipsec_pod_policy(self):
        # create one from DB
        obj = self._create_db_object('tcp', '8000-9000')

        # get the one by uuid
        response = self.get_json(self.get_single_url(obj.uuid))
        self.assertEqual(response[self.COMMON_FIELD],
                         'tcp')

    def test_update_ipsec_pod_policy_success(self):
        obj = self._create_db_object('tcp', '8000-9000')

        data = {
            'protocol': 'udp'
        }
        response = self.patch_dict(self.get_single_url(obj.uuid), data)
        self.assertEqual(response.status_code, 200)

    def test_update_ipsec_pod_policy_with_invalid_protocol(self):
        obj = self._create_db_object('tcp', '8000-9000')

        data = {
            'protocol': 'not_a_protocol'
        }
        response = self.patch_dict(self.get_single_url(obj.uuid), data,
                                   expect_errors=True)
        self.assertEqual(response.status_code, 500)
        self.assertIn("must in ['tcp', 'udp', 'icmp']",
                      response.json['error_message'])

    def test_update_ipsec_pod_policy_with_invalid_port_range(self):
        obj = self._create_db_object('tcp', '8000-9000')

        data = {
            'port': '-888'
        }
        response = self.patch_dict(self.get_single_url(obj.uuid), data,
                                   expect_errors=True)
        self.assertEqual(response.status_code, 500)
        self.assertIn("Invalid port, port range must in 1-65535",
                      response.json['error_message'])

    def test_update_ipsec_pod_policy_with_overlap_port(self):
        self._create_db_object('tcp', '8000-9000')
        obj = self._create_db_object('tcp', '80')
        data = {
            'port': '8080'
        }
        response = self.patch_dict(self.get_single_url(obj.uuid), data,
                                   expect_errors=True)
        self.assertEqual(response.status_code, 500)
        self.assertIn("Duplicate with policy", response.json['error_message'])


class TestList(IpsecPodPolicyTestCase):
    def setUp(self):
        super(TestList, self).setUp()

    def test_ipsec_pod_policy_list(self):
        pilicies = self.get_json(self.API_PREFIX)
        num = len(pilicies[self.RESULT_KEY]) + 1

        # create a single object
        self.single_object = self._create_db_object('tcp', '80')
        response = self.get_json(self.API_PREFIX)
        self.assertEqual(
            num,
            len(response[self.RESULT_KEY]))


class TestDelete(IpsecPodPolicyTestCase):
    def setUp(self):
        super(TestDelete, self).setUp()

    def test_ipsec_pod_policy_delete(self):
        # Delete the API object
        self.delete_object = self._create_db_object('tcp', '80')
        uuid = self.delete_object.uuid
        response = self.delete(self.get_single_url(uuid),
                               headers=self.API_HEADERS)

        # Verify the expected API response for the delete
        self.assertEqual(response.status_code, http_client.NO_CONTENT)
