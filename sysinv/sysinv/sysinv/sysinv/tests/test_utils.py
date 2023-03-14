
# Copyright 2011 Justin Santa Barbara
# Copyright 2012 Hewlett-Packard Development Company, L.P.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#
#
# Copyright (c) 2022 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import errno
import io
import mock
import netaddr
import os
import os.path
import six.moves.builtins as __builtin__
import tempfile
import testtools
import string
import yaml

from oslo_config import cfg

from sysinv.common import constants
from sysinv.common import exception
from sysinv.common import utils
from sysinv.tests import base

CONF = cfg.CONF


class BareMetalUtilsTestCase(base.TestCase):

    def test_random_alnum(self):
        s = utils.random_alnum(10)
        self.assertEqual(len(s), 10)
        s = utils.random_alnum(100)
        self.assertEqual(len(s), 100)

    def test_unlink(self):
        with mock.patch.object(os, "unlink") as unlink_mock:
            unlink_mock.return_value = None
            utils.unlink_without_raise("/fake/path")
            unlink_mock.assert_called_once_with("/fake/path")

    def test_unlink_ENOENT(self):
        with mock.patch.object(os, "unlink") as unlink_mock:
            unlink_mock.side_effect = OSError(errno.ENOENT)
            utils.unlink_without_raise("/fake/path")
            unlink_mock.assert_called_once_with("/fake/path")

    def test_create_link(self):
        with mock.patch.object(os, "symlink") as symlink_mock:
            symlink_mock.return_value = None
            utils.create_link_without_raise("/fake/source", "/fake/link")
            symlink_mock.assert_called_once_with("/fake/source", "/fake/link")

    def test_create_link_EEXIST(self):
        with mock.patch.object(os, "symlink") as symlink_mock:
            symlink_mock.side_effect = OSError(errno.EEXIST)
            utils.create_link_without_raise("/fake/source", "/fake/link")
            symlink_mock.assert_called_once_with("/fake/source", "/fake/link")

    def test_get_os_type_centos(self):
        fd, tmpfile = tempfile.mkstemp()
        with open(tmpfile, 'w') as f:
            f.write('ID="centos\n"')
        os.close(fd)
        os_type = utils.get_os_type(tmpfile)
        self.assertEqual(os_type, constants.OS_CENTOS)
        os.remove(tmpfile)

    def test_get_os_type_debian(self):
        fd, tmpfile = tempfile.mkstemp()
        with open(tmpfile, 'w') as f:
            f.write('ID=debian')
        os.close(fd)
        os_type = utils.get_os_type(tmpfile)
        self.assertEqual(os_type, constants.OS_DEBIAN)
        os.remove(tmpfile)

    def test_get_os_type_missing(self):
        fd, tmpfile = tempfile.mkstemp()
        with open(tmpfile, 'w') as f:
            # Just an empty file
            f.write('')
        os.close(fd)
        self.assertRaises(exception.SysinvException,
                          utils.get_os_type,
                          tmpfile)
        os.remove(tmpfile)

    def test_get_os_type_unsupported(self):
        fd, tmpfile = tempfile.mkstemp()
        with open(tmpfile, 'w') as f:
            # Just a random OS type that we don't support
            f.write('ID=unsupportedOS')
        os.close(fd)
        self.assertRaises(exception.SysinvException,
                          utils.get_os_type,
                          tmpfile)
        os.remove(tmpfile)

    def test_get_os_target_debian(self):
        with mock.patch.object(os.path, "exists") as exists_mock:
            exists_mock.return_value = True
            result = utils.get_os_target('22.12')
            exists_mock.assert_called_once()
            self.assertEqual(constants.OS_DEBIAN, result)

    def test_get_os_target_centos(self):
        with mock.patch.object(os.path, "exists") as exists_mock:
            exists_mock.return_value = False
            result = utils.get_os_target('22.12')
            exists_mock.assert_called_once()
            self.assertEqual(constants.OS_CENTOS, result)


class ExecuteTestCase(base.TestCase):

    def test_retry_on_failure(self):
        fd, tmpfilename = tempfile.mkstemp()
        _, tmpfilename2 = tempfile.mkstemp()
        try:
            fp = os.fdopen(fd, 'w+')
            fp.write('''#!/bin/sh
# If stdin fails to get passed during one of the runs, make a note.
if ! grep -q foo
then
    echo 'failure' > "$1"
fi
# If stdin has failed to get passed during this or a previous run, exit early.
if grep failure "$1"
then
    exit 1
fi
runs="$(cat $1)"
if [ -z "$runs" ]
then
    runs=0
fi
runs=$(($runs + 1))
echo $runs > "$1"
exit 1
''')
            fp.close()
            os.chmod(tmpfilename, 0o755)
            self.assertRaises(exception.ProcessExecutionError,
                              utils.execute,
                              tmpfilename, tmpfilename2, attempts=10,
                              process_input='foo'.encode('utf-8'),
                              delay_on_retry=False)
            fp = open(tmpfilename2, 'r')
            runs = fp.read()
            fp.close()
            self.assertNotEqual(runs.strip(), 'failure', 'stdin did not '
                                                          'always get passed '
                                                          'correctly')
            runs = int(runs.strip())
            self.assertEqual(runs, 10,
                              'Ran %d times instead of 10.' % (runs,))
        finally:
            os.unlink(tmpfilename)
            os.unlink(tmpfilename2)

    def test_unknown_kwargs_raises_error(self):
        self.assertRaises(exception.SysinvException,
                          utils.execute,
                          '/usr/bin/env', 'true',
                          this_is_not_a_valid_kwarg=True)

    def test_check_exit_code_boolean(self):
        utils.execute('/usr/bin/env', 'false', check_exit_code=False)
        self.assertRaises(exception.ProcessExecutionError,
                          utils.execute,
                          '/usr/bin/env', 'false', check_exit_code=True)

    def test_no_retry_on_success(self):
        fd, tmpfilename = tempfile.mkstemp()
        _, tmpfilename2 = tempfile.mkstemp()
        try:
            fp = os.fdopen(fd, 'w+')
            fp.write('''#!/bin/sh
# If we've already run, bail out.
grep -q foo "$1" && exit 1
# Mark that we've run before.
echo foo > "$1"
# Check that stdin gets passed correctly.
grep foo
''')
            fp.close()
            os.chmod(tmpfilename, 0o755)
            utils.execute(tmpfilename,
                          tmpfilename2,
                          process_input='foo'.encode('utf-8'),
                          attempts=2)
        finally:
            os.unlink(tmpfilename)
            os.unlink(tmpfilename2)


class GenericUtilsTestCase(base.TestCase):
    def test_hostname_unicode_sanitization(self):
        hostname = u"\u7684.test.example.com"
        self.assertEqual("test.example.com",
                         utils.sanitize_hostname(hostname))

    def test_hostname_sanitize_periods(self):
        hostname = "....test.example.com..."
        self.assertEqual("test.example.com",
                         utils.sanitize_hostname(hostname))

    def test_hostname_sanitize_dashes(self):
        hostname = "----test.example.com---"
        self.assertEqual("test.example.com",
                         utils.sanitize_hostname(hostname))

    def test_hostname_sanitize_characters(self):
        hostname = "(#@&$!(@*--#&91)(__=+--test-host.example!!.com-0+"
        self.assertEqual("91----test-host.example.com-0",
                         utils.sanitize_hostname(hostname))

    def test_hostname_translate(self):
        hostname = "<}\x1fh\x10e\x08l\x02l\x05o\x12!{>"
        self.assertEqual("hello", utils.sanitize_hostname(hostname))

    def test_read_cached_file(self):
        with mock.patch.object(os.path, "getmtime") as getmtime_mock:
            getmtime_mock.return_value = 1

            cache_data = {"data": 1123, "mtime": 1}
            data = utils.read_cached_file("/this/is/a/fake", cache_data)
            self.assertEqual(cache_data["data"], data)
            getmtime_mock.assert_called_once_with(mock.ANY)

    def test_read_modified_cached_file(self):
        with mock.patch.object(os.path, "getmtime") as getmtime_mock:
            with mock.patch.object(__builtin__, 'open') as open_mock:
                getmtime_mock.return_value = 2
                fake_contents = "lorem ipsum"
                fake_file = mock.Mock()
                fake_file.read.return_value = fake_contents
                fake_context_manager = mock.MagicMock()
                fake_context_manager.__enter__.return_value = fake_file
                fake_context_manager.__exit__.return_value = None
                open_mock.return_value = fake_context_manager

                cache_data = {"data": 1123, "mtime": 1}
                self.reload_called = False

                def test_reload(reloaded_data):
                    self.assertEqual(fake_contents, reloaded_data)
                    self.reload_called = True

                data = utils.read_cached_file("/this/is/a/fake",
                                              cache_data,
                                              reload_func=test_reload)

                self.assertEqual(fake_contents, data)
                self.assertTrue(self.reload_called)
                getmtime_mock.assert_called_once_with(mock.ANY)
                open_mock.assert_called_once_with(mock.ANY)
                fake_file.read.assert_called_once_with()
                fake_context_manager.__exit__.assert_called_once_with(mock.ANY,
                                                                      mock.ANY,
                                                                      mock.ANY)
                fake_context_manager.__enter__.assert_called_once_with()

    def test_is_valid_boolstr(self):
        self.assertTrue(utils.is_valid_boolstr('true'))
        self.assertTrue(utils.is_valid_boolstr('false'))
        self.assertTrue(utils.is_valid_boolstr('yes'))
        self.assertTrue(utils.is_valid_boolstr('no'))
        self.assertTrue(utils.is_valid_boolstr('y'))
        self.assertTrue(utils.is_valid_boolstr('n'))
        self.assertTrue(utils.is_valid_boolstr('1'))
        self.assertTrue(utils.is_valid_boolstr('0'))

        self.assertFalse(utils.is_valid_boolstr('maybe'))
        self.assertFalse(utils.is_valid_boolstr('only on tuesdays'))

    def test_is_valid_ipv4(self):
        self.assertTrue(utils.is_valid_ipv4('127.0.0.1'))
        self.assertFalse(utils.is_valid_ipv4('::1'))
        self.assertFalse(utils.is_valid_ipv4('bacon'))
        self.assertFalse(utils.is_valid_ipv4(""))
        self.assertFalse(utils.is_valid_ipv4(10))

    def test_is_valid_ipv6(self):
        self.assertTrue(utils.is_valid_ipv6("::1"))
        self.assertTrue(utils.is_valid_ipv6(
                            "abcd:ef01:2345:6789:abcd:ef01:192.168.254.254"))
        self.assertTrue(utils.is_valid_ipv6(
                                    "0000:0000:0000:0000:0000:0000:0000:0001"))
        self.assertFalse(utils.is_valid_ipv6("foo"))
        self.assertFalse(utils.is_valid_ipv6("127.0.0.1"))
        self.assertFalse(utils.is_valid_ipv6(""))
        self.assertFalse(utils.is_valid_ipv6(10))

    def test_is_valid_ipv6_cidr(self):
        self.assertTrue(utils.is_valid_ipv6_cidr("2600::/64"))
        self.assertTrue(utils.is_valid_ipv6_cidr(
                "abcd:ef01:2345:6789:abcd:ef01:192.168.254.254/48"))
        self.assertTrue(utils.is_valid_ipv6_cidr(
                "0000:0000:0000:0000:0000:0000:0000:0001/32"))
        self.assertTrue(utils.is_valid_ipv6_cidr(
                "0000:0000:0000:0000:0000:0000:0000:0001"))
        self.assertFalse(utils.is_valid_ipv6_cidr("foo"))
        self.assertFalse(utils.is_valid_ipv6_cidr("127.0.0.1"))

    def test_get_shortened_ipv6(self):
        self.assertEqual("abcd:ef01:2345:6789:abcd:ef01:c0a8:fefe",
                            utils.get_shortened_ipv6(
                                "abcd:ef01:2345:6789:abcd:ef01:192.168.254.254"))
        self.assertEqual("::1", utils.get_shortened_ipv6(
                                    "0000:0000:0000:0000:0000:0000:0000:0001"))
        self.assertEqual("caca::caca:0:babe:201:102",
                          utils.get_shortened_ipv6(
                                    "caca:0000:0000:caca:0000:babe:0201:0102"))
        self.assertRaises(netaddr.AddrFormatError, utils.get_shortened_ipv6,
                          "127.0.0.1")
        self.assertRaises(netaddr.AddrFormatError, utils.get_shortened_ipv6,
                          "failure")

    def test_get_shortened_ipv6_cidr(self):
        self.assertEqual("2600::/64", utils.get_shortened_ipv6_cidr(
                "2600:0000:0000:0000:0000:0000:0000:0000/64"))
        self.assertEqual("2600::/64", utils.get_shortened_ipv6_cidr(
                "2600::1/64"))
        self.assertRaises(netaddr.AddrFormatError,
                          utils.get_shortened_ipv6_cidr,
                          "127.0.0.1")
        self.assertRaises(netaddr.AddrFormatError,
                          utils.get_shortened_ipv6_cidr,
                          "failure")

    def test_is_valid_mac(self):
        self.assertTrue(utils.is_valid_mac("52:54:00:cf:2d:31"))
        self.assertTrue(utils.is_valid_mac(u"52:54:00:cf:2d:31"))
        self.assertFalse(utils.is_valid_mac("127.0.0.1"))
        self.assertFalse(utils.is_valid_mac("not:a:mac:address"))

    def test_safe_rstrip(self):
        value = '/test/'
        rstripped_value = '/test'
        not_rstripped = '/'

        self.assertEqual(utils.safe_rstrip(value, '/'), rstripped_value)
        self.assertEqual(utils.safe_rstrip(not_rstripped, '/'), not_rstripped)

    def test_safe_rstrip_not_raises_exceptions(self):
        # Supplying an integer should normally raise an exception because it
        # does not save the rstrip() method.
        value = 10

        # In the case of raising an exception safe_rstrip() should return the
        # original value.
        self.assertEqual(utils.safe_rstrip(value), value)

    def test_generate_random_password(self):
        special_chars = "!*_-+="

        for x in range(10):
            passwd = utils.generate_random_password(16)
            self.assertEqual(len(passwd), 16)
            self.assertTrue(any(i in string.ascii_uppercase for i in passwd))
            self.assertTrue(any(i in string.ascii_lowercase for i in passwd))
            self.assertTrue(any(i in string.digits for i in passwd))
            self.assertTrue(any(i in special_chars for i in passwd))

            passwd = utils.generate_random_password(32)
            self.assertEqual(len(passwd), 32)
            self.assertTrue(any(i in string.ascii_uppercase for i in passwd))
            self.assertTrue(any(i in string.ascii_lowercase for i in passwd))
            self.assertTrue(any(i in string.digits for i in passwd))
            self.assertTrue(any(i in special_chars for i in passwd))

    def test_generate_random_password_exception(self):
        self.assertRaises(exception.SysinvException,
                          utils.generate_random_password,
                          length=7)

    def test_is_valid_url(self):
        self.assertTrue(utils.is_url('http://controller'))
        self.assertTrue(utils.is_url('https://controller'))
        self.assertFalse(utils.is_url('https://'))
        self.assertFalse(utils.is_url('//controller'))


class MkfsTestCase(base.TestCase):

    @mock.patch.object(utils, 'execute')
    def test_mkfs(self, execute_mock):
        utils.mkfs('ext4', '/my/block/dev')
        utils.mkfs('msdos', '/my/msdos/block/dev')
        utils.mkfs('swap', '/my/swap/block/dev')

        expected = [mock.call('mkfs', '-t', 'ext4', '-F', '/my/block/dev'),
                    mock.call('mkfs', '-t', 'msdos', '/my/msdos/block/dev'),
                    mock.call('mkswap', '/my/swap/block/dev')]
        self.assertEqual(expected, execute_mock.call_args_list)

    @mock.patch.object(utils, 'execute')
    def test_mkfs_with_label(self, execute_mock):
        utils.mkfs('ext4', '/my/block/dev', 'ext4-vol')
        utils.mkfs('msdos', '/my/msdos/block/dev', 'msdos-vol')
        utils.mkfs('swap', '/my/swap/block/dev', 'swap-vol')

        expected = [mock.call('mkfs', '-t', 'ext4', '-F', '-L', 'ext4-vol',
                              '/my/block/dev'),
                    mock.call('mkfs', '-t', 'msdos', '-n', 'msdos-vol',
                              '/my/msdos/block/dev'),
                    mock.call('mkswap', '-L', 'swap-vol',
                              '/my/swap/block/dev')]
        self.assertEqual(expected, execute_mock.call_args_list)


class IntLikeTestCase(base.TestCase):

    def test_is_int_like(self):
        self.assertTrue(utils.is_int_like(1))
        self.assertTrue(utils.is_int_like("1"))
        self.assertTrue(utils.is_int_like("514"))
        self.assertTrue(utils.is_int_like("0"))

        self.assertFalse(utils.is_int_like(1.1))
        self.assertFalse(utils.is_int_like("1.1"))
        self.assertFalse(utils.is_int_like("1.1.1"))
        self.assertFalse(utils.is_int_like(None))
        self.assertFalse(utils.is_int_like("0."))
        self.assertFalse(utils.is_int_like("aaaaaa"))
        self.assertFalse(utils.is_int_like("...."))
        self.assertFalse(utils.is_int_like("1g"))
        self.assertFalse(
            utils.is_int_like("0cc3346e-9fef-4445-abe6-5d2b2690ec64"))
        self.assertFalse(utils.is_int_like("a1"))


# these unit tests do not need to subclass base.TestCase
class FindMetadataTestCase(testtools.TestCase):

    sample_contents = """
app_name: sample-app
app_version: 1.2-3
helm_repo: stx-platform
maintain_user_overrides: true
supported_k8s_version:
  minimum: 'v1.2.3'
  maximum: 'v2.4.6'
behavior:
  platform_managed_app: yes
  desired_state: applied
  evaluate_reapply:
    triggers:
      - type: runtime-apply-puppet # TODO(someuser): an inline comment
      - type: host-availability-updated
      - type: kube-upgrade-complete
        filters:
          - availability: services-enabled
      - type: host-delete
        filters:
          - personality: controller
"""

    bad_contents = """
app_name: sample-app
app_version: 1.2-3
helm_repo: stx-platform
maintain_user_overrides: true
supported_k8s_version:
  minimum: 1       # must be a string, not a number
  maximum: true   # must be a string, not a boolean
behavior:
  platform_managed_app: yes
  desired_state: applied
  evaluate_reapply:
    triggers:
      - type: runtime-apply-puppet # TODO(someuser): an inline comment
      - type: host-availability-updated
      - type: kube-upgrade-complete
        filters:
          - availability: services-enabled
      - type: host-delete
        filters:
          - personality: controller
"""

    def test_find_metadata_file_nofile(self):
        """Verify results of find_metadata_file

        when if no file is found, returns:
        app_name =  "", app_version = "", patches = []
        """
        app_name, app_version, patches = \
            utils.find_metadata_file("invalid_path",
                                     "invalid_file",
                                     upgrade_from_release=None)
        # if the file is not loaded or has invalid contents
        # find_metadata_file returns two empty strings and
        # an empty list  ie:  "","",[]
        self.assertEqual(app_name, "")
        self.assertEqual(app_version, "")
        self.assertEqual(patches, [])

    @mock.patch.object(io, 'open')
    @mock.patch.object(os.path, 'isfile')
    def test_find_metadata_file(self,
                                _mock_isfile,
                                _mock_open):
        """This test mocks file operations
         and returns static file contents to allow unit
         testing the validation code
        """

        _mock_isfile.return_value = "True"

        # load fake yaml file contents for: sample-app 1.2-3
        _mock_open.return_value = io.StringIO(self.sample_contents)

        app_name, app_version, patches = \
            utils.find_metadata_file("valid_path",
                                     "valid_file",
                                     upgrade_from_release=None)
        self.assertEqual(app_name, "sample-app")
        self.assertEqual(app_version, "1.2-3")

    @mock.patch.object(io, 'open')
    @mock.patch.object(os.path, 'isfile')
    def test_find_metadata_file_bad_contents(self,
                                _mock_isfile,
                                _mock_open):
        """This test mocks file operations and verifies
         failure handling in how the yaml is validated
        """
        _mock_isfile.return_value = "True"

        # bad_replacements is a list of atomic changes that
        # will trigger a SysinvException in the validator
        bad_replacements = [
                # app_name cannot be None
                {"app_name": None},
                # app_version cannot be None
                {"app_version": None},
                # behavior must be a dictionary (not a list)
                {"behavior": []},
                # minimum or maximum cannot be a boolean
                {"supported_k8s_version": {"minimum": True, "maximum": "2.4.6"}},
                # minimum or maximum cannot be a number
                {"supported_k8s_version": {"minimum": "1.2.3", "maximum": 2}},
        ]

        # start each loop with valid contents and replace
        # a certain section with bad contents so that the
        # validator will raise a SysinvException
        for bad_dict in bad_replacements:
            contents = yaml.safe_load(self.sample_contents)
            for key, value in bad_dict.items():
                contents[key] = value
            bad_contents = yaml.dump(contents)
            _mock_open.return_value = io.StringIO(bad_contents)
            self.assertRaises(exception.SysinvException,
                              utils.find_metadata_file,
                              "valid_path",
                              "valid_file")
