# -*- coding: utf-8 -*-
# Copyright (C) 2014-2020 Greenbone Networks GmbH
#
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.

import logging
import unittest

from csv import DictReader
from pathlib import Path, PurePath
from collections import OrderedDict
from unittest.mock import patch, MagicMock

from ospd_openvas.notus.metadata import (
    NotusMetadataHandler,
    EXPECTED_FIELD_NAMES_LIST,
    METADATA_DIRECTORY_NAME,
)
from ospd_openvas.errors import OspdOpenvasError


class NotusTestCase(unittest.TestCase):
    @patch('ospd_openvas.nvticache.NVTICache')
    def setUp(self, MockNvti):
        self.nvti = MockNvti()

    @patch('ospd_openvas.notus.metadata.Openvas')
    def test_set_openvas_settings(self, MockOpenvas):
        openvas = MockOpenvas()
        openvas.get_settings.return_value = {'nasl_no_signature_check': 0}

        notus = NotusMetadataHandler()
        no_signature_check = notus.openvas_setting.get(
            "nasl_no_signature_check"
        )

        self.assertEqual(no_signature_check, 0)

    @patch('ospd_openvas.notus.metadata.Openvas')
    def test_metadata_path(self, MockOpenvas):
        openvas = MockOpenvas()
        openvas.get_settings.return_value = {'plugins_folder': './tests/notus'}
        notus = NotusMetadataHandler()

        self.assertIsNone(notus._metadata_path)
        self.assertEqual(
            notus.metadata_path, f'./tests/notus/{METADATA_DIRECTORY_NAME}/'
        )
        self.assertEqual(
            notus._metadata_path, f'./tests/notus/{METADATA_DIRECTORY_NAME}/'
        )

    def test_is_checksum_correct_check_disable(self):
        notus = NotusMetadataHandler()
        notus._openvas_settings_dict = {'nasl_no_signature_check': 1}

        self.assertTrue(notus.is_checksum_correct(Path("foo")))

    def test_is_checksum_correct_enabled_false(self):
        notus = NotusMetadataHandler(nvti=self.nvti)
        notus.nvti.get_file_checksum.return_value = "abc123"
        notus._openvas_settings_dict = {'nasl_no_signature_check': 0}

        self.assertFalse(
            notus.is_checksum_correct(Path("./tests/notus/example.csv"))
        )

    def test_is_checksum_correct_enabled_true(self):
        notus = NotusMetadataHandler(nvti=self.nvti)
        notus.nvti.get_file_checksum.return_value = (
            "2f561b9be5d1a1194f49cd5a6a024dee15a0c0bc7d94287266d0e6358e737f4e"
        )
        notus._openvas_settings_dict = {'nasl_no_signature_check': 0}

        self.assertTrue(
            notus.is_checksum_correct(Path("./tests/notus/example.csv"))
        )

    def test_check_advisory_dict(self):
        advisory_dict = OrderedDict(
            [
                ('OID', '1.3.6.1.4.1.25623.1.1.2.2020.1234'),
                (
                    'TITLE',
                    'VendorOS: Security Advisory for git (VendorOS-2020-1234)',
                ),
                ('CREATION_DATE', '1600269468'),
                ('LAST_MODIFICATION', '1601380531'),
                ('SOURCE_PKGS', "['git']"),
                ('ADVISORY_ID', 'VendorOS-2020-1234'),
                ('CVSS_BASE_VECTOR', 'AV:N/AC:L/Au:N/C:C/I:C/A:C'),
                ('CVSS_BASE', '10.0'),
                ('ADVISORY_XREF', 'https://example.com'),
                ('DESCRIPTION', 'The remote host is missing an update.'),
                ('INSIGHT', 'buffer overflow'),
                ('AFFECTED', "'p1' package(s) on VendorOS V2.0SP1"),
                ('CVE_LIST', "['CVE-2020-1234']"),
                (
                    'BINARY_PACKAGES_FOR_RELEASES',
                    "{'VendorOS V2.0SP1': ['p1-1.1']}",
                ),
                ('XREFS', '[]'),
            ]
        )

        notus = NotusMetadataHandler()
        self.assertTrue(notus._check_advisory_dict(advisory_dict))

    def test_check_advisory_dict_no_value(self):
        advisory_dict = OrderedDict(
            [
                ('OID', '1.3.6.1.4.1.25623.1.1.2.2020.1234'),
                (
                    'TITLE',
                    'VendorOS: Security Advisory for git (VendorOS-2020-1234)',
                ),
                ('CREATION_DATE', None),
                ('LAST_MODIFICATION', '1601380531'),
                ('SOURCE_PKGS', "['git']"),
                ('ADVISORY_ID', 'VendorOS-2020-1234'),
                ('CVSS_BASE_VECTOR', 'AV:N/AC:L/Au:N/C:C/I:C/A:C'),
                ('CVSS_BASE', '10.0'),
                ('ADVISORY_XREF', 'https://example.com'),
                ('DESCRIPTION', 'The remote host is missing an update.'),
                ('INSIGHT', 'buffer overflow'),
                ('AFFECTED', "'p1' package(s) on VendorOS V2.0SP1"),
                ('CVE_LIST', "['CVE-2020-1234']"),
                (
                    'BINARY_PACKAGES_FOR_RELEASES',
                    "{'VendorOS V2.0SP1': ['p1-1.1']}",
                ),
                ('XREFS', '[]'),
            ]
        )

        notus = NotusMetadataHandler()
        self.assertFalse(notus._check_advisory_dict(advisory_dict))

    def test_check_advisory_dict_no_package(self):
        advisory_dict = OrderedDict(
            [
                ('OID', '1.3.6.1.4.1.25623.1.1.2.2020.1234'),
                (
                    'TITLE',
                    'VendorOS: Security Advisory for git (VendorOS-2020-1234)',
                ),
                ('CREATION_DATE', '1600269468'),
                ('LAST_MODIFICATION', '1601380531'),
                ('SOURCE_PKGS', "[]"),
                ('ADVISORY_ID', 'VendorOS-2020-1234'),
                ('CVSS_BASE_VECTOR', 'AV:N/AC:L/Au:N/C:C/I:C/A:C'),
                ('CVSS_BASE', '10.0'),
                ('ADVISORY_XREF', 'https://example.com'),
                ('DESCRIPTION', 'The remote host is missing an update.'),
                ('INSIGHT', 'buffer overflow'),
                ('AFFECTED', "'p1' package(s) on VendorOS V2.0SP1"),
                ('CVE_LIST', "['CVE-2020-1234']"),
                (
                    'BINARY_PACKAGES_FOR_RELEASES',
                    "{'VendorOS V2.0SP1': ['p1-1.1']}",
                ),
                ('XREFS', '[]'),
            ]
        )

        notus = NotusMetadataHandler()
        self.assertFalse(notus._check_advisory_dict(advisory_dict))

    def test_check_advisory_dict_valerr(self):
        advisory_dict = OrderedDict(
            [
                ('OID', '1.3.6.1.4.1.25623.1.1.2.2020.1234'),
                (
                    'TITLE',
                    'VendorOS: Security Advisory for git (VendorOS-2020-1234)',
                ),
                ('CREATION_DATE', '1600269468'),
                ('LAST_MODIFICATION', '1601380531'),
                ('SOURCE_PKGS', "a"),
                ('ADVISORY_ID', 'VendorOS-2020-1234'),
                ('CVSS_BASE_VECTOR', 'AV:N/AC:L/Au:N/C:C/I:C/A:C'),
                ('CVSS_BASE', '10.0'),
                ('ADVISORY_XREF', 'https://example.com'),
                ('DESCRIPTION', 'The remote host is missing an update.'),
                ('INSIGHT', 'buffer overflow'),
                ('AFFECTED', "'p1' package(s) on VendorOS V2.0SP1"),
                ('CVE_LIST', "['CVE-2020-1234']"),
                (
                    'BINARY_PACKAGES_FOR_RELEASES',
                    "{'VendorOS V2.0SP1': ['p1-1.1']}",
                ),
                ('XREFS', '[]'),
            ]
        )

        notus = NotusMetadataHandler()
        self.assertFalse(notus._check_advisory_dict(advisory_dict))

    def test_format_xrefs(self):
        notus = NotusMetadataHandler()
        ret = notus._format_xrefs(
            "https://example.com", ["www.foo.net", "www.bar.net"]
        )

        self.assertEqual(
            ret, "URL:https://example.com, URL:www.foo.net, URL:www.bar.net"
        )

    def test_check_field_names_lsc(self):
        notus = NotusMetadataHandler()
        field_names_list = [
            "OID",
            "TITLE",
            "CREATION_DATE",
            "LAST_MODIFICATION",
            "SOURCE_PKGS",
            "ADVISORY_ID",
            "SEVERITY_ORIGIN",
            "SEVERITY_DATE",
            "SEVERITY_VECTOR",
            "ADVISORY_XREF",
            "DESCRIPTION",
            "INSIGHT",
            "AFFECTED",
            "CVE_LIST",
            "BINARY_PACKAGES_FOR_RELEASES",
            "XREFS",
        ]
        self.assertTrue(notus._check_field_names_lsc(field_names_list))

    def test_check_field_names_lsc_unordered(self):
        notus = NotusMetadataHandler()
        field_names_list = [
            "TITLE",
            "OID",
            "CREATION_DATE",
            "LAST_MODIFICATION",
            "SOURCE_PKGS",
            "ADVISORY_ID",
            "SEVERITY_ORIGIN",
            "SEVERITY_DATE",
            "SEVERITY_VECTOR",
            "ADVISORY_XREF",
            "DESCRIPTION",
            "INSIGHT",
            "AFFECTED",
            "CVE_LIST",
            "BINARY_PACKAGES_FOR_RELEASES",
            "XREFS",
        ]

        self.assertFalse(notus._check_field_names_lsc(field_names_list))

    def test_check_field_names_lsc_missing(self):
        notus = NotusMetadataHandler()
        field_names_list = [
            "OID",
            "CREATION_DATE",
            "LAST_MODIFICATION",
            "SOURCE_PKGS",
            "ADVISORY_ID",
            "CVSS_BASE_VECTOR",
            "CVSS_BASE",
            "ADVISORY_XREF",
            "DESCRIPTION",
            "INSIGHT",
            "AFFECTED",
            "CVE_LIST",
            "BINARY_PACKAGES_FOR_RELEASES",
            "XREFS",
        ]

        self.assertFalse(notus._check_field_names_lsc(field_names_list))

    def test_get_csv_filepath(self):
        path = Path("./tests/notus/example.csv").resolve()

        notus = NotusMetadataHandler(metadata_path="./tests/notus/")
        ret = notus._get_csv_filepaths()

        self.assertEqual(ret, [path])

    @patch('ospd_openvas.notus.metadata.Openvas')
    def test_update_metadata_warning(self, MockOpenvas):
        notus = NotusMetadataHandler()
        logging.Logger.warning = MagicMock()
        path = Path("./tests/notus/example.csv").resolve()
        openvas = MockOpenvas()
        openvas.get_settings.return_value = {'table_driven_lsc': 1}

        notus._get_csv_filepaths = MagicMock(return_value=[path])
        notus.is_checksum_correct = MagicMock(return_value=False)

        notus.update_metadata()
        logging.Logger.warning.assert_called_with(
            f'Checksum for %s failed', path
        )

    @patch('ospd_openvas.notus.metadata.Openvas')
    def test_update_metadata_field_name_failed(self, MockOpenvas):
        notus = NotusMetadataHandler(metadata_path="./tests/notus")
        logging.Logger.warning = MagicMock()
        path = Path("./tests/notus/example.csv").resolve()
        openvas = MockOpenvas()
        openvas.get_settings.return_value = {'table_driven_lsc': 1}

        notus._get_csv_filepaths = MagicMock(return_value=[path])
        notus.is_checksum_correct = MagicMock(return_value=True)
        notus._check_field_names_lsc = MagicMock(return_value=False)

        notus.update_metadata()

        logging.Logger.warning.assert_called_with(
            f'Field names check for %s failed', path
        )

    @patch('ospd_openvas.notus.metadata.Openvas')
    def test_update_metadata_failed(self, MockOpenvas):
        notus = NotusMetadataHandler(metadata_path="./tests/notus")
        logging.Logger.warning = MagicMock()
        path = Path("./tests/notus/example.csv").resolve()
        openvas = MockOpenvas()
        openvas.get_settings.return_value = {'table_driven_lsc': 1}

        notus._get_csv_filepaths = MagicMock(return_value=[path])
        notus.is_checksum_correct = MagicMock(return_value=True)
        notus._check_field_names_lsc = MagicMock(return_value=True)
        notus.upload_lsc_from_csv_reader = MagicMock(return_value=False)

        notus.update_metadata()

        logging.Logger.warning.assert_called_with(
            "Some advaisory was not loaded from %s", path.name
        )

    def test_update_metadata_disabled(self):
        notus = NotusMetadataHandler(metadata_path="./tests/notus")
        ret = notus.update_metadata()
        self.assertIsNone(ret)

    @patch('ospd_openvas.notus.metadata.Openvas')
    def test_update_metadata_success(self, MockOpenvas):
        notus = NotusMetadataHandler(metadata_path="./tests/notus")
        logging.Logger.warning = MagicMock()
        path = Path("./tests/notus/example.csv").resolve()
        purepath = PurePath(path).name
        openvas = MockOpenvas()
        openvas.get_settings.return_value = {'table_driven_lsc': 1}

        notus._get_csv_filepaths = MagicMock(return_value=[path])
        notus.is_checksum_correct = MagicMock(return_value=True)
        notus._check_field_names_lsc = MagicMock(return_value=True)
        notus.upload_lsc_from_csv_reader = MagicMock(return_value=True)

        notus.update_metadata()

        logging.Logger.warning.assert_not_called()

    def test_upload_lsc_from_csv_reader_failed(self):
        general_metadata_dict = {
            'VULDETECT': 'Checks if a vulnerable package version is present on the target host.',
            'SOLUTION': 'Please install the updated package(s).',
            'SOLUTION_TYPE': 'VendorFix',
            'QOD_TYPE': 'package',
        }

        notus = NotusMetadataHandler(
            nvti=self.nvti, metadata_path="./tests/notus"
        )
        notus.nvti.add_vt_to_cache.side_effect = OspdOpenvasError
        logging.Logger.debug = MagicMock()
        path = Path("./tests/notus/example.csv").resolve()
        purepath = PurePath(path).name
        with path.open("r") as openfile:
            for line_string in openfile:
                if line_string.startswith("{"):
                    break
            reader = DictReader(openfile)

            ret = notus.upload_lsc_from_csv_reader(
                purepath, general_metadata_dict, reader
            )

        self.assertFalse(ret)
        logging.Logger.debug.assert_called_with(
            "Loaded %d/%d advisories from %s", 0, 1, purepath
        )

    def test_upload_lsc_from_csv_reader_sucess(self):
        general_metadata_dict = {
            'VULDETECT': 'Checks if a vulnerable package version is present on the target host.',
            'SOLUTION': 'Please install the updated package(s).',
            'SOLUTION_TYPE': 'VendorFix',
            'QOD_TYPE': 'package',
        }

        notus = NotusMetadataHandler(
            nvti=self.nvti, metadata_path="./tests/notus"
        )
        notus.nvti.add_vt_to_cache.return_value = None
        logging.Logger.debug = MagicMock()
        path = Path("./tests/notus/example.csv").resolve()
        purepath = PurePath(path).name
        with path.open("r") as openfile:
            for line_string in openfile:
                if line_string.startswith("{"):
                    break
            reader = DictReader(openfile)

            ret = notus.upload_lsc_from_csv_reader(
                purepath, general_metadata_dict, reader
            )

        self.assertTrue(ret)
        logging.Logger.debug.assert_called_with(
            "Loaded %d/%d advisories from %s", 1, 1, purepath
        )
