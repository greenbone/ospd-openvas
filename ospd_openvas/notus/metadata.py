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


""" Provide functions to upload Notus Metadata in the Redis Cache. """

import logging

import ast
import os

from glob import glob
from hashlib import sha256
from pathlib import Path, PurePath
from csv import DictReader
from typing import List, Dict

from ospd_openvas import db, nvticache
from ospd_openvas.errors import OspdOpenvasError
from ospd_openvas.openvas import Openvas

logger = logging.getLogger(__name__)


# The expected field names in CSV files
EXPECTED_FIELD_NAMES_LIST = [
    "OID",
    "TITLE",
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

METADATA_DIRECTORY_NAME = "notus_metadata"

# Metadata constant field definitions
SCRIPT_CATEGORY = "3"  # ACT_GATHER_INFO
SCRIPT_TIMEOUT = "0"
SCRIPT_FAMILY = "Notus_LSC_Metadata"
BIDS = ""
REQUIRED_KEYS = ""
MANDATORY_KEYS = ""
EXCLUDED_KEYS = ""
REQUIRED_UDP_PORTS = ""
REQUIRED_PORTS = ""
DEPENDENCIES = ""


class NotusMetadataHandler:
    """Class to perform checksum checks and upload metadata for
    CSV files that were created by the Notus Generator."""

    def __init__(self, metadata_path: str = None):

        self.openvas_settings_dict = None
        # Figure out the path to the metadata
        if not metadata_path:
            self.__metadata_path = self._get_metadata_path()
        else:
            self.__metadata_path = metadata_path

        self.__metadata_relative_path_string = f'{METADATA_DIRECTORY_NAME}/'

        # Get a list of all CSV files in that directory with their absolute path
        self.__csv_abs_filepaths_list = self._get_csv_filepaths()

        # Connect to the Redis KB
        try:
            self.__db_ctx = db.OpenvasDB.create_context(1)
            main_db = db.MainDB()
            self.__nvti_cache = nvticache.NVTICache(main_db)
        except SystemExit:
            # Maybe replace this with just a log message
            raise Exception("Could not connect to the Redis KB") from None

    def _get_metadata_path(self) -> str:
        """Find out where the CSV files containing the metadata
        are on the file system, depending on whether this machine
        is a GSM or GVM in a development environment.

        Returns:
            A full path to the directory that contains all Notus
            metadata.
        """
        # Openvas is installed and the plugins folder configured.
        plugins_folder = self.openvas_setting.get("plugins_folder")
        if plugins_folder:
            metadata_path = f'{plugins_folder}/{METADATA_DIRECTORY_NAME}/'
            return metadata_path

        try:
            # From the development environment - Not used in production
            install_prefix = os.environ["INSTALL_PREFIX"]
        except KeyError:
            install_prefix = None

        if not install_prefix:
            # Fall back to the path used in production
            metadata_path = (
                f'/opt/greenbone/feed/plugins/{METADATA_DIRECTORY_NAME}/'
            )
        else:
            metadata_path = f'{install_prefix}/var/lib/openvas/plugins/{METADATA_DIRECTORY_NAME}/'  # pylint: disable=C0301

        return metadata_path

    @property
    def openvas_setting(self):
        """Set OpenVAS option."""
        if self.openvas_settings_dict is None:
            openvas_object = Openvas()
            self.openvas_settings_dict = openvas_object.get_settings()
        return self.openvas_settings_dict

    def _get_csv_filepaths(self) -> List[Path]:
        """Get a list of absolute file paths to all detected CSV files
        in the relevant directory.

        Returns:
            A Path object that contains the absolute file path.
        """
        return [
            Path(csv_file).resolve()
            for csv_file in glob(f'{self.__metadata_path}*.csv')
        ]

    def _check_field_names_lsc(self, field_names_list: list) -> bool:
        """Check if the field names of the parsed CSV file are exactly
        as expected to confirm that this version of the CSV format for
        Notus is supported by this module.

        Arguments:
            field_names_list: A list of field names such as ["OID", "TITLE",...]

        Returns:
            Whether the parsed CSV file conforms to the expected format.
        """
        if not EXPECTED_FIELD_NAMES_LIST == field_names_list:
            return False
        return True

    def _check_advisory_dict(self, advisory_dict: dict) -> bool:
        """Check a row of the parsed CSV file to confirm that
        no field is missing. Also check if any lists are empty
        that should never be empty. This should avoid unexpected
        runtime errors when the CSV file is incomplete. The QA-check
        in the Notus Generator should already catch something like this
        before it happens, but this is another check just to be sure.

        Arguments:
            advisory_dict: Metadata for one vendor advisory
                           in the form of a dict.

        Returns:
            Whether this advisory_dict is as expected or not.
        """
        # Check if there are any empty fields that shouldn't be empty.
        # Skip those that are incorrect.
        for (key, value) in advisory_dict.items():
            # The value is missing entirely
            if not value:
                return False
            # A list is empty when it shouldn't be
            try:
                if key == "SOURCE_PKGS" and len(ast.literal_eval(value)) == 0:
                    return False
            except (ValueError, TypeError):
                # Expected a list, but this was not a list
                return False
        return True

    def _format_xrefs(self, advisory_xref_string: str, xrefs_list: list) -> str:
        """Create a string that contains all links for this advisory, to be
        inserted into the Redis KB.

        Arguments:
            advisory_xref_string: A link to the official advisory page.
            xrefs_list: A list of URLs that were mentioned
                        in the advisory itself.

        Returns:
            All URLs separated by ", ".
            Example: URL:www.example.com, URL:www.example2.com
        """
        formatted_list = list()
        advisory_xref_string = f'URL:{advisory_xref_string}'
        formatted_list.append(advisory_xref_string)
        for url_string in xrefs_list:
            url_string = f'URL:{url_string}'
            formatted_list.append(url_string)
        return ", ".join(formatted_list)

    def is_checksum_correct(self, file_abs_path: Path) -> bool:
        """Perform a checksum check on a specific file, if
        signature checks have been enabled in OpenVAS.

        Arguments:
            file_abs_path: A Path object that points to the
                           absolute path of a file.

        Returns:
            Whether the checksum check was successful or not.
            Also returns true if the checksum check is disabled.
        """

        no_signature_check = self.openvas_setting.get("nasl_no_signature_check")
        if not no_signature_check:
            with file_abs_path.open("rb") as file_file_bytes:
                sha256_object = sha256()
                # Read chunks of 4096 bytes sequentially to avoid
                # filling up the RAM if the file is extremely large
                for byte_block in iter(lambda: file_file_bytes.read(4096), b""):
                    sha256_object.update(byte_block)

                # Calculate the checksum for this file
                file_calculated_checksum_string = sha256_object.hexdigest()
                # Extract the downloaded checksum for this file
                # from the Redis KB
                file_downloaded_checksum_string = db.OpenvasDB.get_single_item(
                    self.__db_ctx, f'sha256sums:{file_abs_path}'
                )

                # Checksum check
                if (
                    not file_calculated_checksum_string
                    == file_downloaded_checksum_string
                ):
                    return False
        # Checksum check was either successful or it was skipped
        return True

    def upload_lsc_from_csv_reader(
        self,
        file_name: str,
        general_metadata_dict: Dict,
        csv_reader: DictReader,
    ) -> bool:
        """For each advisory_dict, write its contents to the
        Redis KB as metadata.

        Arguments:
            file_name: CSV file name with metadata to be uploaded
            general_metadata_dict: General metadata common for all advisories
                                   in the CSV file.
            csv_reader: DictReader iterator to access the advisories

        Return True if success, False otherwise
        """

        loaded = 0
        total = 0
        for advisory_dict in csv_reader:
            # Make sure that no element is missing in the advisory_dict,
            # else skip that advisory
            total += 1
            is_correct = self._check_advisory_dict(advisory_dict)
            if not is_correct:
                continue
            # For each advisory_dict,
            # write its contents to the Redis KB as metadata.
            # Create a list with all the metadata. Refer to:
            # https://github.com/greenbone/ospd-openvas/blob/232d04e72d2af0199d60324e8820d9e73498a831/ospd_openvas/db.py#L39 # pylint: disable=C0321
            advisory_metadata_list = list()
            # File name
            advisory_metadata_list.append(
                f'{self.__metadata_relative_path_string}{file_name}'
            )
            # Required keys
            advisory_metadata_list.append(REQUIRED_KEYS)
            # Mandatory keys
            advisory_metadata_list.append(MANDATORY_KEYS)
            # Excluded keys
            advisory_metadata_list.append(EXCLUDED_KEYS)
            # Required UDP ports
            advisory_metadata_list.append(REQUIRED_UDP_PORTS)
            # Required ports
            advisory_metadata_list.append(REQUIRED_PORTS)
            # Dependencies
            advisory_metadata_list.append(DEPENDENCIES)
            # Tags
            tags_string = (
                "cvss_base_vector={}|last_modification={}|"
                "creation_date={}|summary={}|vuldetect={}|"
                "insight={}|affected={}|solution={}|"
                "solution_type={}|qod_type={}"
            )
            tags_string = tags_string.format(
                advisory_dict["CVSS_BASE_VECTOR"],
                advisory_dict["LAST_MODIFICATION"],
                advisory_dict["CREATION_DATE"],
                advisory_dict["DESCRIPTION"],
                general_metadata_dict["VULDETECT"],
                advisory_dict["INSIGHT"],
                advisory_dict["AFFECTED"],
                general_metadata_dict["SOLUTION"],
                general_metadata_dict["SOLUTION_TYPE"],
                general_metadata_dict["QOD_TYPE"],
            )
            advisory_metadata_list.append(tags_string)
            # CVEs
            advisory_metadata_list.append(
                ", ".join(ast.literal_eval(advisory_dict["CVE_LIST"]))
            )

            advisory_metadata_list.append(BIDS)
            # XREFS
            advisory_metadata_list.append(
                self._format_xrefs(
                    advisory_dict["ADVISORY_XREF"],
                    ast.literal_eval(advisory_dict["XREFS"]),
                )
            )

            # Script category
            advisory_metadata_list.append(SCRIPT_CATEGORY)
            # Script timeout
            advisory_metadata_list.append(SCRIPT_TIMEOUT)
            # Script family
            advisory_metadata_list.append(SCRIPT_FAMILY)
            # Script Name / Title
            advisory_metadata_list.append(advisory_dict["TITLE"])

            # Write the metadata list to the respective Redis KB key,
            # overwriting any existing values
            oid = advisory_dict["OID"]
            kb_key_string = f'nvt:{oid}'
            try:
                self.__nvti_cache.add_vt_to_cache(
                    vt_id=kb_key_string, vt=advisory_metadata_list
                )
            except OspdOpenvasError:
                logger.warning(
                    "LSC will not be loaded. The advisory_metadata_"
                    "list was either not a list or does not include "
                    "15 entries"
                )
                continue
            loaded += 1

        logger.debug(
            "Loaded %d/%d advisories from %s", loaded, total, file_name
        )
        return loaded == total

    def update_metadata(self) -> None:
        """Parse all CSV files that are present in the
        Notus metadata directory, perform a checksum check,
        read their metadata, format some fields
        and write this information to the Redis KB.
        """

        logger.debug("Starting the Notus metadata load up")
        # 1. Read each CSV file
        for csv_abs_path in self.__csv_abs_filepaths_list:
            # 2. Check the checksums, unless they have been disabled
            if not self.is_checksum_correct(csv_abs_path):
                # Skip this file if the checksum does not match
                logger.warning('Checksum for %s failed', csv_abs_path)
                continue

            logger.debug("Checksum check for %s successful", csv_abs_path)
            with csv_abs_path.open("r") as csv_file:
                # Skip the license header, so the actual content
                # can be parsed by the DictReader
                general_metadata_dict = dict()
                for line_string in csv_file:
                    if line_string.startswith("{"):
                        general_metadata_dict = ast.literal_eval(line_string)
                        break
                # Check if the file can be parsed by the CSV module
                reader = DictReader(csv_file)
                # Check if the CSV file has the expected field names,
                # else skip the file
                is_correct = self._check_field_names_lsc(reader.fieldnames)
                if not is_correct:
                    continue

                file_name = PurePath(csv_file.name).name
                if not self.upload_lsc_from_csv_reader(
                    file_name, general_metadata_dict, reader
                ):
                    logger.debug(
                        "Some advaisory was not loaded from %s", file_name
                    )

        logger.debug("Notus metadata load up finished.")
