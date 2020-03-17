# -*- coding: utf-8 -*-
# Copyright (C) 2019 Greenbone Networks GmbH
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA

# pylint: disable=too-many-lines

""" Prepare the preferences to be used by OpenVAS """

import logging
import uuid

from typing import Optional, Dict, List, Tuple, Iterator

logger = logging.getLogger(__name__)


class PreferenceHandler:
    def __init__(self, scan_id, kbdb, scan_collection):
        self.scan_id = scan_id
        self.kbdb = kbdb
        self.scan_collection = scan_collection

        self._openvas_scan_id = None

        self._target_options = None

    @property
    def openvas_scan_id(self):
        if self._openvas_scan_id is not None:
            return self._openvas_scan_id

        self._openvas_scan_id = str(uuid.uuid4())
        self.kbdb.add_scan_id(self.scan_id, self._openvas_scan_id)

        return self._openvas_scan_id

    @property
    def target_options(self):
        if self._target_options is not None:
            return self._target_options

        self._target_options = self.scan_collection.get_target_options(
            self.scan_id
        )
        return self._target_options

    def process_vts(
        self, vts: Dict[str, Dict[str, str]]
    ) -> Tuple[List[str], Dict[str, str]]:
        """ Add single VTs and their parameters. """
        vts_list = []
        vts_params = {}
        vtgroups = vts.pop('vt_groups')

        if vtgroups:
            vts_list = self.get_vts_in_groups(vtgroups)

        for vtid, vt_params in vts.items():
            if vtid not in self.temp_vts:
                logger.warning(
                    'The VT %s was not found and it will not be loaded.', vtid
                )
                continue

            vts_list.append(vtid)
            for vt_param_id, vt_param_value in vt_params.items():
                param_type = self.get_vt_param_type(vtid, vt_param_id)
                param_name = self.get_vt_param_name(vtid, vt_param_id)

                if not param_type or not param_name:
                    logger.debug(
                        'Missing type or name for VT parameter %s of %s. '
                        'It could not be loaded.',
                        vt_param_id,
                        vtid,
                    )
                    continue

                if vt_param_id == '0':
                    type_aux = 'integer'
                else:
                    type_aux = param_type

                if self.check_param_type(vt_param_value, type_aux):
                    logger.debug(
                        'The VT parameter %s for %s could not be loaded. '
                        'Expected %s type for parameter value %s',
                        vt_param_id,
                        vtid,
                        type_aux,
                        str(vt_param_value),
                    )
                    continue

                if type_aux == 'checkbox':
                    vt_param_value = _from_bool_to_str(int(vt_param_value))

                vts_params[
                    "{0}:{1}:{2}:{3}".format(
                        vtid, vt_param_id, param_type, param_name
                    )
                ] = str(vt_param_value)

        return vts_list, vts_params

    def set_plugins(
        self, vts,
    ):
        nvts = self.scan_collection.get_vts(self.scan_id)
        if nvts != '':
            nvts_list, nvts_params = self.process_vts(nvts)
            # Add nvts list
            separ = ';'
            plugin_list = 'plugin_set|||%s' % separ.join(nvts_list)
            kbdb.add_scan_preferences(self.openvas_scan_id, [plugin_list])

            # Set alive test option. Overwrite the scan config settings.
            if self.target_options:
                # Check if test_alive_hosts_only feature of openvas is active.
                # If active, put ALIVE_TEST enum in preferences.
                settings = Openvas.get_settings()
                if settings:
                    test_alive_hosts_only = settings.get(
                        'test_alive_hosts_only'
                    )
                    if test_alive_hosts_only:
                        if self.target_options and self.target_options.get(
                            'alive_test'
                        ):
                            try:
                                alive_test = int(
                                    self.target_options.get('alive_test')
                                )
                            except ValueError:
                                logger.debug(
                                    'Alive test settings not applied. '
                                    'Invalid alive test value %s',
                                    self.target_options.get('alive_test'),
                                )
                            # Put ALIVE_TEST enum in db, this is then taken
                            # by openvas to determine the method to use
                            # for the alive test.
                            if alive_test >= 1 and alive_test <= 31:
                                item = 'ALIVE_TEST|||%s' % str(alive_test)
                                kbdb.add_scan_preferences(
                                    self.openvas_scan_id, [item]
                                )

                alive_test_opt = self.build_alive_test_opt_as_prefs(
                    self.target_options
                )
                for elem in alive_test_opt:
                    key, val = elem.split("|||", 2)
                    nvts_params[key] = val

            # Add nvts parameters
            for key, val in nvts_params.items():
                item = '%s|||%s' % (key, val)
                kbdb.add_scan_preferences(self.openvas_scan_id, [item])

            nvts_params = None
            nvts_list = None
            item = None
            plugin_list = None
            nvts = None

            # Release temp vts dict memory.
            self.temp_vts = None
        else:
            self.add_scan_error(
                self.scan_id, name='', host=target, value='No VTS to run.'
            )
            do_not_launch = True
