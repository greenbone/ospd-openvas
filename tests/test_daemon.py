# -*- coding: utf-8 -*-
# Copyright (C) 2014-2021 Greenbone Networks GmbH
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


# pylint: disable=line-too-long

""" Unit Test for ospd-openvas """

import io
import logging

from unittest import TestCase
from unittest.mock import patch, Mock, MagicMock

from ospd.protocol import OspRequest

from tests.dummydaemon import DummyDaemon
from tests.helper import assert_called_once

from ospd_openvas.daemon import (
    OSPD_PARAMS,
    OpenVasVtsFilter,
)
from ospd_openvas.openvas import Openvas

from .helper import OSPD_PARAMS_OUT


class TestOspdOpenvas(TestCase):
    @patch('ospd_openvas.daemon.Openvas')
    def test_set_params_from_openvas_settings(self, mock_openvas: Openvas):
        mock_openvas.get_settings.return_value = {
            'non_simult_ports': '139, 445, 3389, Services/irc',
            'plugins_folder': '/foo/bar',
        }
        dummy = DummyDaemon()
        dummy.set_params_from_openvas_settings()

        self.assertEqual(mock_openvas.get_settings.call_count, 1)
        self.assertEqual(OSPD_PARAMS, OSPD_PARAMS_OUT)
        self.assertEqual(
            dummy.scan_only_params.get('plugins_folder'), '/foo/bar'
        )

    @patch('ospd_openvas.daemon.Openvas')
    def test_sudo_available(self, mock_openvas):
        mock_openvas.check_sudo.return_value = True

        dummy = DummyDaemon()
        dummy._sudo_available = None  # pylint: disable=protected-access
        dummy._is_running_as_root = False  # pylint: disable=protected-access

        self.assertTrue(dummy.sudo_available)

    def test_get_custom_xml(self):
        out = (
            '<custom>'
            '<required_ports>Services/www, 80</required_ports>'
            '<category>3</category>'
            '<excluded_keys>Settings/disable_cgi_scanning</excluded_keys>'
            '<family>Product detection</family>'
            '<filename>mantis_detect.nasl</filename>'
            '<timeout>0</timeout>'
            '</custom>'
        )
        dummy = DummyDaemon()

        vt = dummy.VTS['1.3.6.1.4.1.25623.1.0.100061']
        res = dummy.get_custom_vt_as_xml_str(
            '1.3.6.1.4.1.25623.1.0.100061', vt.get('custom')
        )
        self.assertEqual(len(res), len(out))

    def test_get_custom_xml_failed(self):
        dummy = DummyDaemon()
        logging.Logger.warning = Mock()

        custom = {'a': u"\u0006"}
        dummy.get_custom_vt_as_xml_str(
            '1.3.6.1.4.1.25623.1.0.100061', custom=custom
        )

        assert_called_once(logging.Logger.warning)

    def test_get_severities_xml(self):
        dummy = DummyDaemon()

        out = (
            '<severities>'
            '<severity type="cvss_base_v2">'
            '<value>AV:N/AC:L/Au:N/C:N/I:N/A:N</value>'
            '<origin>Greenbone</origin>'
            '<date>1237458156</date>'
            '</severity>'
            '</severities>'
        )
        vt = dummy.VTS['1.3.6.1.4.1.25623.1.0.100061']
        severities = vt.get('severities')
        res = dummy.get_severities_vt_as_xml_str(
            '1.3.6.1.4.1.25623.1.0.100061', severities
        )

        self.assertEqual(res, out)

    def test_get_severities_xml_failed(self):
        dummy = DummyDaemon()
        logging.Logger.warning = Mock()

        sever = {'severity_base_vector': u"\u0006"}
        dummy.get_severities_vt_as_xml_str(
            '1.3.6.1.4.1.25623.1.0.100061', severities=sever
        )

        assert_called_once(logging.Logger.warning)

    def test_get_params_xml(self):
        dummy = DummyDaemon()
        out = (
            '<params>'
            '<param type="checkbox" id="2">'
            '<name>Do not randomize the  order  in  which ports are '
            'scanned</name>'
            '<default>no</default>'
            '</param>'
            '<param type="entry" id="1">'
            '<name>Data length :</name>'
            '</param>'
            '</params>'
        )

        vt = dummy.VTS['1.3.6.1.4.1.25623.1.0.100061']
        params = vt.get('vt_params')
        res = dummy.get_params_vt_as_xml_str(
            '1.3.6.1.4.1.25623.1.0.100061', params
        )

        self.assertEqual(len(res), len(out))

    def test_get_params_xml_failed(self):
        dummy = DummyDaemon()
        logging.Logger.warning = Mock()

        params = {
            '1': {
                'id': '1',
                'type': 'entry',
                'default': u'\u0006',
                'name': 'dns-fuzz.timelimit',
                'description': 'Description',
            }
        }
        dummy.get_params_vt_as_xml_str('1.3.6.1.4.1.25623.1.0.100061', params)

        assert_called_once(logging.Logger.warning)

    def test_get_refs_xml(self):
        dummy = DummyDaemon()

        out = '<refs><ref type="url" id="http://www.mantisbt.org/"/></refs>'
        vt = dummy.VTS['1.3.6.1.4.1.25623.1.0.100061']
        refs = vt.get('vt_refs')
        res = dummy.get_refs_vt_as_xml_str('1.3.6.1.4.1.25623.1.0.100061', refs)

        self.assertEqual(res, out)

    def test_get_dependencies_xml(self):
        dummy = DummyDaemon()

        out = (
            '<dependencies>'
            '<dependency vt_id="1.3.6.1.4.1.25623.1.2.3.4"/>'
            '<dependency vt_id="1.3.6.1.4.1.25623.4.3.2.1"/>'
            '</dependencies>'
        )
        dep = ['1.3.6.1.4.1.25623.1.2.3.4', '1.3.6.1.4.1.25623.4.3.2.1']
        res = dummy.get_dependencies_vt_as_xml_str(
            '1.3.6.1.4.1.25623.1.0.100061', dep
        )

        self.assertEqual(res, out)

    def test_get_dependencies_xml_missing_dep(self):
        dummy = DummyDaemon()

        out = (
            '<dependencies>'
            '<dependency vt_id="1.3.6.1.4.1.25623.1.2.3.4"/>'
            '</dependencies>'
        )
        dep = ['1.3.6.1.4.1.25623.1.2.3.4', 'file_name.nasl']
        res = dummy.get_dependencies_vt_as_xml_str(
            '1.3.6.1.4.1.25623.1.0.100061', dep
        )

        self.assertEqual(res, out)

    def test_get_dependencies_xml_failed(self):
        dummy = DummyDaemon()
        logging.Logger.error = Mock()

        dep = [u"\u0006"]
        dummy.get_dependencies_vt_as_xml_str(
            '1.3.6.1.4.1.25623.1.0.100061', vt_dependencies=dep
        )

        assert_called_once(logging.Logger.error)

    def test_get_ctime_xml(self):
        dummy = DummyDaemon()

        out = '<creation_time>1237458156</creation_time>'
        vt = dummy.VTS['1.3.6.1.4.1.25623.1.0.100061']
        ctime = vt.get('creation_time')
        res = dummy.get_creation_time_vt_as_xml_str(
            '1.3.6.1.4.1.25623.1.0.100061', ctime
        )

        self.assertEqual(res, out)

    def test_get_ctime_xml_failed(self):
        dummy = DummyDaemon()
        logging.Logger.warning = Mock()

        ctime = u'\u0006'
        dummy.get_creation_time_vt_as_xml_str(
            '1.3.6.1.4.1.25623.1.0.100061', vt_creation_time=ctime
        )

        assert_called_once(logging.Logger.warning)

    def test_get_mtime_xml(self):
        dummy = DummyDaemon()

        out = '<modification_time>1533906565</modification_time>'
        vt = dummy.VTS['1.3.6.1.4.1.25623.1.0.100061']
        mtime = vt.get('modification_time')
        res = dummy.get_modification_time_vt_as_xml_str(
            '1.3.6.1.4.1.25623.1.0.100061', mtime
        )

        self.assertEqual(res, out)

    def test_get_mtime_xml_failed(self):
        dummy = DummyDaemon()
        logging.Logger.warning = Mock()

        mtime = u'\u0006'
        dummy.get_modification_time_vt_as_xml_str(
            '1.3.6.1.4.1.25623.1.0.100061', mtime
        )

        assert_called_once(logging.Logger.warning)

    def test_get_summary_xml(self):
        dummy = DummyDaemon()

        out = '<summary>some summary</summary>'
        vt = dummy.VTS['1.3.6.1.4.1.25623.1.0.100061']
        summary = vt.get('summary')
        res = dummy.get_summary_vt_as_xml_str(
            '1.3.6.1.4.1.25623.1.0.100061', summary
        )

        self.assertEqual(res, out)

    def test_get_summary_xml_failed(self):
        dummy = DummyDaemon()

        summary = u'\u0006'
        logging.Logger.warning = Mock()
        dummy.get_summary_vt_as_xml_str('1.3.6.1.4.1.25623.1.0.100061', summary)

        assert_called_once(logging.Logger.warning)

    def test_get_impact_xml(self):
        dummy = DummyDaemon()

        out = '<impact>some impact</impact>'
        vt = dummy.VTS['1.3.6.1.4.1.25623.1.0.100061']
        impact = vt.get('impact')
        res = dummy.get_impact_vt_as_xml_str(
            '1.3.6.1.4.1.25623.1.0.100061', impact
        )

        self.assertEqual(res, out)

    def test_get_impact_xml_failed(self):
        dummy = DummyDaemon()
        logging.Logger.warning = Mock()

        impact = u'\u0006'
        dummy.get_impact_vt_as_xml_str('1.3.6.1.4.1.25623.1.0.100061', impact)

        assert_called_once(logging.Logger.warning)

    def test_get_insight_xml(self):
        dummy = DummyDaemon()

        out = '<insight>some insight</insight>'
        vt = dummy.VTS['1.3.6.1.4.1.25623.1.0.100061']
        insight = vt.get('insight')
        res = dummy.get_insight_vt_as_xml_str(
            '1.3.6.1.4.1.25623.1.0.100061', insight
        )

        self.assertEqual(res, out)

    def test_get_insight_xml_failed(self):
        dummy = DummyDaemon()
        logging.Logger.warning = Mock()

        insight = u'\u0006'
        dummy.get_insight_vt_as_xml_str('1.3.6.1.4.1.25623.1.0.100061', insight)

        assert_called_once(logging.Logger.warning)

    def test_get_solution_xml(self):
        dummy = DummyDaemon()

        out = (
            '<solution type="WillNotFix" method="DebianAPTUpgrade">'
            'some solution'
            '</solution>'
        )
        vt = dummy.VTS['1.3.6.1.4.1.25623.1.0.100061']
        solution = vt.get('solution')
        solution_type = vt.get('solution_type')
        solution_method = vt.get('solution_method')

        res = dummy.get_solution_vt_as_xml_str(
            '1.3.6.1.4.1.25623.1.0.100061',
            solution,
            solution_type,
            solution_method,
        )

        self.assertEqual(res, out)

    def test_get_solution_xml_failed(self):
        dummy = DummyDaemon()
        logging.Logger.warning = Mock()

        solution = u'\u0006'
        dummy.get_solution_vt_as_xml_str(
            '1.3.6.1.4.1.25623.1.0.100061', solution
        )

        assert_called_once(logging.Logger.warning)

    def test_get_detection_xml(self):
        dummy = DummyDaemon()

        out = '<detection qod_type="remote_banner"/>'
        vt = dummy.VTS['1.3.6.1.4.1.25623.1.0.100061']
        detection_type = vt.get('qod_type')

        res = dummy.get_detection_vt_as_xml_str(
            '1.3.6.1.4.1.25623.1.0.100061', qod_type=detection_type
        )

        self.assertEqual(res, out)

    def test_get_detection_xml_failed(self):
        dummy = DummyDaemon()
        logging.Logger.warning = Mock()

        detection = u'\u0006'
        dummy.get_detection_vt_as_xml_str(
            '1.3.6.1.4.1.25623.1.0.100061', detection
        )

        assert_called_once(logging.Logger.warning)

    def test_get_affected_xml(self):
        dummy = DummyDaemon()
        out = '<affected>some affection</affected>'
        vt = dummy.VTS['1.3.6.1.4.1.25623.1.0.100061']
        affected = vt.get('affected')

        res = dummy.get_affected_vt_as_xml_str(
            '1.3.6.1.4.1.25623.1.0.100061', affected=affected
        )

        self.assertEqual(res, out)

    def test_get_affected_xml_failed(self):
        dummy = DummyDaemon()
        logging.Logger.warning = Mock()

        affected = u"\u0006" + "affected"
        dummy.get_affected_vt_as_xml_str(
            '1.3.6.1.4.1.25623.1.0.100061', affected=affected
        )

        assert_called_once(logging.Logger.warning)

    @patch('ospd_openvas.daemon.Path.exists')
    @patch('ospd_openvas.daemon.OSPDopenvas.set_params_from_openvas_settings')
    def test_feed_is_outdated_none(
        self, mock_set_params: MagicMock, mock_path_exists: MagicMock
    ):
        dummy = DummyDaemon()

        dummy.scan_only_params['plugins_folder'] = '/foo/bar'

        # Return None
        mock_path_exists.return_value = False

        ret = dummy.feed_is_outdated('1234')
        self.assertIsNone(ret)

        self.assertEqual(mock_set_params.call_count, 1)
        self.assertEqual(mock_path_exists.call_count, 1)

    @patch('ospd_openvas.daemon.Path.exists')
    @patch('ospd_openvas.daemon.Path.open')
    def test_feed_is_outdated_true(
        self,
        mock_path_open: MagicMock,
        mock_path_exists: MagicMock,
    ):
        read_data = 'PLUGIN_SET = "1235";'

        mock_path_exists.return_value = True
        mock_read = MagicMock(name='Path open context manager')
        mock_read.__enter__ = MagicMock(return_value=io.StringIO(read_data))
        mock_path_open.return_value = mock_read

        dummy = DummyDaemon()

        # Return True
        dummy.scan_only_params['plugins_folder'] = '/foo/bar'

        ret = dummy.feed_is_outdated('1234')
        self.assertTrue(ret)

        self.assertEqual(mock_path_exists.call_count, 1)
        self.assertEqual(mock_path_open.call_count, 1)

    @patch('ospd_openvas.daemon.Path.exists')
    @patch('ospd_openvas.daemon.Path.open')
    def test_feed_is_outdated_false(
        self,
        mock_path_open: MagicMock,
        mock_path_exists: MagicMock,
    ):
        mock_path_exists.return_value = True

        read_data = 'PLUGIN_SET = "1234"'
        mock_path_exists.return_value = True
        mock_read = MagicMock(name='Path open context manager')
        mock_read.__enter__ = MagicMock(return_value=io.StringIO(read_data))
        mock_path_open.return_value = mock_read

        dummy = DummyDaemon()
        dummy.scan_only_params['plugins_folder'] = '/foo/bar'

        ret = dummy.feed_is_outdated('1234')
        self.assertFalse(ret)

        self.assertEqual(mock_path_exists.call_count, 1)
        self.assertEqual(mock_path_open.call_count, 1)

    def test_check_feed_cache_unavailable(self):
        dummy = DummyDaemon()
        dummy.vts.is_cache_available = False
        dummy.feed_is_outdated = Mock()

        dummy.feed_is_outdated.assert_not_called()

    @patch('ospd_openvas.daemon.BaseDB')
    @patch('ospd_openvas.daemon.ResultList.add_scan_log_to_list')
    def test_get_openvas_result(self, mock_add_scan_log_to_list, db_class_mock):
        dummy = DummyDaemon()

        target_element = dummy.create_xml_target()
        targets = OspRequest.process_target_element(target_element)
        dummy.create_scan('123-456', targets, None, [])

        results = [
            "LOG|||192.168.0.1|||localhost|||general/Host_Details||||||Host"
            " dead",
        ]
        db_class_mock.get_result.return_value = results
        mock_add_scan_log_to_list.return_value = None

        dummy.report_openvas_results(db_class_mock, '123-456')
        mock_add_scan_log_to_list.assert_called_with(
            host='192.168.0.1',
            hostname='localhost',
            name='',
            port='general/Host_Details',
            qod='',
            test_id='',
            uri='',
            value='Host dead',
        )

    @patch('ospd_openvas.daemon.BaseDB')
    @patch('ospd_openvas.daemon.ResultList.add_scan_error_to_list')
    def test_get_openvas_result_host_deny(
        self, mock_add_scan_error_to_list, db_class_mock
    ):
        dummy = DummyDaemon()

        target_element = dummy.create_xml_target()
        targets = OspRequest.process_target_element(target_element)
        dummy.create_scan('123-456', targets, None, [])

        results = [
            "ERRMSG|||127.0.0.1|||localhost|||||||||Host access denied.",
        ]
        db_class_mock.get_result.return_value = results
        mock_add_scan_error_to_list.return_value = None

        dummy.report_openvas_results(db_class_mock, '123-456')
        mock_add_scan_error_to_list.assert_called_with(
            host='127.0.0.1',
            hostname='localhost',
            name='',
            port='',
            test_id='',
            uri='',
            value='Host access denied.',
        )

    @patch('ospd_openvas.daemon.BaseDB')
    def test_get_openvas_result_dead_hosts(self, db_class_mock):
        dummy = DummyDaemon()
        target_element = dummy.create_xml_target()
        targets = OspRequest.process_target_element(target_element)
        dummy.create_scan('123-456', targets, None, [])

        results = [
            "DEADHOST||| ||| ||| ||| |||4",
        ]
        db_class_mock.get_result.return_value = results
        dummy.scan_collection.set_amount_dead_hosts = MagicMock()

        dummy.report_openvas_results(db_class_mock, '123-456')
        dummy.scan_collection.set_amount_dead_hosts.assert_called_with(
            '123-456',
            total_dead=4,
        )

    @patch('ospd_openvas.daemon.BaseDB')
    @patch('ospd_openvas.daemon.ResultList.add_scan_log_to_list')
    def test_get_openvas_result_host_start(
        self, mock_add_scan_log_to_list, db_class_mock
    ):
        dummy = DummyDaemon()
        target_element = dummy.create_xml_target()
        targets = OspRequest.process_target_element(target_element)
        dummy.create_scan('123-456', targets, None, [])

        results = [
            "HOST_START|||192.168.10.124||| ||| ||||||today 1",
        ]

        db_class_mock.get_result.return_value = results
        mock_add_scan_log_to_list.return_value = None

        dummy.report_openvas_results(db_class_mock, '123-456')

        mock_add_scan_log_to_list.assert_called_with(
            host='192.168.10.124',
            name='HOST_START',
            value='today 1',
        )

    @patch('ospd_openvas.daemon.BaseDB')
    def test_get_openvas_result_hosts_count(self, db_class_mock):
        dummy = DummyDaemon()
        target_element = dummy.create_xml_target()
        targets = OspRequest.process_target_element(target_element)
        dummy.create_scan('123-456', targets, None, [])

        results = [
            "HOSTS_COUNT||| ||| ||| ||| |||4",
        ]
        db_class_mock.get_result.return_value = results
        dummy.set_scan_total_hosts = MagicMock()

        dummy.report_openvas_results(db_class_mock, '123-456')
        dummy.set_scan_total_hosts.assert_called_with(
            '123-456',
            4,
        )

    @patch('ospd_openvas.daemon.BaseDB')
    @patch('ospd_openvas.daemon.ResultList.add_scan_alarm_to_list')
    def test_result_without_vt_oid(
        self, mock_add_scan_alarm_to_list, db_class_mock
    ):
        dummy = DummyDaemon()
        logging.Logger.warning = Mock()

        target_element = dummy.create_xml_target()
        targets = OspRequest.process_target_element(target_element)
        dummy.create_scan('123-456', targets, None, [])
        dummy.scan_collection.scans_table['123-456']['results'] = list()
        results = ["ALARM||| ||| ||| ||| |||some alarm|||path", None]
        db_class_mock.get_result.return_value = results
        mock_add_scan_alarm_to_list.return_value = None

        dummy.report_openvas_results(db_class_mock, '123-456')

        assert_called_once(logging.Logger.warning)

    @patch('psutil.Popen')
    def test_openvas_is_alive_already_stopped(self, mock_process):
        dummy = DummyDaemon()

        mock_process.is_running.return_value = True
        ret = dummy.is_openvas_process_alive(mock_process)
        self.assertTrue(ret)

    @patch('psutil.Popen')
    def test_openvas_is_alive_still(self, mock_process):
        dummy = DummyDaemon()

        mock_process.is_running.return_value = False
        ret = dummy.is_openvas_process_alive(mock_process)
        self.assertFalse(ret)

    @patch('ospd_openvas.daemon.OSPDaemon.set_scan_progress_batch')
    @patch('ospd_openvas.daemon.OSPDaemon.sort_host_finished')
    @patch('ospd_openvas.db.KbDB')
    def test_report_openvas_scan_status(
        self, mock_db, mock_sort_host_finished, mock_set_scan_progress_batch
    ):
        dummy = DummyDaemon()

        mock_set_scan_progress_batch.return_value = None
        mock_sort_host_finished.return_value = None
        mock_db.get_scan_status.return_value = [
            '192.168.0.1/15/1000',
            '192.168.0.2/15/0',
            '192.168.0.3/15/-1',
            '192.168.0.4/1500/1500',
        ]

        target_element = dummy.create_xml_target()
        targets = OspRequest.process_target_element(target_element)

        dummy.create_scan('123-456', targets, None, [])
        dummy.report_openvas_scan_status(mock_db, '123-456')

        mock_set_scan_progress_batch.assert_called_with(
            '123-456',
            host_progress={
                '192.168.0.1': 1,
                '192.168.0.3': -1,
                '192.168.0.4': 100,
            },
        )

        mock_sort_host_finished.assert_called_with(
            '123-456', ['192.168.0.3', '192.168.0.4']
        )


class TestFilters(TestCase):
    def test_format_vt_modification_time(self):
        ovformat = OpenVasVtsFilter(None)
        td = '1517443741'
        formatted = ovformat.format_vt_modification_time(td)
        self.assertEqual(formatted, "20180201000901")

    def test_get_filtered_vts_false(self):
        dummy = DummyDaemon()
        vts_collection = ['1234', '1.3.6.1.4.1.25623.1.0.100061']

        ovfilter = OpenVasVtsFilter(dummy.nvti)
        res = ovfilter.get_filtered_vts_list(
            vts_collection, "modification_time<10"
        )
        self.assertNotIn('1.3.6.1.4.1.25623.1.0.100061', res)

    def test_get_filtered_vts_true(self):
        dummy = DummyDaemon()
        vts_collection = ['1234', '1.3.6.1.4.1.25623.1.0.100061']

        ovfilter = OpenVasVtsFilter(dummy.nvti)
        res = ovfilter.get_filtered_vts_list(
            vts_collection, "modification_time>10"
        )
        self.assertIn('1.3.6.1.4.1.25623.1.0.100061', res)

    def test_get_severity_score_v2(self):
        dummy = DummyDaemon()
        vtaux = {
            'severities': {
                'severity_type': 'cvss_base_v2',
                'severity_base_vector': 'AV:N/AC:L/Au:N/C:P/I:N/A:N',
            }
        }

        dummy.get_severity_score(vtaux)
        self.assertEqual(dummy.get_severity_score(vtaux), 5.0)

    def test_get_severity_score_v3(self):
        dummy = DummyDaemon()
        vtaux = {
            'severities': {
                'severity_type': 'cvss_base_v3',
                'severity_base_vector': (
                    'CVSS:3.0/AV:L/AC:H/PR:H/UI:R/S:U/C:N/I:L/A:L'
                ),
            }
        }

        self.assertEqual(dummy.get_severity_score(vtaux), 2.9)
