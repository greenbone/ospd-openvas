# -*- coding: utf-8 -*-
# Copyright (C) 2021 Greenbone AG
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


# pylint: disable=too-many-lines

""" Methods for dry run """

import logging
import time

from random import uniform, choice

from ospd.scan import ScanProgress, ScanStatus
from ospd.network import target_str_to_list, ports_as_list
from ospd.resultlist import ResultList
from ospd_openvas.vthelper import VtHelper

logger = logging.getLogger(__name__)


class DryRun:
    def __init__(self, daemon):
        self._daemon = daemon

    def exec_dry_run_scan(self, scan_id, nvti, ospd_params):
        options = self._daemon.scan_collection.get_options(scan_id)
        results_per_host = None
        if "results_per_host" in options:
            results_per_host = options.get("results_per_host")

        if not results_per_host or not isinstance(results_per_host, int):
            logger.debug("Using default value for results_per_host options")
            results_per_host = ospd_params["results_per_host"].get("default")

        # Get the host list
        target = self._daemon.scan_collection.get_host_list(scan_id)
        logger.info("The target list %s", target)
        host_list = target_str_to_list(target)

        # Get the port list
        ports = self._daemon.scan_collection.get_ports(scan_id)
        logger.info("The port list %s", ports)
        tcp, _ = ports_as_list(ports)
        # Get exclude hosts list. It must not be scanned
        exclude_hosts = self._daemon.scan_collection.get_exclude_hosts(scan_id)
        logger.info("The exclude hosts list %s", exclude_hosts)

        self._daemon.set_scan_total_hosts(
            scan_id,
            count_total=len(host_list),
        )
        self._daemon.scan_collection.set_amount_dead_hosts(
            scan_id, total_dead=0
        )

        # Get list of VTS. Ignore script params
        vts = list(self._daemon.scan_collection.get_vts(scan_id))
        if "vt_groups" in vts:
            vts.remove("vt_groups")
        vthelper = VtHelper(nvti, None)

        # Run the scan.
        # Scan simulation for each single host.
        # Run the scan against the host, and generates results.
        while host_list:
            # Get a host from the list
            current_host = host_list.pop()

            # Check if the scan was stopped.
            status = self._daemon.get_scan_status(scan_id)
            if status == ScanStatus.STOPPED or status == ScanStatus.FINISHED:
                logger.debug(
                    'Task %s stopped or finished.',
                    scan_id,
                )
                return

            res_list = ResultList()

            res_list.add_scan_log_to_list(
                host=current_host,
                name="HOST_START",
                value=str(int(time.time())),
            )

            # Generate N results per host. Default 10 results
            res_count = 0
            while res_count < results_per_host:
                res_count += 1
                oid = choice(vts)
                port = choice(tcp)
                vt = vthelper.get_single_vt(oid)
                if vt:
                    if vt.get('qod_type'):
                        qod_t = vt.get('qod_type')
                        rqod = nvti.QOD_TYPES[qod_t]
                    elif vt.get('qod'):
                        rqod = vt.get('qod')

                    rname = vt.get('name')
                else:
                    logger.debug("oid %s not found", oid)

                res_type = int(uniform(1, 5))
                # Error
                if res_type == 1:
                    res_list.add_scan_error_to_list(
                        host=current_host,
                        hostname=current_host + ".hostname.net",
                        name=rname,
                        value="error running the script " + oid,
                        port=port,
                        test_id=oid,
                        uri="No location",
                    )
                # Log
                elif res_type == 2:
                    res_list.add_scan_log_to_list(
                        host=current_host,
                        hostname=current_host + ".hostname.net",
                        name=rname,
                        value="Log generate from a dry run scan for the script "
                        + oid,
                        port=port,
                        qod=rqod,
                        test_id=oid,
                        uri="No location",
                    )
                # Alarm
                else:
                    r_severity = vthelper.get_severity_score(vt)
                    res_list.add_scan_alarm_to_list(
                        host=current_host,
                        hostname=current_host + ".hostname.net",
                        name=rname,
                        value="Log generate from a dry run scan for the script "
                        + oid,
                        port=port,
                        test_id=oid,
                        severity=r_severity,
                        qod=rqod,
                        uri="No location",
                    )

            res_list.add_scan_log_to_list(
                host=current_host,
                name="HOST_END",
                value=str(int(time.time())),
            )

            # Add the result to the scan collection
            if len(res_list):
                logger.debug(
                    '%s: Inserting %d results into scan '
                    'scan collection table',
                    scan_id,
                    len(res_list),
                )
                self._daemon.scan_collection.add_result_list(scan_id, res_list)

            # Set the host scan progress as finished
            host_progress = dict()
            host_progress[current_host] = ScanProgress.FINISHED
            self._daemon.set_scan_progress_batch(
                scan_id, host_progress=host_progress
            )

            # Update the host status, Finished host. So ospd can
            # calculate the scan progress.
            # This is quite importan, since the final scan status depends on
            # the progress calculation.
            finished_host = list()
            finished_host.append(current_host)
            self._daemon.sort_host_finished(scan_id, finished_host)

            time.sleep(1)
        logger.debug('%s: End task', scan_id)
