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
import multiprocessing
import time
import uuid

from collections import OrderedDict
from enum import Enum
from typing import List, Any, Dict, Iterator, Optional, Iterable

from ospd.network import target_str_to_list

LOGGER = logging.getLogger(__name__)


class ScanStatus(Enum):
    """Scan status. """

    PENDING = 0
    INIT = 1
    RUNNING = 2
    STOPPED = 3
    FINISHED = 4


class ScanCollection:

    """ Scans collection, managing scans and results read and write, exposing
    only needed information.

    Each scan has meta-information such as scan ID, current progress (from 0 to
    100), start time, end time, scan target and options and a list of results.

    There are 4 types of results: Alarms, Logs, Errors and Host Details.

    Todo:
    - Better checking for Scan ID existence and handling otherwise.
    - More data validation.
    - Mutex access per table/scan_info.

    """

    def __init__(self) -> None:
        """ Initialize the Scan Collection. """

        self.data_manager = (
            None
        )  # type: Optional[multiprocessing.managers.SyncManager]
        self.scans_table = dict()  # type: Dict

    def init_data_manager(self):
        self.data_manager = multiprocessing.Manager()

    def add_result(
        self,
        scan_id: str,
        result_type: int,
        host: str = '',
        hostname: str = '',
        name: str = '',
        value: str = '',
        port: str = '',
        test_id: str = '',
        severity: str = '',
        qod: str = '',
    ) -> None:
        """ Add a result to a scan in the table. """

        assert scan_id
        assert len(name) or len(value)

        result = OrderedDict()  # type: Dict
        result['type'] = result_type
        result['name'] = name
        result['severity'] = severity
        result['test_id'] = test_id
        result['value'] = value
        result['host'] = host
        result['hostname'] = hostname
        result['port'] = port
        result['qod'] = qod
        results = self.scans_table[scan_id]['results']
        results.append(result)

        # Set scan_info's results to propagate results to parent process.
        self.scans_table[scan_id]['results'] = results

    def add_result_list(
        self, scan_id: str, result_list: Iterable[Dict[str, str]]
    ) -> None:
        """
        Add a batch of results to the result's table for the corresponding
        scan_id
        """
        results = self.scans_table[scan_id]['results']
        results.extend(result_list)

        # Set scan_info's results to propagate results to parent process.
        self.scans_table[scan_id]['results'] = results

    def remove_hosts_from_target_progress(
        self, scan_id: str, hosts: List
    ) -> None:
        """Remove a list of hosts from the main scan progress table to avoid
        the hosts to be included in the calculation of the scan progress"""
        if not hosts:
            return

        target = self.scans_table[scan_id].get('target_progress')
        for host in hosts:
            if host in target:
                del target[host]

        # Set scan_info's target_progress to propagate progresses
        # to parent process.
        self.scans_table[scan_id]['target_progress'] = target

    def set_progress(self, scan_id: str, progress: int) -> None:
        """ Sets scan_id scan's progress. """

        if progress > 0 and progress <= 100:
            self.scans_table[scan_id]['progress'] = progress

        if progress == 100:
            self.scans_table[scan_id]['end_time'] = int(time.time())

    def set_host_progress(
        self, scan_id: str, host_progress_batch: Dict[str, int]
    ) -> None:
        """ Sets scan_id scan's progress. """

        host_progresses = self.scans_table[scan_id].get('target_progress')
        host_progresses.update(host_progress_batch)

        # Set scan_info's target_progress to propagate progresses
        # to parent process.
        self.scans_table[scan_id]['target_progress'] = host_progresses

    def set_host_finished(self, scan_id: str, hosts: List[str]) -> None:
        """ Increase the amount of finished hosts which were alive."""

        total_finished = len(hosts)
        count_alive = (
            self.scans_table[scan_id].get('count_alive') + total_finished
        )
        self.scans_table[scan_id]['count_alive'] = count_alive

    def set_host_dead(self, scan_id: str, hosts: List[str]) -> None:
        """ Increase the amount of dead hosts. """

        total_dead = len(hosts)
        count_dead = self.scans_table[scan_id].get('count_dead') + total_dead
        self.scans_table[scan_id]['count_dead'] = count_dead

    def set_amount_dead_hosts(self, scan_id: str, total_dead: int) -> None:
        """ Increase the amount of dead hosts. """

        count_dead = self.scans_table[scan_id].get('count_dead') + total_dead
        self.scans_table[scan_id]['count_dead'] = count_dead

    def results_iterator(
        self, scan_id: str, pop_res: bool = False, max_res: int = None
    ) -> Iterator[Any]:
        """ Returns an iterator over scan_id scan's results. If pop_res is True,
        it removed the fetched results from the list.

        If max_res is None, return all the results.
        Otherwise, if max_res = N > 0 return N as maximum number of results.

        max_res works only together with pop_results.
        """
        if pop_res and max_res:
            result_aux = self.scans_table[scan_id]['results']
            self.scans_table[scan_id]['results'] = result_aux[max_res:]
            return iter(result_aux[:max_res])
        elif pop_res:
            result_aux = self.scans_table[scan_id]['results']
            self.scans_table[scan_id]['results'] = list()
            return iter(result_aux)

        return iter(self.scans_table[scan_id]['results'])

    def ids_iterator(self) -> Iterator[str]:
        """ Returns an iterator over the collection's scan IDS. """

        return iter(self.scans_table.keys())

    def create_scan(
        self,
        scan_id: str = '',
        target: Dict = None,
        options: Optional[Dict] = None,
        vts: Dict = None,
    ) -> str:
        """ Creates a new scan with provided scan information. """

        if not target:
            target = {}

        if not options:
            options = dict()

        scan_info = self.data_manager.dict()  # type: Dict
        scan_info['results'] = list()
        scan_info['progress'] = 0
        scan_info['target_progress'] = dict()
        scan_info['count_alive'] = 0
        scan_info['count_dead'] = 0
        scan_info['target'] = target
        scan_info['vts'] = vts
        scan_info['options'] = options
        scan_info['start_time'] = int(time.time())
        scan_info['end_time'] = 0
        scan_info['status'] = ScanStatus.PENDING

        if scan_id is None or scan_id == '':
            scan_id = str(uuid.uuid4())

        scan_info['scan_id'] = scan_id

        self.scans_table[scan_id] = scan_info
        return scan_id

    def set_status(self, scan_id: str, status: ScanStatus) -> None:
        """ Sets scan_id scan's status. """
        self.scans_table[scan_id]['status'] = status
        if status == ScanStatus.STOPPED:
            self.scans_table[scan_id]['end_time'] = int(time.time())

    def get_status(self, scan_id: str) -> ScanStatus:
        """ Get scan_id scans's status."""

        return self.scans_table[scan_id]['status']

    def get_options(self, scan_id: str) -> Dict:
        """ Get scan_id scan's options list. """

        return self.scans_table[scan_id]['options']

    def set_option(self, scan_id, name: str, value: Any) -> None:
        """ Set a scan_id scan's name option to value. """

        self.scans_table[scan_id]['options'][name] = value

    def get_progress(self, scan_id: str) -> int:
        """ Get a scan's current progress value. """

        return self.scans_table[scan_id]['progress']

    def get_count_dead(self, scan_id: str) -> int:
        """ Get a scan's current dead host count. """

        return self.scans_table[scan_id]['count_dead']

    def get_count_alive(self, scan_id: str) -> int:
        """ Get a scan's current dead host count. """

        return self.scans_table[scan_id]['count_alive']

    def get_current_target_progress(self, scan_id: str) -> Dict[str, int]:
        """ Get a scan's current hosts progress """
        return self.scans_table[scan_id]['target_progress']

    def simplify_exclude_host_count(self, scan_id: str) -> int:
        """ Remove from exclude_hosts the received hosts in the finished_hosts
        list sent by the client.
        The finished hosts are sent also as exclude hosts for backward
        compatibility purposses.

        Return:
            Count of excluded host.
        """

        exc_hosts_list = target_str_to_list(self.get_exclude_hosts(scan_id))

        finished_hosts_list = target_str_to_list(
            self.get_finished_hosts(scan_id)
        )

        if finished_hosts_list and exc_hosts_list:
            for finished in finished_hosts_list:
                if finished in exc_hosts_list:
                    exc_hosts_list.remove(finished)

        return len(exc_hosts_list) if exc_hosts_list else 0

    def calculate_target_progress(self, scan_id: str) -> int:
        """ Get a target's current progress value.
        The value is calculated with the progress of each single host
        in the target."""

        total_hosts = self.get_host_count(scan_id)
        exc_hosts = self.simplify_exclude_host_count(scan_id)
        count_alive = self.get_count_alive(scan_id)
        count_dead = self.get_count_dead(scan_id)
        host_progresses = self.get_current_target_progress(scan_id)

        try:
            t_prog = int(
                (sum(host_progresses.values()) + 100 * count_alive)
                / (total_hosts - exc_hosts - count_dead)
            )
        except ZeroDivisionError:
            LOGGER.error(
                "Zero division error in %s",
                self.calculate_target_progress.__name__,
            )
            raise

        return t_prog

    def get_start_time(self, scan_id: str) -> str:
        """ Get a scan's start time. """

        return self.scans_table[scan_id]['start_time']

    def get_end_time(self, scan_id: str) -> str:
        """ Get a scan's end time. """

        return self.scans_table[scan_id]['end_time']

    def get_host_list(self, scan_id: str) -> Dict:
        """ Get a scan's host list. """

        return self.scans_table[scan_id]['target'].get('hosts')

    def get_host_count(self, scan_id: str) -> int:
        """ Get total host count in the target. """
        host = self.get_host_list(scan_id)
        total_hosts = len(target_str_to_list(host))

        return total_hosts

    def get_ports(self, scan_id: str):
        """ Get a scan's ports list.
        """
        target = self.scans_table[scan_id].get('target')
        ports = target.pop('ports')
        self.scans_table[scan_id]['target'] = target
        return ports

    def get_exclude_hosts(self, scan_id: str):
        """ Get an exclude host list for a given target.
        """
        return self.scans_table[scan_id]['target'].get('exclude_hosts')

    def get_finished_hosts(self, scan_id: str):
        """ Get the finished host list sent by the client for a given target.
        """
        return self.scans_table[scan_id]['target'].get('finished_hosts')

    def get_credentials(self, scan_id: str):
        """ Get a scan's credential list. It return dictionary with
        the corresponding credential for a given target.
        """
        return self.scans_table[scan_id]['target'].get('credentials')

    def get_target_options(self, scan_id: str):
        """ Get a scan's target option dictionary.
        It return dictionary with the corresponding options for
        a given target.
        """
        return self.scans_table[scan_id]['target'].get('options')

    def get_vts(self, scan_id: str) -> Dict:
        """ Get a scan's vts. """
        scan_info = self.scans_table[scan_id]
        vts = scan_info.pop('vts')
        self.scans_table[scan_id] = scan_info

        return vts

    def id_exists(self, scan_id: str) -> bool:
        """ Check whether a scan exists in the table. """

        return self.scans_table.get(scan_id) is not None

    def delete_scan(self, scan_id: str) -> bool:
        """ Delete a scan if fully finished. """

        if self.get_status(scan_id) == ScanStatus.RUNNING:
            return False

        scans_table = self.scans_table
        del scans_table[scan_id]
        self.scans_table = scans_table

        return True
