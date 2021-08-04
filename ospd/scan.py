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

import logging
import multiprocessing
import time
import uuid

from pprint import pformat
from collections import OrderedDict
from enum import Enum, IntEnum
from typing import List, Any, Dict, Iterator, Optional, Iterable, Union

from ospd.network import target_str_to_list
from ospd.datapickler import DataPickler
from ospd.errors import OspdCommandError

LOGGER = logging.getLogger(__name__)


class ScanStatus(Enum):
    """Scan status. """

    QUEUED = 0
    INIT = 1
    RUNNING = 2
    STOPPED = 3
    FINISHED = 4
    INTERRUPTED = 5


class ScanProgress(IntEnum):
    """Scan or host progress. """

    FINISHED = 100
    INIT = 0
    DEAD_HOST = -1
    INTERRUPTED = -2


class ScanCollection:

    """Scans collection, managing scans and results read and write, exposing
    only needed information.

    Each scan has meta-information such as scan ID, current progress (from 0 to
    100), start time, end time, scan target and options and a list of results.

    There are 4 types of results: Alarms, Logs, Errors and Host Details.

    Todo:
    - Better checking for Scan ID existence and handling otherwise.
    - More data validation.
    - Mutex access per table/scan_info.

    """

    def __init__(self, file_storage_dir: str) -> None:
        """ Initialize the Scan Collection. """

        self.data_manager = (
            None
        )  # type: Optional[multiprocessing.managers.SyncManager]
        self.scans_table = dict()  # type: Dict
        self.file_storage_dir = file_storage_dir

    def init(self):
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
        uri: str = '',
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
        result['uri'] = uri
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

        LOGGER.debug(
            '%s: Remove the following hosts from the target list, '
            'as they are already finished or are dead: %s',
            scan_id,
            pformat(hosts),
        )

        target = self.scans_table[scan_id].get('target_progress')
        for host in hosts:
            if host in target:
                del target[host]

        # Set scan_info's target_progress to propagate progresses
        # to parent process.
        self.scans_table[scan_id]['target_progress'] = target

    def set_progress(self, scan_id: str, progress: int) -> None:
        """ Sets scan_id scan's progress. """

        if progress > ScanProgress.INIT and progress <= ScanProgress.FINISHED:
            self.scans_table[scan_id]['progress'] = progress

        if progress == ScanProgress.FINISHED:
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

        LOGGER.debug(
            '%s: Setting the following hosts as finished: %s',
            scan_id,
            pformat(hosts),
        )
        total_finished = len(hosts)
        count_alive = (
            self.scans_table[scan_id].get('count_alive') + total_finished
        )
        self.scans_table[scan_id]['count_alive'] = count_alive

    def set_host_dead(self, scan_id: str, hosts: List[str]) -> None:
        """ Increase the amount of dead hosts. """

        LOGGER.debug(
            '%s: Setting the following hosts as dead: %s',
            scan_id,
            pformat(hosts),
        )
        total_dead = len(hosts)
        count_dead = self.scans_table[scan_id].get('count_dead') + total_dead
        self.scans_table[scan_id]['count_dead'] = count_dead

    def set_amount_dead_hosts(self, scan_id: str, total_dead: int) -> None:
        """ Increase the amount of dead hosts. """

        count_dead = self.scans_table[scan_id].get('count_dead') + total_dead
        self.scans_table[scan_id]['count_dead'] = count_dead

    def clean_temp_result_list(self, scan_id):
        """ Clean the results stored in the temporary list. """
        self.scans_table[scan_id]['temp_results'] = list()

    def restore_temp_result_list(self, scan_id):
        """Add the results stored in the temporary list into the results
        list again."""
        result_aux = self.scans_table[scan_id].get('results', list())
        result_aux.extend(self.scans_table[scan_id].get('temp_results', list()))

        # Propagate results
        self.scans_table[scan_id]['results'] = result_aux
        self.clean_temp_result_list(scan_id)

    def results_iterator(
        self, scan_id: str, pop_res: bool = False, max_res: int = None
    ) -> Iterator[Any]:
        """Returns an iterator over scan_id scan's results. If pop_res is True,
        it removed the fetched results from the list.

        If max_res is None, return all the results.
        Otherwise, if max_res = N > 0 return N as maximum number of results.

        max_res works only together with pop_results.
        """
        if pop_res and max_res:
            result_aux = self.scans_table[scan_id].get('results', list())
            self.scans_table[scan_id]['results'] = result_aux[max_res:]
            self.scans_table[scan_id]['temp_results'] = result_aux[:max_res]
            return iter(self.scans_table[scan_id]['temp_results'])
        elif pop_res:
            self.scans_table[scan_id]['temp_results'] = self.scans_table[
                scan_id
            ].get('results', list())
            self.scans_table[scan_id]['results'] = list()
            return iter(self.scans_table[scan_id]['temp_results'])

        return iter(self.scans_table[scan_id]['results'])

    def ids_iterator(self) -> Iterator[str]:
        """ Returns an iterator over the collection's scan IDS. """

        # Do not iterate over the scans_table because it can change
        # during iteration, since it is accessed by multiple processes.
        scan_id_list = list(self.scans_table)
        return iter(scan_id_list)

    def clean_up_pickled_scan_info(self) -> None:
        """ Remove files of pickled scan info """
        for scan_id in self.ids_iterator():
            if self.get_status(scan_id) == ScanStatus.QUEUED:
                self.remove_file_pickled_scan_info(scan_id)

    def remove_file_pickled_scan_info(self, scan_id: str) -> None:
        pickler = DataPickler(self.file_storage_dir)
        pickler.remove_file(scan_id)

    def unpickle_scan_info(self, scan_id: str) -> None:
        """Unpickle a stored scan_inf corresponding to the scan_id
        and store it in the scan_table"""

        scan_info = self.scans_table.get(scan_id)
        scan_info_hash = scan_info.pop('scan_info_hash')

        pickler = DataPickler(self.file_storage_dir)
        unpickled_scan_info = pickler.load_data(scan_id, scan_info_hash)

        if not unpickled_scan_info:
            pickler.remove_file(scan_id)
            raise OspdCommandError(
                'Not possible to unpickle stored scan info for %s' % scan_id,
                'start_scan',
            )

        scan_info['results'] = list()
        scan_info['temp_results'] = list()
        scan_info['progress'] = ScanProgress.INIT.value
        scan_info['target_progress'] = dict()
        scan_info['count_alive'] = 0
        scan_info['count_dead'] = 0
        scan_info['count_total'] = None
        scan_info['excluded_simplified'] = None
        scan_info['target'] = unpickled_scan_info.pop('target')
        scan_info['vts'] = unpickled_scan_info.pop('vts')
        scan_info['options'] = unpickled_scan_info.pop('options')
        scan_info['start_time'] = int(time.time())
        scan_info['end_time'] = 0

        self.scans_table[scan_id] = scan_info

        pickler.remove_file(scan_id)

    def create_scan(
        self,
        scan_id: str = '',
        target: Dict = None,
        options: Optional[Dict] = None,
        vts: Dict = None,
    ) -> str:
        """Creates a new scan with provided scan information.

        @target: Target to scan.
        @options: Miscellaneous scan options supplied via <scanner_params>
                  XML element.

        @return: Scan's ID. None if error occurs.
        """

        if not options:
            options = dict()

        credentials = target.pop('credentials')

        scan_info = self.data_manager.dict()  # type: Dict
        scan_info['status'] = ScanStatus.QUEUED
        scan_info['credentials'] = credentials
        scan_info['start_time'] = int(time.time())
        scan_info['end_time'] = 0

        scan_info_to_pickle = {'target': target, 'options': options, 'vts': vts}

        if scan_id is None or scan_id == '':
            scan_id = str(uuid.uuid4())

        pickler = DataPickler(self.file_storage_dir)
        scan_info_hash = None
        try:
            scan_info_hash = pickler.store_data(scan_id, scan_info_to_pickle)
        except OspdCommandError as e:
            LOGGER.error(e)
            return

        scan_info['scan_id'] = scan_id
        scan_info['scan_info_hash'] = scan_info_hash

        self.scans_table[scan_id] = scan_info
        return scan_id

    def set_status(self, scan_id: str, status: ScanStatus) -> None:
        """ Sets scan_id scan's status. """
        self.scans_table[scan_id]['status'] = status
        if status == ScanStatus.STOPPED or status == ScanStatus.INTERRUPTED:
            self.scans_table[scan_id]['end_time'] = int(time.time())

    def get_status(self, scan_id: str) -> ScanStatus:
        """ Get scan_id scans's status."""

        return self.scans_table[scan_id].get('status')

    def get_options(self, scan_id: str) -> Dict:
        """ Get scan_id scan's options list. """

        return self.scans_table[scan_id].get('options')

    def set_option(self, scan_id, name: str, value: Any) -> None:
        """ Set a scan_id scan's name option to value. """

        self.scans_table[scan_id]['options'][name] = value

    def get_progress(self, scan_id: str) -> int:
        """ Get a scan's current progress value. """

        return self.scans_table[scan_id].get('progress', ScanProgress.INIT)

    def get_count_dead(self, scan_id: str) -> int:
        """ Get a scan's current dead host count. """

        return self.scans_table[scan_id]['count_dead']

    def get_count_alive(self, scan_id: str) -> int:
        """ Get a scan's current alive host count. """

        return self.scans_table[scan_id]['count_alive']

    def update_count_total(self, scan_id: str, count_total: int) -> int:
        """ Sets a scan's total hosts."""

        self.scans_table[scan_id]['count_total'] = count_total

    def get_count_total(self, scan_id: str) -> int:
        """ Get a scan's total host count. """

        count_total = self.scans_table[scan_id]['count_total']

        # The value set by the server has priority over the value
        # calculated from the original target list by ospd.
        # As ospd is not intelligent enough to check the amount of valid
        # hosts, check for duplicated or invalid hosts, consider a negative
        # value set for the server, in case it detects an invalid target string
        # or a different amount than the original amount in the target list.
        if count_total == -1:
            count_total = 0
        # If the server does not set the total host count
        # ospd set the amount of host from the original host list.
        elif count_total is None:
            count_total = self.get_host_count(scan_id)
            self.update_count_total(scan_id, count_total)

        return count_total

    def get_current_target_progress(self, scan_id: str) -> Dict[str, int]:
        """ Get a scan's current hosts progress """
        return self.scans_table[scan_id]['target_progress']

    def simplify_exclude_host_count(self, scan_id: str) -> int:
        """Remove from exclude_hosts the received hosts in the finished_hosts
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

        # Remove finished hosts from excluded host list
        if finished_hosts_list and exc_hosts_list:
            for finished in finished_hosts_list:
                if finished in exc_hosts_list:
                    exc_hosts_list.remove(finished)

        # Remove excluded hosts which don't belong to the target list
        host_list = target_str_to_list(self.get_host_list(scan_id))
        excluded_simplified = 0
        invalid_exc_hosts = 0
        if exc_hosts_list:
            for exc_host in exc_hosts_list:
                if exc_host in host_list:
                    excluded_simplified += 1
                else:
                    invalid_exc_hosts += 1

        if invalid_exc_hosts > 0:
            LOGGER.warning(
                "Please check the excluded host list. It contains hosts which "
                "do not belong to the target. This warning can be ignored if "
                "this was done on purpose (e.g. to exclude specific hostname)."
            )

        # Set scan_info's excluded simplified to propagate excluded count
        # to parent process.
        self.scans_table[scan_id]['excluded_simplified'] = excluded_simplified

        return excluded_simplified

    def get_simplified_exclude_host_count(self, scan_id: str) -> int:
        """ Get a scan's excluded host count. """
        excluded_simplified = self.scans_table[scan_id]['excluded_simplified']
        # Check for None because it is the init value, as excluded can be 0
        # as well
        if excluded_simplified is not None:
            return excluded_simplified

        return self.simplify_exclude_host_count(scan_id)

    def calculate_target_progress(self, scan_id: str) -> int:
        """Get a target's current progress value.
        The value is calculated with the progress of each single host
        in the target."""

        total_hosts = self.get_count_total(scan_id)
        exc_hosts = self.get_simplified_exclude_host_count(scan_id)
        count_alive = self.get_count_alive(scan_id)
        count_dead = self.get_count_dead(scan_id)
        host_progresses = self.get_current_target_progress(scan_id)

        try:
            t_prog = int(
                (sum(host_progresses.values()) + 100 * count_alive)
                / (total_hosts - exc_hosts - count_dead)
            )
        except ZeroDivisionError:
            # Consider the case in which all hosts are dead or excluded
            LOGGER.debug('%s: All hosts dead or excluded.', scan_id)
            t_prog = ScanProgress.FINISHED.value

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
        total_hosts = 0

        if host:
            total_hosts = len(target_str_to_list(host))

        return total_hosts

    def get_ports(self, scan_id: str) -> str:
        """Get a scan's ports list."""
        target = self.scans_table[scan_id].get('target')
        ports = target.pop('ports')
        self.scans_table[scan_id]['target'] = target
        return ports

    def get_exclude_hosts(self, scan_id: str) -> str:
        """Get an exclude host list for a given target."""
        return self.scans_table[scan_id]['target'].get('exclude_hosts')

    def get_finished_hosts(self, scan_id: str) -> str:
        """Get the finished host list sent by the client for a given target."""
        return self.scans_table[scan_id]['target'].get('finished_hosts')

    def get_credentials(self, scan_id: str) -> Dict[str, Dict[str, str]]:
        """Get a scan's credential list. It return dictionary with
        the corresponding credential for a given target.
        """
        return self.scans_table[scan_id].get('credentials')

    def get_target_options(self, scan_id: str) -> Dict[str, str]:
        """Get a scan's target option dictionary.
        It return dictionary with the corresponding options for
        a given target.
        """
        return self.scans_table[scan_id]['target'].get('options')

    def get_vts(self, scan_id: str) -> Dict[str, Union[Dict[str, str], List]]:
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
