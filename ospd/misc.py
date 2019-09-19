# Copyright (C) 2014-2018 Greenbone Networks GmbH
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
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

# pylint: disable=too-many-lines

""" Miscellaneous classes and functions related to OSPD.
"""

import logging
import os
import sys
import time
import uuid
import multiprocessing

from enum import Enum
from collections import OrderedDict
from pathlib import Path

from ospd.network import target_str_to_list

LOGGER = logging.getLogger(__name__)


class ScanStatus(Enum):
    """Scan status. """

    INIT = 0
    RUNNING = 1
    STOPPED = 2
    FINISHED = 3


class ScanCollection(object):

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

    def __init__(self):
        """ Initialize the Scan Collection. """

        self.data_manager = None
        self.scans_table = dict()

    def add_result(
        self,
        scan_id,
        result_type,
        host='',
        hostname='',
        name='',
        value='',
        port='',
        test_id='',
        severity='',
        qod='',
    ):
        """ Add a result to a scan in the table. """

        assert scan_id
        assert len(name) or len(value)
        result = OrderedDict()
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

    def set_progress(self, scan_id, progress):
        """ Sets scan_id scan's progress. """

        if progress > 0 and progress <= 100:
            self.scans_table[scan_id]['progress'] = progress
        if progress == 100:
            self.scans_table[scan_id]['end_time'] = int(time.time())

    def set_host_progress(self, scan_id, target, host, progress):
        """ Sets scan_id scan's progress. """
        if progress > 0 and progress <= 100:
            targets = self.scans_table[scan_id]['target_progress']
            targets[target][host] = progress
            # Set scan_info's target_progress to propagate progresses
            # to parent process.
            self.scans_table[scan_id]['target_progress'] = targets

    def set_host_finished(self, scan_id, target, host):
        """ Add the host in a list of finished hosts """
        finished_hosts = self.scans_table[scan_id]['finished_hosts']
        finished_hosts[target].append(host)
        self.scans_table[scan_id]['finished_hosts'] = finished_hosts

    def get_hosts_unfinished(self, scan_id):
        """ Get a list of unfinished hosts."""

        unfinished_hosts = list()
        for target in self.scans_table[scan_id]['finished_hosts']:
            unfinished_hosts.extend(target_str_to_list(target))
        for target in self.scans_table[scan_id]['finished_hosts']:
            for host in self.scans_table[scan_id]['finished_hosts'][target]:
                unfinished_hosts.remove(host)

        return unfinished_hosts

    def get_hosts_finished(self, scan_id):
        """ Get a list of finished hosts."""

        finished_hosts = list()
        for target in self.scans_table[scan_id]['finished_hosts']:
            finished_hosts.extend(
                self.scans_table[scan_id]['finished_hosts'].get(target)
            )

        return finished_hosts

    def results_iterator(self, scan_id, pop_res):
        """ Returns an iterator over scan_id scan's results. If pop_res is True,
        it removed the fetched results from the list.
        """
        if pop_res:
            result_aux = self.scans_table[scan_id]['results']
            self.scans_table[scan_id]['results'] = list()
            return iter(result_aux)

        return iter(self.scans_table[scan_id]['results'])

    def ids_iterator(self):
        """ Returns an iterator over the collection's scan IDS. """

        return iter(self.scans_table.keys())

    def remove_single_result(self, scan_id, result):
        """Removes a single result from the result list in scan_table.

        Parameters:
            scan_id (uuid): Scan ID to identify the scan process to be resumed.
            result (dict): The result to be removed from the results list.
        """
        results = self.scans_table[scan_id]['results']
        results.remove(result)
        self.scans_table[scan_id]['results'] = results

    def del_results_for_stopped_hosts(self, scan_id):
        """ Remove results from the result table for those host
        """
        unfinished_hosts = self.get_hosts_unfinished(scan_id)
        for result in self.results_iterator(scan_id, False):
            if result['host'] in unfinished_hosts:
                self.remove_single_result(scan_id, result)

    def resume_scan(self, scan_id, options):
        """ Reset the scan status in the scan_table to INIT.
        Also, overwrite the options, because a resume task cmd
        can add some new option. E.g. exclude hosts list.
        Parameters:
            scan_id (uuid): Scan ID to identify the scan process to be resumed.
            options (dict): Options for the scan to be resumed. This options
                            are not added to the already existent ones.
                            The old ones are removed

        Return:
            Scan ID which identifies the current scan.
        """
        self.scans_table[scan_id]['status'] = ScanStatus.INIT
        if options:
            self.scans_table[scan_id]['options'] = options

        self.del_results_for_stopped_hosts(scan_id)

        return scan_id

    def create_scan(self, scan_id='', targets='', options=None, vts=''):
        """ Creates a new scan with provided scan information. """

        if self.data_manager is None:
            self.data_manager = multiprocessing.Manager()

        # Check if it is possible to resume task. To avoid to resume, the
        # scan must be deleted from the scans_table.
        if (
            scan_id
            and self.id_exists(scan_id)
            and (self.get_status(scan_id) == ScanStatus.STOPPED)
        ):
            return self.resume_scan(scan_id, options)

        if not options:
            options = dict()
        scan_info = self.data_manager.dict()
        scan_info['results'] = list()
        scan_info['finished_hosts'] = dict(
            [[target, []] for target, _, _, _ in targets]
        )
        scan_info['progress'] = 0
        scan_info['target_progress'] = dict(
            [[target, {}] for target, _, _, _ in targets]
        )
        scan_info['targets'] = targets
        scan_info['vts'] = vts
        scan_info['options'] = options
        scan_info['start_time'] = int(time.time())
        scan_info['end_time'] = "0"
        scan_info['status'] = ScanStatus.INIT
        if scan_id is None or scan_id == '':
            scan_id = str(uuid.uuid4())
        scan_info['scan_id'] = scan_id
        self.scans_table[scan_id] = scan_info
        return scan_id

    def set_status(self, scan_id, status):
        """ Sets scan_id scan's status. """
        self.scans_table[scan_id]['status'] = status

    def get_status(self, scan_id):
        """ Get scan_id scans's status."""

        return self.scans_table[scan_id]['status']

    def get_options(self, scan_id):
        """ Get scan_id scan's options list. """

        return self.scans_table[scan_id]['options']

    def set_option(self, scan_id, name, value):
        """ Set a scan_id scan's name option to value. """

        self.scans_table[scan_id]['options'][name] = value

    def get_progress(self, scan_id):
        """ Get a scan's current progress value. """

        return self.scans_table[scan_id]['progress']

    def get_target_progress(self, scan_id, target):
        """ Get a target's current progress value.
        The value is calculated with the progress of each single host
        in the target."""

        total_hosts = len(target_str_to_list(target))
        host_progresses = self.scans_table[scan_id]['target_progress'].get(
            target
        )
        try:
            t_prog = sum(host_progresses.values()) / total_hosts
        except ZeroDivisionError:
            LOGGER.error(
                "Zero division error in %s", self.get_target_progress.__name__
            )
            raise
        return t_prog

    def get_start_time(self, scan_id):
        """ Get a scan's start time. """

        return self.scans_table[scan_id]['start_time']

    def get_end_time(self, scan_id):
        """ Get a scan's end time. """

        return self.scans_table[scan_id]['end_time']

    def get_target_list(self, scan_id):
        """ Get a scan's target list. """

        target_list = []
        for target, _, _, _ in self.scans_table[scan_id]['targets']:
            target_list.append(target)
        return target_list

    def get_ports(self, scan_id, target):
        """ Get a scan's ports list. If a target is specified
        it will return the corresponding port for it. If not,
        it returns the port item of the first nested list in
        the target's list.
        """
        if target:
            for item in self.scans_table[scan_id]['targets']:
                if target == item[0]:
                    return item[1]

        return self.scans_table[scan_id]['targets'][0][1]

    def get_exclude_hosts(self, scan_id, target):
        """ Get an exclude host list for a given target.
        """
        if target:
            for item in self.scans_table[scan_id]['targets']:
                if target == item[0]:
                    return item[3]

    def get_credentials(self, scan_id, target):
        """ Get a scan's credential list. It return dictionary with
        the corresponding credential for a given target.
        """
        if target:
            for item in self.scans_table[scan_id]['targets']:
                if target == item[0]:
                    return item[2]

    def get_vts(self, scan_id):
        """ Get a scan's vts list. """

        return self.scans_table[scan_id]['vts']

    def id_exists(self, scan_id):
        """ Check whether a scan exists in the table. """

        return self.scans_table.get(scan_id) is not None

    def delete_scan(self, scan_id):
        """ Delete a scan if fully finished. """

        if self.get_status(scan_id) == ScanStatus.RUNNING:
            return False
        self.scans_table.pop(scan_id)
        if len(self.scans_table) == 0:
            del self.data_manager
            self.data_manager = None
        return True


class ResultType(object):

    """ Various scan results types values. """

    ALARM = 0
    LOG = 1
    ERROR = 2
    HOST_DETAIL = 3

    @classmethod
    def get_str(cls, result_type):
        """ Return string name of a result type. """
        if result_type == cls.ALARM:
            return "Alarm"
        elif result_type == cls.LOG:
            return "Log Message"
        elif result_type == cls.ERROR:
            return "Error Message"
        elif result_type == cls.HOST_DETAIL:
            return "Host Detail"
        else:
            assert False, "Erroneous result type {0}.".format(result_type)

    @classmethod
    def get_type(cls, result_name):
        """ Return string name of a result type. """
        if result_name == "Alarm":
            return cls.ALARM
        elif result_name == "Log Message":
            return cls.LOG
        elif result_name == "Error Message":
            return cls.ERROR
        elif result_name == "Host Detail":
            return cls.HOST_DETAIL
        else:
            assert False, "Erroneous result name {0}.".format(result_name)


def valid_uuid(value):
    """ Check if value is a valid UUID. """

    try:
        uuid.UUID(value, version=4)
        return True
    except (TypeError, ValueError, AttributeError):
        return False


def go_to_background():
    """ Daemonize the running process. """
    try:
        if os.fork():
            sys.exit()
    except OSError as errmsg:
        LOGGER.error('Fork failed: %s', errmsg)
        sys.exit(1)

def create_pid(pidfile):
    """ Check if there is an already running daemon and creates the pid file.
    Otherwise gives an error. """

    pid = str(os.getpid())

    if Path(pidfile).is_file():
        LOGGER.error("There is an already running process.")
        return False

    try:
        with open(pidfile, 'w') as f:
            f.write(pid)
    except (FileNotFoundError, PermissionError) as e:
        msg = "Failed to create pid file %s. %s" % (os.path.dirname(pidfile), e)
        LOGGER.error(msg)
        return False

    return True

def remove_pidfile(pidfile, signum=None, frame=None):
    """ Removes the pidfile before ending the daemon. """
    pidpath = Path(pidfile)
    if pidpath.is_file():
        with pidpath.open() as f:
            if int(f.read()) == os.getpid():
                LOGGER.debug("Finishing daemon process")
                pidpath.unlink()
                sys.exit()
