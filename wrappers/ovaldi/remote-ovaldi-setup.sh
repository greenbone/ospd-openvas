#!/bin/sh
#
# OpenVAS
# $Id: $
# Description: Setup helper script for remote-ovaldi.sh. Checks if
# ovaldi is installed and creates directories for input and output.
#
# Authors:
# Timo Pollmeier <timo.pollmeier@greenbone.net>
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# or, at your option, any later version as published by the Free
# Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

if [ 4 -gt $# ]
then
  echo "Expecting 4 parameters, $# were found."
  exit 1
fi

# Base directory
BASE_DIR="$1"
# Directory for input.
INPUT_SUBDIR="$2"
# Directory for results.
RESULTS_SUBDIR="$3"
# ovaldi command
CMD_OVALDI="$4"


CMD_OVALDI_TEST=`which "$CMD_OVALDI"`
RET=$?
case "$RET" in
  0)
  ;;
  1)
    echo "which - ovaldi (as '$CMD_OVALDI') could not be found in '$PATH' or is not executable on remote host (code 1)."
    REMOTE_TMP=""
    exit 2
  ;;
  *)
    echo "which - Command failed (return code $RET)."
    REMOTE_TMP=""
    exit 2
  ;;
esac

mkdir "$BASE_DIR/$INPUT_SUBDIR"
RET=$?
case "$RET" in
  0)
  ;;
  *)
    echo "mkdir - Could not create '$BASE_DIR/$INPUT_SUBDIR' on remote host (return code $RET)."
    exit 3
  ;;
esac

mkdir "$BASE_DIR/$RESULTS_SUBDIR"
RET=$?
case "$RET" in
  0)
  ;;
  *)
    echo "mkdir - Could not create '$BASE_DIR/$INPUT_SUBDIR' on remote host (return code $RET)."
    exit 3
  ;;
esac

echo "Installation of ovaldi OK, created subdirectories."

exit 0
