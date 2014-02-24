#!/bin/sh
#
# OpenVAS
# $Id: $
# Description: Script for remote execution of the OVAL interpreter (ovaldi).
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

# Scripts to copy and execute on the remote host.
# Base directory for local script files to be copied to the remote host.
LOCAL_COPY_SCRIPT_BASE=`dirname "$0"` # TODO: add actual installation dir
# Script to set up directories and test ovaldi installation on remote host.
SETUP_SCRIPT="remote-ovaldi-setup.sh"

# Other local directories
# Base directory for local temporary files (default: "/tmp")
DEFAULT_LOCAL_TMP_BASE="/tmp/ovaldi-test/" # TODO: unused / set to "/tmp"
# Directory for result files
DEFAULT_LOCAL_RESULTS_DIR="./ovaldi-results"

# Remote directories
# Base directory for remote temporary files (default: "/tmp")
DEFAULT_REMOTE_TMP_BASE="/tmp"
# Remote subdirectory for input.
REMOTE_INPUT_SUBDIR="input"
# Remote subdirectory for results.
REMOTE_RESULTS_SUBDIR="results"

# ovaldi options that are always used.
BASE_OVALDI_OPTIONS="-m"

# default ovaldi binary (default: "ovaldi")
DEFAULT_OVALDI_CMD="ovaldi"
# default schematron directory (remote) for ovaldi
# default: "" (use installation default)
# TODO: fix for ovaldi installation package
DEFAULT_OVALDI_SCHEMATRON="/usr/share/ovaldi/xml"

# default SSH port
DEFAULT_SSH_PORT=22
# extra ssh options (blank by default)
EXTRA_SSH_OPTS=""
# extra scp options (default: "-C")
EXTRA_SCP_OPTS="-C"

# Verbose mode (set by command line option --verbose)
VERBOSE=0


do_help () {
  echo "$0: Run ovaldi on a remote host and retrieve results"
  echo "--help               Show this help text."
  echo ""
  echo "-h <hostname>        Log in to host <hostname>. (Required)"
  echo "-p <port>            Use port number <port> to log in to host."
  echo "-u <username>        Log in as user <username>. (Required)"
  echo ""
  echo "-o <filename>        Run defintions in file <filename>. (Required)"
  echo "-v <filename>        Run using external variables from file <filename>."
  echo "-i <filename>        Run using systems characteristics from <filename>."
  echo ""
  echo "--remote-base <dir>  Place temp directory in directory <dir> on remote host."
  echo "--results-dir <dir>  Copy results to this local directory."
  echo "--ovaldi-cmd <cmd>   Run ovaldi using the command <cmd>"
  echo "--schematron <dir>   Run ovaldi with Schematron at <dir>."
  echo "--verbose            Enable verbose mode (outputs more information)"
  echo
  echo "Return codes on errors:"
  echo "1 : local error, 2 : SSH error, 3 : SCP error, 4 : error on remote host"
}

# log functions

log_info () {
  echo "[i] $1"
}

log_info_verbose () {
  if [ "$VERBOSE" -ne 0 ]
  then
    echo "[i] $1"
  fi
}

log_warning () {
  echo "[w] $1"
}

log_error () {
  echo "[ERROR] $1"
}

# Check options and set variables
check_options () {
  if [ -z "$REMOTE_HOST" ]
  then
    log_error "No host specified!"
    exit 1
  fi

  if [ -z "$REMOTE_USER" ]
  then
    log_error "No remote user name specified!"
    exit 1
  fi

  if [ -z "$REMOTE_PORT" ]
  then
    log_info "Using default port $DEFAULT_SSH_PORT."
    REMOTE_PORT=$DEFAULT_SSH_PORT
  fi

  if ! [ $REMOTE_PORT -ge 0 2> /dev/null ] || ! [ $REMOTE_PORT -le 65535 2> /dev/null ]
  then
    log_error "Invalid port number: $REMOTE_PORT"
    exit 1
  fi

  log_info "Using login: $REMOTE_USER@$REMOTE_HOST port:$REMOTE_PORT"

  if [ -z "$OVAL_DEF_PATH" ]
  then
    log_error "No OVAL definitions file specified."
    exit 1
  else
    if ! [ -f "$OVAL_DEF_PATH" ] || ! [ -r "$OVAL_DEF_PATH" ]
    then
      log_error "Cannot read OVAL definitions file '$OVAL_DEF_PATH'."
      exit 1
    else
      log_info "Using OVAL definitions from '$OVAL_DEF_PATH'."
      OVAL_DEF_FNAME="${OVAL_DEF_PATH##*/}"
    fi
  fi

  if [ -z "$OVAL_VAR_PATH" ]
  then
    log_info "No external variables file specified."
  else
    if ! [ -f "$OVAL_VAR_PATH" ] || ! [ -r "$OVAL_VAR_PATH" ]
    then
      log_error "Cannot read external variables file '$OVAL_VAR_PATH'."
      exit 1
    else
      log_info "Using external variables from '$OVAL_VAR_PATH'."
      OVAL_VAR_FNAME="${OVAL_VAR_PATH##*/}"
    fi
  fi

  if [ -z "$OVAL_SYSCHAR_PATH" ]
  then
    log_info "No OVAL system characteristics file specified."
  else
    if ! [ -f "$OVAL_SYSCHAR_PATH" ] || ! [ -r "$OVAL_SYSCHAR_PATH" ]
    then
      log_error "Cannot read system characteristics file '$OVAL_SYSCHAR_PATH'."
      exit 1
    else
      log_info "Using system characteristics from '$OVAL_SYSCHAR_PATH'."
      OVAL_SYSCHAR_FNAME="${OVAL_SYSCHAR_PATH##*/}"
    fi
  fi


  if [ -z "$LOCAL_RESULTS_DIR" ]
  then
    log_info "No local results directory specified, using default '$DEFAULT_LOCAL_RESULTS_DIR'."
    LOCAL_RESULTS_DIR="$DEFAULT_LOCAL_RESULTS_DIR"
  fi

  if ! [ -d "$LOCAL_RESULTS_DIR" ]
  then
    log_warning "Cannot find results directory '$LOCAL_RESULTS_DIR', creating it."
    OUT=`mkdir -p "$LOCAL_RESULTS_DIR" 2>&1`
    RET="$?"
    if [ $RET -ne 0 ]
    then
      log_error "Cannot create directory '$LOCAL_RESULTS_DIR' ($OUT)."
      exit 1
    fi
  fi

  if ! [ -w "$LOCAL_RESULTS_DIR" ]
  then
    log_error "Cannot write to results directory '$LOCAL_RESULTS_DIR'."
    exit 1
  else
    log_info "Using local results directory '$LOCAL_RESULTS_DIR'."
  fi


#  if [ -z "$LOCAL_TMP_BASE" ]
#  then
#    log_info "No local temp base directory specified, using default."
#    LOCAL_TMP_BASE="$DEFAULT_LOCAL_TMP_BASE"
#  fi

#  if ! [ -d "$LOCAL_TMP_BASE" ]
#  then
#    log_error "Cannot find temp base directory '$LOCAL_TMP_BASE'."
#    exit 1
#  elif ! [ -w "$LOCAL_TMP_BASE" ]
#  then
#    log_error "Cannot write to temp base directory '$LOCAL_TMP_BASE'."
#    exit 1
#  else
#    log_info "Using local results directory '$LOCAL_TMP_BASE'."
#  fi

  if [ -z "$REMOTE_TMP_BASE" ]
  then
    log_info_verbose "No remote temp base directory specified, using default '$DEFAULT_REMOTE_TMP_BASE'."
    REMOTE_TMP_BASE="$DEFAULT_REMOTE_TMP_BASE"
  fi
  log_info "Using remote base directory '$REMOTE_TMP_BASE'."

  if [ -z $OVALDI_CMD ]
  then
    OVALDI_CMD=$DEFAULT_OVALDI_CMD
    log_info_verbose "No ovaldi command specified, using default '$OVALDI_CMD'."
  else
    log_info "Using ovaldi command '$OVALDI_CMD'."
  fi

  if [ -z $OVALDI_SCHEMATRON_SET ]
  then
    OVALDI_SCHEMATRON=$DEFAULT_OVALDI_SCHEMATRON
    if [ -z $OVALDI_SCHEMATRON ]
    then
      log_info_verbose "No ovaldi Schematron specified, using installation default."
    else
      log_info_verbose "No ovaldi Schematron specified, using default '$OVALDI_SCHEMATRON'."
    fi
  else
    if [ -z $OVALDI_SCHEMATRON ]
    then
      log_info "Using installation default ovaldi Schematron."
    else
      log_info "Using ovaldi Schematron '$OVALDI_SCHEMATRON'."
    fi
  fi

}

do_local_self_test () {
  if ! [ -f "$LOCAL_COPY_SCRIPT_BASE/$SETUP_SCRIPT" ]
  then
    log_error "Setup script '$LOCAL_COPY_SCRIPT_BASE/$SETUP_SCRIPT' not found."
    exit 1;
  fi

  if ! [ -r "$LOCAL_COPY_SCRIPT_BASE/$SETUP_SCRIPT" ]
  then
    log_error "Cannot read setup script '$LOCAL_COPY_SCRIPT_BASE/$SETUP_SCRIPT'."
    exit 1;
  fi

  CMD_SSH=`which ssh`
  RET=$?
  if [ -z "$CMD_SSH" ] || [ 0 -ne "$RET" ]
  then
    log_error "ssh not found or not executable."
    exit 1;
  fi

  CMD_SCP=`which scp`
  RET=$?
  if [ -z "$CMD_SSH" ] || [ 0 -ne "$RET" ]
  then
    log_error "ssh not found or not executable."
    exit 1;
  fi
}

ssh_cmd () {
  ssh "$REMOTE_USER@$REMOTE_HOST" -p "$REMOTE_PORT" $EXTRA_SSH_OPTS "$@"
}

scp_cmd () {
  scp -P "$REMOTE_PORT" $EXTRA_SCP_OPTS "$@"
}

try_cleanup () {
  log_info "Trying cleanup on remote host via ssh..."
  if [ -n "$REMOTE_TMP" ]
  then
    ssh_cmd rm -r "$REMOTE_TMP"
    RET="$?"
    case "$RET" in
    0)
    ;;
    255)
    log_error "SSH connection failed during cleanup (return 255)."
    ;;
    *)
    log_error "Could not clean up remote host ($RET)"
    ;;
    esac
  fi
  log_info "Finished clean up on remote host."
}

do_main () {

  log_info "Creating remote temp directory via ssh..."
  REMOTE_TMP=`ssh_cmd mktemp -d "$REMOTE_TMP_BASE/openvas-ovaldi-XXXXXXX"`
  RET="$?"
  case "$RET" in
    0)
    ;;
    255)
      log_error "SSH connection failed (code 255)."
      try_cleanup
      exit 2
    ;;
    *)
      log_error "mktemp - Creation of remote temp directory failed (return code $RET)."
      try_cleanup
      exit 4
    ;;
  esac
  log_info_verbose "Created remote temp dir '$REMOTE_TMP'."

  log_info "Copying setup script to remote host via scp..."
  SCP_DEST="$REMOTE_USER@$REMOTE_HOST:$REMOTE_TMP"
  scp_cmd "$LOCAL_COPY_SCRIPT_BASE/$SETUP_SCRIPT" "$SCP_DEST/$SETUP_SCRIPT"
  RET="$?"
  case "$RET" in
    0)
    ;;
    *)
      log_error "SCP to remote failed (code $RET)."
      try_cleanup
      exit 3
    ;;
  esac
  log_info_verbose "Setup script successfully copied."

  log_info "Making script executable on remote host via ssh..."
  ssh_cmd chmod +x "$REMOTE_TMP/$SETUP_SCRIPT"
  RET="$?"
  case "$RET" in
    0)
    ;;
    126)
      log_error "Could not chmod setup script, permission denied (126)"
      try_cleanup
      exit 4
      ;;
    127)
      log_error "Could not chmod setup script, not found (127)"
      try_cleanup
      exit 4
      ;;
    255)
      log_error "SSH connection failed (code 255)."
      try_cleanup
      exit 2
      ;;
    *)
      log_error "Other error during chmod of setup script (code $RET)."
      try_cleanup
      exit 4
    ;;
  esac
  log_info_verbose "chmod successful"

  log_info "Running setup script on remote host via ssh..."
  # -t is applied to use a interactive shell to gain the individual PATH
  # environment of the remote user. Else it would not be possible to use
  # local installations of ovaldi, only system wide ones.
  MESSAGE=`ssh_cmd -t "/bin/bash -i $REMOTE_TMP/$SETUP_SCRIPT" "$REMOTE_TMP" "$REMOTE_INPUT_SUBDIR" "$REMOTE_RESULTS_SUBDIR" "$OVALDI_CMD"`
  RET="$?"
  case "$RET" in
    0)
    ;;
    1)
      log_error "Script incompatible: $MESSAGE"
      try_cleanup
      exit 4
      ;;
    2)
      log_error "Failed ovaldi installation test: $MESSAGE"
      try_cleanup
      exit 4
      ;;
    3)
      log_error "Failed directory creation: $MESSAGE"
      try_cleanup
      exit 4
      ;;
    255)
      log_error "SSH connection failed (code 255)."
      try_cleanup
      exit 2
      ;;
    *)
      log_error "Other error while executing setup script (code $RET)."
      try_cleanup
      exit 4
    ;;
  esac
  log_info_verbose "Setup script successful: $MESSAGE"

  # generate ovaldi options
  REMOTE_INPUT_DIR="$REMOTE_TMP/$REMOTE_INPUT_SUBDIR"
  REMOTE_RESULTS_DIR="$REMOTE_TMP/$REMOTE_RESULTS_SUBDIR"

  OVALDI_OPTS="$BASE_OVALDI_OPTIONS"
  if [ -n "$OVALDI_SCHEMATRON" ]
  then
    OVALDI_OPTS="$OVALDI_OPTS -a $OVALDI_SCHEMATRON"
  fi

  OVALDI_OPTS="$OVALDI_OPTS -o $REMOTE_INPUT_DIR/$OVAL_DEF_FNAME"

  if [ -n "$OVAL_VAR_PATH" ]
  then
    OVALDI_OPTS="$OVALDI_OPTS -v $REMOTE_INPUT_DIR/$OVAL_VAR_FNAME"
  fi

  if [ -n "$OVAL_SYSCHAR_PATH" ]
  then
    OVALDI_OPTS="$OVALDI_OPTS -i $REMOTE_INPUT_DIR/$OVAL_SYSCHAR_FNAME"
  else
    OVALDI_OPTS="$OVALDI_OPTS -d $REMOTE_RESULTS_DIR/oval_syschar.xml"
  fi

  log_info "Copying input files to remote host via scp..."
  SCP_DST="$REMOTE_USER@$REMOTE_HOST:$REMOTE_INPUT_DIR/."
  if [ -n "$OVAL_VAR_PATH" ]
  then
    if [ -n "$OVAL_SYSCHAR_PATH" ]
    then
      scp_cmd "$OVAL_DEF_PATH" "$OVAL_VAR_PATH" "$OVAL_SYSCHAR_PATH" "$SCP_DST"
      RET="$?"
    else
      scp_cmd "$OVAL_DEF_PATH" "$OVAL_VAR_PATH" "$SCP_DST"
      RET="$?"
    fi
  else
    if [ -n "$OVAL_SYSCHAR_PATH" ]
    then
      scp_cmd "$OVAL_DEF_PATH" "$OVAL_SYSCHAR_PATH" "$SCP_DST"
      RET="$?"
    else
      scp_cmd "$OVAL_DEF_PATH" "$SCP_DST"
      RET="$?"
    fi
  fi
  case "$RET" in
    0)
    ;;
    *)
      log_error "SCP to remote failed (code $RET)."
      try_cleanup
      exit 3
    ;;
  esac
  log_info_verbose "Successfully copied input files."

  OVALDI_OPTS="$OVALDI_OPTS -r $REMOTE_RESULTS_DIR/results.xml -x $REMOTE_RESULTS_DIR/result.html -y $REMOTE_RESULTS_DIR"
  log_info_verbose "ovaldi options: $OVALDI_OPTS"

  log_info "Running $OVALDI_CMD on remote host via ssh..."
  ssh_cmd "/bin/bash -i -c '$OVALDI_CMD $OVALDI_OPTS'"
  RET="$?"
  case "$RET" in
    0)
    ;;
    255)
      log_error "SSH connection failed (code 255)."
    ;;
    *)
      log_warning "Error while running ovaldi (code $RET)"
    ;;
  esac
  log_info_verbose "Finished ovaldi run."


  log_info "Copying results from remote host via scp..."
  if [ 1 = 1 ] # insert auth method check here
  then
    scp_cmd "$REMOTE_USER@$REMOTE_HOST:$REMOTE_RESULTS_DIR/*" "$LOCAL_RESULTS_DIR"
  fi
  RET="$?"
  case "$RET" in
    0)
    ;;
    *)
      log_error "Copying of results failed ($RET)"
      try_cleanup
      exit 3
    ;;
  esac
  log_info_verbose "Copying of results successful."


  log_info "Cleaning up temp directory on remote host via ssh..."
  ssh_cmd rm -r "$REMOTE_TMP"
  RET="$?"
  case "$RET" in
    0)
    ;;
    255)
      log_error "SSH connection failed (code 255)."
      exit 2;
    ;;
    *)
      log_error "Could not remove temp directory (code $RET)"
      exit 4;
    ;;
  esac
  log_info_verbose "Finished clean up on remote host."

}

if [ -n "$1" ]; then
  while test $# -gt 0; do
    case "$1" in
      --help)
        do_help
        exit 0
        ;;
      -h)
        REMOTE_HOST="$2"
        shift
        ;;
      -p)
        REMOTE_PORT="$2"
        shift
        ;;
      -u)
        REMOTE_USER="$2"
        shift
        ;;
      -o)
        OVAL_DEF_PATH="$2"
        shift
        ;;
      -v)
        OVAL_VAR_PATH="$2"
        shift
        ;;
      -i)
        OVAL_SYSCHAR_PATH="$2"
        shift
        ;;
      --remote-base)
        REMOTE_TMP_BASE="$2"
        shift
        ;;
      --results-dir)
        LOCAL_RESULTS_DIR="$2"
        shift
        ;;
      --ovaldi-cmd)
        OVALDI_CMD="$2"
        shift
        ;;
      --schematron)
        OVALDI_SCHEMATRON="$2"
        OVALDI_SCHEMATRON_SET="1"
        shift
        ;;
      --verbose)
        VERBOSE=1
        ;;
    esac
    shift
  done
  do_local_self_test
  check_options
  do_main
else
  log_error "No options given. Run $0 --help for a list of options."
  exit 1
fi
