#!/bin/dash
# Copyright 2009-2010 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# dev-mode functionality for crosh

# shellcheck disable=SC2034
USAGE_systrace='[<start | stop | status>]'
# shellcheck disable=SC2034
HELP_systrace='
  Start/stop system tracing.  Turning tracing off will generate a trace
  log file in the Downloads directory with all the events collected
  since the last time tracing was enabled.  One can control the events
  collected by specifying categories after "start"; e.g. "start gfx"
  will collect only graphics-related system events.  "systrace status"
  (or just "systrace") will display the current state of tracing, including
  the set of events being traced.
'
cmd_systrace() (
  case x"$1" in
  xstart)
    local categories;
    shift; categories="$*"
    if [ -z "${categories}" ]; then
       categories="all"
    fi
    debugd SystraceStart "string:${categories}"
    ;;
  xstop)
    local downloads_dir="/home/${USER}/user/MyFiles/Downloads"
    local data_file
    if ! data_file="$(mktemp "${downloads_dir}/systrace.XXXXXX")"; then
      echo "Cannot create data file ${data_file}"
      return 1
    fi
    debugd SystraceStop "fd:1" > "${data_file}"
    echo "Trace data saved to ${data_file}"
    # add symlink to the latest capture file
    ln -sf "$(basename "${data_file}")" "${downloads_dir}/systrace.latest"
    ;;
  xstatus|x)
    debugd SystraceStatus
    ;;
  esac
)
