# Copyright 2018 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Check whether the name of the event requested to be emitted is within the
# set of events shill is allowed to generate.
case "${EVENT_NAME}" in
  shill-connected|shill-disconnected)
    initctl emit "${EVENT_NAME}"
    ;;
  *)
    logger -t "${UPSTART_JOB}" "Bad event ${EVENT_NAME}"
    ;;
esac
