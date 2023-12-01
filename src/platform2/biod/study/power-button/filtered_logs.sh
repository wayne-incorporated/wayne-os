#!/bin/bash
#
# Copyright 2022 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Generate ChromeOS system logs and filter events for FPS UX Study
#
# Print filtered log on the terminal:
#   bash filtered_logs.sh
#
# Save output on a file:
#   bash filtered_logs.sh > filtered.log
#
# Log custom events:
#   logger FpsUxStudy <custom message>
#
# Notes:
# - Edit the list of patterns below to filter different events
# - Save both the **full** and filtered system logs

PATTERNS_FILENAME=log_patterns.txt

{
# Custom logs from UX study
cat <<\EOF
FpsUxStudy
EOF

# Events from FPMCU related to FPS
cat <<\EOF
Capturing
Enrolling
Enroll =>
Matching
Match =>
EOF

# Events from biod related to FPS
cat <<\EOF
StartEnrollSession
EndEnrollSession
DoEnrollImageEvent
StartAuthSession
EndAuthSession
DoMatchEvent result
Ignoring fp match
Done writing record
Done deleting record
EOF

# Events from EC firmware related to power button
cat <<\EOF
PB pressed
PB released
PB task
PB PCH
power button released
power button pressed
EOF

# Events from powerd related to power button and screen
cat <<\EOF
Power button down
Power button up
Shutting down
all displays off
all displays on
Turning screen
imming screen
EOF
} >"${PATTERNS_FILENAME}"

LOG_FILENAME=cros_$(date --iso-8601=seconds).log
generate_logs --compress=false --output="${LOG_FILENAME}"

grep --text -f "${PATTERNS_FILENAME}" "${LOG_FILENAME}" | sort | uniq

rm "${PATTERNS_FILENAME}"
