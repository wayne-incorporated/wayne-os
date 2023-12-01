#!/bin/sh
# Copyright 2019 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Check with Chrome over D-Bus if a particular feature is enabled.
output="$(minijail0 -u chronos /usr/bin/dbus-send --system \
  --type=method_call --print-reply \
  --dest=org.chromium.ChromeFeaturesService \
  /org/chromium/ChromeFeaturesService \
  'org.chromium.ChromeFeaturesServiceInterface.IsFeatureEnabled' \
  "string:$1" 2>/dev/null || true)"
[ "${output##* }" = 'true' ]
