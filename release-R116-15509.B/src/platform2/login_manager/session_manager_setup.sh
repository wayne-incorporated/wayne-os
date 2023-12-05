#!/bin/sh

# Copyright 2014 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

cat <<EOF 1>&2
This file is no longer used; Chrome's command line is now generated directly by
session_manager. Either make your changes there and rebuild the chromeos-login
package or modify /etc/chrome_dev.conf to make local changes to Chrome's
environment and command line.
EOF

exit 1
