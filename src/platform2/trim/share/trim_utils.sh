# Copyright 2015 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

: ${CHROMEOS_TRIM_DIR:="/var/lib/trim"}
CHROMEOS_TRIM_DATA="${CHROMEOS_TRIM_DIR}/stateful_trim_data"
CHROMEOS_TRIM_STATE="${CHROMEOS_TRIM_DIR}/stateful_trim_state"
CHROMEOS_TRIM_LOCK="/run/lock/chromeos_trim.lock"

TRIM_SUPPORTED="supported"
TRIM_NOT_SUPPORTED="not supported"
TRIM_COMPLETED="completed"
TRIM_FAILED="failed"
TRIM_IN_PROGRESS="in progress"
TRIM_TEST_ONLY="test_only"
