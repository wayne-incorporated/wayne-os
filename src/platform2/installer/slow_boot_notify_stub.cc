// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "installer/slow_boot_notify.h"

void SlowBootNotifyPreFwUpdate(const base::FilePath& fspm_main) {}

void SlowBootNotifyPostFwUpdate(const base::FilePath& fspm_next) {}

bool SlowBootNotifyRequired(const base::FilePath& fspm_main,
                            const base::FilePath& fspm_next) {
  return false;
}
