/* Copyright 2023 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "landlock.h"

#include <unistd.h>

int landlock_create_ruleset(const struct landlock_ruleset_attr* const attr,
                            const size_t size,
                            const uint32_t flags) {
  return syscall(__NR_landlock_create_ruleset, attr, size, flags);
}
