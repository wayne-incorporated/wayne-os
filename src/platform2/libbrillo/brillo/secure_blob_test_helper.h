// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBBRILLO_BRILLO_SECURE_BLOB_TEST_HELPER_H_
#define LIBBRILLO_BRILLO_SECURE_BLOB_TEST_HELPER_H_

#include <inttypes.h>
#include <unistd.h>

#include <cstddef>
#include <cstdio>

#include <base/logging.h>

namespace brillo {

// Wait on the event fd returning 0 on success and 1 on failure.
inline int wait_for_event(int fd) {
  // event fd
  uint64_t event = 0;
  if (read(fd, &event, sizeof(event)) < 0) {
    PLOG(ERROR) << "read event failed";
    return 1;
  }
  return 0;
}

// Trigger the event fd returning 0 on success and 1 on failure.
inline int send_event(int fd) {
  // event fd
  uint64_t event = 1;
  if (write(fd, &event, sizeof(event)) < 0) {
    PLOG(ERROR) << "write event failed";
    return 1;
  }
  return 0;
}

}  // namespace brillo

#endif  // LIBBRILLO_BRILLO_SECURE_BLOB_TEST_HELPER_H_
