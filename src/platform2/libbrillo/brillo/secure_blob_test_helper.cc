// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Helper executable used by secure_blob_test_runner to create a SecureBlob and
// send the memory location so its value can be audited before and after
// deallocation.

#include "brillo/secure_blob_test_helper.h"

#include <cstddef>
#include <cstdio>

#include <base/logging.h>
#include <base/files/scoped_file.h>
#include <brillo/secure_blob.h>

// Fill the secure blob with the expected value.
void assign_value(brillo::SecureBlob* value, size_t test_blob_size) {
  value->reserve(test_blob_size);
  for (size_t x = 0; x < test_blob_size; ++x) {
    value->push_back(static_cast<uint8_t>(x + 1));
  }
}

int main(int argc, char** argv) {
  logging::LoggingSettings settings;
  settings.logging_dest = logging::LOG_TO_STDERR;
  logging::InitLogging(settings);

  if (argc != 4) {
    LOG(ERROR) << "got wrong number of arguments";
    return 1;
  }
  // Set up eventfds for synchronizing with parent process.
  base::ScopedFD child_to_parent(atoi(argv[1]));
  if (!child_to_parent.is_valid() || child_to_parent.get() == 0) {
    LOG(ERROR) << "failed to get event fd from first arg";
    return 1;
  }
  base::ScopedFD parent_to_child(atoi(argv[2]));
  if (!parent_to_child.is_valid() || parent_to_child.get() == 0) {
    LOG(ERROR) << "failed to get event fd from second arg";
    return 1;
  }
  size_t test_blob_size;
  if (sscanf(argv[3], "%zu", &test_blob_size) != 1) {
    LOG(ERROR) << "failed test_blob_size from third arg";
    return 1;
  }

  int errors = 0;
  // Test with clear.
  {
    brillo::SecureBlob value;
    value.reserve(64);
    for (int x = 0; x < 2; ++x) {
      assign_value(&value, test_blob_size);

      // Write location of SecureBlob to stdout so parent process can check it.
      printf("%p\n", reinterpret_cast<void*>(value.data()));
      fflush(stdout);

      // Wait for parent process to read the data before clearing it.
      errors += brillo::wait_for_event(parent_to_child.get());
      value.clear();

      // Notify the parent process the value has been cleared and wait for it to
      // verify the clear was performed.
      errors += brillo::send_event(child_to_parent.get());
      errors += brillo::wait_for_event(parent_to_child.get());
    }
  }

  // Test with deallocate.
  {
    brillo::SecureBlob value;
    assign_value(&value, test_blob_size);

    // Write location of SecureBlob to stdout so parent process can check it.
    printf("%p\n", reinterpret_cast<void*>(value.data()));
    fflush(stdout);

    // Wait for parent process to read the data before clearing it.
    errors += brillo::wait_for_event(parent_to_child.get());
  }
  // Reserve some memory to avoid an io error.
  brillo::SecureBlob value;
  value.reserve(64);
  // Notify the parent process the value has been cleared and wait for it to
  // verify the clear was performed.
  errors += brillo::send_event(child_to_parent.get());
  errors += brillo::wait_for_event(parent_to_child.get());
  return !!errors;
}
