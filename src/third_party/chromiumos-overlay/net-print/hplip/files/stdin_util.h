// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_PRINT_HPLIP_FILES_STDIN_UTIL_H_
#define NET_PRINT_HPLIP_FILES_STDIN_UTIL_H_

#include <cstddef>
#include <cstdint>

// Sets stdin to the provided content. Returns a
// non-zero error code if an error occurs.
int fuzzer_set_stdin(const uint8_t* data, size_t size);

// Rewinds stdin to the start of the stream.
// Returns false on failure.
bool fuzzer_rewind_stdin();

#endif  // NET_PRINT_HPLIP_FILES_STDIN_UTIL_H_
