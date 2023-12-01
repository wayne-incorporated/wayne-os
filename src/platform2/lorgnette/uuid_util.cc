// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "lorgnette/uuid_util.h"

#include <uuid/uuid.h>

namespace lorgnette {

namespace {

constexpr size_t kUUIDStringLength = 37;

}  // namespace

std::string GenerateUUID() {
  uuid_t uuid_bytes;
  uuid_generate_random(uuid_bytes);
  std::string uuid(kUUIDStringLength, '\0');
  uuid_unparse(uuid_bytes, &uuid[0]);
  // Remove the null terminator from the string.
  uuid.resize(kUUIDStringLength - 1);
  return uuid;
}

}  // namespace lorgnette
