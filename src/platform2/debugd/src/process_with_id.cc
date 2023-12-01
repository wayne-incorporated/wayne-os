// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "debugd/src/process_with_id.h"

#include <string>
#include <vector>

#include <base/rand_util.h>
#include <base/strings/string_number_conversions.h>

namespace debugd {

namespace {

constexpr int kNumRandomBytesInId = 16;

}  // namespace

bool ProcessWithId::Init(const std::vector<std::string>& minijail_extra_args) {
  if (SandboxedProcess::Init(minijail_extra_args)) {
    GenerateId();
    return true;
  }
  return false;
}

bool ProcessWithId::Init() {
  return ProcessWithId::Init({});
}

void ProcessWithId::GenerateId() {
  std::string random_bytes = base::RandBytesAsString(kNumRandomBytesInId);
  id_ = base::HexEncode(random_bytes.data(), random_bytes.size());
}

}  // namespace debugd
