// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libhwsec-foundation/profiling/profiling.h"

#include <cctype>
#include <cstdlib>
#include <cstring>
#include <optional>
#include <string>

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/rand_util.h>
#include <base/strings/string_util.h>

extern "C" {
const char* __llvm_profile_get_filename();
void __llvm_profile_set_filename(const char*);
}

namespace hwsec_foundation {

#if ENABLE_PROFILING
namespace {

constexpr char kProcessCommandNameFilename[] = "/proc/self/comm";
constexpr char kProfileFileDir[] =
    "/mnt/stateful_partition/unencrypted/profraws";
constexpr char kProfileFileSuffix[] = "-%m-%p.profraw";
constexpr char kDefaultPrefix[] = "UNKNOWN";

std::optional<std::string> GetProcessCommandName() {
  std::string name;
  if (!base::ReadFileToString(base::FilePath(kProcessCommandNameFilename),
                              &name)) {
    return {};
  }
  // Remove the characters we are not interested in, e.g., new line character.
  base::TrimWhitespaceASCII(name, base::TRIM_TRAILING, &name);
  return name;
}

std::string ConstructFilename(std::string command_name) {
  // Get a random uint64_t.
  // It helps maintain unique profraw filenames.
  // Previously, we were using instrumented binary's signature,
  // daemon name, and PID. But it doesn't always guarantee
  // uniqueness (i.e. PIDs might be same in different namespaces).
  std::string random_int = std::to_string(base::RandUint64());

  // Build the entire string.
  const base::FilePath filename =
      base::FilePath(kProfileFileDir)
          .Append(base::FilePath(command_name + "-" + random_int +
                                 kProfileFileSuffix));

  return filename.value();
}

}  // namespace

void SetUpProfiling() {
  std::string command_name = GetProcessCommandName().value_or(kDefaultPrefix);

  if (command_name == kDefaultPrefix) {
    LOG(WARNING) << ": Cannot fetch command name; use '" << kDefaultPrefix
                 << "' instead.";
  }
  const char* current_profile_path = __llvm_profile_get_filename();

  if (current_profile_path != nullptr && strlen(current_profile_path) != 0) {
    LOG(WARNING) << __func__ << ": Overriding the current profile path: "
                 << current_profile_path;
  }
  std::string profile_file_path = ConstructFilename(command_name);

  // Set the destination filename for profraws.
  __llvm_profile_set_filename(profile_file_path.c_str());
}

#else

void SetUpProfiling() {
  // No-ops.
}

#endif

}  // namespace hwsec_foundation
