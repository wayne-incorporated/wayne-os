// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <optional>
#include <stdio.h>
#include <string>
#include <utility>

#include <base/command_line.h>
#include <base/logging.h>
#include <brillo/syslog_logging.h>

#include "hwsec-test-utils/ownership_id/ownership_id_factory.h"

using hwsec_test_utils::GetOwnershipId;
using hwsec_test_utils::OwnershipId;

namespace {

constexpr char kIdCommand[] = "id";
constexpr char kDiffCommand[] = "diff";
constexpr char kIdArg[] = "id";

constexpr char kUsage[] = R"(
Usage: hwsec-ownership-id <command> [<args>]
Commands:
  |id|
      Output the ownership ID of this device to stdout.
  |diff| --id=<id>
      Compare the ownership ID of this device with the input.
      Success (exit 0) means the ownership ID is different from the input or
      the device ownership ID is empty.
      Failed in the other cases.
)";

void PrintUsage() {
  printf("%s", kUsage);
}

}  // namespace

int main(int argc, char* argv[]) {
  base::CommandLine::Init(argc, argv);
  brillo::InitLog(brillo::kLogToStderr);

  base::CommandLine* cl = base::CommandLine::ForCurrentProcess();
  const auto& args = cl->GetArgs();
  if (args.empty()) {
    PrintUsage();
    return 1;
  }

  std::unique_ptr<OwnershipId> ownership_id = GetOwnershipId();

  if (!ownership_id) {
    LOG(ERROR) << "Null ownership id.";
    return 1;
  }

  std::optional<std::string> id = ownership_id->Get();

  if (!id.has_value()) {
    LOG(ERROR) << "Failed to get ownership id.";
    return 1;
  }

  if (args.front() == kIdCommand) {
    puts(id->c_str());
    return 0;
  } else if (args.front() == kDiffCommand) {
    if (id->empty()) {
      return 0;
    }

    std::string original_id = cl->GetSwitchValueASCII(kIdArg);
    if (original_id == *id) {
      return 1;
    }

    return 0;
  }

  // None of the command matches; print usage and return non-zero exit status.
  PrintUsage();
  return 1;
}
