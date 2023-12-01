// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// A tool that can be used to read from or write to bootlockbox. For example:
// bootlockboxtool --action=read --key="xxx"
// This command prints the value stored in bootlockbox indexed by xxx.

#include <iostream>
#include <memory>

#include <stdlib.h>

#include <base/logging.h>
#include <brillo/flag_helper.h>
#include <brillo/syslog_logging.h>

#include "bootlockbox/boot_lockbox_client.h"

namespace {

constexpr char kActionStore[] = "store";
constexpr char kActionRead[] = "read";
constexpr char kActionFinalize[] = "finalize";

}  // namespace

int main(int argc, char** argv) {
  DEFINE_string(action, "",
                "Choose one action [store|read|finalize] to perform.");
  DEFINE_string(key, "", "key for the data");
  DEFINE_string(data, "", "The data to be stored");
  brillo::FlagHelper::Init(argc, argv, "bootlockbox");

  brillo::OpenLog("bootlockbox", true);
  brillo::InitLog(brillo::kLogToSyslog | brillo::kLogToStderr);

  if (FLAGS_action.empty()) {
    LOG(ERROR) << "must specify one action: [store|read|finalize]";
    return EXIT_FAILURE;
  }

  if (FLAGS_action != kActionStore && FLAGS_action != kActionRead &&
      FLAGS_action != kActionFinalize) {
    LOG(ERROR) << "Invalid action: [store|read|finalize]";
    return EXIT_FAILURE;
  }

  std::unique_ptr<bootlockbox::BootLockboxClient> boot_lockbox_client =
      bootlockbox::BootLockboxClient::CreateBootLockboxClient();

  if (FLAGS_action == kActionFinalize) {
    if (!boot_lockbox_client->Finalize()) {
      LOG(ERROR) << "Failed to finalize bootlockbox";
      return EXIT_FAILURE;
    }
    LOG(INFO) << "Success";
    return EXIT_SUCCESS;
  }

  if (FLAGS_key.empty()) {
    LOG(ERROR) << "must specify key to " << FLAGS_action;
    return EXIT_FAILURE;
  }
  std::string key(FLAGS_key);
  if (FLAGS_action == kActionStore) {
    if (FLAGS_data.empty()) {
      LOG(ERROR) << "must specify data to store";
      return EXIT_FAILURE;
    }
    std::string data(FLAGS_data);
    if (!boot_lockbox_client->Store(key, data)) {
      LOG(ERROR) << "Failed to store";
      return EXIT_FAILURE;
    }
    LOG(INFO) << "Success";
  } else if (FLAGS_action == kActionRead) {
    std::string data;
    if (!boot_lockbox_client->Read(key, &data)) {
      LOG(ERROR) << "Failed to read";
      return EXIT_FAILURE;
    }
    std::cout << data;
  }

  return EXIT_SUCCESS;
}
