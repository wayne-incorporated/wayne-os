// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>

#include <base/files/scoped_file.h>
#include <base/logging.h>
#include <base/strings/string_util.h>
#include <brillo/flag_helper.h>

#include "debugd/src/helpers/dev_features_password_utils.h"

namespace {

const char kUsageMessage[] =
    "\n"
    "Sets a password or checks whether the username already has a password.\n"
    "When setting a password, the new password is read from stdin.\n"
    "\n"
    "This is needed instead of the standard passwd utility to allow scripted\n"
    "password input, but is not meant to be a general-purpose tool as it\n"
    "doesn't check any other fields in the file except for the password.\n"
    "\n"
    "By default this uses the dev mode password, but can also use system\n"
    "passwords with the --system flag."
    "\n";

const char kDevModePath[] = "/mnt/stateful_partition/etc/devmode.passwd";
const char kSystemPath[] = "/etc/shadow";

}  // namespace

int main(int argc, char** argv) {
  DEFINE_bool(q, false, "Query whether a password exists for the given user");
  DEFINE_bool(system, false, "Use the system password instead of dev mode");
  DEFINE_string(user, "chronos", "User name");
  brillo::FlagHelper::Init(argc, argv, kUsageMessage);

  debugd::DevFeaturesPasswordUtils utils;

  if (!utils.IsUsernameValid(FLAGS_user)) {
    LOG(WARNING) << "Invalid username \"" << FLAGS_user << '"';
    return EXIT_FAILURE;
  }
  base::FilePath password_file(FLAGS_system ? kSystemPath : kDevModePath);

  base::ScopedFD init_ns_fd(open("/proc/1/ns/mnt", O_CLOEXEC));
  // Since debugd is running in a sandboxed envrionment, the stateful partition
  // isn't mounted.  All of these checks need to be done in the init namespace
  // instead of the debugd sandboxed namespace.
  setns(init_ns_fd.get(), CLONE_NEWNS);

  if (FLAGS_q) {
    if (utils.IsPasswordSet(FLAGS_user, password_file)) {
      return EXIT_SUCCESS;
    }
    return EXIT_FAILURE;
  }

  // New password should be provided on stdin.
  char* password_buffer = nullptr;
  size_t buffer_size = 0;
  ssize_t password_length;
  password_length = getline(&password_buffer, &buffer_size, stdin);
  if (password_length == -1) {
    PLOG(WARNING) << "Failed to read password from stdin";
    return EXIT_FAILURE;
  }
  std::string password(password_buffer);
  // Remove trailing newline.
  if (password.back() == '\n')
    password.pop_back();

  if (utils.SetPassword(FLAGS_user, password, password_file)) {
    return EXIT_SUCCESS;
  }
  LOG(WARNING) << "SetPassword() failed";
  return EXIT_FAILURE;
}
