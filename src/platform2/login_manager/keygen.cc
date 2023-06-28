// Copyright (c) 2012 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <string>
#include <vector>

#include <base/at_exit.h>
#include <base/command_line.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <crypto/rsa_private_key.h>

#include "login_manager/keygen_worker.h"
#include "login_manager/nss_util.h"
#include "login_manager/policy_key.h"
#include "login_manager/system_utils.h"

namespace switches {

// Name of the flag that determines the path to log file.
static const char kLogFile[] = "log-file";
// The default path to the log file.
static const char kDefaultLogFile[] = "/var/log/session_manager";

}  // namespace switches

int main(int argc, char* argv[]) {
  base::AtExitManager exit_manager;
  base::CommandLine::Init(argc, argv);
  base::CommandLine* cl = base::CommandLine::ForCurrentProcess();
  std::string log_file = cl->GetSwitchValueASCII(switches::kLogFile);
  if (log_file.empty())
    log_file.assign(switches::kDefaultLogFile);
  logging::LoggingSettings settings;
  settings.logging_dest = logging::LOG_TO_ALL;
  settings.log_file_path = log_file.c_str();
  settings.lock_log = logging::DONT_LOCK_LOG_FILE;
  settings.delete_old = logging::APPEND_TO_OLD_LOG_FILE;
  logging::InitLogging(settings);

  if (cl->GetArgs().size() != 2) {
    LOG(FATAL) << "Usage: keygen /path/to/output_file /path/to/user/homedir";
  }
  std::unique_ptr<login_manager::NssUtil> nss =
      login_manager::NssUtil::Create();
  return login_manager::keygen::GenerateKey(base::FilePath(cl->GetArgs()[0]),
                                            base::FilePath(cl->GetArgs()[1]),
                                            nss.get());
}
