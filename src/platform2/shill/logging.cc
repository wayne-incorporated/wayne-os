// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/logging.h"

#include <string>

#include <base/command_line.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>

#include "shill/scope_logger.h"

namespace shill {

namespace switches {

const char kLogLevel[] = "log-level";
const char kLogScopes[] = "log-scopes";

}  // namespace switches

void SetLogLevelFromCommandLine(base::CommandLine* cl) {
  if (cl->HasSwitch(switches::kLogLevel)) {
    std::string log_level = cl->GetSwitchValueASCII(switches::kLogLevel);
    int level = 0;
    if (base::StringToInt(log_level, &level) &&
        level < logging::LOGGING_NUM_SEVERITIES) {
      logging::SetMinLogLevel(level);
      // Like VLOG, SLOG uses negative verbose level.
      shill::ScopeLogger::GetInstance()->set_verbose_level(-level);
    } else {
      LOG(WARNING) << "Bad log level: " << log_level;
    }
  }

  if (cl->HasSwitch(switches::kLogScopes)) {
    std::string log_scopes = cl->GetSwitchValueASCII(switches::kLogScopes);
    shill::ScopeLogger::GetInstance()->EnableScopesByName(log_scopes);
  }
}

}  // namespace shill
