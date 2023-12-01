// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LORGNETTE_DEBUG_LOG_H_
#define LORGNETTE_DEBUG_LOG_H_

#include <base/files/file_path.h>
#include <lorgnette/proto_bindings/lorgnette_service.pb.h>

namespace lorgnette {

class DebugLogManager {
 public:
  DebugLogManager();
  DebugLogManager(const DebugLogManager&) = delete;
  DebugLogManager operator=(const DebugLogManager&) = delete;

  bool IsDebuggingEnabled() const;
  SetDebugConfigResponse UpdateDebugConfig(
      const SetDebugConfigRequest& request);

  // If the file at `debug_flag_path_` exists, set up environment variables to
  // put SANE backends into debug mode.  Returns true if debugging was enabled
  // or false if not.
  bool SetupDebugging();

  void SetFlagPathForTesting(base::FilePath flagPath);

 private:
  base::FilePath debug_flag_path_;
};

}  // namespace lorgnette

#endif  // LORGNETTE_DEBUG_LOG_H_
