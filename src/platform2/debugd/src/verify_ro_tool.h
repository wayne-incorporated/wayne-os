// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DEBUGD_SRC_VERIFY_RO_TOOL_H_
#define DEBUGD_SRC_VERIFY_RO_TOOL_H_

#include <string>

#include <base/files/scoped_file.h>
#include <brillo/errors/error.h>

#include "debugd/src/subprocess_tool.h"

namespace debugd {

class VerifyRoTool : public SubprocessTool {
 public:
  VerifyRoTool() = default;
  VerifyRoTool(const VerifyRoTool&) = delete;
  VerifyRoTool& operator=(const VerifyRoTool&) = delete;

  ~VerifyRoTool() override = default;

  // Checks and updates the Cr50 FW and verifies the AP and EC RO FW integrity
  // of the the USB-connected DUT. This function binds stdout and stderr of the
  // process it calls internally to |outfd| and stores the process handle in
  // |handle|.
  //
  // Returns whether the entire process is successful.
  bool UpdateAndVerifyFWOnUsb(brillo::ErrorPtr* error,
                              const base::ScopedFD& outfd,
                              const std::string& image_file,
                              const std::string& ro_db_dir,
                              std::string* handle);

 private:
  // Checks and returns if |absolute_path| points to a valid cr50 resource
  // location, i.e., a file or dir under /opt/google/cr50. If |is_dir| is set,
  // returns false if |absolute_path| isn't a dir.
  bool CheckCr50ResourceLocation(const base::FilePath& absolute_path,
                                 bool is_dir);
};

}  // namespace debugd

#endif  // DEBUGD_SRC_VERIFY_RO_TOOL_H_
