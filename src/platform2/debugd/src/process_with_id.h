// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DEBUGD_SRC_PROCESS_WITH_ID_H_
#define DEBUGD_SRC_PROCESS_WITH_ID_H_

#include <string>
#include <vector>

#include "debugd/src/sandboxed_process.h"

namespace debugd {

// @brief Represents a process with an immutable ID.
//
// The ID is random, unguessable, and may be given to other processes. It is a
// null-terminated ASCII string.
class ProcessWithId : public SandboxedProcess {
 public:
  ProcessWithId() = default;
  ~ProcessWithId() override = default;

  bool Init() override;
  bool Init(const std::vector<std::string>& minijail_extra_args) override;

  const std::string& id() const { return id_; }

 private:
  void GenerateId();

  std::string id_;
};

}  // namespace debugd

#endif  // DEBUGD_SRC_PROCESS_WITH_ID_H_
