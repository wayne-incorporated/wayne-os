// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SECANOMALYD_PROCESSES_H_
#define SECANOMALYD_PROCESSES_H_

#include <sys/types.h>

#include <bitset>
#include <optional>
#include <string>
#include <vector>

#include <base/files/file_path.h>
#include <base/strings/string_piece.h>

#include <brillo/process/process.h>

namespace secanomalyd {

namespace testing {
class ProcessesTestFixture;
}

class ProcEntry {
 public:
  // A given process can be sandboxed using zero or more mechanisms.
  using SandboxStatus = std::bitset<4>;
  static constexpr size_t kLandlockBit = 0;  // Least Significant Bit
  static constexpr size_t kSecCompBit = 1;
  static constexpr size_t kSELinuxBit = 2;
  static constexpr size_t kNoNewPrivsBit = 3;

  static std::optional<ProcEntry> CreateFromPath(
      const base::FilePath& pid_path);

  // Copying the private fields is fine.
  ProcEntry(const ProcEntry& other) = default;
  ProcEntry& operator=(const ProcEntry& other) = default;

  pid_t pid() const { return pid_; }
  ino_t pidns() const { return pidns_; }
  ino_t mntns() const { return mntns_; }
  std::string comm() const { return comm_; }
  std::string args() const { return args_; }
  SandboxStatus sandbox_status() const { return sandbox_status_; }

 private:
  friend class testing::ProcessesTestFixture;
  FRIEND_TEST(ReporterTest, FullReport);

  ProcEntry(pid_t pid,
            ino_t pidns,
            ino_t mntns,
            std::string comm,
            std::string args,
            SandboxStatus sandbox_status)
      : pid_(pid),
        pidns_(pidns),
        mntns_(mntns),
        comm_(comm),
        args_(args),
        sandbox_status_(sandbox_status) {}

  pid_t pid_;
  ino_t pidns_;
  ino_t mntns_;
  std::string comm_;
  std::string args_;
  SandboxStatus sandbox_status_;
};

using MaybeProcEntry = std::optional<ProcEntry>;
using ProcEntries = std::vector<ProcEntry>;
using MaybeProcEntries = std::optional<ProcEntries>;

enum class ProcessFilter { kAll = 0, kInitPidNamespaceOnly };

MaybeProcEntries ReadProcesses(ProcessFilter filter);

}  // namespace secanomalyd

#endif  // SECANOMALYD_PROCESSES_H_
