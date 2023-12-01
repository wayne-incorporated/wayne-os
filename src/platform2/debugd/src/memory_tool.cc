// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>

#include "debugd/src/memory_tool.h"

#include "debugd/src/process_with_id.h"

namespace debugd {

namespace {

const char kMemtesterpath[] = "/usr/sbin/memtester";
constexpr char kOomScoreAdjFileFormat[] = "/proc/%d/oom_score_adj";
constexpr char kOomScoreKillable[] = "1000";

}  // namespace

std::string MemtesterTool::Start(const base::ScopedFD& outfd,
                                 const uint32_t& memory) {
  ProcessWithId* p =
      CreateProcess(false /* sandboxed */, false /* access_root_mount_ns */);
  if (!p)
    return "";

  p->AddArg(kMemtesterpath);
  p->AddArg(base::StringPrintf("%u", memory));
  p->AddArg("1");
  p->BindFd(outfd.get(), STDOUT_FILENO);
  p->BindFd(outfd.get(), STDERR_FILENO);
  LOG(INFO) << "memtester: running process id: " << p->id();
  p->Start();

  // Make it the most killable possible instead of the default (unkillable).
  base::FilePath oom_file(base::StringPrintf(kOomScoreAdjFileFormat, p->pid()));
  ssize_t bytes_written =
      base::WriteFile(oom_file, kOomScoreKillable, strlen(kOomScoreKillable));
  if (bytes_written < 0 ||
      static_cast<size_t>(bytes_written) < strlen(kOomScoreKillable))
    PLOG(WARNING) << "memtester: can't write OOM score, got: " << bytes_written;

  return p->id();
}

}  // namespace debugd
