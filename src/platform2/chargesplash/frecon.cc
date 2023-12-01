// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <errno.h>
#include <fstream>
#include <signal.h>
#include <string>
#include <sys/types.h>
#include <vector>

#include <base/check.h>
#include <base/logging.h>
#include <base/process/launch.h>

#include "chargesplash/test_util.h"

#include "chargesplash/frecon.h"

namespace {

constexpr char kFreconPath[] = "/sbin/frecon";
constexpr char kFreconPidfile[] = "/run/frecon/pid";
constexpr char kFreconVt[] = "/run/frecon/vt0";

int GetRunningFreconPid() {
  std::ifstream pidfile(chargesplash::GetPath(kFreconPidfile));

  if (!pidfile.is_open()) {
    // Frecon is not running.
    return -1;
  }

  int pid = -1;
  pidfile >> pid;

  return pid;
}

}  // namespace

namespace chargesplash {

bool Frecon::InitFrecon() {
  int pid = GetRunningFreconPid();
  if (pid > 0) {
    LOG(INFO) << "Terminating running frecon with pid " << pid;
    if (kill(pid, SIGTERM) < 0 && errno != ESRCH) {
      LOG(ERROR) << "Failed to terminate pid " << pid;
      return false;
    }
  }

  std::vector<std::string> argv = {
      GetPath(kFreconPath), "--daemon",     "--no-login",
      "--enable-vt1",       "--enable-osc", "--pre-create-vts",
  };
  std::string output;
  if (!base::GetAppOutputAndError(argv, &output)) {
    LOG(ERROR) << "Failed to start frecon: " << output;
    return false;
  }

  frecon_pid_ = GetRunningFreconPid();
  if (frecon_pid_ < 0) {
    LOG(ERROR) << "Failed to get frecon pid";
    return false;
  }
  LOG(INFO) << "Frecon started with pid " << frecon_pid_;

  frecon_vt_.open(GetPath(kFreconVt), std::ofstream::out | std::ofstream::app);
  if (!frecon_vt_.is_open()) {
    LOG(ERROR) << "Failed to open " << kFreconVt;
    return false;
  }

  AttachOutput(&frecon_vt_);
  return true;
}

void Frecon::AttachOutput(std::ostream* output) {
  DCHECK(output);
  outputs_.push_back(output);
}

void Frecon::Write(const std::string& msg) {
  for (auto output : outputs_) {
    *output << msg;
    output->flush();
  }
}

Frecon::~Frecon() {
  if (frecon_pid_ >= 0) {
    LOG(INFO) << "Terminating frecon";
    if (kill(frecon_pid_, SIGTERM) < 0) {
      LOG(ERROR) << "Failed to terminate frecon with pid " << frecon_pid_;
    }
  }
}

}  // namespace chargesplash
