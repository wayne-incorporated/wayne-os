// Copyright (c) 2012 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LOGIN_MANAGER_CHILD_JOB_H_
#define LOGIN_MANAGER_CHILD_JOB_H_

#include <unistd.h>

#include <string>
#include <vector>

#include <base/macros.h>
#include <base/time/time.h>

namespace login_manager {

class SystemUtils;

// An interface declaring the basic functionality of a job that can be managed
// by SessionManagerService.
class ChildJobInterface {
 public:
  // Potential exit codes for use in Subprocess::Run().
  static const int kCantSetUid;
  static const int kCantSetGid;
  static const int kCantSetGroups;
  static const int kCantSetEnv;
  static const int kCantExec;

  virtual ~ChildJobInterface() {}

  // Creates a background process and starts the job running in it. Does any
  // necessary bookkeeping.
  // Returns true if the process was created, false otherwise.
  virtual bool RunInBackground() = 0;

  // Attempt to kill the current instance of this job by sending
  // signal to the _entire process group_, sending message (if set) to
  // the instance to tell it why it must die.
  virtual void KillEverything(int signal, const std::string& message) = 0;

  // Attempt to kill the current instance of this job by sending
  // signal, sending message (if set) to the instance to tell it
  // why it must die.
  virtual void Kill(int signal, const std::string& message) = 0;

  // Returns the name of the job.
  virtual const std::string GetName() const = 0;

  // Returns the pid of the current instance of this job. May be -1.
  virtual pid_t CurrentPid() const = 0;
};

}  // namespace login_manager

#endif  // LOGIN_MANAGER_CHILD_JOB_H_
