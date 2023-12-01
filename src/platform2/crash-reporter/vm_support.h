// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRASH_REPORTER_VM_SUPPORT_H_
#define CRASH_REPORTER_VM_SUPPORT_H_

#include <base/files/file_util.h>
#include <string>

class UserCollector;
class UserCollectorBase;

// Various methods and utilities for working with crashes that occur in a VM (as
// opposed to the host).
class VmSupport {
 public:
  // If we are running in a VM, returns a handle to the VM-support wrapper,
  // otherwise returns nullptr.
  static VmSupport* Get();

  // For testing, override the value returned by VmSupport::Get(). Does not
  // take ownership of the supplied pointer. Call with nullptr to restore the
  // default behavior.
  static void SetForTesting(VmSupport* vm_support);

  virtual ~VmSupport();

  // Add vm-specific info, such as the container OS and vm board, to
  // |collector|'s crash metadata.
  virtual void AddMetadata(UserCollector* collector) = 0;

  // Perform the extra steps needed when reporting a crash in the VM, such as
  // informing cicerone. |crash_meta_path| is a path to the .meta file, which we
  // use to identify the necessary crash files.
  virtual void FinishCrash(const base::FilePath& crash_meta_path) = 0;

  // Query the host for metrics consent state.
  virtual bool GetMetricsConsent() = 0;

  // Perform extra checks to exclude |collector|'s crash for software CrOS
  // doesn't care about (i.e. non first-party apps e.g. gedit). Returns |true|
  // if we care about this crash, and if we don't explains why in |out_reason|.
  virtual bool ShouldDump(pid_t pid, std::string* out_reason) = 0;
};

#endif  // CRASH_REPORTER_VM_SUPPORT_H_
