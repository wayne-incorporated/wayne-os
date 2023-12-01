// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRASH_REPORTER_VM_COLLECTOR_H_
#define CRASH_REPORTER_VM_COLLECTOR_H_

#include "crash-reporter/crash_collector.h"

// Collector for processing crashes inside a VM. This collector runs on the host
// and is used to write out a crash report to the appropriate location. For the
// code that manages generating reports inside the VM, see VmSupportProper.
class VmCollector : public CrashCollector {
 public:
  VmCollector();
  bool Collect(pid_t pid);

  static CollectorInfo GetHandlerInfo(bool vm_crash, int32_t vm_pid);

  VmCollector(const VmCollector&) = delete;
  VmCollector& operator=(const VmCollector&) = delete;
};

#endif  // CRASH_REPORTER_VM_COLLECTOR_H_
