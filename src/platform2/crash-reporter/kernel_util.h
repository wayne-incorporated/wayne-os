// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRASH_REPORTER_KERNEL_UTIL_H_
#define CRASH_REPORTER_KERNEL_UTIL_H_

#include <string>

#include "crash-reporter/crash_collector.h"

namespace kernel_util {

// Enumeration to specify architecture type.
enum ArchKind {
  kArchUnknown,
  kArchArm,
  kArchMips,
  kArchX86,
  kArchX86_64,

  kArchCount,  // Number of architectures.
  kMaxValue = kArchCount
};

extern const char kKernelExecName[];
extern const char kHypervisorExecName[];

// Check if this is a hypervisor kernel crash.
bool IsHypervisorCrash(const std::string& kernel_dump);

// Returns the architecture kind for which we are built.
ArchKind GetCompilerArch();

// Compute a stack signature string from a kernel dump.
std::string ComputeKernelStackSignature(const std::string& kernel_dump,
                                        ArchKind arch);

// BIOS crashes use a simple signature containing the crash PC.
std::string BiosCrashSignature(const std::string& dump);

// Compute a signature string from a NoC error.
std::string ComputeNoCErrorSignature(const std::string& dump);

// Watchdog reboots leave no stack trace. Generate a poor man's signature out
// of the last log line instead (minus the timestamp ended by ']').
std::string WatchdogSignature(const std::string& console_ramoops,
                              const std::string& watchdogRebootReason);

// If console_log contains a hypervisor log snippet, copy it to hypervisor_log
// and remove it from console_log, otherwise leave both unchanged. Returns true
// if hypervisor_log was found, false otherwise.
bool ExtractHypervisorLog(std::string& console_ramoops,
                          std::string& hypervisor_log);

}  // namespace kernel_util

#endif  // CRASH_REPORTER_KERNEL_UTIL_H_
