// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VM_TOOLS_COMMON_PSTORE_H_
#define VM_TOOLS_COMMON_PSTORE_H_

#include <cstdint>

namespace vm_tools {

constexpr int64_t kArcVmRamoopsSize = 1024 * 1024;
constexpr int64_t kArcVmRamoopsRecordSize = kArcVmRamoopsSize / 4;
constexpr int64_t kArcVmRamoopsConsoleSize = kArcVmRamoopsSize / 4;
constexpr int64_t kArcVmRamoopsFtraceSize = 0x1000;
constexpr int64_t kArcVmRamoopsPmsgSize = 0x1000;

}  // namespace vm_tools

#endif  // VM_TOOLS_COMMON_PSTORE_H_
