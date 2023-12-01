// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef HPS_UTILS_H_
#define HPS_UTILS_H_

#include <optional>
#include <string>
#include <utility>

#include <base/files/file_path.h>
#include <base/strings/stringprintf.h>

#include "hps/dev.h"
#include "hps/hps_reg.h"

namespace hps {

constexpr int kVersionOffset = 20;

// Read the version number from the MCU firmware version file.
// Returns false on failure.
bool ReadVersionFromFile(const base::FilePath& path, uint32_t* version);

enum class RegType {
  kUint16,
  kPartIdArray,  // decoding this is not implemented
  kString,
};

struct RegInfo {
  HpsReg num;
  const char* name;
  bool readable;
  RegType type;
};

// Look up info about the given register.
// Returns nullopt for unrecognized registers.
std::optional<RegInfo> HpsRegInfo(int reg);
std::optional<RegInfo> HpsRegInfo(HpsReg reg);

// Return a pretty printed register value,
// or empty string if there is nothing pretty to print
std::string HpsRegValToString(HpsReg reg, uint16_t val);

// Iterate through all HPS registers from `start` to `end` (inclusive),
// reading their values and writing their contents to `callback`.
// Only registers which are known to exist and be readable are included;
// others are silently skipped.
// `callback` should be a functor that accepts std::string.
template <typename Callback>
int DumpHpsRegisters(DevInterface& dev,
                     Callback callback,
                     int start = 0,
                     int end = static_cast<int>(HpsReg::kMax)) {
  int failures = 0;
  for (int i = start; i <= end; i++) {
    auto reg = HpsRegInfo(i);
    if (!reg.has_value()) {
      // Not a real register, skip it.
      continue;
    }
    if (!reg->readable) {
      continue;
    }
    std::string dump_out;
    switch (reg->type) {
      // Part IDs are [u32; 5] but decoding it is not implemented yet.
      case RegType::kPartIdArray:
      case RegType::kUint16: {
        std::optional<uint16_t> result = dev.ReadReg(reg->num);
        if (!result) {
          dump_out =
              base::StringPrintf("Register %3d: error (%s)", i, reg->name);
          failures++;
        } else {
          dump_out = base::StringPrintf(
              "Register %3d: 0x%04x (%s) %s", i, result.value(), reg->name,
              HpsRegValToString(reg->num, result.value()).c_str());
        }
        break;
      }
      case RegType::kString: {
        std::optional<std::string> result = dev.ReadStringReg(reg->num, 256);
        if (!result) {
          dump_out =
              base::StringPrintf("Register %3d: error (%s)", i, reg->name);
          failures++;
        } else {
          dump_out = base::StringPrintf("Register %3d: ...... (%s) %s", i,
                                        reg->name, result.value().c_str());
        }
        break;
      }
    }
    callback(std::move(dump_out));
  }
  return failures;
}

}  // namespace hps

#endif  // HPS_UTILS_H_
