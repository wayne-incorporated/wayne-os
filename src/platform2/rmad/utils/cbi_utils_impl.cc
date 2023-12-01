// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "rmad/utils/cbi_utils_impl.h"

#include <limits>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_util.h>
#include <re2/re2.h>

#include "rmad/utils/cmd_utils_impl.h"

namespace {

constexpr char kEctoolCmdPath[] = "/usr/sbin/ectool";
constexpr char kEctoolIntValRegex[] = R"(As uint: (\d+))";

constexpr int kCbiTagSkuId = 2;
constexpr int kCbiTagDramPartNum = 3;
constexpr int kCbiTagSsfc = 8;

}  // namespace

namespace rmad {

CbiUtilsImpl::CbiUtilsImpl() {
  cmd_utils_ = std::make_unique<CmdUtilsImpl>();
}

CbiUtilsImpl::CbiUtilsImpl(std::unique_ptr<CmdUtils> cmd_utils)
    : cmd_utils_(std::move(cmd_utils)) {}

bool CbiUtilsImpl::GetSkuId(uint64_t* sku_id) const {
  CHECK(sku_id);

  return GetCbi(kCbiTagSkuId, sku_id);
}

bool CbiUtilsImpl::GetDramPartNum(std::string* dram_part_num) const {
  CHECK(dram_part_num);

  return GetCbi(kCbiTagDramPartNum, dram_part_num);
}

bool CbiUtilsImpl::GetSsfc(uint32_t* ssfc) const {
  CHECK(ssfc);

  uint64_t buf;
  if (!GetCbi(kCbiTagSsfc, &buf)) {
    return false;
  }

  if (buf > static_cast<uint64_t>(std::numeric_limits<uint32_t>::max())) {
    return false;
  }

  *ssfc = static_cast<uint32_t>(buf);
  return true;
}

bool CbiUtilsImpl::SetSkuId(uint64_t sku_id) {
  int byte_size = 0;
  uint64_t tmp = sku_id;

  // To tackle |sku_id| = 0, we use do-while to ensure that |byte_size| >= 1.
  do {
    tmp >>= 8;
    byte_size++;
  } while (tmp);

  return SetCbi(kCbiTagSkuId, sku_id, byte_size);
}

bool CbiUtilsImpl::SetDramPartNum(const std::string& dram_part_num) {
  return SetCbi(kCbiTagDramPartNum, dram_part_num);
}

bool CbiUtilsImpl::SetSsfc(uint32_t ssfc) {
  // For SSFC, we always use 4 bytes.
  return SetCbi(kCbiTagSsfc, ssfc, 4);
}

bool CbiUtilsImpl::SetCbi(int tag, const std::string& value, int set_flag) {
  std::vector<std::string> argv{kEctoolCmdPath,
                                "cbi",
                                "set",
                                base::NumberToString(tag),
                                value,
                                "0",
                                base::NumberToString(set_flag)};
  static std::string unused_output;
  return cmd_utils_->GetOutput(argv, &unused_output);
}

bool CbiUtilsImpl::GetCbi(int tag, std::string* value, int get_flag) const {
  CHECK(value != nullptr);

  std::vector<std::string> argv{kEctoolCmdPath, "cbi", "get",
                                base::NumberToString(tag),
                                base::NumberToString(get_flag)};
  if (!cmd_utils_->GetOutput(argv, value)) {
    return false;
  }

  base::TrimWhitespaceASCII(*value, base::TRIM_TRAILING, value);
  return true;
}

bool CbiUtilsImpl::SetCbi(int tag, uint64_t value, int size, int set_flag) {
  CHECK_GE(size, 1);
  CHECK_LE(size, 8);
  CHECK(size == 8 || 1ull << (size * 8) > value);

  std::vector<std::string> argv{kEctoolCmdPath,
                                "cbi",
                                "set",
                                base::NumberToString(tag),
                                base::NumberToString(value),
                                base::NumberToString(size),
                                base::NumberToString(set_flag)};
  static std::string unused_output;
  return cmd_utils_->GetOutput(argv, &unused_output);
}

bool CbiUtilsImpl::GetCbi(int tag, uint64_t* value, int get_flag) const {
  CHECK(value != nullptr);

  std::vector<std::string> argv{kEctoolCmdPath, "cbi", "get",
                                base::NumberToString(tag),
                                base::NumberToString(get_flag)};
  std::string output;
  if (!cmd_utils_->GetOutput(argv, &output)) {
    return false;
  }

  if (!re2::RE2::PartialMatch(output, kEctoolIntValRegex, value)) {
    LOG(ERROR) << "Failed to parse output from ectool";
    return false;
  }

  return true;
}

}  // namespace rmad
