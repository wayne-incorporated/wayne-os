// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RMAD_UTILS_CBI_UTILS_IMPL_H_
#define RMAD_UTILS_CBI_UTILS_IMPL_H_

#include "rmad/utils/cbi_utils.h"

#include <memory>
#include <string>
#include <vector>

#include "rmad/utils/cmd_utils.h"

namespace rmad {

// Calls `ectool` command to set/get CBI values.

class CbiUtilsImpl : public CbiUtils {
 public:
  CbiUtilsImpl();
  explicit CbiUtilsImpl(std::unique_ptr<CmdUtils> cmd_utils);
  ~CbiUtilsImpl() override = default;

  bool GetSkuId(uint64_t* sku_id) const override;
  bool GetDramPartNum(std::string* dram_part_num) const override;
  bool GetSsfc(uint32_t* ssfc) const override;
  bool SetSkuId(uint64_t sku_id) override;
  bool SetDramPartNum(const std::string& dram_part_num) override;
  bool SetSsfc(uint32_t ssfc) override;

 protected:
  bool SetCbi(int tag, const std::string& value, int set_flag = 0);
  bool GetCbi(int tag, std::string* value, int get_flag = 0) const;
  bool SetCbi(int tag, uint64_t value, int size, int set_flag = 0);
  bool GetCbi(int tag, uint64_t* value, int get_flag = 0) const;

 private:
  std::unique_ptr<CmdUtils> cmd_utils_;
};

}  // namespace rmad

#endif  // RMAD_UTILS_CBI_UTILS_IMPL_H_
