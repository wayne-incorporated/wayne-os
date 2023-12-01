// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RMAD_UTILS_CR50_UTILS_IMPL_H_
#define RMAD_UTILS_CR50_UTILS_IMPL_H_

#include <rmad/utils/cr50_utils.h>

#include <memory>
#include <string>

#include "rmad/utils/cmd_utils.h"

namespace rmad {

class Cr50UtilsImpl : public Cr50Utils {
 public:
  Cr50UtilsImpl();
  explicit Cr50UtilsImpl(std::unique_ptr<CmdUtils> cmd_utils);
  ~Cr50UtilsImpl() override = default;

  bool GetRsuChallengeCode(std::string* challenge_code) const override;
  bool PerformRsu(const std::string& unlock_code) const override;
  bool EnableFactoryMode() const override;
  bool DisableFactoryMode() const override;
  bool IsFactoryModeEnabled() const override;
  bool GetBoardIdType(std::string* board_id_type) const override;
  bool GetBoardIdFlags(std::string* board_id_flags) const override;
  bool SetBoardId(bool is_custom_label) const override;

 private:
  std::unique_ptr<CmdUtils> cmd_utils_;
};

}  // namespace rmad

#endif  // RMAD_UTILS_CR50_UTILS_IMPL_H_
