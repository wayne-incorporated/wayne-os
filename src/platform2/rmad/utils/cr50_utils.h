// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RMAD_UTILS_CR50_UTILS_H_
#define RMAD_UTILS_CR50_UTILS_H_

#include <string>

namespace rmad {

class Cr50Utils {
 public:
  Cr50Utils() = default;
  virtual ~Cr50Utils() = default;

  // Get the RSU challenge code. Return true if successfully get the challenge
  // code, false if failed to get the challenge code.
  virtual bool GetRsuChallengeCode(std::string* challenge_code) const = 0;

  // Use the unlock code to perform RSU. Return true if the unlock code is
  // correct, false if the unlock code is rejected.
  virtual bool PerformRsu(const std::string& unlock_code) const = 0;

  // Enable factory mode. Return true if the command succeeds, or factory mode
  // is already enabled, false if fails to enable factory mode (e.g. blocked by
  // FWMP).
  virtual bool EnableFactoryMode() const = 0;

  // Disable factory mode. Return true if the command succeeds, false if fails
  // to disable factory mode.
  virtual bool DisableFactoryMode() const = 0;

  // Check if cr50 factory mode is enabled.
  virtual bool IsFactoryModeEnabled() const = 0;

  // Get cr50 board ID type.
  virtual bool GetBoardIdType(std::string* board_id_type) const = 0;

  // Get cr50 board ID flags.
  virtual bool GetBoardIdFlags(std::string* board_id_flags) const = 0;

  // Set cr50 board ID.
  virtual bool SetBoardId(bool is_custom_label) const = 0;
};

}  // namespace rmad

#endif  // RMAD_UTILS_CR50_UTILS_H_
