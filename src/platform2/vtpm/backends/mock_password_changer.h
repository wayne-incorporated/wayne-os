// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VTPM_BACKENDS_MOCK_PASSWORD_CHANGER_H_
#define VTPM_BACKENDS_MOCK_PASSWORD_CHANGER_H_

#include "vtpm/backends/password_changer.h"

#include <string>

#include <gmock/gmock.h>
#include <trunks/tpm_generated.h>

namespace vtpm {

class MockPasswordChanger : public PasswordChanger {
 public:
  ~MockPasswordChanger() override = default;
  MOCK_METHOD(trunks::TPM_RC, Change, (std::string&), (override));
};

}  // namespace vtpm

#endif  // VTPM_BACKENDS_MOCK_PASSWORD_CHANGER_H_
