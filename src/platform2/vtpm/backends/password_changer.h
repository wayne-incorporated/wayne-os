// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VTPM_BACKENDS_PASSWORD_CHANGER_H_
#define VTPM_BACKENDS_PASSWORD_CHANGER_H_

#include <string>

#include <trunks/tpm_generated.h>

namespace vtpm {

// This interface abstracts the password translation from virtual password to
// one that is recognaized by the host TPM.
class PasswordChanger {
 public:
  virtual ~PasswordChanger() = default;
  // Changes the password in `command` if `command` is considered as using some
  // virtual password that is supposed to be mapped to a password set on the
  // host TPM.
  virtual trunks::TPM_RC Change(std::string& command) = 0;
};

}  // namespace vtpm

#endif  // VTPM_BACKENDS_PASSWORD_CHANGER_H_
