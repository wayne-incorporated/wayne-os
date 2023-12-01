// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBEC_FINGERPRINT_FP_SEED_COMMAND_H_
#define LIBEC_FINGERPRINT_FP_SEED_COMMAND_H_

#include <algorithm>
#include <memory>

#include <base/memory/ptr_util.h>
#include <brillo/brillo_export.h>
#include <brillo/secure_blob.h>
#include "libec/ec_command.h"

namespace ec {

class BRILLO_EXPORT FpSeedCommand
    : public EcCommand<struct ec_params_fp_seed, EmptyParam> {
 public:
  static constexpr int kTpmSeedSize = FP_CONTEXT_TPM_BYTES;

  template <typename T = FpSeedCommand>
  static std::unique_ptr<T> Create(const brillo::SecureVector& seed,
                                   uint16_t seed_version) {
    static_assert(std::is_base_of<FpSeedCommand, T>::value,
                  "Only classes derived from FpSeedCommand can use Create");

    if (seed.size() != kTpmSeedSize) {
      return nullptr;
    }

    // Using new to access non-public constructor. See
    // https://abseil.io/tips/134.
    auto seed_cmd = base::WrapUnique(new T());
    auto* req = seed_cmd->Req();
    req->struct_version = seed_version;
    std::copy(seed.cbegin(), seed.cbegin() + sizeof(req->seed), req->seed);
    return seed_cmd;
  }
  ~FpSeedCommand() override;

  bool Run(int fd) override;

  /**
   * @warning Only intended to be used for testing.
   */
  const brillo::SecureVector seed() const {
    return brillo::SecureVector(Req()->seed, Req()->seed + sizeof(Req()->seed));
  }

  /**
   * @warning Only intended to be used for testing.
   */
  const uint16_t seed_version() const { return Req()->struct_version; }

 protected:
  virtual bool EcCommandRun(int fd);
  void ClearSeedBuffer();
  FpSeedCommand() : EcCommand(EC_CMD_FP_SEED) {}
};

}  // namespace ec

#endif  // LIBEC_FINGERPRINT_FP_SEED_COMMAND_H_
