/* Copyright 2019 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef HARDWARE_VERIFIER_HW_VERIFICATION_SPEC_GETTER_IMPL_H_
#define HARDWARE_VERIFIER_HW_VERIFICATION_SPEC_GETTER_IMPL_H_

#include <memory>
#include <optional>

#include <base/files/file_path.h>

#include "hardware_verifier/hw_verification_spec_getter.h"

namespace hardware_verifier {

// A wrapper to access the vboot system properties.
class VbSystemPropertyGetter {
 public:
  virtual ~VbSystemPropertyGetter() = default;
  virtual int GetCrosDebug() const;
};

// The actual implementation to the |HwVerificationSpecGetter|.
class HwVerificationSpecGetterImpl : public HwVerificationSpecGetter {
 public:
  HwVerificationSpecGetterImpl();
  explicit HwVerificationSpecGetterImpl(
      std::unique_ptr<VbSystemPropertyGetter> vb_system_property_getter);
  HwVerificationSpecGetterImpl(const HwVerificationSpecGetterImpl&) = delete;
  HwVerificationSpecGetterImpl& operator=(const HwVerificationSpecGetterImpl&) =
      delete;

  std::optional<HwVerificationSpec> GetDefault() const override;
  std::optional<HwVerificationSpec> GetFromFile(
      const base::FilePath& file_path) const override;

 private:
  friend class HwVerificationSpecGetterImplTest;

  std::unique_ptr<VbSystemPropertyGetter> vb_system_property_getter_;
  base::FilePath root_;
};

}  // namespace hardware_verifier

#endif  // HARDWARE_VERIFIER_HW_VERIFICATION_SPEC_GETTER_IMPL_H_
