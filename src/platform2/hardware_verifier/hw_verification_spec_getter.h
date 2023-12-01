/* Copyright 2019 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef HARDWARE_VERIFIER_HW_VERIFICATION_SPEC_GETTER_H_
#define HARDWARE_VERIFIER_HW_VERIFICATION_SPEC_GETTER_H_

#include <optional>

#include <base/files/file_path.h>

#include "hardware_verifier/hardware_verifier.pb.h"

namespace hardware_verifier {

// Interface that provides ways to retrieve |HwVericationSpec| messages.
class HwVerificationSpecGetter {
 public:
  virtual ~HwVerificationSpecGetter() = default;

  // Reads the |HwVerificationSpec| message from the default path.
  //
  // The default path is |/etc/hardware_verifier/verification_payload.prototxt|
  // on the rootfs.  If |cros_debug| is 1, this method will read the spec on the
  // stateful partition first, then the one on the rootfs.
  //
  // @return A |HwVerificationSpec| message if it succeeds.
  virtual std::optional<HwVerificationSpec> GetDefault() const = 0;

  // Reads the |HwVerificationSpec| message from the given path.
  //
  // The given file name must ends with ".prototxt" and the content must be
  // in protobuf text format.  |hardware_verifier| is not allowed to open
  // arbitrary hardware verification spec file if |cros_debug| is 0 so
  // this method does the check and returns |false| in that case.
  //
  // @param file_path: Path to the file that contains the data.
  //
  // @return A |HwVerificationSpec| message if it succeeds.
  virtual std::optional<HwVerificationSpec> GetFromFile(
      const base::FilePath& file_path) const = 0;
};

}  // namespace hardware_verifier

#endif  // HARDWARE_VERIFIER_HW_VERIFICATION_SPEC_GETTER_H_
