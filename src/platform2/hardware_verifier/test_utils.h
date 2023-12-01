/* Copyright 2019 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef HARDWARE_VERIFIER_TEST_UTILS_H_
#define HARDWARE_VERIFIER_TEST_UTILS_H_

#include <base/files/file_path.h>

#include "hardware_verifier/hardware_verifier.pb.h"

namespace hardware_verifier {

// Gets the root path to the test data.
base::FilePath GetTestDataPath();

HwVerificationReport LoadHwVerificationReport(const base::FilePath& file_path);

}  // namespace hardware_verifier

#endif  // HARDWARE_VERIFIER_TEST_UTILS_H_
