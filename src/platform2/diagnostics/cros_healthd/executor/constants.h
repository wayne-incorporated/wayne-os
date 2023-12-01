// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_EXECUTOR_CONSTANTS_H_
#define DIAGNOSTICS_CROS_HEALTHD_EXECUTOR_CONSTANTS_H_

namespace diagnostics {

namespace cpu_msr {
// The msr address for IA32_TME_CAPABILITY (0x981), used to report tme telemetry
// data.
inline constexpr uint32_t kIA32TmeCapability = 0x981;
// The msr address for IA32_TME_ACTIVATE_MSR (0x982), used to report tme
// telemetry data.
inline constexpr uint32_t kIA32TmeActivate = 0x982;
// The msr address for IA32_FEATURE_CONTROL, used to report vmx
// virtualization data.
inline constexpr uint32_t kIA32FeatureControl = 0x3A;
// The msr address for VM_CR, used to report svm virtualization
// data.
inline constexpr uint32_t kVmCr = 0xC0010114;

}  // namespace cpu_msr

namespace fingerprint {

// The path to the fingerprint device node.
inline constexpr char kCrosFpPath[] = "/dev/cros_fp";

}  // namespace fingerprint

namespace psr {

// The path to the psr device node.
inline constexpr char kCrosMeiPath[] = "/dev/mei0";

}  // namespace psr

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_EXECUTOR_CONSTANTS_H_
