// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TPM2_SIMULATOR_TPM_NVCHIP_UTILS_H_
#define TPM2_SIMULATOR_TPM_NVCHIP_UTILS_H_

namespace tpm2_simulator {

constexpr inline char kNVChipMountPoint[] = "NVChip_mount";
bool MountAndEnterNVChip();
bool CorrectWorkingDirectoryFilesOwner();

}  // namespace tpm2_simulator

#endif  // TPM2_SIMULATOR_TPM_NVCHIP_UTILS_H_
