// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TPM_MANAGER_SERVER_TPM_MANAGER_METRICS_NAMES_H_
#define TPM_MANAGER_SERVER_TPM_MANAGER_METRICS_NAMES_H_

namespace tpm_manager {

inline constexpr char kDictionaryAttackResetStatusHistogram[] =
    "Platform.TPM.DictionaryAttackResetStatus";
inline constexpr char kDictionaryAttackCounterHistogram[] =
    "Platform.TPM.DictionaryAttackCounter";
inline constexpr char kTPMVersionFingerprint[] =
    "Platform.TPM.VersionFingerprint";
inline constexpr char kTPMTimeToTakeOwnership[] =
    "Platform.TPM.TimeToTakeOwnership";
inline constexpr char kTPMAlertsHistogram[] = "Platform.TPM.HardwareAlerts";
inline constexpr char kTPMPowerWashResult[] = "Platform.TPM.PowerWashResult";
inline constexpr char kTPMTakeOwnershipResult[] =
    "Platform.TPM.TakeOwnershipResult";

// The secret status records the presence of each secret in the bit fields along
// with the TPM version information. Currently only the least significant byte
// is used.
inline constexpr char kSecretStatusHitogram[] =
    "Platform.TPM.TpmManagerSecretStatus";
inline constexpr int kSecretStatusHasResetLockPermissions = 1 << 0;
inline constexpr int kSecretStatusHasOwnerDelegate = 1 << 1;
inline constexpr int kSecretStatusHasLockoutPassword = 1 << 2;
inline constexpr int kSecretStatusHasEndorsementPassword = 1 << 3;
inline constexpr int kSecretStatusHasOwnerPassword = 1 << 4;
// (1<<5) ~ (1<<6) are reserved for future use.
inline constexpr int kSecretStatusIsTpm2 = 1 << 7;
inline constexpr int kSecretMaxBit = kSecretStatusIsTpm2;

inline constexpr char kFilesystemUtilization[] =
    "Platform.TPM.FilesystemUtilization";
inline constexpr char kFilesystemInitTime[] = "Platform.TPM.FilesystemInitTime";
inline constexpr char kApRoVerificationTime[] =
    "Platform.TPM.ApRoVerificationTime";
inline constexpr char kExpandedApRoVerificationStatus[] =
    "Platform.TPM.ExpandedApRoVerificationStatus";

}  // namespace tpm_manager

#endif  // TPM_MANAGER_SERVER_TPM_MANAGER_METRICS_NAMES_H_
