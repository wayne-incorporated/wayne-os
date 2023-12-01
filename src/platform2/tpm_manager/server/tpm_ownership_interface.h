// Copyright 2015 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TPM_MANAGER_SERVER_TPM_OWNERSHIP_INTERFACE_H_
#define TPM_MANAGER_SERVER_TPM_OWNERSHIP_INTERFACE_H_

#include <base/functional/callback.h>
#include <tpm_manager/proto_bindings/tpm_manager.pb.h>

#include "tpm_manager/common/export.h"

namespace tpm_manager {

// The command interface for TPM administration. Inherited by both IPC proxy
// and service classes. All methods are asynchronous because all TPM operations
// may take a long time to finish.
class TPM_MANAGER_EXPORT TpmOwnershipInterface {
 public:
  virtual ~TpmOwnershipInterface() = default;

  // Gets TPM status, which includes enabled, owned, passwords, etc. Processes
  // |request| and calls |callback| with a reply when the process is done.
  using GetTpmStatusCallback =
      base::OnceCallback<void(const GetTpmStatusReply&)>;
  virtual void GetTpmStatus(const GetTpmStatusRequest& request,
                            GetTpmStatusCallback callback) = 0;

  // Gets TPM nonsensitive status, which includes enabled, owned, presence of
  // password, etc. Processes |request| and calls |callback| with a reply when
  // the process is done.
  using GetTpmNonsensitiveStatusCallback =
      base::OnceCallback<void(const GetTpmNonsensitiveStatusReply&)>;
  virtual void GetTpmNonsensitiveStatus(
      const GetTpmNonsensitiveStatusRequest& request,
      GetTpmNonsensitiveStatusCallback callback) = 0;

  // Gets TPM version info. Processes |request| and calls |callback| with a
  // reply when the process is done.
  using GetVersionInfoCallback =
      base::OnceCallback<void(const GetVersionInfoReply&)>;
  virtual void GetVersionInfo(const GetVersionInfoRequest& request,
                              GetVersionInfoCallback callback) = 0;

  // Gets TPM supported features. Processes |request| and calls |callback| with
  // a reply when the process is done.
  using GetSupportedFeaturesCallback =
      base::OnceCallback<void(const GetSupportedFeaturesReply&)>;
  virtual void GetSupportedFeatures(const GetSupportedFeaturesRequest& request,
                                    GetSupportedFeaturesCallback callback) = 0;

  // Gets dictionary attack (DA) info. Processes |request| and calls |callback|
  // with a reply when the process is done.
  using GetDictionaryAttackInfoCallback =
      base::OnceCallback<void(const GetDictionaryAttackInfoReply&)>;
  virtual void GetDictionaryAttackInfo(
      const GetDictionaryAttackInfoRequest& request,
      GetDictionaryAttackInfoCallback callback) = 0;

  // Gets RO verification status. Processes |request| and calls |callback|
  // with a reply when the process is done.
  using GetRoVerificationStatusCallback =
      base::OnceCallback<void(const GetRoVerificationStatusReply&)>;
  virtual void GetRoVerificationStatus(
      const GetRoVerificationStatusRequest& request,
      GetRoVerificationStatusCallback callback) = 0;

  // Resets dictionary attack (DA) lock. Processes |request| and calls
  // |callback| with a reply when the process is done.
  using ResetDictionaryAttackLockCallback =
      base::OnceCallback<void(const ResetDictionaryAttackLockReply&)>;
  virtual void ResetDictionaryAttackLock(
      const ResetDictionaryAttackLockRequest& request,
      ResetDictionaryAttackLockCallback callback) = 0;

  // Processes a TakeOwnershipRequest and responds with a TakeOwnershipReply.
  using TakeOwnershipCallback =
      base::OnceCallback<void(const TakeOwnershipReply&)>;
  virtual void TakeOwnership(const TakeOwnershipRequest& request,
                             TakeOwnershipCallback callback) = 0;

  // Processes a RemoveOwnerDependencyRequest and responds with a
  // RemoveOwnerDependencyReply.
  using RemoveOwnerDependencyCallback =
      base::OnceCallback<void(const RemoveOwnerDependencyReply&)>;
  virtual void RemoveOwnerDependency(
      const RemoveOwnerDependencyRequest& request,
      RemoveOwnerDependencyCallback callback) = 0;

  // Processes a ClearStoredOwnerPasswordRequest and responds with a
  // ClearStoredOwnerPasswordReply.
  using ClearStoredOwnerPasswordCallback =
      base::OnceCallback<void(const ClearStoredOwnerPasswordReply&)>;
  virtual void ClearStoredOwnerPassword(
      const ClearStoredOwnerPasswordRequest& request,
      ClearStoredOwnerPasswordCallback callback) = 0;
};

}  // namespace tpm_manager

#endif  // TPM_MANAGER_SERVER_TPM_OWNERSHIP_INTERFACE_H_
