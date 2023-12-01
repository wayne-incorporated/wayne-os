// Copyright 2015 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "tpm_manager/server/mock_tpm_ownership_interface.h"

#include <utility>

using testing::_;
using testing::Invoke;
using testing::WithArgs;

namespace {

template <typename ReplyProtoType>
void RunCallback(base::OnceCallback<void(const ReplyProtoType&)> callback) {
  ReplyProtoType empty_proto;
  std::move(callback).Run(empty_proto);
}

}  // namespace

namespace tpm_manager {

MockTpmOwnershipInterface::MockTpmOwnershipInterface() {
  ON_CALL(*this, GetTpmStatus(_, _))
      .WillByDefault(WithArgs<1>(Invoke(RunCallback<GetTpmStatusReply>)));
  ON_CALL(*this, GetTpmNonsensitiveStatus(_, _))
      .WillByDefault(
          WithArgs<1>(Invoke(RunCallback<GetTpmNonsensitiveStatusReply>)));
  ON_CALL(*this, GetVersionInfo(_, _))
      .WillByDefault(WithArgs<1>(Invoke(RunCallback<GetVersionInfoReply>)));
  ON_CALL(*this, GetSupportedFeatures(_, _))
      .WillByDefault(
          WithArgs<1>(Invoke(RunCallback<GetSupportedFeaturesReply>)));
  ON_CALL(*this, GetDictionaryAttackInfo(_, _))
      .WillByDefault(
          WithArgs<1>(Invoke(RunCallback<GetDictionaryAttackInfoReply>)));
  ON_CALL(*this, GetRoVerificationStatus(_, _))
      .WillByDefault(
          WithArgs<1>(Invoke(RunCallback<GetRoVerificationStatusReply>)));
  ON_CALL(*this, ResetDictionaryAttackLock(_, _))
      .WillByDefault(
          WithArgs<1>(Invoke(RunCallback<ResetDictionaryAttackLockReply>)));
  ON_CALL(*this, TakeOwnership(_, _))
      .WillByDefault(WithArgs<1>(Invoke(RunCallback<TakeOwnershipReply>)));
  ON_CALL(*this, RemoveOwnerDependency(_, _))
      .WillByDefault(
          WithArgs<1>(Invoke(RunCallback<RemoveOwnerDependencyReply>)));
  ON_CALL(*this, ClearStoredOwnerPassword(_, _))
      .WillByDefault(
          WithArgs<1>(Invoke(RunCallback<ClearStoredOwnerPasswordReply>)));
}

MockTpmOwnershipInterface::~MockTpmOwnershipInterface() {}

}  // namespace tpm_manager
