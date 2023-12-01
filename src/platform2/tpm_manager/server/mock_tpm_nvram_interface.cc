// Copyright 2015 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "tpm_manager/server/mock_tpm_nvram_interface.h"

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

MockTpmNvramInterface::MockTpmNvramInterface() {
  ON_CALL(*this, DefineSpace(_, _))
      .WillByDefault(WithArgs<1>(Invoke(RunCallback<DefineSpaceReply>)));
  ON_CALL(*this, DestroySpace(_, _))
      .WillByDefault(WithArgs<1>(Invoke(RunCallback<DestroySpaceReply>)));
  ON_CALL(*this, WriteSpace(_, _))
      .WillByDefault(WithArgs<1>(Invoke(RunCallback<WriteSpaceReply>)));
  ON_CALL(*this, ReadSpace(_, _))
      .WillByDefault(WithArgs<1>(Invoke(RunCallback<ReadSpaceReply>)));
  ON_CALL(*this, LockSpace(_, _))
      .WillByDefault(WithArgs<1>(Invoke(RunCallback<LockSpaceReply>)));
  ON_CALL(*this, ListSpaces(_, _))
      .WillByDefault(WithArgs<1>(Invoke(RunCallback<ListSpacesReply>)));
  ON_CALL(*this, GetSpaceInfo(_, _))
      .WillByDefault(WithArgs<1>(Invoke(RunCallback<GetSpaceInfoReply>)));
}

MockTpmNvramInterface::~MockTpmNvramInterface() {}

}  // namespace tpm_manager
