// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "libec/ec_command.h"

using testing::_;
using testing::InvokeWithoutArgs;
using testing::Return;

namespace ec {
namespace {

constexpr int kDummyFd = 0;
constexpr int kIoctlFailureRetVal = -1;

template <typename O, typename I>
class MockEcCommand : public EcCommand<O, I> {
 public:
  using EcCommand<O, I>::EcCommand;
  ~MockEcCommand() override = default;

  using Data = typename EcCommand<O, I>::Data;
  MOCK_METHOD(int, ioctl, (int fd, uint32_t request, Data* data));
};

class MockFpModeCommand : public MockEcCommand<struct ec_params_fp_mode,
                                               struct ec_response_fp_mode> {
 public:
  MockFpModeCommand() : MockEcCommand(EC_CMD_FP_MODE, 0, {.mode = 1}) {}
};

class MockEmptyResponseCommand
    : public MockEcCommand<struct ec_params_fp_seed, EmptyParam> {
 public:
  MockEmptyResponseCommand()
      : MockEcCommand(EC_CMD_FP_SEED, 0, {.seed = "foo"}) {}
};

// ioctl behavior for EC commands:
//   returns sizeof(EC response) (>=0) when the command goes to the EC, -1 if
//   there's a failure to communicate with the EC or other kernel failure.
//
//   In the case where the command went to the EC, cmd.result is error code from
//   returned from the EC (EC_RES_SUCCESS, EC_RES_BUSY, EC_RES_UNAVAILABLE,
//   etc.)
//
//   In the case where an error code (i.e., not EC_RES_SUCCESS) is returned
//   by code in the EC, the EC logic will set the "response_size" to 0. In
//   this case, the ioctl returns 0 since it is returning the size of the
//   response. See
//   https://source.chromium.org/chromiumos/chromiumos/codesearch/+/main:src/platform/ec/common/host_command.c;l=202-205;drc=d64d5ca86d1fd6274011146e33597ef01bf551b1

TEST(EcCommand, Run_Success) {
  MockFpModeCommand mock;
  EXPECT_CALL(mock, ioctl)
      .WillOnce([](int, uint32_t, MockFpModeCommand::Data* data) {
        data->cmd.result = EC_RES_SUCCESS;
        return data->cmd.insize;
      });
  EXPECT_TRUE(mock.Run(kDummyFd));
}

TEST(EcCommand, Run_IoctlFailure) {
  MockFpModeCommand mock;
  EXPECT_CALL(mock, ioctl).WillOnce(Return(kIoctlFailureRetVal));
  EXPECT_FALSE(mock.Run(kDummyFd));
}

TEST(EcCommand, Run_CommandFailure) {
  MockFpModeCommand mock;
  EXPECT_CALL(mock, ioctl)
      .WillOnce([](int, uint32_t, MockFpModeCommand::Data* data) {
        // Test the case where the ioctl itself succeeds, the but the EC
        // command did not. In this case, "result" will be set, but the
        // response size will not match the command's response size.
        data->cmd.result = EC_RES_ACCESS_DENIED;
        return 0;
      });

  EXPECT_FALSE(mock.Run(kDummyFd));
}

// It's possible for the implementation of the command to incorrectly return
// the wrong size. The kernel driver does not check for this, but Run() should
// return an error since the data returned is not what was requested.
TEST(EcCommand, Run_ResponseSizeTooSmall) {
  MockFpModeCommand mock;
  EXPECT_CALL(mock, ioctl)
      .WillOnce([](int, uint32_t, MockFpModeCommand::Data* data) {
        data->cmd.result = EC_RES_SUCCESS;
        return data->cmd.insize - 1;
      });
  EXPECT_FALSE(mock.Run(kDummyFd));
}

// It's possible for the implementation of the command to incorrectly return
// the wrong size. In the case where the size is too large, the kernel driver
// will return an error, but we'll be defensive and check as well in case the
// implementation changes.
// See
// https://source.chromium.org/chromiumos/chromiumos/codesearch/+/main:src/third_party/kernel/upstream/drivers/platform/chrome/cros_ec_spi.c;l=259-261;drc=a0386bba70934d42f586eaf68b21d5eeaffa7bd0
TEST(EcCommand, Run_ResponseSizeTooLarge) {
  MockFpModeCommand mock;
  EXPECT_CALL(mock, ioctl)
      .WillOnce([](int, uint32_t, MockFpModeCommand::Data* data) {
        data->cmd.result = EC_RES_SUCCESS;
        return data->cmd.insize + 1;
      });
  EXPECT_FALSE(mock.Run(kDummyFd));
}

TEST(EcCommand, Run_CommandWithEmptyResponse_Failure) {
  MockEmptyResponseCommand mock;
  EXPECT_CALL(mock, ioctl)
      .WillOnce([](int, uint32_t, MockEmptyResponseCommand::Data* data) {
        // In the case where code in the EC sets a return value of something
        // other than EC_RES_SUCCESS, the code that sends the response from the
        // EC sets the size to 0, so the ioctl will always return 0 in that
        // case. See
        // https://source.chromium.org/chromiumos/chromiumos/codesearch/+/main:src/platform/ec/common/host_command.c;l=202-205;drc=d64d5ca86d1fd6274011146e33597ef01bf551b1
        data->cmd.result = EC_RES_INVALID_PARAM;
        return 0;
      });
  EXPECT_FALSE(mock.Run(kDummyFd));
}

TEST(EcCommand, ConstReq) {
  const MockFpModeCommand mock;
  EXPECT_TRUE(mock.Req());
}

TEST(EcCommand, ConstResp) {
  const MockFpModeCommand mock;
  EXPECT_TRUE(mock.Resp());
}

TEST(EcCommand, Run_CheckResult_Success) {
  MockFpModeCommand mock;
  EXPECT_CALL(mock, ioctl)
      .WillOnce([](int, uint32_t, MockFpModeCommand::Data* data) {
        data->cmd.result = EC_RES_SUCCESS;
        return data->cmd.insize;
      });
  EXPECT_TRUE(mock.Run(kDummyFd));
  EXPECT_EQ(mock.Result(), EC_RES_SUCCESS);
}

TEST(EcCommand, Run_CheckResult_Failure) {
  MockFpModeCommand mock;
  EXPECT_CALL(mock, ioctl)
      .WillOnce([](int, uint32_t, MockFpModeCommand::Data* data) {
        // Note that it's not expected that the result would be set by the
        // kernel driver in this case, but we want to be defensive against
        // the behavior in case there is an instance where it does.
        data->cmd.result = EC_RES_ERROR;
        return kIoctlFailureRetVal;
      });
  EXPECT_FALSE(mock.Run(kDummyFd));
  EXPECT_EQ(mock.Result(), kEcCommandUninitializedResult);
}

TEST(EcCommand, Run_CheckResult_CommandWithEmptyResponse_Failure) {
  MockEmptyResponseCommand mock;
  EXPECT_CALL(mock, ioctl)
      .WillOnce([](int, uint32_t, MockEmptyResponseCommand::Data* data) {
        // In the case where code in the EC sets a return value of something
        // other than EC_RES_SUCCESS, the code that sends the response from the
        // EC sets the size to 0, so the ioctl will always return 0 in that
        // case. See
        // https://source.chromium.org/chromiumos/chromiumos/codesearch/+/main:src/platform/ec/common/host_command.c;l=202-205;drc=d64d5ca86d1fd6274011146e33597ef01bf551b1
        data->cmd.result = EC_RES_ACCESS_DENIED;
        return 0;
      });
  EXPECT_FALSE(mock.Run(kDummyFd));
  EXPECT_EQ(mock.Result(), EC_RES_ACCESS_DENIED);
}

TEST(EcCommand, RunWithMultipleAttempts_Success) {
  constexpr int kNumAttempts = 2;
  MockFpModeCommand mock;
  EXPECT_CALL(mock, ioctl)
      .Times(kNumAttempts)
      // First ioctl() fails
      .WillOnce(InvokeWithoutArgs([]() {
        errno = ETIMEDOUT;
        return kIoctlFailureRetVal;
      }))
      // Second ioctl() succeeds
      .WillOnce([](int, uint32_t, MockFpModeCommand::Data* data) {
        data->cmd.result = EC_RES_SUCCESS;
        return data->cmd.insize;
      });
  EXPECT_TRUE(mock.RunWithMultipleAttempts(kDummyFd, kNumAttempts));
}

TEST(EcCommand, RunWithMultipleAttempts_Timeout_Failure) {
  constexpr int kNumAttempts = 2;
  MockFpModeCommand mock;
  EXPECT_CALL(mock, ioctl)
      .Times(kNumAttempts)
      // All calls to ioctl() timeout
      .WillRepeatedly(InvokeWithoutArgs([]() {
        errno = ETIMEDOUT;
        return kIoctlFailureRetVal;
      }));
  EXPECT_FALSE(mock.RunWithMultipleAttempts(kDummyFd, kNumAttempts));
}

TEST(EcCommand, RunWithMultipleAttempts_ErrorNotTimeout_Failure) {
  constexpr int kNumAttempts = 2;
  MockFpModeCommand mock;
  EXPECT_CALL(mock, ioctl)
      // Errors other than timeout should cause immediate failure even when
      // attempting retries.
      .Times(1)
      .WillOnce(InvokeWithoutArgs([]() {
        errno = EINVAL;
        return kIoctlFailureRetVal;
      }));
  EXPECT_FALSE(mock.RunWithMultipleAttempts(kDummyFd, kNumAttempts));
}

TEST(EcCommand, RunWithMultipleAttempts_AccessDenied) {
  MockFpModeCommand mock;

  // ioctl should only be called once because we won't retry access denied
  // failures.
  EXPECT_CALL(mock, ioctl)
      .WillOnce([](int, uint32_t, MockFpModeCommand::Data* data) {
        // ioctl succeeds, but the EC command did not. In this case, "result"
        // will be set, but the response size will not match the command's
        // response size.
        data->cmd.result = EC_RES_ACCESS_DENIED;
        return 0;
      });

  constexpr int kNumAttempts = 2;
  EXPECT_FALSE(mock.RunWithMultipleAttempts(kDummyFd, kNumAttempts));
}

TEST(EcCommand, RequestDoesNotChangeAfterRun) {
  MockFpModeCommand mock;
  EXPECT_EQ(mock.Req()->mode, 1);
  EXPECT_CALL(mock, ioctl)
      .WillOnce([](int, uint32_t, MockFpModeCommand::Data* data) {
        data->cmd.result = EC_RES_SUCCESS;
        // b/248622515: Set a new value in the response, so that we can make
        // sure that the request is not affected.
        data->resp.mode = 2;
        return data->cmd.insize;
      });
  EXPECT_TRUE(mock.Run(kDummyFd));
  EXPECT_EQ(mock.Req()->mode, 1);
}

TEST(EcCommand, RequestDoesNotAffectResponse) {
  MockFpModeCommand mock;
  // b/248622515: Modifying the request should not change the response.
  EXPECT_EQ(mock.Resp()->mode, 0);
  mock.SetReq({.mode = 1});
  EXPECT_EQ(mock.Resp()->mode, 0);
}

}  // namespace
}  // namespace ec
