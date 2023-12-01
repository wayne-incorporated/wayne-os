// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "libec/ec_command_async.h"

using testing::_;
using testing::InvokeWithoutArgs;
using testing::Return;

namespace ec {
namespace {

constexpr int kDummyFd = 0;
constexpr int kIoctlFailureRetVal = -1;

template <typename O, typename I>
class MockEcCommandAsync : public EcCommandAsync<O, I> {
 public:
  using EcCommandAsync<O, I>::EcCommandAsync;
  ~MockEcCommandAsync() override = default;

  using Data = typename EcCommandAsync<O, I>::Data;
  MOCK_METHOD(int, ioctl, (int fd, uint32_t request, Data* data), (override));
};

class MockAddEntropyCommand
    : public MockEcCommandAsync<struct ec_params_rollback_add_entropy,
                                EmptyParam> {
 public:
  explicit MockAddEntropyCommand(const Options& options)
      : MockEcCommandAsync(
            EC_CMD_ADD_ENTROPY, ADD_ENTROPY_GET_RESULT, options) {}
  static constexpr std::size_t expected_response_size = 0;
};

class MockFlashProtectCommand
    : public MockEcCommandAsync<struct ec_params_flash_protect_v2,
                                struct ec_response_flash_protect> {
 public:
  explicit MockFlashProtectCommand(const Options& options)
      : MockEcCommandAsync(
            EC_CMD_FLASH_PROTECT, FLASH_PROTECT_GET_RESULT, options) {}
  static constexpr std::size_t expected_response_size =
      sizeof(ec_response_flash_protect);
};

template <typename T>
class EcCommandAsyncTest : public testing::Test {};

using EcCommandAsyncTestTypes =
    ::testing::Types<MockAddEntropyCommand, MockFlashProtectCommand>;

TYPED_TEST_SUITE(EcCommandAsyncTest, EcCommandAsyncTestTypes);

// ioctl behavior for EC commands:
//   returns sizeof(EC response) (>=0) on success, -1 on failure
//   cmd.result is error code from EC (EC_RES_SUCCESS, etc)

TYPED_TEST(EcCommandAsyncTest, Run_Success) {
  TypeParam mock_cmd({.poll_for_result_num_attempts = 2,
                      .poll_interval = base::Milliseconds(1)});
  EXPECT_CALL(mock_cmd, ioctl)
      .Times(3)
      // First call to ioctl() to start the command; EC returns success.
      .WillOnce([](int, uint32_t, typename TypeParam::Data* data) {
        data->cmd.result = EC_RES_SUCCESS;
        EXPECT_EQ(data->cmd.insize, 0);
        return data->cmd.insize;
      })
      // Second call to ioctl() to get the result; EC returns busy.
      .WillOnce([](int, uint32_t, typename TypeParam::Data* data) {
        data->cmd.result = EC_RES_BUSY;
        EXPECT_EQ(data->cmd.insize, TypeParam::expected_response_size);
        return data->cmd.insize;
      })
      // Third call to ioctl() to get the result; EC returns success.
      .WillOnce([](int, uint32_t, typename TypeParam::Data* data) {
        data->cmd.result = EC_RES_SUCCESS;
        EXPECT_EQ(data->cmd.insize, TypeParam::expected_response_size);
        return data->cmd.insize;
      });

  EXPECT_TRUE(mock_cmd.Run(kDummyFd));
  EXPECT_EQ(mock_cmd.Result(), EC_RES_SUCCESS);
}

TYPED_TEST(EcCommandAsyncTest, Run_TimeoutFailure) {
  TypeParam mock_cmd({.poll_for_result_num_attempts = 2,
                      .poll_interval = base::Milliseconds(1)});

  EXPECT_CALL(mock_cmd, ioctl)
      .Times(3)
      // First call to ioctl() to start the command; EC returns success.
      .WillOnce([](int, uint32_t, typename TypeParam::Data* data) {
        data->cmd.result = EC_RES_SUCCESS;
        EXPECT_EQ(data->cmd.insize, 0);
        return data->cmd.insize;
      })
      // All remaining ioctl() calls; EC returns busy.
      .WillRepeatedly([](int, uint32_t, typename TypeParam::Data* data) {
        data->cmd.result = EC_RES_BUSY;
        EXPECT_EQ(data->cmd.insize, TypeParam::expected_response_size);
        return data->cmd.insize;
      });

  EXPECT_FALSE(mock_cmd.Run(kDummyFd));
  EXPECT_EQ(mock_cmd.Result(), EC_RES_BUSY);
}

TYPED_TEST(EcCommandAsyncTest, Run_Failure) {
  TypeParam mock_cmd({// With the number of attempts set to 2, there will be at
                      // most 3 ioctl calls (the extra one starts the command).
                      // In this test case, we're validating that the last
                      // ioctl() call will not be performed because we got an
                      // error on the second ioctl() call.
                      .poll_for_result_num_attempts = 2,
                      .poll_interval = base::Milliseconds(1)});
  EXPECT_CALL(mock_cmd, ioctl)
      .Times(2)
      // First call to ioctl() to start the command; EC returns success.
      .WillOnce([](int, uint32_t, typename TypeParam::Data* data) {
        data->cmd.result = EC_RES_SUCCESS;
        EXPECT_EQ(data->cmd.insize, 0);
        return data->cmd.insize;
      })
      // Second call to ioctl() to get the result; EC returns error.
      .WillOnce([](int, uint32_t, typename TypeParam::Data* data) {
        data->cmd.result = EC_RES_ERROR;
        EXPECT_EQ(data->cmd.insize, TypeParam::expected_response_size);
        return data->cmd.insize;
      });

  EXPECT_FALSE(mock_cmd.Run(kDummyFd));
  EXPECT_EQ(mock_cmd.Result(), EC_RES_ERROR);
}

TYPED_TEST(EcCommandAsyncTest, Run_IoctlTimesOut) {
  TypeParam mock({
      // With the number of attempts set to 2, there will be at
      // most 3 ioctl calls (the extra one starts the command). In
      // this test case, we're validating that the last ioctl()
      // call will not be performed because we got an error on
      // the second ioctl() call.
      .poll_for_result_num_attempts = 2,
      .poll_interval = base::Milliseconds(1),
  });
  EXPECT_CALL(mock, ioctl)
      .Times(2)
      // First call to ioctl() to start the command; EC returns success.
      .WillOnce([](int, uint32_t, typename TypeParam::Data* data) {
        data->cmd.result = EC_RES_SUCCESS;
        EXPECT_EQ(data->cmd.insize, 0);
        return data->cmd.insize;
      })
      // Second call to ioctl() to get the result returns error (EC not
      // responding).
      .WillOnce([](int, uint32_t, typename TypeParam::Data* data) {
        errno = ETIMEDOUT;
        EXPECT_EQ(data->cmd.insize, TypeParam::expected_response_size);
        return kIoctlFailureRetVal;
      });

  EXPECT_FALSE(mock.Run(kDummyFd));
  EXPECT_EQ(mock.Result(), kEcCommandUninitializedResult);
}

TYPED_TEST(EcCommandAsyncTest, Run_IoctlTimesOut_IgnoreFailure) {
  TypeParam mock({.poll_for_result_num_attempts = 2,
                  .poll_interval = base::Milliseconds(1),
                  .validate_poll_result = false});
  EXPECT_CALL(mock, ioctl)
      .Times(3)
      // First call to ioctl() to start the command; EC returns success.
      .WillOnce([](int, uint32_t, typename TypeParam::Data* data) {
        data->cmd.result = EC_RES_SUCCESS;
        EXPECT_EQ(data->cmd.insize, 0);
        return data->cmd.insize;
      })
      // Second call to ioctl() to get the result returns error; EC not
      // responding.
      .WillOnce([](int, uint32_t, typename TypeParam::Data* data) {
        errno = ETIMEDOUT;
        EXPECT_EQ(data->cmd.insize, TypeParam::expected_response_size);
        return kIoctlFailureRetVal;
      })
      // Third call to ioctl() to get the result; EC returns success.
      .WillOnce([](int, uint32_t, typename TypeParam::Data* data) {
        data->cmd.result = EC_RES_SUCCESS;
        EXPECT_EQ(data->cmd.insize, TypeParam::expected_response_size);
        return data->cmd.insize;
      });

  EXPECT_TRUE(mock.Run(kDummyFd));
  EXPECT_EQ(mock.Result(), EC_RES_SUCCESS);
}

TYPED_TEST(EcCommandAsyncTest, Run_InvalidOptions_ZeroPollAttempts) {
  TypeParam mock({.poll_for_result_num_attempts = 0});
  EXPECT_DEATH(mock.Run(kDummyFd), "poll_for_result_num_attempts > 0");
}

TYPED_TEST(EcCommandAsyncTest, Run_InvalidOptions_NegativePollAttempts) {
  TypeParam mock({.poll_for_result_num_attempts = -1});
  EXPECT_DEATH(mock.Run(kDummyFd), "poll_for_result_num_attempts > 0");
}

TYPED_TEST(EcCommandAsyncTest, DefaultOptions) {
  typename TypeParam::Options options;
  EXPECT_EQ(options.validate_poll_result, true);
  EXPECT_EQ(options.poll_for_result_num_attempts, 20);
  EXPECT_EQ(options.poll_interval, base::Milliseconds(100));
}

// It's possible for the implementation of the command to incorrectly return
// the wrong size. The kernel driver does not check for this, but Run() should
// return an error since the data returned is not what was requested.
TYPED_TEST(EcCommandAsyncTest, Run_SecondBaseCmdResponseSizeLarge) {
  TypeParam mock_cmd({// With the number of attempts set to 2, there will be at
                      // most 3 ioctl calls (the extra one starts the command).
                      // In this test case, we're validating that the last
                      // ioctl() call will not be performed because we got a
                      // success on the second ioctl() call.
                      .poll_for_result_num_attempts = 2,
                      .poll_interval = base::Milliseconds(1)});
  EXPECT_CALL(mock_cmd, ioctl)
      .Times(2)
      // First call to ioctl() to start the command; EC returns success.
      .WillOnce([](int, uint32_t, typename TypeParam::Data* data) {
        data->cmd.result = EC_RES_SUCCESS;
        EXPECT_EQ(data->cmd.insize, 0);
        return data->cmd.insize;
      })
      // Second call to ioctl() to get the result; EC returns success. However,
      // the size is different from the expected command size.
      .WillOnce([](int, uint32_t, typename TypeParam::Data* data) {
        data->cmd.result = EC_RES_SUCCESS;
        return data->cmd.insize + 1;
      });

  EXPECT_FALSE(mock_cmd.Run(kDummyFd));
}

TYPED_TEST(EcCommandAsyncTest, Run_FirstBaseCmdFail) {
  TypeParam mock_cmd({.poll_for_result_num_attempts = 2,
                      .poll_interval = base::Milliseconds(1)});
  EXPECT_CALL(mock_cmd, ioctl)
      .Times(1)
      // First call to ioctl() to start the command; EC returns error.
      .WillOnce([](int, uint32_t, typename TypeParam::Data* data) {
        data->cmd.result = EC_RES_ERROR;
        EXPECT_EQ(data->cmd.insize, 0);
        return data->cmd.insize;
      });

  EXPECT_FALSE(mock_cmd.Run(kDummyFd));
}

}  // namespace
}  // namespace ec
