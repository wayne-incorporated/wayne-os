// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <limits>
#include <memory>
#include <vector>

#include <base/test/task_environment.h>
#include <base/time/time.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "libec/fingerprint/fp_frame_command.h"

namespace ec {
namespace {

using ::testing::Return;

constexpr int kValidMaxWriteSize = 128;
constexpr int kValidFrameSize = 4096;
constexpr int kValidIndex = 0;

TEST(FpFrameCommand, FpFrameCommand) {
  auto cmd =
      FpFrameCommand::Create(kValidIndex, kValidFrameSize, kValidMaxWriteSize);
  EXPECT_TRUE(cmd);
  EXPECT_EQ(cmd->Version(), 0);
  EXPECT_EQ(cmd->Command(), EC_CMD_FP_FRAME);
}

TEST(FpFrameCommand, InvalidReadSize) {
  constexpr int kInvalidMaxReadSize = kMaxPacketSize + 1;
  EXPECT_FALSE(FpFrameCommand::Create(kValidIndex, kValidFrameSize,
                                      kInvalidMaxReadSize));
}

TEST(FpFrameCommand, InvalidReadSizeZero) {
  constexpr int kInvalidMaxReadSize = 0;
  EXPECT_FALSE(FpFrameCommand::Create(kValidIndex, kValidFrameSize,
                                      kInvalidMaxReadSize));
}

TEST(FpFrameCommand, MaxReadSizeEqualsMaxPacketSize) {
  constexpr int kValidReadSize = kMaxPacketSize;
  EXPECT_TRUE(
      FpFrameCommand::Create(kValidIndex, kValidFrameSize, kValidReadSize));
}

TEST(FpFrameCommand, ZeroFrameSize) {
  constexpr int kInvalidFrameSize = 0;
  EXPECT_FALSE(FpFrameCommand::Create(kValidIndex, kInvalidFrameSize,
                                      kValidMaxWriteSize));
}

// Mock the underlying EcCommand to test
class FpFrameCommandTest : public testing::Test {
 public:
  class MockFpFrameCommand : public FpFrameCommand {
   public:
    MockFpFrameCommand(int index, uint32_t frame_size, ssize_t max_read_size)
        : FpFrameCommand(index, frame_size, max_read_size) {
      // Unless overridden, return packets full of zeroes.
      static FpFramePacket packet = {0};
      ON_CALL(*this, Resp).WillByDefault(Return(&packet));
    }
    MOCK_METHOD(bool, EcCommandRun, (int fd), (override));
    MOCK_METHOD(FpFramePacket*, Resp, (), (override));
    MOCK_METHOD(uint32_t, Result, (), (const, override));
    MOCK_METHOD(void, Sleep, (base::TimeDelta duration), (override));
  };

 protected:
  base::test::TaskEnvironment task_environment_{
      base::test::TaskEnvironment::TimeSource::MOCK_TIME};
};

TEST_F(FpFrameCommandTest, SmallTemplateSuccess) {
  FpFramePacket packet = {1, 2, 3, 4, 5};
  EXPECT_EQ(packet.size(), 544);
  // Ec command payload is empty until EcCommandRun is called.
  FpFramePacket payload = {0};

  constexpr int kMaxReadSize = 536;  // SPI max packet size is 544. Subtract
                                     // the sizeof(struct ec_host_response)
                                     // to get 536.
  static_assert(kMaxReadSize <= packet.size(),
                "Read size must be less than or equal to packet size");

  // Create a frame that has two full packets worth of data and one partial
  // packet.
  constexpr int kFrameSize = kMaxReadSize + kMaxReadSize + 10;
  auto mock_fp_frame_command =
      FpFrameCommand::Create<MockFpFrameCommand>(0, kFrameSize, kMaxReadSize);

  EXPECT_CALL(*mock_fp_frame_command, Resp).WillRepeatedly(Return(&payload));

  EXPECT_CALL(*mock_fp_frame_command, EcCommandRun)
      .WillRepeatedly(
          // Command is run, so start returning actual packet.
          [&payload, &packet](int fd) {
            payload = packet;
            return true;
          });
  EXPECT_TRUE(mock_fp_frame_command->Run(-1));
  const auto& frame = mock_fp_frame_command->frame();

  // First chunk
  std::vector<uint8_t> packet_vec(packet.begin(),
                                  packet.begin() + kMaxReadSize);
  auto frame_begin = frame->begin();
  auto frame_end = frame->begin() + packet_vec.size();
  std::vector<uint8_t> frame_chunk_1(frame_begin, frame_end);
  EXPECT_EQ(packet_vec, frame_chunk_1);

  // Second chunk
  frame_begin += packet_vec.size();
  frame_end += packet_vec.size();
  std::vector<uint8_t> frame_chunk_2(frame_begin, frame_end);
  EXPECT_EQ(packet_vec, frame_chunk_2);

  // Last chunk (short)
  frame_begin += packet_vec.size();
  frame_end += 10;
  packet_vec.resize(10);
  std::vector<uint8_t> frame_chunk_3(frame_begin, frame_end);
  EXPECT_EQ(packet_vec, frame_chunk_3);
}

TEST_F(FpFrameCommandTest, LargeTemplateSuccess) {
  FpFramePacket packet = {1, 2, 3, 4, 5};
  EXPECT_EQ(packet.size(), 544);
  // Ec command payload is empty until EcCommandRun is called.
  FpFramePacket payload = {0};

  constexpr int kMaxReadSize = 536;  // SPI max packet size is 544. Subtract
                                     // the sizeof(struct ec_host_response)
                                     // to get 536.
  static_assert(kMaxReadSize <= packet.size(),
                "Read size must be less than or equal to packet size");

  // Create a frame that is larger than the max uint16_t value.
  constexpr int kFrameSize = std::numeric_limits<uint16_t>::max() + 10;
  auto mock_fp_frame_command =
      FpFrameCommand::Create<MockFpFrameCommand>(0, kFrameSize, kMaxReadSize);

  EXPECT_CALL(*mock_fp_frame_command, Resp).WillRepeatedly(Return(&payload));

  EXPECT_CALL(*mock_fp_frame_command, EcCommandRun)
      .WillRepeatedly(
          // Command is run, so start returning actual packet.
          [&payload, &packet](int fd) {
            payload = packet;
            return true;
          });
  EXPECT_TRUE(mock_fp_frame_command->Run(-1));
  const auto& frame = mock_fp_frame_command->frame();

  std::vector<uint8_t> packet_vec(packet.begin(),
                                  packet.begin() + kMaxReadSize);
  auto frame_begin = frame->begin();
  auto frame_end = frame->begin() + packet_vec.size();
  while (frame_end + packet_vec.size() < frame->end()) {
    std::vector<uint8_t> chunk(frame_begin, frame_end);
    EXPECT_EQ(packet_vec, chunk);
    frame_begin += packet_vec.size();
    frame_end += packet_vec.size();
  }

  // Last chunk (short).
  frame_begin += packet_vec.size();
  frame_end += kFrameSize % kMaxReadSize;
  EXPECT_EQ(frame_end, frame->end());
  packet_vec.resize(kFrameSize % kMaxReadSize);
  std::vector<uint8_t> chunk(frame_begin, frame_end);
  EXPECT_EQ(packet_vec, chunk);
}

TEST_F(FpFrameCommandTest, RetriesWhenBusy) {
  auto mock_fp_frame_command =
      FpFrameCommand::Create<MockFpFrameCommand>(0, 4096, 128);
  EXPECT_TRUE(mock_fp_frame_command);
  EXPECT_CALL(*mock_fp_frame_command, Result).WillOnce(Return(EC_RES_BUSY));
  EXPECT_CALL(*mock_fp_frame_command, EcCommandRun)
      .WillOnce(Return(false))
      .WillRepeatedly(Return(true));

  EXPECT_TRUE(mock_fp_frame_command->Run(-1));
}

TEST_F(FpFrameCommandTest, FailsIfBusyAfterFirstRequest) {
  auto mock_fp_frame_command =
      FpFrameCommand::Create<MockFpFrameCommand>(0, 4096, 128);
  EXPECT_TRUE(mock_fp_frame_command);
  EXPECT_CALL(*mock_fp_frame_command, Result).WillOnce(Return(EC_RES_BUSY));
  EXPECT_CALL(*mock_fp_frame_command, EcCommandRun)
      .WillOnce(Return(false))   // Failure on first request; triggers retry.
      .WillOnce(Return(true))    // Retry succeeds.
      .WillOnce(Return(false));  // Next request fails. Since it wasn't first
                                 // request, no more retries.

  EXPECT_FALSE(mock_fp_frame_command->Run(-1));
}

TEST_F(FpFrameCommandTest, StopsBusyRetriesAfterMaxAttempts) {
  auto mock_fp_frame_command =
      FpFrameCommand::Create<MockFpFrameCommand>(0, 4096, 128);
  EXPECT_TRUE(mock_fp_frame_command);
  EXPECT_CALL(*mock_fp_frame_command, EcCommandRun)
      .Times(51)
      .WillRepeatedly(Return(false));
  EXPECT_CALL(*mock_fp_frame_command, Result)
      .Times(51)
      .WillRepeatedly(Return(EC_RES_BUSY));
  EXPECT_FALSE(mock_fp_frame_command->Run(-1));
}

}  // namespace
}  // namespace ec
