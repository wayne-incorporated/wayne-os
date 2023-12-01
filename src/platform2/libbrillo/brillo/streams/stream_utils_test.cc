// Copyright 2015 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <brillo/streams/stream_utils.h>

#include <limits>
#include <memory>
#include <string>
#include <utility>

#include <brillo/streams/stream_errors.h>
#include <gtest/gtest.h>

namespace brillo {

TEST(StreamUtils, ErrorStreamClosed) {
  ErrorPtr error;
  EXPECT_FALSE(stream_utils::ErrorStreamClosed(FROM_HERE, &error));
  EXPECT_EQ(errors::stream::kDomain, error->GetDomain());
  EXPECT_EQ(errors::stream::kStreamClosed, error->GetCode());
  EXPECT_EQ("Stream is closed", error->GetMessage());
}

TEST(StreamUtils, ErrorOperationNotSupported) {
  ErrorPtr error;
  EXPECT_FALSE(stream_utils::ErrorOperationNotSupported(FROM_HERE, &error));
  EXPECT_EQ(errors::stream::kDomain, error->GetDomain());
  EXPECT_EQ(errors::stream::kOperationNotSupported, error->GetCode());
  EXPECT_EQ("Stream operation not supported", error->GetMessage());
}

TEST(StreamUtils, ErrorReadPastEndOfStream) {
  ErrorPtr error;
  EXPECT_FALSE(stream_utils::ErrorReadPastEndOfStream(FROM_HERE, &error));
  EXPECT_EQ(errors::stream::kDomain, error->GetDomain());
  EXPECT_EQ(errors::stream::kPartialData, error->GetCode());
  EXPECT_EQ("Reading past the end of stream", error->GetMessage());
}

TEST(StreamUtils, CheckInt64Overflow) {
  const int64_t max_int64 = std::numeric_limits<int64_t>::max();
  const uint64_t max_uint64 = std::numeric_limits<uint64_t>::max();
  EXPECT_TRUE(stream_utils::CheckInt64Overflow(FROM_HERE, 0, 0, nullptr));
  EXPECT_TRUE(
      stream_utils::CheckInt64Overflow(FROM_HERE, 0, max_int64, nullptr));
  EXPECT_TRUE(
      stream_utils::CheckInt64Overflow(FROM_HERE, max_int64, 0, nullptr));
  EXPECT_TRUE(stream_utils::CheckInt64Overflow(FROM_HERE, 100, -90, nullptr));
  EXPECT_TRUE(
      stream_utils::CheckInt64Overflow(FROM_HERE, 1000, -1000, nullptr));

  ErrorPtr error;
  EXPECT_FALSE(stream_utils::CheckInt64Overflow(FROM_HERE, 100, -101, &error));
  EXPECT_EQ(errors::stream::kDomain, error->GetDomain());
  EXPECT_EQ(errors::stream::kInvalidParameter, error->GetCode());
  EXPECT_EQ("The stream offset value is out of range", error->GetMessage());

  EXPECT_FALSE(
      stream_utils::CheckInt64Overflow(FROM_HERE, max_int64, 1, nullptr));
  EXPECT_FALSE(
      stream_utils::CheckInt64Overflow(FROM_HERE, max_uint64, 0, nullptr));
  EXPECT_FALSE(stream_utils::CheckInt64Overflow(FROM_HERE, max_uint64,
                                                max_int64, nullptr));
}

TEST(StreamUtils, CalculateStreamPosition) {
  using Whence = Stream::Whence;
  const uint64_t current_pos = 1234;
  const uint64_t end_pos = 2000;
  uint64_t pos = 0;

  EXPECT_TRUE(stream_utils::CalculateStreamPosition(
      FROM_HERE, 0, Whence::FROM_BEGIN, current_pos, end_pos, &pos, nullptr));
  EXPECT_EQ(0u, pos);

  EXPECT_TRUE(stream_utils::CalculateStreamPosition(
      FROM_HERE, 0, Whence::FROM_CURRENT, current_pos, end_pos, &pos, nullptr));
  EXPECT_EQ(current_pos, pos);

  EXPECT_TRUE(stream_utils::CalculateStreamPosition(
      FROM_HERE, 0, Whence::FROM_END, current_pos, end_pos, &pos, nullptr));
  EXPECT_EQ(end_pos, pos);

  EXPECT_TRUE(stream_utils::CalculateStreamPosition(
      FROM_HERE, 10, Whence::FROM_BEGIN, current_pos, end_pos, &pos, nullptr));
  EXPECT_EQ(10u, pos);

  EXPECT_TRUE(stream_utils::CalculateStreamPosition(
      FROM_HERE, 10, Whence::FROM_CURRENT, current_pos, end_pos, &pos,
      nullptr));
  EXPECT_EQ(current_pos + 10, pos);

  EXPECT_TRUE(stream_utils::CalculateStreamPosition(
      FROM_HERE, 10, Whence::FROM_END, current_pos, end_pos, &pos, nullptr));
  EXPECT_EQ(end_pos + 10, pos);

  EXPECT_TRUE(stream_utils::CalculateStreamPosition(
      FROM_HERE, -10, Whence::FROM_CURRENT, current_pos, end_pos, &pos,
      nullptr));
  EXPECT_EQ(current_pos - 10, pos);

  EXPECT_TRUE(stream_utils::CalculateStreamPosition(
      FROM_HERE, -10, Whence::FROM_END, current_pos, end_pos, &pos, nullptr));
  EXPECT_EQ(end_pos - 10, pos);

  ErrorPtr error;
  EXPECT_FALSE(stream_utils::CalculateStreamPosition(
      FROM_HERE, -1, Whence::FROM_BEGIN, current_pos, end_pos, &pos, &error));
  EXPECT_EQ(errors::stream::kInvalidParameter, error->GetCode());
  EXPECT_EQ("The stream offset value is out of range", error->GetMessage());

  EXPECT_FALSE(stream_utils::CalculateStreamPosition(
      FROM_HERE, -1001, Whence::FROM_CURRENT, 1000, end_pos, &pos, nullptr));

  const uint64_t max_int64 = std::numeric_limits<int64_t>::max();
  EXPECT_FALSE(stream_utils::CalculateStreamPosition(
      FROM_HERE, 1, Whence::FROM_CURRENT, max_int64, end_pos, &pos, nullptr));
}

}  // namespace brillo
