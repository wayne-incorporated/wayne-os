// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stdint.h>

#include <base/posix/eintr_wrapper.h>
#include <gtest/gtest.h>

#include "arc/vm/libvda/decode/test/decode_unittest_common.h"

class LibvdaFakeTest : public ::testing::Test {
 public:
  LibvdaFakeTest() = default;
  LibvdaFakeTest(const LibvdaFakeTest&) = delete;
  LibvdaFakeTest& operator=(const LibvdaFakeTest&) = delete;

  ~LibvdaFakeTest() override = default;
};

// Test that the fake implementation initializes and deinitializes
// successfully.
TEST_F(LibvdaFakeTest, InitializeFake) {
  ImplPtr impl = SetupImpl(FAKE);
  EXPECT_NE(impl, nullptr);
}

// Test that the fake implementation creates and closes a decode session
// successfully.
TEST_F(LibvdaFakeTest, InitDecodeSessionFake) {
  ImplPtr impl = SetupImpl(FAKE);
  SessionPtr session = SetupSession(impl, H264PROFILE_MAIN);
  ASSERT_NE(session, nullptr);
  EXPECT_NE(session->ctx, nullptr);
  EXPECT_GT(session->event_pipe_fd, 0);
}

// Test that the fake implementation processes a decode event, and echoes back
// a PICTURE_READY event that can be read from the event FD.
TEST_F(LibvdaFakeTest, DecodeAndGetPictureReadyEventFake) {
  ImplPtr impl = SetupImpl(FAKE);
  SessionPtr session = SetupSession(impl, H264PROFILE_MAIN);
  int32_t fake_bitstream_id = 12345;
  vda_decode(session->ctx, fake_bitstream_id /* bitstream_id */, -1 /* fd */,
             0 /* offset */, 0 /* bytes_used */);
  vda_event_t event;
  ASSERT_GT(
      HANDLE_EINTR(read(session->event_pipe_fd, &event, sizeof(vda_event_t))),
      0);
  EXPECT_EQ(event.event_type, PICTURE_READY);
  EXPECT_EQ(event.event_data.picture_ready.bitstream_id, fake_bitstream_id);
}

// Test that the dummy implementation will process multiple events and return
// a response.
TEST_F(LibvdaFakeTest, ReadMultipleEventsFake) {
  ImplPtr impl = SetupImpl(FAKE);
  SessionPtr session = SetupSession(impl, H264PROFILE_MAIN);
  vda_flush(session->ctx);
  vda_event_t event;
  EXPECT_GT(
      HANDLE_EINTR(read(session->event_pipe_fd, &event, sizeof(vda_event_t))),
      0);
  EXPECT_EQ(event.event_type, FLUSH_RESPONSE);
  vda_reset(session->ctx);
  EXPECT_GT(
      HANDLE_EINTR(read(session->event_pipe_fd, &event, sizeof(vda_event_t))),
      0);
  EXPECT_EQ(event.event_type, RESET_RESPONSE);
}
