// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stdint.h>

#include <base/posix/eintr_wrapper.h>
#include <gtest/gtest.h>

#include "arc/vm/libvda/encode/test/encode_unittest_common.h"

namespace {
std::unique_ptr<vea_config_t> CreateVeaConfig() {
  auto config = std::make_unique<vea_config_t>();
  config->input_format = YV12;
  config->input_visible_height = 800;
  config->input_visible_width = 600;
  config->output_profile = H264PROFILE_MAIN;
  return config;
}
}  // namespace

class LibvdaFakeVeaImplTest : public ::testing::Test {
 public:
  LibvdaFakeVeaImplTest() = default;
  LibvdaFakeVeaImplTest(const LibvdaFakeVeaImplTest&) = delete;
  LibvdaFakeVeaImplTest& operator=(const LibvdaFakeVeaImplTest&) = delete;

  ~LibvdaFakeVeaImplTest() override = default;
};

// Test that the fake implementation initializes and deinitializes
// successfully.
TEST_F(LibvdaFakeVeaImplTest, InitializeFake) {
  auto impl = SetupImpl(VEA_FAKE);
  EXPECT_NE(impl, nullptr);
}

// Test that the fake implementation creates and closes a decode session
// successfully.
TEST_F(LibvdaFakeVeaImplTest, InitEncodeSessionFake) {
  auto impl = SetupImpl(VEA_FAKE);
  auto config = CreateVeaConfig();
  auto session = SetupSession(impl, config.get());
  ASSERT_NE(session, nullptr);
  EXPECT_NE(session->ctx, nullptr);
  EXPECT_GT(session->event_pipe_fd, 0);
}

// Test that the fake implementation processes an encode event, and returns
// the buffer with a PROCESSED_INPUT_BUFFER event.
TEST_F(LibvdaFakeVeaImplTest, EncodeAndReturnsBuffer) {
  auto impl = SetupImpl(VEA_FAKE);
  auto config = CreateVeaConfig();
  auto session = SetupSession(impl, config.get());
  uint32_t input_buffer_id = 42;
  // TODO(alexlau): Consider passing a real FD.
  int fd = -1;

  video_frame_plane_t planes[3];
  planes[0].offset = 0;
  planes[0].stride = 600;
  planes[1].offset = 48000;
  planes[1].stride = 600;
  planes[2].offset = 96000;
  planes[2].stride = 600;

  vea_encode(session->ctx, input_buffer_id, fd,
             /* num_planes= */ 3, planes,
             /* timestamp= */ 0,
             /* force_keyframe= */ false);

  vea_event_t event;
  ASSERT_GT(
      HANDLE_EINTR(read(session->event_pipe_fd, &event, sizeof(vea_event_t))),
      0);
  EXPECT_EQ(event.event_type, PROCESSED_INPUT_BUFFER);
  EXPECT_EQ(event.event_data.processed_input_buffer_id, input_buffer_id);
}
