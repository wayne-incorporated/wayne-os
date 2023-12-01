// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "faced/camera/fake_camera_client.h"

#include <memory>

#include <absl/status/status.h>
#include <base/functional/bind.h>
#include <base/memory/scoped_refptr.h>
#include <base/test/task_environment.h>
#include <gtest/gtest.h>

#include "faced/camera/camera_client.h"
#include "faced/testing/status.h"
#include "faced/util/blocking_future.h"
#include "faced/util/task.h"

namespace faced::testing {
namespace {

class FakeCameraClientTest : public ::testing::Test {
 private:
  base::test::TaskEnvironment task_environment_{
      base::test::TaskEnvironment::TimeSource::MOCK_TIME};
};

class CountingFrameProcessor : public FrameProcessor {
 public:
  // `FrameProcessor` interface implementation.
  void ProcessFrame(std::unique_ptr<Frame> frame,
                    ProcessFrameDoneCallback done) override {
    // Count the number of frames seen.
    count_++;

    // Stop if the user has requested us to.
    PostToCurrentSequence(base::BindOnce(
        std::move(done), should_stop_
                             ? std::optional<absl::Status>(absl::OkStatus())
                             : std::nullopt));
  }

  // Number of frames seen.
  int frames_seen() const { return count_; }

  // Indicate that the frame processor should stop the camera after processing
  // the next frame.
  void StopNextFrame() { should_stop_ = true; }

 private:
  bool should_stop_ = false;
  int count_ = 0;
};

TEST_F(FakeCameraClientTest, SimpleCapture) {
  FakeCameraClient client;

  // Capture from the fake camera's default config.
  FACE_ASSERT_OK_AND_ASSIGN(CameraClient::DeviceInfo info, client.GetDevice(0));
  CameraClient::CaptureFramesConfig config = {
      .camera_id = info.id,
      .format = info.formats.at(0),
  };

  // Start a capture.
  auto processor = base::MakeRefCounted<CountingFrameProcessor>();
  BlockingFuture<absl::Status> future;
  client.CaptureFrames(config, processor, future.PromiseCallback());

  // Send in frames.
  EXPECT_EQ(processor->frames_seen(), 0);
  FACE_EXPECT_OK(client.WriteFrameAndWait(Frame{}));
  EXPECT_EQ(processor->frames_seen(), 1);
  FACE_EXPECT_OK(client.WriteFrameAndWait(Frame{}));
  EXPECT_EQ(processor->frames_seen(), 2);

  // Stop processing, and ensure the the complete callback is called.
  processor->StopNextFrame();
  FACE_EXPECT_OK(client.WriteFrameAndWait(Frame{}));
  EXPECT_EQ(processor->frames_seen(), 3);
  EXPECT_EQ(future.Wait(), absl::OkStatus());
}

}  // namespace
}  // namespace faced::testing
