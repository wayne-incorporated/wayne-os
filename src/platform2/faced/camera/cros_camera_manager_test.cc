// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "faced/camera/cros_camera_manager.h"

#include <memory>
#include <utility>

#include <absl/status/status.h>
#include <absl/status/statusor.h>
#include <base/test/task_environment.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "faced/camera/camera_client.h"
#include "faced/camera/camera_manager.h"
#include "faced/camera/fake_camera_client.h"
#include "faced/testing/status.h"
#include "faced/util/blocking_future.h"

namespace faced {
namespace {

using ::faced::testing::FakeCameraClient;

// Close the given CameraManager synchronously.
void SynchronousClose(FakeCameraClient& client, CameraManager& manager) {
  BlockingFuture<void> future;

  // Start shutting down the manager.
  manager.Close(future.PromiseCallback());

  // The camera manager requires an additional frame to come in before it can
  // stop.
  //
  // TODO(b/254429209): Update the CameraClient API to avoid the need to wait
  // here.
  client.WriteFrame(Frame{}, base::BindOnce([](absl::Status) {}));

  // Wait for shutdown to complete.
  future.Wait();
}

// Read from the given CameraStreamReader synchronously.
StreamValue<CameraStreamValue> SynchronousRead(CameraStreamReader& reader) {
  BlockingFuture<StreamValue<CameraStreamValue>> future;
  reader.Read(future.PromiseCallback());
  future.Wait();
  return std::move(future.value());
}

// Read from the given CameraStreamReader synchronously.
absl::StatusOr<Frame> SynchronousReadFrame(CameraStreamReader& reader) {
  StreamValue<CameraStreamValue> value = SynchronousRead(reader);
  if (!value.value.has_value()) {
    return absl::CancelledError("Stream closed.");
  }
  if (!value.value->ok()) {
    return value.value->status();
  }
  return *(value.value->value());
}

class CrosCameraManagerTest : public ::testing::Test {
 private:
  base::test::TaskEnvironment task_environment_{
      base::test::TaskEnvironment::TimeSource::MOCK_TIME};
};

TEST_F(CrosCameraManagerTest, CreateDestroy) {
  FakeCameraClient client;
  CrosCameraManager camera(client, client.DefaultConfig());
}

TEST_F(CrosCameraManagerTest, CaptureFrame) {
  FakeCameraClient client;
  CrosCameraManager camera(client, client.DefaultConfig());

  // Start the camera.
  FACE_ASSERT_OK_AND_ASSIGN(std::unique_ptr<CameraStreamReader> reader,
                            camera.Open());

  // Write some frames, and ensure they are received again.
  for (int i = 0; i < 3; i++) {
    FACE_ASSERT_OK(client.WriteFrameAndWait(Frame{}));
    FACE_ASSERT_OK(SynchronousReadFrame(*reader));
  }

  SynchronousClose(client, camera);
}

TEST_F(CrosCameraManagerTest, FramesDropped) {
  FakeCameraClient client;
  CrosCameraManager camera(client, client.DefaultConfig());

  // Start the camera.
  FACE_ASSERT_OK_AND_ASSIGN(std::unique_ptr<CameraStreamReader> reader,
                            camera.Open());

  // Write a single frame, and ensure we are not told to expedite the packet.
  {
    FACE_ASSERT_OK(client.WriteFrameAndWait(Frame{.data = "A"}));
    StreamValue<CameraStreamValue> value = SynchronousRead(*reader);
    EXPECT_FALSE(value.expedite);
  }

  // Write several frames, and ensure we are told to expedite the packet.
  {
    FACE_ASSERT_OK(client.WriteFrameAndWait(Frame{.data = "A"}));
    FACE_ASSERT_OK(client.WriteFrameAndWait(Frame{.data = "B"}));
    FACE_ASSERT_OK(client.WriteFrameAndWait(Frame{.data = "C"}));
    FACE_ASSERT_OK(client.WriteFrameAndWait(Frame{.data = "D"}));
    StreamValue<CameraStreamValue> value = SynchronousRead(*reader);
    EXPECT_TRUE(value.expedite);
  }

  SynchronousClose(client, camera);
}

}  // namespace
}  // namespace faced
