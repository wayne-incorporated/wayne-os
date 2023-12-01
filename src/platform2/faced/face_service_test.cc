// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "faced/face_service.h"

#include <gtest/gtest.h>

#include "faced/testing/status.h"

namespace faced {

TEST(FaceServiceClient, TestCreateAndShutDown) {
  // Create a FaceServiceClient from test socket.
  std::pair<base::ScopedFD, base::ScopedFD> sockets;
  FACE_ASSERT_OK_AND_ASSIGN(sockets, SocketPair());
  sockets.second.reset();
  FaceServiceClient client(std::move(sockets.first));

  // Ensure the async client can be accessed.
  EXPECT_FALSE(client.GetAsyncClient() == nullptr);

  // Shut down the client.
  client.ShutDown();

  // Ensure the async client is no longer accessible.
  EXPECT_TRUE(client.GetAsyncClient() == nullptr);
}

}  // namespace faced
