// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <base/run_loop.h>
#include <brillo/message_loops/base_message_loop.h>
#include <gtest/gtest.h>
#include <mojo/core/core.h>
#include <mojo/core/embedder/embedder.h>
#include <mojo/public/cpp/bindings/pending_remote.h>

#include "midis/client.h"
#include "midis/device_tracker.h"
#include "mojo/midis.mojom.h"

// Local implementation of the mojo MidisClient interface.
class ClientImpl : public arc::mojom::MidisClient {
 public:
  ~ClientImpl() override{};
  void OnDeviceAdded(arc::mojom::MidisDeviceInfoPtr device) override {}

  void OnDeviceRemoved(arc::mojom::MidisDeviceInfoPtr device) override {}

  mojo::PendingRemote<arc::mojom::MidisClient> CreatePendingRemote() {
    return receiver_.BindNewPipeAndPassRemote();
  }

 private:
  mojo::Receiver<arc::mojom::MidisClient> receiver_{this};
};

namespace midis {

class ClientTest : public ::testing::Test {
 public:
  ClientTest() = default;
  ClientTest(const ClientTest&) = delete;
  ClientTest& operator=(const ClientTest&) = delete;

  ~ClientTest() override = default;

 protected:
  void SetUp() override {
    message_loop_.SetAsCurrent();
    mojo::core::Init();
  }

  void TearDown() override {
    auto core = mojo::core::Core::Get();
    std::vector<MojoHandle> leaks;
    core->GetActiveHandlesForTest(&leaks);
    EXPECT_TRUE(leaks.empty());
  }

 private:
  brillo::BaseMessageLoop message_loop_;
};

// Check that the MidisServer implementation sends back the correct
// number of devices.
TEST_F(ClientTest, ListDevices) {
  DeviceTracker tracker;
  mojo::Remote<arc::mojom::MidisServer> remote_server;

  ClientImpl client;

  Client client_class(&tracker, 0, base::BindOnce([](uint32_t client_id) {}),
                      remote_server.BindNewPipeAndPassReceiver(),
                      client.CreatePendingRemote());

  // Check that initially there are no devices listed.
  int64_t num_devices = -1;
  remote_server->ListDevices(base::BindOnce(
      [](int64_t* num_devices,
         std::vector<arc::mojom::MidisDeviceInfoPtr> devices) {
        *num_devices = devices.size();
      },
      &num_devices));
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(num_devices, 0);

  // TODO(b/122623049): Add a device, then check that ListDevices works as
  // expected.
}

}  // namespace midis
