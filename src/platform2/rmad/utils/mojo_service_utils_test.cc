// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/memory/scoped_refptr.h"
#include "mojo/core/embedder/embedder.h"
#include "mojo/public/cpp/bindings/receiver.h"
#include "rmad/utils/mock_sensor_service.h"
#include "rmad/utils/mojo_service_utils.h"

#include <base/test/task_environment.h>

using testing::_;
using testing::StrictMock;

namespace rmad {

class MojoServiceUtilsTest : public testing::Test {
 public:
  MojoServiceUtilsTest() = default;

 protected:
  void SetUp() override { mojo::core::Init(); }

  base::test::TaskEnvironment task_environment_;
};

TEST_F(MojoServiceUtilsTest, Request_Sensor_Device_Before_Initialization) {
  auto utils = base::MakeRefCounted<MojoServiceUtilsImpl>();
  EXPECT_EQ(utils->GetSensorDevice(1), nullptr);
}

TEST_F(MojoServiceUtilsTest, Request_Nonexistent_Sensor_Device) {
  auto utils = base::MakeRefCounted<MojoServiceUtilsImpl>();
  utils->SetInitializedForTesting();

  MockSensorService mock_sensor_service;
  EXPECT_CALL(mock_sensor_service, GetDevice(_, _)).Times(1);
  mojo::Receiver<cros::mojom::SensorService> receiver{&mock_sensor_service};

  utils->SetSensorServiceForTesting(receiver.BindNewPipeAndPassRemote());
  utils->GetSensorDevice(1);
  receiver.FlushForTesting();
}

TEST_F(MojoServiceUtilsTest, Request_Existent_Sensor_Device) {
  auto utils = base::MakeRefCounted<MojoServiceUtilsImpl>();
  utils->SetInitializedForTesting();

  MockSensorService mock_sensor_service;
  EXPECT_CALL(mock_sensor_service, GetDevice(_, _)).Times(1);
  mojo::Receiver<cros::mojom::SensorService> receiver{&mock_sensor_service};

  utils->SetSensorServiceForTesting(receiver.BindNewPipeAndPassRemote());

  // 1 call from |InsertDeviceForTesting|, 0 call from |GetSensorDevice|.
  utils->InsertDeviceForTesting(1);
  utils->GetSensorDevice(1);
  receiver.FlushForTesting();
}

}  // namespace rmad
