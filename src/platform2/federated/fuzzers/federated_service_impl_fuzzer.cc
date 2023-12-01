// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "federated/federated_service_impl.h"

#include <memory>
#include <string>
#include <vector>

#include <base/at_exit.h>
#include <base/check.h>
#include <base/run_loop.h>
#include <brillo/message_loops/base_message_loop.h>
#include <dbus/mock_bus.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <gtest/gtest.h>
#include <mojo/public/cpp/bindings/remote.h>

#include "federated/mock_scheduler.h"
#include "federated/mock_storage_manager.h"
#include "federated/mojom/example.mojom.h"
#include "federated/mojom/federated_service.mojom.h"
#include "mojo/core/embedder/embedder.h"
#include "mojo/core/embedder/scoped_ipc_support.h"

namespace federated {

namespace {

constexpr int kMaxLengthOfRandomString = 100;
constexpr int kMinSizeOfFeatureValueList = 1;
constexpr int kMaxSizeOfFeatureValueList = 100;

using chromeos::federated::mojom::Example;
using chromeos::federated::mojom::ExamplePtr;
using chromeos::federated::mojom::Features;
using chromeos::federated::mojom::FederatedService;
using chromeos::federated::mojom::StringList;
using chromeos::federated::mojom::ValueList;
using chromeos::federated::mojom::ValueListPtr;
using testing::_;
using testing::NiceMock;
using testing::Return;
using testing::StrictMock;

class Environment {
 public:
  Environment() {
    logging::SetMinLogLevel(logging::LOGGING_FATAL);  // <- DISABLE LOGGING.
    mojo::core::Init();
  }
};

ValueListPtr CreateStringList(const std::vector<std::string>& values) {
  ValueListPtr value_list = ValueList::NewStringList(StringList::New());
  value_list->get_string_list()->value = values;
  return value_list;
}
}  // namespace

class FederatedServiceImplFuzer {
 public:
  FederatedServiceImplFuzer()
      : mock_dbus_(new NiceMock<dbus::MockBus>(dbus::Bus::Options())) {}
  FederatedServiceImplFuzer(const FederatedServiceImplFuzer&) = delete;
  FederatedServiceImplFuzer& operator=(const FederatedServiceImplFuzer&) =
      delete;
  ~FederatedServiceImplFuzer() = default;

  void SetUp() {
    ipc_support_ = std::make_unique<mojo::core::ScopedIPCSupport>(
        base::SingleThreadTaskRunner::GetCurrentDefault(),
        mojo::core::ScopedIPCSupport::ShutdownPolicy::FAST);

    storage_manager_ = std::make_unique<StrictMock<MockStorageManager>>();
    scheduler_ = std::make_unique<StrictMock<MockScheduler>>(
        storage_manager_.get(),
        std::make_unique<DeviceStatusMonitor>(
            std::vector<std::unique_ptr<TrainingCondition>>()),
        mock_dbus_.get());

    EXPECT_CALL(*storage_manager_, OnExampleReceived(_, _))
        .WillRepeatedly(Return(true));

    federated_service_impl_ = std::make_unique<FederatedServiceImpl>(
        federated_service_.BindNewPipeAndPassReceiver().PassPipe(),
        base::OnceClosure(), storage_manager_.get(), scheduler_.get());
  }

  void PerformInference(const uint8_t* data, size_t size) {
    // Populates random strings for client_name, feature_key and feature_value
    // list respectively.
    FuzzedDataProvider fdp(data, size);
    const std::string client_name =
        fdp.ConsumeRandomLengthString(kMaxLengthOfRandomString);

    ExamplePtr example = Example::New();
    example->features = Features::New();
    auto& feature_map = example->features->feature;

    const std::string feature_key =
        fdp.ConsumeRandomLengthString(kMaxLengthOfRandomString);

    int value_list_size = fdp.ConsumeIntegralInRange(
        kMinSizeOfFeatureValueList, kMaxSizeOfFeatureValueList);
    std::vector<std::string> values;
    values.reserve(value_list_size);
    while (values.size() < value_list_size && fdp.remaining_bytes()) {
      values.push_back(fdp.ConsumeRandomLengthString(kMaxLengthOfRandomString));
    }

    feature_map[feature_key] = CreateStringList(values);
    federated_service_->ReportExample(client_name, std::move(example));
  }

 private:
  mojo::Remote<FederatedService> federated_service_;
  scoped_refptr<dbus::MockBus> mock_dbus_;
  std::unique_ptr<mojo::core::ScopedIPCSupport> ipc_support_;
  std::unique_ptr<MockStorageManager> storage_manager_;
  std::unique_ptr<MockScheduler> scheduler_;
  std::unique_ptr<FederatedServiceImpl> federated_service_impl_;
};

}  // namespace federated

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  static federated::Environment env;
  base::AtExitManager at_exit_manager;

  // Mock main task runner
  base::SingleThreadTaskExecutor task_executor(base::MessagePumpType::IO);
  brillo::BaseMessageLoop brillo_loop(task_executor.task_runner());
  brillo_loop.SetAsCurrent();

  federated::FederatedServiceImplFuzer fuzzer;
  fuzzer.SetUp();
  fuzzer.PerformInference(data, size);

  return 0;
}
