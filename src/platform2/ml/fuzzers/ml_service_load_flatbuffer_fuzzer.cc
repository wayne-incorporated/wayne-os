// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#include "ml/machine_learning_service_impl.h"

#include <memory>
#include <string>
#include <vector>

#include <base/at_exit.h>
#include <base/check.h>
#include <base/functional/bind.h>
#include <base/run_loop.h>
#include <brillo/message_loops/base_message_loop.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <mojo/public/cpp/bindings/remote.h>

#include "ml/mojom/graph_executor.mojom.h"
#include "ml/mojom/machine_learning_service.mojom.h"
#include "ml/mojom/model.mojom.h"
#include "ml/tensor_view.h"
#include "mojo/core/embedder/embedder.h"
#include "mojo/core/embedder/scoped_ipc_support.h"

namespace ml {
namespace {

using ::chromeos::machine_learning::mojom::FlatBufferModelSpec;
using ::chromeos::machine_learning::mojom::FlatBufferModelSpecPtr;
using ::chromeos::machine_learning::mojom::LoadModelResult;
using ::chromeos::machine_learning::mojom::MachineLearningService;
using ::chromeos::machine_learning::mojom::Model;

class Environment {
 public:
  Environment() {
    logging::SetMinLogLevel(logging::LOGGING_FATAL);  // <- DISABLE LOGGING.
    mojo::core::Init();
  }
};

}  // namespace

class MLServiceFuzzer {
 public:
  MLServiceFuzzer() = default;
  MLServiceFuzzer(const MLServiceFuzzer&) = delete;
  MLServiceFuzzer& operator=(const MLServiceFuzzer&) = delete;

  ~MLServiceFuzzer() = default;
  void SetUp() {
    ipc_support_ = std::make_unique<mojo::core::ScopedIPCSupport>(
        base::SingleThreadTaskRunner::GetCurrentDefault(),
        mojo::core::ScopedIPCSupport::ShutdownPolicy::FAST);
    ml_service_impl_ = std::make_unique<MachineLearningServiceImpl>(
        ml_service_.BindNewPipeAndPassReceiver(), base::OnceClosure());
  }
  void PerformInference(const uint8_t* data, size_t size) {
    FlatBufferModelSpecPtr spec = FlatBufferModelSpec::New();
    spec->model_string = std::string(reinterpret_cast<const char*>(data), size);
    spec->inputs["input"] = 3;
    spec->outputs["output"] = 4;
    spec->metrics_model_name = "TestModel";

    // Load model.
    bool load_model_done = false;
    ml_service_->LoadFlatBufferModel(
        std::move(spec), model_.BindNewPipeAndPassReceiver(),
        base::BindOnce(
            [](bool* load_model_done, const LoadModelResult result) {
              *load_model_done = true;
            },
            &load_model_done));
    base::RunLoop().RunUntilIdle();
    CHECK(load_model_done);
  }

 private:
  std::unique_ptr<mojo::core::ScopedIPCSupport> ipc_support_;
  mojo::Remote<MachineLearningService> ml_service_;
  std::unique_ptr<MachineLearningServiceImpl> ml_service_impl_;
  mojo::Remote<Model> model_;
};

}  // namespace ml

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  static ml::Environment env;
  base::AtExitManager at_exit_manager;

  // Mock main task runner
  base::SingleThreadTaskExecutor task_executor(base::MessagePumpType::IO);
  brillo::BaseMessageLoop brillo_loop(task_executor.task_runner());
  brillo_loop.SetAsCurrent();

  ml::MLServiceFuzzer fuzzer;
  fuzzer.SetUp();
  fuzzer.PerformInference(data, size);

  return 0;
}
