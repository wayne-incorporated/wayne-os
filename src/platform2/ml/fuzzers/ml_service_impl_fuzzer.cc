// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#include "ml/machine_learning_service_impl.h"

#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <base/at_exit.h>
#include <base/check.h>
#include <base/check_op.h>
#include <base/containers/flat_map.h>
#include <base/files/file_util.h>
#include <base/functional/bind.h>
#include <base/run_loop.h>
#include <base/task/single_thread_task_executor.h>
#include <brillo/message_loops/base_message_loop.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <mojo/public/cpp/bindings/pending_receiver.h>
#include <mojo/public/cpp/bindings/pending_remote.h>
#include <mojo/public/cpp/bindings/remote.h>

#include "ml/mojom/graph_executor.mojom.h"
#include "ml/mojom/machine_learning_service.mojom.h"
#include "ml/mojom/model.mojom.h"
#include "ml/tensor_view.h"
#include "ml/test_utils.h"
#include "mojo/core/embedder/embedder.h"
#include "mojo/core/embedder/scoped_ipc_support.h"

namespace ml {

namespace {

using ::chromeos::machine_learning::mojom::BuiltinModelId;
using ::chromeos::machine_learning::mojom::BuiltinModelSpec;
using ::chromeos::machine_learning::mojom::BuiltinModelSpecPtr;
using ::chromeos::machine_learning::mojom::CreateGraphExecutorResult;
using ::chromeos::machine_learning::mojom::ExecuteResult;
using ::chromeos::machine_learning::mojom::GraphExecutor;
using ::chromeos::machine_learning::mojom::GraphExecutorOptions;
using ::chromeos::machine_learning::mojom::LoadModelResult;
using ::chromeos::machine_learning::mojom::MachineLearningService;
using ::chromeos::machine_learning::mojom::Model;
using ::chromeos::machine_learning::mojom::TensorPtr;

const int kSmartDim20190521InputSize = 592;
// TODO(pmalani): Need a better way to determine where model files are stored.
constexpr char kModelDirForFuzzer[] = "/usr/libexec/fuzzers/";

}  // namespace

class MachineLearningServiceImplForTesting : public MachineLearningServiceImpl {
 public:
  // Pass an empty callback and use the testing model directory.
  explicit MachineLearningServiceImplForTesting(
      mojo::PendingReceiver<MachineLearningService> receiver)
      : MachineLearningServiceImpl(std::move(receiver),
                                   base::OnceClosure(),
                                   std::string(kModelDirForFuzzer)) {}
};

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

    ml_service_impl_ = std::make_unique<MachineLearningServiceImplForTesting>(
        ml_service_.BindNewPipeAndPassReceiver());

    // Set up model spec.
    BuiltinModelSpecPtr spec = BuiltinModelSpec::New();
    spec->id = BuiltinModelId::SMART_DIM_20190521;

    // Load model.
    bool model_callback_done = false;
    ml_service_->LoadBuiltinModel(
        std::move(spec), model_.BindNewPipeAndPassReceiver(),
        base::BindOnce(
            [](bool* model_callback_done, const LoadModelResult result) {
              CHECK_EQ(result, LoadModelResult::OK);
              *model_callback_done = true;
            },
            &model_callback_done));
    base::RunLoop().RunUntilIdle();
    CHECK(model_callback_done);
    CHECK(model_.is_bound());

    // Get graph executor.
    bool ge_callback_done = false;
    model_->CreateGraphExecutor(
        GraphExecutorOptions::New(),
        graph_executor_.BindNewPipeAndPassReceiver(),
        base::BindOnce(
            [](bool* ge_callback_done, const CreateGraphExecutorResult result) {
              CHECK_EQ(result, CreateGraphExecutorResult::OK);
              *ge_callback_done = true;
            },
            &ge_callback_done));
    base::RunLoop().RunUntilIdle();
    CHECK(ge_callback_done);
    CHECK(graph_executor_.is_bound());
  }

  void PerformInference(const uint8_t* data, size_t size) {
    // Construct input.
    base::flat_map<std::string, TensorPtr> inputs;

    // Create input vector
    FuzzedDataProvider data_provider(data, size);
    std::vector<double> input_vec;
    for (int i = 0; i < kSmartDim20190521InputSize; i++)
      input_vec.push_back(
          data_provider.ConsumeFloatingPointInRange<double>(0, 1));

    inputs.emplace(
        "input", NewTensor<double>({1, kSmartDim20190521InputSize}, input_vec));
    std::vector<std::string> outputs({"output"});

    // Perform inference.
    bool infer_callback_done = false;
    graph_executor_->Execute(
        std::move(inputs), std::move(outputs),
        base::BindOnce(
            [](bool* infer_callback_done, const ExecuteResult result,
               std::optional<std::vector<TensorPtr>> outputs) {
              // Basic inference checks.
              CHECK_EQ(result, ExecuteResult::OK);
              CHECK(outputs.has_value());
              CHECK_EQ(outputs->size(), 1);

              const TensorView<double> out_tensor((*outputs)[0]);
              CHECK(out_tensor.IsValidType());
              CHECK(out_tensor.IsValidFormat());
              *infer_callback_done = true;
            },
            &infer_callback_done));
    base::RunLoop().RunUntilIdle();
    CHECK(infer_callback_done);
  }

 private:
  std::unique_ptr<mojo::core::ScopedIPCSupport> ipc_support_;
  mojo::Remote<MachineLearningService> ml_service_;
  std::unique_ptr<MachineLearningServiceImplForTesting> ml_service_impl_;
  mojo::Remote<Model> model_;
  mojo::Remote<GraphExecutor> graph_executor_;
};

}  // namespace ml

class Environment {
 public:
  Environment() {
    logging::SetMinLogLevel(logging::LOGGING_FATAL);  // <- DISABLE LOGGING.
    mojo::core::Init();
  }
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  static Environment environment;
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
