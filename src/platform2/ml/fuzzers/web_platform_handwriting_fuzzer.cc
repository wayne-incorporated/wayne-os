// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <base/at_exit.h>
#include <base/check.h>
#include <base/check_op.h>
#include <base/functional/bind.h>
#include <base/run_loop.h>
#include <base/task/single_thread_task_executor.h>
#include <brillo/message_loops/base_message_loop.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <libprotobuf-mutator/src/libfuzzer/libfuzzer_macro.h>
#include <mojo/public/cpp/bindings/remote.h>

#include "chrome/knowledge/handwriting/handwriting_interface.pb.h"
#include "chrome/knowledge/handwriting/web_platform_handwriting_fuzz_container.pb.h"
#include "ml/fuzzers/handwriting_fake.h"
#include "ml/handwriting.h"
#include "ml/machine_learning_service_impl.h"
#include "ml/mojom/machine_learning_service.mojom.h"
#include "ml/mojom/web_platform_handwriting.mojom.h"
#include "ml/process.h"
#include "mojo/core/embedder/embedder.h"
#include "mojo/core/embedder/scoped_ipc_support.h"

namespace ml {

namespace {

using ::chromeos::machine_learning::mojom::LoadHandwritingModelResult;
using ::chromeos::machine_learning::mojom::MachineLearningService;
using ::chromeos::machine_learning::web_platform::mojom::HandwritingHints;
using ::chromeos::machine_learning::web_platform::mojom::HandwritingHintsPtr;
using ::chromeos::machine_learning::web_platform::mojom::HandwritingPoint;
using ::chromeos::machine_learning::web_platform::mojom::
    HandwritingPredictionPtr;
using ::chromeos::machine_learning::web_platform::mojom::HandwritingStroke;
using ::chromeos::machine_learning::web_platform::mojom::HandwritingStrokePtr;

}  // namespace

class WebPlatformHandwritingFuzzer {
 public:
  WebPlatformHandwritingFuzzer() = default;
  WebPlatformHandwritingFuzzer(const WebPlatformHandwritingFuzzer&) = delete;
  WebPlatformHandwritingFuzzer& operator=(const WebPlatformHandwritingFuzzer&) =
      delete;

  ~WebPlatformHandwritingFuzzer() = default;

  void SetUp(const std::string& language) {
    ipc_support_ = std::make_unique<mojo::core::ScopedIPCSupport>(
        base::SingleThreadTaskRunner::GetCurrentDefault(),
        mojo::core::ScopedIPCSupport::ShutdownPolicy::FAST);

    Process::GetInstance()->SetTypeForTesting(
        Process::Type::kSingleProcessForTest);

    ml_service_impl_ = std::make_unique<MachineLearningServiceImpl>(
        ml_service_.BindNewPipeAndPassReceiver(), base::OnceClosure());

    bool model_callback_done = false;
    auto constraint = chromeos::machine_learning::web_platform::mojom::
        HandwritingModelConstraint::New();
    constraint->languages.push_back(language);
    ml_service_->LoadWebPlatformHandwritingModel(
        std::move(constraint), recognizer_.BindNewPipeAndPassReceiver(),
        base::BindOnce(
            [](bool* model_callback_done,
               const LoadHandwritingModelResult result) {
              CHECK_EQ(result, LoadHandwritingModelResult::OK);
              *model_callback_done = true;
            },
            &model_callback_done));
    base::RunLoop().RunUntilIdle();
    CHECK(model_callback_done);
    CHECK(recognizer_.is_bound());
  }

  // Populates inputs with the fuzzed proto and calls GetPrediction, this fuzzes
  // the input and output conversion code.
  void PerformPrediction(
      const chrome_knowledge::WebPlatformHandwritingFuzzContainer&
          random_container_proto) {
    // Populates inputs with the random_container_proto.
    std::vector<HandwritingStrokePtr> strokes;
    HandwritingHintsPtr hints = HandwritingHints::New();
    hints->alternatives = random_container_proto.hint_alternatives();
    hints->text_context = random_container_proto.hint_text_context();

    for (const chrome_knowledge::InkStroke& ink_stroke :
         random_container_proto.strokes()) {
      auto stroke = HandwritingStroke::New();
      for (const chrome_knowledge::InkPoint& ink_point : ink_stroke.points()) {
        auto point = HandwritingPoint::New();
        auto location = gfx::mojom::PointF::New();
        location->x = ink_point.x();
        location->y = ink_point.y();
        point->location = std::move(location);
        stroke->points.push_back(std::move(point));
      }
      strokes.push_back(std::move(stroke));
    }

    bool infer_callback_done = false;
    recognizer_->GetPrediction(
        std::move(strokes), std::move(hints),
        base::BindOnce([](bool* infer_callback_done,
                          std::optional<std::vector<HandwritingPredictionPtr>>
                              predictions) { *infer_callback_done = true; },
                       &infer_callback_done));
    base::RunLoop().RunUntilIdle();
    CHECK(infer_callback_done);
  }

 private:
  std::unique_ptr<mojo::core::ScopedIPCSupport> ipc_support_;
  std::unique_ptr<MachineLearningServiceImpl> ml_service_impl_;
  mojo::Remote<MachineLearningService> ml_service_;
  mojo::Remote<
      chromeos::machine_learning::web_platform::mojom::HandwritingRecognizer>
      recognizer_;
};

}  // namespace ml

class Environment {
 public:
  Environment() {
    logging::SetMinLogLevel(logging::LOGGING_FATAL);  // <- DISABLE LOGGING.
    mojo::core::Init();
  }
};

DEFINE_PROTO_FUZZER(const chrome_knowledge::WebPlatformHandwritingFuzzContainer&
                        random_container_proto) {
  static Environment environment;
  base::AtExitManager at_exit_manager;

  // Mock main task runner
  base::SingleThreadTaskExecutor task_executor(base::MessagePumpType::IO);
  brillo::BaseMessageLoop brillo_loop(task_executor.task_runner());
  brillo_loop.SetAsCurrent();

  ml::HandwritingLibraryFake handwriting_library_fake;
  handwriting_library_fake.SetOutput(
      random_container_proto.recognizer_result());
  ml::HandwritingLibrary::UseFakeHandwritingLibraryForTesting(
      &handwriting_library_fake);

  ml::WebPlatformHandwritingFuzzer fuzzer;
  fuzzer.SetUp(random_container_proto.constraint_language());
  fuzzer.PerformPrediction(random_container_proto);
}
