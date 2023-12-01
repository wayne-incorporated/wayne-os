// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "ml/handwriting_recognizer_impl.h"

#include <utility>
#include <vector>

#include "base/debug/leak_annotations.h"
#include "ml/handwriting_proto_mojom_conversion.h"
#include "ml/request_metrics.h"

#include <base/check.h>
#include <brillo/message_loops/message_loop.h>

namespace ml {
namespace {

using ::chromeos::machine_learning::mojom::HandwritingRecognitionQueryPtr;
using ::chromeos::machine_learning::mojom::HandwritingRecognizer;
using ::chromeos::machine_learning::mojom::HandwritingRecognizerCandidatePtr;
using ::chromeos::machine_learning::mojom::HandwritingRecognizerResult;
using ::chromeos::machine_learning::mojom::HandwritingRecognizerSpecPtr;

}  // namespace

bool HandwritingRecognizerImpl::Create(
    HandwritingRecognizerSpecPtr spec,
    mojo::PendingReceiver<HandwritingRecognizer> receiver) {
  auto recognizer_impl =
      new HandwritingRecognizerImpl(std::move(spec), std::move(receiver));

  // In production, `recognizer_impl` is intentionally leaked, because this
  // model runs in its own process and the model's memory is freed when the
  // process exits. However, if being tested with ASAN, this memory leak could
  // cause an error. Therefore, we annotate it as an intentional leak.
  ANNOTATE_LEAKING_OBJECT_PTR(recognizer_impl);

  // Set the disconnection handler to quit the message loop (i.e. exit the
  // process) when the connection is gone, because this model is always run in
  // a dedicated process.
  // base::Unretained is safe here because the caller does not outlive the
  // message loop. HandwritingRecognizerImpl runs in its own worker process,
  // and if the message loop quits, the disconnect handler is not run.
  recognizer_impl->receiver_.set_disconnect_handler(
      base::BindOnce(&brillo::MessageLoop::BreakLoop,
                     base::Unretained(brillo::MessageLoop::current())));

  return recognizer_impl->successfully_loaded_;
}

HandwritingRecognizerImpl::HandwritingRecognizerImpl(
    HandwritingRecognizerSpecPtr spec,
    mojo::PendingReceiver<HandwritingRecognizer> receiver)
    : library_(ml::HandwritingLibrary::GetInstance()),
      receiver_(this, std::move(receiver)) {
  DCHECK(library_->GetStatus() == ml::HandwritingLibrary::Status::kOk)
      << "HandwritingRecognizerImpl should be created only if "
         "HandwritingLibrary is initialized successfully.";

  recognizer_ = library_->CreateHandwritingRecognizer();

  successfully_loaded_ =
      library_->LoadHandwritingRecognizer(recognizer_, std::move(spec));
}

HandwritingRecognizerImpl::~HandwritingRecognizerImpl() {
  library_->DestroyHandwritingRecognizer(recognizer_);
}

void HandwritingRecognizerImpl::Recognize(HandwritingRecognitionQueryPtr query,
                                          RecognizeCallback callback) {
  RequestMetrics request_metrics("HandwritingModel", "Recognize");
  request_metrics.StartRecordingPerformanceMetrics();

  chrome_knowledge::HandwritingRecognizerResult result_proto;

  if (library_->RecognizeHandwriting(
          recognizer_, HandwritingRecognitionQueryToProto(std::move(query)),
          &result_proto)) {
    // Recognition succeeded, run callback on the result.
    std::move(callback).Run(HandwritingRecognizerResultFromProto(result_proto));
    request_metrics.FinishRecordingPerformanceMetrics();
    request_metrics.RecordRequestEvent(HandwritingRecognizerResult::Status::OK);
  } else {
    // Recognition failed, run callback on empty result and status = ERROR.
    std::move(callback).Run(HandwritingRecognizerResult::New(
        HandwritingRecognizerResult::Status::ERROR,
        std::vector<HandwritingRecognizerCandidatePtr>()));
    request_metrics.RecordRequestEvent(
        HandwritingRecognizerResult::Status::ERROR);
  }
}

}  // namespace ml
