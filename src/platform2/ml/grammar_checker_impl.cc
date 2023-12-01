// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "ml/grammar_checker_impl.h"

#include <utility>
#include <vector>

#include <base/check.h>
#include <base/debug/leak_annotations.h>
#include <brillo/message_loops/message_loop.h>

#include "ml/grammar_proto_mojom_conversion.h"
#include "ml/request_metrics.h"

namespace ml {
namespace {

using ::chromeos::machine_learning::mojom::GrammarChecker;
using ::chromeos::machine_learning::mojom::GrammarCheckerCandidatePtr;
using ::chromeos::machine_learning::mojom::GrammarCheckerQueryPtr;
using ::chromeos::machine_learning::mojom::GrammarCheckerResult;

}  // namespace

bool GrammarCheckerImpl::Create(
    mojo::PendingReceiver<GrammarChecker> receiver) {
  auto checker_impl = new GrammarCheckerImpl(std::move(receiver));

  // In production, `checker_impl` is intentionally leaked, because this model
  // runs in its own process and the model's memory is freed when the process
  // exits. However, if being tested with ASAN, this memory leak could cause an
  // error. Therefore, we annotate it as an intentional leak.
  ANNOTATE_LEAKING_OBJECT_PTR(checker_impl);

  //  Set the disconnection handler to quit the message loop (i.e. exit the
  //  process) when the connection is gone, because this model is always run in
  //  a dedicated process.
  checker_impl->receiver_.set_disconnect_handler(
      base::BindOnce(&brillo::MessageLoop::BreakLoop,
                     base::Unretained(brillo::MessageLoop::current())));

  return checker_impl->successfully_loaded_;
}

GrammarCheckerImpl::GrammarCheckerImpl(
    mojo::PendingReceiver<GrammarChecker> receiver)
    : library_(ml::GrammarLibrary::GetInstance()),
      receiver_(this, std::move(receiver)) {
  DCHECK(library_->GetStatus() == ml::GrammarLibrary::Status::kOk)
      << "GrammarCheckerImpl should be created only if GrammarLibrary is "
         "initialized successfully.";

  checker_ = library_->CreateGrammarChecker();

  successfully_loaded_ = library_->LoadGrammarChecker(checker_);
}

GrammarCheckerImpl::~GrammarCheckerImpl() {
  library_->DestroyGrammarChecker(checker_);
}

void GrammarCheckerImpl::Check(GrammarCheckerQueryPtr query,
                               CheckCallback callback) {
  RequestMetrics request_metrics("GrammarChecker", "Check");
  request_metrics.StartRecordingPerformanceMetrics();

  chrome_knowledge::GrammarCheckerResult result_proto;

  if (library_->CheckGrammar(checker_,
                             GrammarCheckerQueryToProto(std::move(query)),
                             &result_proto)) {
    // Check succeeded, run callback on the result.
    std::move(callback).Run(GrammarCheckerResultFromProto(result_proto));
    request_metrics.FinishRecordingPerformanceMetrics();
    request_metrics.RecordRequestEvent(GrammarCheckerResult::Status::OK);
  } else {
    // Check failed, run callback on empty result and status = ERROR.
    std::move(callback).Run(
        GrammarCheckerResult::New(GrammarCheckerResult::Status::ERROR,
                                  std::vector<GrammarCheckerCandidatePtr>()));
    request_metrics.RecordRequestEvent(GrammarCheckerResult::Status::ERROR);
  }
}

}  // namespace ml
