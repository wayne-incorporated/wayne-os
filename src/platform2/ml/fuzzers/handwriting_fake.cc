// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "ml/fuzzers/handwriting_fake.h"

#include <string>

namespace ml {
namespace {

using chromeos::machine_learning::mojom::HandwritingRecognizerSpecPtr;

}  // namespace

HandwritingLibraryFake::HandwritingLibraryFake() = default;
HandwritingLibraryFake::~HandwritingLibraryFake() = default;

HandwritingLibrary::Status HandwritingLibraryFake::GetStatus() const {
  return Status::kOk;
}

HandwritingRecognizer HandwritingLibraryFake::CreateHandwritingRecognizer()
    const {
  return nullptr;
}

bool HandwritingLibraryFake::LoadHandwritingRecognizer(
    HandwritingRecognizer recognizer, HandwritingRecognizerSpecPtr spec) const {
  return true;
}

bool HandwritingLibraryFake::LoadHandwritingRecognizerFromRootFs(
    HandwritingRecognizer recognizer, const std::string& language) const {
  return true;
}

bool HandwritingLibraryFake::RecognizeHandwriting(
    HandwritingRecognizer recognizer,
    const chrome_knowledge::HandwritingRecognizerRequest& request,
    chrome_knowledge::HandwritingRecognizerResult* result) const {
  // Makes result a copy of fake output_proto_. This fuzzes the output
  // conversion code in web_platform_handwriting_proto_mojom_conversion.h/cc.
  result->CopyFrom(output_proto_);
  return true;
}

void HandwritingLibraryFake::DestroyHandwritingRecognizer(
    HandwritingRecognizer recognizer) const {}

void HandwritingLibraryFake::SetOutput(
    const chrome_knowledge::HandwritingRecognizerResult& output) {
  output_proto_.CopyFrom(output);
}

}  // namespace ml
