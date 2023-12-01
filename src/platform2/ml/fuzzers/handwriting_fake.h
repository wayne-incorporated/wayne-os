// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ML_FUZZERS_HANDWRITING_FAKE_H_
#define ML_FUZZERS_HANDWRITING_FAKE_H_

#include "ml/handwriting.h"

#include <string>

#include <fuzzer/FuzzedDataProvider.h>

namespace ml {

// This is the fake impl of HandwritingLibrary, for use in
// web_platform_handwriting_fuzzer only.
// Handles method calls like GetStatus, LoadHandwritingRecognizer by simply
// returning Status::kOk/true;
// Handles CreateHandwritingRecognizer by returning a nullptr, and does nothing
// when DestroyHandwritingRecognizer is called.
// Handles RecognizeHandwriting method call by returning the value specified by
// a previous call to SetOutput.
class HandwritingLibraryFake : public HandwritingLibrary {
 public:
  HandwritingLibraryFake();
  HandwritingLibraryFake(const HandwritingLibraryFake&) = delete;
  HandwritingLibraryFake& operator=(const HandwritingLibraryFake&) = delete;

  ~HandwritingLibraryFake() override;

  // HandwritingLibrary:
  Status GetStatus() const override;
  HandwritingRecognizer CreateHandwritingRecognizer() const override;
  bool LoadHandwritingRecognizer(
      HandwritingRecognizer recognizer,
      chromeos::machine_learning::mojom::HandwritingRecognizerSpecPtr spec)
      const override;
  bool LoadHandwritingRecognizerFromRootFs(
      HandwritingRecognizer recognizer,
      const std::string& language) const override;
  bool RecognizeHandwriting(
      HandwritingRecognizer recognizer,
      const chrome_knowledge::HandwritingRecognizerRequest& request,
      chrome_knowledge::HandwritingRecognizerResult* result) const override;
  void DestroyHandwritingRecognizer(
      HandwritingRecognizer recognizer) const override;

  // Sets the fake result proto that will be used for subsequent calls
  // RecognizeHandwriting.
  void SetOutput(const chrome_knowledge::HandwritingRecognizerResult& output);

 private:
  chrome_knowledge::HandwritingRecognizerResult output_proto_;
};

}  // namespace ml

#endif  // ML_FUZZERS_HANDWRITING_FAKE_H_
