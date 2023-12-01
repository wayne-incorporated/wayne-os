// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ML_WEB_PLATFORM_HANDWRITING_RECOGNIZER_IMPL_H_
#define ML_WEB_PLATFORM_HANDWRITING_RECOGNIZER_IMPL_H_

#include <vector>

#include <mojo/public/cpp/bindings/pending_receiver.h>
#include <mojo/public/cpp/bindings/receiver.h>

#include "chrome/knowledge/handwriting/handwriting_interface.pb.h"
#include "ml/handwriting.h"
#include "ml/mojom/web_platform_handwriting.mojom.h"

namespace ml {

class WebPlatformHandwritingRecognizerImpl
    : public chromeos::machine_learning::web_platform::mojom::
          HandwritingRecognizer {
 public:
  // Constructs a WebPlatformHandwritingRecognizerImpl; and set disconnect
  // handler so that the WebPlatformHandwritingRecognizerImpl will be deleted
  // when the mojom connection is destroyed. Returns whether the object is
  // create successfully.
  static bool Create(
      chromeos::machine_learning::web_platform::mojom::
          HandwritingModelConstraintPtr constraint,
      mojo::PendingReceiver<chromeos::machine_learning::web_platform::mojom::
                                HandwritingRecognizer> receiver);

  // Called when mojom connection is destroyed.
  ~WebPlatformHandwritingRecognizerImpl() override;

 private:
  // Creates a HandwritingRecognizer and Binds to `receiver` inside so that
  // Recognize can be called on the other side for a particular handwriting
  // reconition query.
  WebPlatformHandwritingRecognizerImpl(
      chromeos::machine_learning::web_platform::mojom::
          HandwritingModelConstraintPtr constraint,
      mojo::PendingReceiver<chromeos::machine_learning::web_platform::mojom::
                                HandwritingRecognizer> receiver);
  WebPlatformHandwritingRecognizerImpl(
      const WebPlatformHandwritingRecognizerImpl&) = delete;
  // web_platform::mojom::HandwritingRecognizer:
  void GetPrediction(
      std::vector<
          chromeos::machine_learning::web_platform::mojom::HandwritingStrokePtr>
          strokes,
      chromeos::machine_learning::web_platform::mojom::HandwritingHintsPtr
          hints,
      GetPredictionCallback callback) override;

  bool successfully_loaded_;
  // Pointer to the internal implementation of HandwritingRecognizer inside
  // the HandwritingLibrary.
  ::HandwritingRecognizer recognizer_;
  const ml::HandwritingLibrary* const library_;

  mojo::Receiver<
      chromeos::machine_learning::web_platform::mojom::HandwritingRecognizer>
      receiver_;
};

}  // namespace ml

#endif  // ML_WEB_PLATFORM_HANDWRITING_RECOGNIZER_IMPL_H_
