// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ML_HANDWRITING_RECOGNIZER_IMPL_H_
#define ML_HANDWRITING_RECOGNIZER_IMPL_H_

#include <base/functional/callback_forward.h>
#include <mojo/public/cpp/bindings/pending_receiver.h>
#include <mojo/public/cpp/bindings/receiver.h>

#include "chrome/knowledge/handwriting/handwriting_interface.pb.h"
#include "ml/handwriting.h"
#include "ml/mojom/handwriting_recognizer.mojom.h"

namespace ml {

// The implementation of HandwritingRecognizer.
class HandwritingRecognizerImpl
    : public chromeos::machine_learning::mojom::HandwritingRecognizer {
 public:
  // Constructs a HandwritingRecognizerImpl; and set disconnect handler so
  // that the HandwritingRecognizerImpl will be deleted when the mojom
  // connection is destroyed.
  // Returns whether the object is create successfully.
  static bool Create(
      chromeos::machine_learning::mojom::HandwritingRecognizerSpecPtr spec,
      mojo::PendingReceiver<
          chromeos::machine_learning::mojom::HandwritingRecognizer> receiver);

  // Called when mojom connection is destroyed.
  ~HandwritingRecognizerImpl();

 private:
  // Creates a HandwritingRecognizer and Binds to `receiver` inside so that
  // Recognize can be called on the other side for a particular handwriting
  // reconition query.
  HandwritingRecognizerImpl(
      chromeos::machine_learning::mojom::HandwritingRecognizerSpecPtr spec,
      mojo::PendingReceiver<
          chromeos::machine_learning::mojom::HandwritingRecognizer> receiver);
  HandwritingRecognizerImpl(const HandwritingRecognizerImpl&) = delete;
  HandwritingRecognizerImpl& operator=(const HandwritingRecognizerImpl&) =
      delete;

  // mojom::HandwritingRecognizer:
  void Recognize(
      chromeos::machine_learning::mojom::HandwritingRecognitionQueryPtr query,
      RecognizeCallback callback) override;

  bool successfully_loaded_;
  // Pointer to the internal implementation of HandwritingRecognizer inside
  // the HandwritingLibrary.
  ::HandwritingRecognizer recognizer_;
  const ml::HandwritingLibrary* const library_;

  mojo::Receiver<chromeos::machine_learning::mojom::HandwritingRecognizer>
      receiver_;
};

}  // namespace ml

#endif  // ML_HANDWRITING_RECOGNIZER_IMPL_H_
