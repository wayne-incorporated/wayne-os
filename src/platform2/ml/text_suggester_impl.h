// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ML_TEXT_SUGGESTER_IMPL_H_
#define ML_TEXT_SUGGESTER_IMPL_H_

#include <base/functional/callback_forward.h>
#include <mojo/public/cpp/bindings/pending_receiver.h>
#include <mojo/public/cpp/bindings/receiver.h>

#include "chrome/knowledge/suggest/text_suggester_interface.pb.h"
#include "ml/mojom/text_suggester.mojom.h"
#include "ml/text_suggestions.h"

namespace ml {

class TextSuggesterImpl
    : public chromeos::machine_learning::mojom::TextSuggester {
 public:
  // Constructs a TextSuggesterImpl; and set disconnect handler so
  // that the TextSuggesterImpl will be deleted when the mojom connection is
  // destroyed. Returns whether the object is created successfully.
  static bool Create(
      mojo::PendingReceiver<chromeos::machine_learning::mojom::TextSuggester>
          receiver,
      chromeos::machine_learning::mojom::TextSuggesterSpecPtr spec);

  // Called when mojom connection is destroyed.
  ~TextSuggesterImpl();

 private:
  // Creates a TextSuggester and Binds to `receiver` inside so that
  // Suggest can be called on the other side for a particular text
  // suggester query.

  TextSuggesterImpl(
      mojo::PendingReceiver<chromeos::machine_learning::mojom::TextSuggester>
          receiver,
      chromeos::machine_learning::mojom::TextSuggesterSpecPtr spec);
  TextSuggesterImpl(const TextSuggesterImpl&) = delete;
  TextSuggesterImpl& operator=(const TextSuggesterImpl&) = delete;

  // mojom::TextSuggester
  void Suggest(chromeos::machine_learning::mojom::TextSuggesterQueryPtr query,
               SuggestCallback callback) override;

  bool successfully_loaded_;

  // Pointer to the internal implementation of TextSuggester
  // inside of TextSuggestions.
  ::TextSuggester suggester_;
  const ml::TextSuggestions* const library_;

  mojo::Receiver<chromeos::machine_learning::mojom::TextSuggester> receiver_;
};

};  // namespace ml

#endif  // ML_TEXT_SUGGESTER_IMPL_H_
