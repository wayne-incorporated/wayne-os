// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ML_GRAMMAR_CHECKER_IMPL_H_
#define ML_GRAMMAR_CHECKER_IMPL_H_

#include <base/functional/callback_forward.h>
#include <mojo/public/cpp/bindings/pending_receiver.h>
#include <mojo/public/cpp/bindings/receiver.h>

#include "chrome/knowledge/grammar/grammar_interface.pb.h"
#include "ml/grammar_library.h"
#include "ml/mojom/grammar_checker.mojom.h"

namespace ml {

class GrammarCheckerImpl
    : public chromeos::machine_learning::mojom::GrammarChecker {
 public:
  // Constructs a GrammarCheckerImpl; and set disconnect handler so that the
  // GrammarCheckerImpl will be deleted when the mojom connection is destroyed.
  // Returns whether the object is create successfully.
  static bool Create(
      mojo::PendingReceiver<chromeos::machine_learning::mojom::GrammarChecker>
          receiver);

  // Called when mojom connection is destroyed.
  ~GrammarCheckerImpl();

 private:
  // Creates a GrammarChecker and Binds to `receiver` inside so that Check can
  // be called on the other side for a particular grammar check query.
  GrammarCheckerImpl(
      mojo::PendingReceiver<chromeos::machine_learning::mojom::GrammarChecker>
          receiver);
  GrammarCheckerImpl(const GrammarCheckerImpl&) = delete;
  GrammarCheckerImpl& operator=(const GrammarCheckerImpl&) = delete;

  // mojom::GrammarChecker
  void Check(chromeos::machine_learning::mojom::GrammarCheckerQueryPtr query,
             CheckCallback callback) override;

  bool successfully_loaded_;

  // Pointer to the internal implementation of GrammarChecker inside the
  // GrammarLibrary.
  ::GrammarChecker checker_;
  const ml::GrammarLibrary* const library_;

  mojo::Receiver<chromeos::machine_learning::mojom::GrammarChecker> receiver_;
};

}  // namespace ml

#endif  // ML_GRAMMAR_CHECKER_IMPL_H_
