// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ML_GRAMMAR_PROTO_MOJOM_CONVERSION_H_
#define ML_GRAMMAR_PROTO_MOJOM_CONVERSION_H_

#include "chrome/knowledge/grammar/grammar_interface.pb.h"
#include "ml/mojom/grammar_checker.mojom.h"

namespace ml {

// Converts mojom::GrammarCheckerQueryPtr into
// chrome_knowledge::GrammarCheckerRequest proto.
chrome_knowledge::GrammarCheckerRequest GrammarCheckerQueryToProto(
    chromeos::machine_learning::mojom::GrammarCheckerQueryPtr query);

// Converts chrome_knowledge::GrammarCheckerRequest proto into
// mojom::GrammarCheckerQueryPtr.
chromeos::machine_learning::mojom::GrammarCheckerQueryPtr
GrammarCheckerQueryFromProtoForTesting(
    const chrome_knowledge::GrammarCheckerRequest& request_proto);

// Converts chrome_knowledge::GrammarCheckerResult proto into
// mojom::GrammarCheckerResultPtr.
chromeos::machine_learning::mojom::GrammarCheckerResultPtr
GrammarCheckerResultFromProto(
    const chrome_knowledge::GrammarCheckerResult& result_proto);

}  // namespace ml

#endif  // ML_GRAMMAR_PROTO_MOJOM_CONVERSION_H_
