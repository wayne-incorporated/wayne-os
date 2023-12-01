// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ML_TEXT_SUGGESTER_PROTO_MOJOM_CONVERSION_H_
#define ML_TEXT_SUGGESTER_PROTO_MOJOM_CONVERSION_H_

#include "chrome/knowledge/suggest/text_suggester_interface.pb.h"
#include "ml/mojom/text_suggester.mojom.h"

namespace ml {

// Converts mojom::TextSuggesterQueryPtr into
// chrome_knowledge::TextSuggesterRequest proto.
chrome_knowledge::TextSuggesterRequest TextSuggesterQueryToProto(
    chromeos::machine_learning::mojom::TextSuggesterQueryPtr query);

// Converts chrome_knowledge::TextSuggesterResult proto into
// mojom::TextSuggesterResultPtr.
chromeos::machine_learning::mojom::TextSuggesterResultPtr
TextSuggesterResultFromProto(
    const chrome_knowledge::TextSuggesterResult& result_proto);

// Converts mojom::MultiWordExperimentGroup into
// chrome_knowledge::MultiWordExperiment proto.
chrome_knowledge::MultiWordExperiment MultiWordExperimentGroupToProto(
    chromeos::machine_learning::mojom::MultiWordExperimentGroup experiment);

}  // namespace ml

#endif  // ML_TEXT_SUGGESTER_PROTO_MOJOM_CONVERSION_H_
