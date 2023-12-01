// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ML_WEB_PLATFORM_HANDWRITING_PROTO_MOJOM_CONVERSION_H_
#define ML_WEB_PLATFORM_HANDWRITING_PROTO_MOJOM_CONVERSION_H_

#include <optional>
#include <vector>

#include "chrome/knowledge/handwriting/handwriting_interface.pb.h"
#include "ml/mojom/web_platform_handwriting.mojom.h"

namespace ml {

// Converts vector<web_platform::mojom::HandwritingStroke> and
// chromeos::machine_learning::web_platform::mojom::HandwritingHints into
// chrome_knowledge::HandwritingRecognizerRequest proto.
chrome_knowledge::HandwritingRecognizerRequest
WebPlatformHandwritingStrokesAndHintsToProto(
    const std::vector<
        chromeos::machine_learning::web_platform::mojom::HandwritingStrokePtr>&
        strokes,
    const chromeos::machine_learning::web_platform::mojom::HandwritingHintsPtr&
        hints);

// Converts chrome_knowledge::HandwritingRecognizerResult proto into a vector
// of web_platform::mojom::HandwritingPredictionPtr.
std::optional<std::vector<
    chromeos::machine_learning::web_platform::mojom::HandwritingPredictionPtr>>
WebPlatformHandwritingPredictionsFromProto(
    const std::vector<
        chromeos::machine_learning::web_platform::mojom::HandwritingStrokePtr>&
        strokes,
    const chrome_knowledge::HandwritingRecognizerResult& result_proto);

}  // namespace ml

#endif  // ML_WEB_PLATFORM_HANDWRITING_PROTO_MOJOM_CONVERSION_H_
