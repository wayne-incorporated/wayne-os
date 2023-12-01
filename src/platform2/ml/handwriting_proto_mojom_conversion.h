// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ML_HANDWRITING_PROTO_MOJOM_CONVERSION_H_
#define ML_HANDWRITING_PROTO_MOJOM_CONVERSION_H_

#include "chrome/knowledge/handwriting/handwriting_interface.pb.h"
#include "ml/mojom/handwriting_recognizer.mojom.h"

namespace ml {

// Converts mojom::HandwritingRecognitionQueryPtr into
// chrome_knowledge::HandwritingRecognizerRequest proto.
chrome_knowledge::HandwritingRecognizerRequest
HandwritingRecognitionQueryToProto(
    chromeos::machine_learning::mojom::HandwritingRecognitionQueryPtr query);

// Converts chrome_knowledge::HandwritingRecognizerRequest proto into
// mojom::HandwritingRecognitionQueryPtr.
chromeos::machine_learning::mojom::HandwritingRecognitionQueryPtr
HandwritingRecognitionQueryFromProtoForTesting(
    const chrome_knowledge::HandwritingRecognizerRequest& request_proto);

// Converts chrome_knowledge::HandwritingRecognizerResult proto into
// mojom::HandwritingRecognizerResultPtr.
chromeos::machine_learning::mojom::HandwritingRecognizerResultPtr
HandwritingRecognizerResultFromProto(
    const chrome_knowledge::HandwritingRecognizerResult& result_proto);

}  // namespace ml

#endif  // ML_HANDWRITING_PROTO_MOJOM_CONVERSION_H_
