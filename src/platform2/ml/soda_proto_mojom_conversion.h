// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ML_SODA_PROTO_MOJOM_CONVERSION_H_
#define ML_SODA_PROTO_MOJOM_CONVERSION_H_

#include "chrome/knowledge/soda/extended_soda_api.pb.h"
#include "ml/mojom/soda.mojom.h"

namespace ml {
chromeos::machine_learning::mojom::SpeechRecognizerEventPtr
SpeechRecognizerEventFromProto(
    const speech::soda::chrome::SodaResponse& soda_response);

bool IsStopSodaResponse(
    const speech::soda::chrome::SodaResponse& soda_response);
bool IsStartSodaResponse(
    const speech::soda::chrome::SodaResponse& soda_response);
bool IsShutdownSodaResponse(
    const speech::soda::chrome::SodaResponse& soda_response);

// Exposed to ease testing.
namespace internal {
chromeos::machine_learning::mojom::AudioLevelEventPtr AudioLevelEventFromProto(
    const speech::soda::chrome::SodaResponse& soda_response);

chromeos::machine_learning::mojom::PartialResultPtr PartialResultFromProto(
    const speech::soda::chrome::SodaResponse& soda_response);

chromeos::machine_learning::mojom::PartialResultPtr
PartialResultFromPrefetchProto(
    const speech::soda::chrome::SodaResponse& soda_response);

chromeos::machine_learning::mojom::FinalResultPtr FinalResultFromProto(
    const speech::soda::chrome::SodaResponse& soda_response);

chromeos::machine_learning::mojom::EndpointerEventPtr EndpointerEventFromProto(
    const speech::soda::chrome::SodaResponse& soda_response);

chromeos::machine_learning::mojom::TimingInfoPtr
TimingInfoFromTimingMetricsProto(
    const speech::soda::chrome::TimingMetrics& timing_metric);

}  // namespace internal

}  // namespace ml

#endif  // ML_SODA_PROTO_MOJOM_CONVERSION_H_
