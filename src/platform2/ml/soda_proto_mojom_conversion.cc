// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "ml/soda_proto_mojom_conversion.h"

#include <string>
#include <utility>
#include <base/logging.h>
#include <base/time/time.h>

using chromeos::machine_learning::mojom::EndpointerType;
using speech::soda::chrome::SodaEndpointEvent;
using speech::soda::chrome::SodaRecognitionResult;
using speech::soda::chrome::SodaResponse;

namespace ml {

chromeos::machine_learning::mojom::SpeechRecognizerEventPtr
SpeechRecognizerEventFromProto(const SodaResponse& soda_response) {
  chromeos::machine_learning::mojom::SpeechRecognizerEventPtr
      speech_recognizer_event;
  if (soda_response.soda_type() == SodaResponse::AUDIO_LEVEL) {
    auto audio_level_event = internal::AudioLevelEventFromProto(soda_response);
    speech_recognizer_event =
        chromeos::machine_learning::mojom::SpeechRecognizerEvent::NewAudioEvent(
            std::move(audio_level_event));
  } else if (soda_response.soda_type() == SodaResponse::RECOGNITION) {
    const auto& rec_result = soda_response.recognition_result();
    if (rec_result.result_type() == SodaRecognitionResult::PARTIAL) {
      speech_recognizer_event =
          chromeos::machine_learning::mojom::SpeechRecognizerEvent::
              NewPartialResult(internal::PartialResultFromProto(soda_response));
    } else if (rec_result.result_type() == SodaRecognitionResult::FINAL) {
      speech_recognizer_event =
          chromeos::machine_learning::mojom::SpeechRecognizerEvent::
              NewFinalResult(internal::FinalResultFromProto(soda_response));
    } else if (rec_result.result_type() == SodaRecognitionResult::PREFETCH) {
      speech_recognizer_event = chromeos::machine_learning::mojom::
          SpeechRecognizerEvent::NewPartialResult(
              internal::PartialResultFromPrefetchProto(soda_response));
    } else {
      LOG(ERROR) << "Only partial/prefetch/final results are supported, not "
                 << speech::soda::chrome::SodaRecognitionResult_ResultType_Name(
                        rec_result.result_type());
    }
  } else if (soda_response.soda_type() == SodaResponse::ENDPOINT) {
    speech_recognizer_event = chromeos::machine_learning::mojom::
        SpeechRecognizerEvent::NewEndpointerEvent(
            internal::EndpointerEventFromProto(soda_response));
  } else {
    LOG(DFATAL) << "Unexpected type of soda type to convert: "
                << speech::soda::chrome::SodaResponse_SodaMessageType_Name(
                       soda_response.soda_type());
  }
  return speech_recognizer_event;
}

bool IsStopSodaResponse(const SodaResponse& soda_response) {
  return soda_response.soda_type() == SodaResponse::STOP;
}
bool IsStartSodaResponse(const SodaResponse& soda_response) {
  return soda_response.soda_type() == SodaResponse::START;
}

bool IsShutdownSodaResponse(const SodaResponse& soda_response) {
  return soda_response.soda_type() == SodaResponse::SHUTDOWN;
}

namespace internal {
chromeos::machine_learning::mojom::AudioLevelEventPtr AudioLevelEventFromProto(
    const SodaResponse& soda_response) {
  auto audio_level_event =
      chromeos::machine_learning::mojom::AudioLevelEvent::New();
  if (!soda_response.has_audio_level_info()) {
    LOG(DFATAL) << "Should only call this method if audio level info is set.";
    return audio_level_event;
  }
  const auto& audio_level_info = soda_response.audio_level_info();
  audio_level_event->rms = audio_level_info.rms();
  audio_level_event->audio_level = audio_level_info.audio_level();

  // TODO(robsc): add support for time here.
  return audio_level_event;
}

chromeos::machine_learning::mojom::PartialResultPtr
PartialResultFromPrefetchProto(
    const speech::soda::chrome::SodaResponse& soda_response) {
  auto partial_result = chromeos::machine_learning::mojom::PartialResult::New();
  if (!soda_response.has_recognition_result() ||
      soda_response.soda_type() != SodaResponse::RECOGNITION ||
      soda_response.recognition_result().result_type() !=
          SodaRecognitionResult::PREFETCH) {
    LOG(DFATAL) << "Should only be called when there's a prefetch result.";
  }
  for (const std::string& hyp :
       soda_response.recognition_result().hypothesis()) {
    partial_result->partial_text.push_back(hyp);
  }
  return partial_result;
}

chromeos::machine_learning::mojom::PartialResultPtr PartialResultFromProto(
    const SodaResponse& soda_response) {
  auto partial_result = chromeos::machine_learning::mojom::PartialResult::New();
  if (!soda_response.has_recognition_result() ||
      soda_response.soda_type() != SodaResponse::RECOGNITION ||
      soda_response.recognition_result().result_type() !=
          SodaRecognitionResult::PARTIAL) {
    LOG(DFATAL)
        << "Should only call when there's a partial recognition result.";
    return partial_result;
  }
  for (const std::string& hyp :
       soda_response.recognition_result().hypothesis()) {
    partial_result->partial_text.push_back(hyp);
  }
  if (soda_response.recognition_result().has_timing_metrics()) {
    partial_result->timing_event = TimingInfoFromTimingMetricsProto(
        soda_response.recognition_result().timing_metrics());
  }
  return partial_result;
}

chromeos::machine_learning::mojom::FinalResultPtr FinalResultFromProto(
    const SodaResponse& soda_response) {
  auto final_result = chromeos::machine_learning::mojom::FinalResult::New();
  if (!soda_response.has_recognition_result() ||
      soda_response.soda_type() != SodaResponse::RECOGNITION ||
      soda_response.recognition_result().result_type() !=
          SodaRecognitionResult::FINAL) {
    LOG(DFATAL) << "Should only call when there's a final recognition result.";
    return final_result;
  }
  for (const std::string& hyp :
       soda_response.recognition_result().hypothesis()) {
    final_result->final_hypotheses.push_back(hyp);
  }
  if (soda_response.recognition_result().hypothesis_part_size() > 0) {
    final_result->hypothesis_part.emplace();

    for (const auto& hypothesis_part :
         soda_response.recognition_result().hypothesis_part()) {
      auto part_in_result =
          chromeos::machine_learning::mojom::HypothesisPartInResult::New();
      for (const std::string& part : hypothesis_part.text()) {
        part_in_result->text.push_back(part);
      }
      part_in_result->alignment =
          base::Milliseconds(hypothesis_part.alignment_ms());
      final_result->hypothesis_part->push_back(std::move(part_in_result));
    }
  }
  // TODO(robsc): Add endpoint reason when available from
  final_result->endpoint_reason =
      chromeos::machine_learning::mojom::EndpointReason::ENDPOINT_UNKNOWN;

  if (soda_response.recognition_result().has_timing_metrics()) {
    final_result->timing_event = TimingInfoFromTimingMetricsProto(
        soda_response.recognition_result().timing_metrics());
  }
  return final_result;
}

chromeos::machine_learning::mojom::EndpointerEventPtr EndpointerEventFromProto(
    const SodaResponse& soda_response) {
  auto endpointer_event =
      chromeos::machine_learning::mojom::EndpointerEvent::New();
  if (!soda_response.has_endpoint_event() ||
      soda_response.soda_type() != SodaResponse::ENDPOINT) {
    LOG(DFATAL) << "Shouldn't have been called without an endpoint event.";
    return endpointer_event;
  }
  const auto& soda_endpoint_event = soda_response.endpoint_event();
  // Set the type, we don't have the timing right here.
  switch (soda_endpoint_event.endpoint_type()) {
    case SodaEndpointEvent::START_OF_SPEECH:
      endpointer_event->endpointer_type = EndpointerType::START_OF_SPEECH;
      break;
    case SodaEndpointEvent::END_OF_SPEECH:
      endpointer_event->endpointer_type = EndpointerType::END_OF_SPEECH;
      break;
    case SodaEndpointEvent::END_OF_AUDIO:
      endpointer_event->endpointer_type = EndpointerType::END_OF_AUDIO;
      break;
    case SodaEndpointEvent::END_OF_UTTERANCE:
      endpointer_event->endpointer_type = EndpointerType::END_OF_UTTERANCE;
      break;
    default:
      LOG(DFATAL) << "Unknown endpointer type.";
      endpointer_event->endpointer_type = EndpointerType::END_OF_UTTERANCE;
      break;
  }
  if (soda_response.recognition_result().has_timing_metrics()) {
    endpointer_event->timing_event = TimingInfoFromTimingMetricsProto(
        soda_response.recognition_result().timing_metrics());
  }
  return endpointer_event;
}

chromeos::machine_learning::mojom::TimingInfoPtr
TimingInfoFromTimingMetricsProto(
    const speech::soda::chrome::TimingMetrics& timing_metric) {
  auto timing_info = chromeos::machine_learning::mojom::TimingInfo::New();
  if (timing_metric.has_audio_start_epoch_usec()) {
    timing_info->audio_start_epoch = base::Time::FromDeltaSinceWindowsEpoch(
        base::Microseconds(timing_metric.audio_start_epoch_usec()));
  }
  if (timing_metric.has_audio_start_time_usec()) {
    timing_info->audio_start_time =
        base::Microseconds(timing_metric.audio_start_time_usec());
  }
  if (timing_metric.has_elapsed_wall_time_usec()) {
    timing_info->elapsed_wall_time =
        base::Microseconds(timing_metric.elapsed_wall_time_usec());
  }
  if (timing_metric.has_event_end_time_usec()) {
    timing_info->event_end_time =
        base::Microseconds(timing_metric.event_end_time_usec());
  }
  return timing_info;
}

}  // namespace internal
}  // namespace ml
