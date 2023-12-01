// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <gtest/gtest.h>
#include <string>
#include <utility>

#include "ml/soda_proto_mojom_conversion.h"

namespace ml {

using speech::soda::chrome::SodaResponse;
using speech::soda::chrome::TimingMetrics;

TEST(SodaProtoMojomConversionTest, AudioLevelsTest) {
  SodaResponse response;
  response.set_soda_type(SodaResponse::AUDIO_LEVEL);
  response.mutable_audio_level_info()->set_audio_level(0.1);
  response.mutable_audio_level_info()->set_rms(0.3);
  auto actual_audio_mojom = internal::AudioLevelEventFromProto(response);

  auto expected_audio_mojom =
      chromeos::machine_learning::mojom::AudioLevelEvent::New();
  expected_audio_mojom->rms = 0.3;
  expected_audio_mojom->audio_level = 0.1;

  EXPECT_TRUE(actual_audio_mojom.Equals(expected_audio_mojom));

  // now for the full mojom
  auto actual_mojom = SpeechRecognizerEventFromProto(response);
  chromeos::machine_learning::mojom::SpeechRecognizerEventPtr expected_mojom;
  expected_mojom =
      chromeos::machine_learning::mojom::SpeechRecognizerEvent::NewAudioEvent(
          std::move(expected_audio_mojom));
  EXPECT_TRUE(actual_mojom.Equals(expected_mojom));

  // Let's check the other tests.
  EXPECT_FALSE(IsStopSodaResponse(response));
  EXPECT_FALSE(IsStartSodaResponse(response));
  EXPECT_FALSE(IsShutdownSodaResponse(response));
}

TEST(SodaProtoMojomConversionTest, PartialResultsTest) {
  SodaResponse response;
  response.set_soda_type(SodaResponse::RECOGNITION);
  auto* rec = response.mutable_recognition_result();
  rec->add_hypothesis("first hyp");
  rec->add_hypothesis("second hyp");
  rec->set_result_type(speech::soda::chrome::SodaRecognitionResult::PARTIAL);
  rec->mutable_timing_metrics()->set_audio_start_epoch_usec(5);

  auto expected_rec_mojom =
      chromeos::machine_learning::mojom::PartialResult::New();
  expected_rec_mojom->partial_text.push_back("first hyp");
  expected_rec_mojom->partial_text.push_back("second hyp");
  auto expected_timing_mojom =
      chromeos::machine_learning::mojom::TimingInfo::New();
  expected_timing_mojom->audio_start_epoch =
      base::Time::FromDeltaSinceWindowsEpoch(base::Microseconds(5));
  expected_rec_mojom->timing_event = std::move(expected_timing_mojom);
  auto actual_rec_mojom = internal::PartialResultFromProto(response);
  EXPECT_TRUE(actual_rec_mojom.Equals(expected_rec_mojom));

  // now for the full mojom
  auto actual_mojom = SpeechRecognizerEventFromProto(response);
  auto expected_mojom = chromeos::machine_learning::mojom::
      SpeechRecognizerEvent::NewPartialResult(std::move(actual_rec_mojom));
  EXPECT_TRUE(actual_mojom.Equals(expected_mojom));

  // Let's check the other tests.
  EXPECT_FALSE(IsStopSodaResponse(response));
  EXPECT_FALSE(IsStartSodaResponse(response));
  EXPECT_FALSE(IsShutdownSodaResponse(response));
}

TEST(SodaProtoMojomConversionTest, PrefetchResultsTest) {
  // We decided to treat a PREFETCH as a Partial.
  SodaResponse response;
  response.set_soda_type(SodaResponse::RECOGNITION);
  auto* rec = response.mutable_recognition_result();
  rec->add_hypothesis("first hyp");
  rec->add_hypothesis("second hyp");
  rec->set_result_type(speech::soda::chrome::SodaRecognitionResult::PREFETCH);

  auto expected_rec_mojom =
      chromeos::machine_learning::mojom::PartialResult::New();
  expected_rec_mojom->partial_text.push_back("first hyp");
  expected_rec_mojom->partial_text.push_back("second hyp");
  auto actual_rec_mojom = internal::PartialResultFromPrefetchProto(response);
  EXPECT_TRUE(actual_rec_mojom.Equals(expected_rec_mojom));

  // now for the full mojom
  auto actual_mojom = SpeechRecognizerEventFromProto(response);
  auto expected_mojom = chromeos::machine_learning::mojom::
      SpeechRecognizerEvent::NewPartialResult(std::move(actual_rec_mojom));
  EXPECT_TRUE(actual_mojom.Equals(expected_mojom));

  // Let's check the other tests.
  EXPECT_FALSE(IsStopSodaResponse(response));
  EXPECT_FALSE(IsStartSodaResponse(response));
  EXPECT_FALSE(IsShutdownSodaResponse(response));
}

TEST(SodaProtoMojomConversionTest, FinalResultsWithHypPartTest) {
  SodaResponse response;
  response.set_soda_type(SodaResponse::RECOGNITION);
  auto* rec = response.mutable_recognition_result();
  rec->add_hypothesis("first, hypo.");
  rec->add_hypothesis("second hypo");
  rec->set_result_type(speech::soda::chrome::SodaRecognitionResult::FINAL);
  // Add the hyp parts.
  auto* hyp_part = rec->add_hypothesis_part();
  hyp_part->add_text("first,");
  hyp_part->add_text("first");
  hyp_part->set_alignment_ms(0);

  hyp_part = rec->add_hypothesis_part();
  hyp_part->add_text("hypo.");
  hyp_part->add_text("hypo");
  hyp_part->set_alignment_ms(50);

  auto expected_rec_mojom =
      chromeos::machine_learning::mojom::FinalResult::New();
  expected_rec_mojom->final_hypotheses.push_back("first, hypo.");
  expected_rec_mojom->final_hypotheses.push_back("second hypo");
  expected_rec_mojom->hypothesis_part.emplace();
  auto part = chromeos::machine_learning::mojom::HypothesisPartInResult::New();
  part->text.push_back("first,");
  part->text.push_back("first");
  part->alignment = base::Milliseconds(0);
  expected_rec_mojom->hypothesis_part->push_back(std::move(part));
  part = chromeos::machine_learning::mojom::HypothesisPartInResult::New();
  part->text.push_back("hypo.");
  part->text.push_back("hypo");
  part->alignment = base::Milliseconds(50);
  expected_rec_mojom->hypothesis_part->push_back(std::move(part));

  auto actual_rec_mojom = internal::FinalResultFromProto(response);
  EXPECT_TRUE(actual_rec_mojom.Equals(expected_rec_mojom));
}

TEST(SodaProtoMojomConversionTest, FinalResultsTest) {
  SodaResponse response;
  response.set_soda_type(SodaResponse::RECOGNITION);
  auto* rec = response.mutable_recognition_result();
  rec->add_hypothesis("first hypo");
  rec->add_hypothesis("second hypo");
  rec->set_result_type(speech::soda::chrome::SodaRecognitionResult::FINAL);

  auto expected_rec_mojom =
      chromeos::machine_learning::mojom::FinalResult::New();
  expected_rec_mojom->final_hypotheses.push_back("first hypo");
  expected_rec_mojom->final_hypotheses.push_back("second hypo");
  auto actual_rec_mojom = internal::FinalResultFromProto(response);
  EXPECT_TRUE(actual_rec_mojom.Equals(expected_rec_mojom));

  // now for the full mojom
  auto actual_mojom = SpeechRecognizerEventFromProto(response);
  auto expected_mojom =
      chromeos::machine_learning::mojom::SpeechRecognizerEvent::NewFinalResult(
          std::move(actual_rec_mojom));
  EXPECT_TRUE(actual_mojom.Equals(expected_mojom));

  // Let's check the other tests.
  EXPECT_FALSE(IsStopSodaResponse(response));
  EXPECT_FALSE(IsStartSodaResponse(response));
  EXPECT_FALSE(IsShutdownSodaResponse(response));
}

TEST(SodaProtoMojomConversionTest, EndpointTest) {
  SodaResponse response;
  response.set_soda_type(SodaResponse::ENDPOINT);
  auto* end = response.mutable_endpoint_event();
  end->set_endpoint_type(
      speech::soda::chrome::SodaEndpointEvent::END_OF_SPEECH);

  auto expected_end_mojom =
      chromeos::machine_learning::mojom::EndpointerEvent::New();
  expected_end_mojom->endpointer_type =
      chromeos::machine_learning::mojom::EndpointerType::END_OF_SPEECH;
  auto actual_end_mojom = internal::EndpointerEventFromProto(response);
  EXPECT_TRUE(actual_end_mojom.Equals(expected_end_mojom));

  // now for the full mojom
  auto actual_mojom = SpeechRecognizerEventFromProto(response);
  auto expected_mojom = chromeos::machine_learning::mojom::
      SpeechRecognizerEvent::NewEndpointerEvent(std::move(actual_end_mojom));
  EXPECT_TRUE(actual_mojom.Equals(expected_mojom));

  // Let's check the other tests.
  EXPECT_FALSE(IsStopSodaResponse(response));
  EXPECT_FALSE(IsStartSodaResponse(response));
  EXPECT_FALSE(IsShutdownSodaResponse(response));
}

TEST(SodaProtoMojomConversionTest, BooleanFunctionTest) {
  SodaResponse response;

  response.set_soda_type(SodaResponse::STOP);
  EXPECT_TRUE(IsStopSodaResponse(response));
  EXPECT_FALSE(IsStartSodaResponse(response));
  EXPECT_FALSE(IsShutdownSodaResponse(response));

  response.set_soda_type(SodaResponse::START);
  EXPECT_FALSE(IsStopSodaResponse(response));
  EXPECT_TRUE(IsStartSodaResponse(response));
  EXPECT_FALSE(IsShutdownSodaResponse(response));

  response.set_soda_type(SodaResponse::SHUTDOWN);
  EXPECT_FALSE(IsStopSodaResponse(response));
  EXPECT_FALSE(IsStartSodaResponse(response));
  EXPECT_TRUE(IsShutdownSodaResponse(response));
}

TEST(SodaProtoMojomConversionTest, EmptyTimeTest) {
  TimingMetrics metrics;
  chromeos::machine_learning::mojom::TimingInfoPtr expected_mojom =
      chromeos::machine_learning::mojom::TimingInfo::New();
  auto actual_mojom = internal::TimingInfoFromTimingMetricsProto(metrics);
  EXPECT_TRUE(actual_mojom.Equals(expected_mojom));
}

TEST(SodaProtoMojomConversionTest, FilledTimeTest) {
  TimingMetrics metrics;
  metrics.set_audio_start_epoch_usec(1);
  metrics.set_audio_start_time_usec(2);
  metrics.set_elapsed_wall_time_usec(3);
  metrics.set_event_end_time_usec(4);

  chromeos::machine_learning::mojom::TimingInfoPtr expected_mojom =
      chromeos::machine_learning::mojom::TimingInfo::New();
  expected_mojom->audio_start_epoch =
      base::Time::FromDeltaSinceWindowsEpoch(base::Microseconds(1));
  expected_mojom->audio_start_time = base::Microseconds(2);
  expected_mojom->elapsed_wall_time = base::Microseconds(3);
  expected_mojom->event_end_time = base::Microseconds(4);

  auto actual_mojom = internal::TimingInfoFromTimingMetricsProto(metrics);
  EXPECT_TRUE(actual_mojom.Equals(expected_mojom));
}

}  // namespace ml
