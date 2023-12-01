// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This file contains the implementation of `SodaRecognizerImpl` when SODA is
// not intended to be supported.

// Suppress unused-private-field since this fake class impl is deliberately
// non-functional and needn't reference all variables.
#pragma GCC diagnostic ignored "-Wunused-private-field"

#include "ml/soda_recognizer_impl.h"

namespace ml {
namespace {

using ::chromeos::machine_learning::mojom::EndpointReason;
using ::chromeos::machine_learning::mojom::FinalResult;
using ::chromeos::machine_learning::mojom::FinalResultPtr;
using ::chromeos::machine_learning::mojom::SodaClient;
using ::chromeos::machine_learning::mojom::SodaConfigPtr;
using ::chromeos::machine_learning::mojom::SodaRecognizer;
using ::chromeos::machine_learning::mojom::SpeechRecognizerEvent;
using ::chromeos::machine_learning::mojom::SpeechRecognizerEventPtr;

constexpr char kOnDeviceSpeechNotSupportedMessage[] =
    "On-device speech is not supported.";

void SodaCallback(const char* soda_response_str,
                  int size,
                  void* soda_recognizer_impl) {
  reinterpret_cast<SodaRecognizerImpl*>(soda_recognizer_impl)
      ->OnSodaEvent(std::string());
}

}  // namespace

bool SodaRecognizerImpl::Create(
    SodaConfigPtr spec,
    mojo::PendingRemote<SodaClient> soda_client,
    mojo::PendingReceiver<SodaRecognizer> soda_recognizer) {
  auto recognizer_impl = new SodaRecognizerImpl(
      std::move(spec), std::move(soda_client), std::move(soda_recognizer));
  // Set the disconnection handler to strongly bind `recognizer_impl` to delete
  // `recognizer_impl` when the connection is gone.
  recognizer_impl->receiver_.set_disconnect_handler(base::BindOnce(
      [](const SodaRecognizerImpl* const recognizer_impl) {
        delete recognizer_impl;
      },
      base::Unretained(recognizer_impl)));

  return recognizer_impl->successfully_loaded_;
}

void SodaRecognizerImpl::AddAudio(const std::vector<uint8_t>& audio) {
  // Immediately sends the error message to client.
  SodaCallback(nullptr, 0, this);
}

void SodaRecognizerImpl::Stop() {
  // Immediately sends the error message to client.
  SodaCallback(nullptr, 0, this);
}

void SodaRecognizerImpl::Start() {
  // Immediately sends the error message to client.
  SodaCallback(nullptr, 0, this);
}

void SodaRecognizerImpl::MarkDone() {
  // Immediately sends the error message to client.
  SodaCallback(nullptr, 0, this);
}

void SodaRecognizerImpl::OnSodaEvent(const std::string& ignored_response) {
  SpeechRecognizerEventPtr event;
  FinalResultPtr final_result = FinalResult::New();
  final_result->final_hypotheses.push_back(kOnDeviceSpeechNotSupportedMessage);
  final_result->endpoint_reason = EndpointReason::ENDPOINT_UNKNOWN;
  event = SpeechRecognizerEvent::NewFinalResult(std::move(final_result));
  client_remote_->OnSpeechRecognizerEvent(std::move(event));
}

SodaRecognizerImpl::SodaRecognizerImpl(
    SodaConfigPtr spec,
    mojo::PendingRemote<SodaClient> soda_client,
    mojo::PendingReceiver<SodaRecognizer> soda_recognizer)
    : successfully_loaded_(true),
      recognizer_(nullptr),
      receiver_(this, std::move(soda_recognizer)),
      client_remote_(std::move(soda_client)) {}

SodaRecognizerImpl::~SodaRecognizerImpl() = default;

}  // namespace ml
