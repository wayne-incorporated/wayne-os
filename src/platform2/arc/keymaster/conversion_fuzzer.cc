// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stddef.h>
#include <stdint.h>

#include <utility>
#include <vector>

#include <base/logging.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <mojo/keymaster.mojom.h>

#include "arc/keymaster/conversion.h"
#include "arc/keymaster/keymaster_logger.h"

class Environment {
 public:
  Environment() { arc::keymaster::KeymasterLogger logger; }
};

std::vector<arc::mojom::KeyParameterPtr> consumeKeyParameters(
    FuzzedDataProvider* fdp) {
  uint8_t size = fdp->ConsumeIntegral<uint8_t>();
  std::vector<arc::mojom::KeyParameterPtr> params(size);

  for (size_t i = 0; i < size; ++i) {
    uint32_t tag = fdp->ConsumeIntegral<uint32_t>();
    arc::mojom::IntegerKeyParamPtr param;

    switch (fdp->ConsumeIntegralInRange<uint8_t>(0, 4)) {
      case 0:
        param =
            arc::mojom::IntegerKeyParam::NewBooleanValue(fdp->ConsumeBool());
        break;
      case 1:
        param = arc::mojom::IntegerKeyParam::NewInteger(
            fdp->ConsumeIntegral<uint32_t>());
        break;
      case 2:
        param = arc::mojom::IntegerKeyParam::NewLongInteger(
            fdp->ConsumeIntegral<uint64_t>());
        break;
      case 3:
        param = arc::mojom::IntegerKeyParam::NewDateTime(
            fdp->ConsumeIntegral<uint64_t>());
        break;
      case 4:
        param = arc::mojom::IntegerKeyParam::NewBlob(
            fdp->ConsumeBytes<uint8_t>(fdp->ConsumeIntegral<uint8_t>()));
        break;
    }

    params[i] = arc::mojom::KeyParameter::New(tag, std::move(param));
  }

  return params;
}

void fuzzGetKeyCharacteristics(FuzzedDataProvider* fdp) {
  auto input = arc::mojom::GetKeyCharacteristicsRequest::New(
      fdp->ConsumeBytes<uint8_t>(fdp->ConsumeIntegral<uint8_t>()),
      fdp->ConsumeBytes<uint8_t>(fdp->ConsumeIntegral<uint8_t>()),
      fdp->ConsumeBytes<uint8_t>(fdp->ConsumeIntegral<uint8_t>()));

  arc::keymaster::MakeGetKeyCharacteristicsRequest(input);
}

void fuzzGenerateKey(FuzzedDataProvider* fdp) {
  arc::keymaster::MakeGenerateKeyRequest(consumeKeyParameters(fdp));
}

void fuzzImportKey(FuzzedDataProvider* fdp) {
  auto input = arc::mojom::ImportKeyRequest::New(
      consumeKeyParameters(fdp),
      static_cast<arc::mojom::KeyFormat>(fdp->ConsumeIntegral<uint32_t>()),
      fdp->ConsumeBytes<uint8_t>(fdp->ConsumeIntegral<uint8_t>()));

  arc::keymaster::MakeImportKeyRequest(input);
}

void fuzzExportKey(FuzzedDataProvider* fdp) {
  auto input = arc::mojom::ExportKeyRequest::New(
      static_cast<arc::mojom::KeyFormat>(fdp->ConsumeIntegral<uint32_t>()),
      fdp->ConsumeBytes<uint8_t>(fdp->ConsumeIntegral<uint8_t>()),
      fdp->ConsumeBytes<uint8_t>(fdp->ConsumeIntegral<uint8_t>()),
      fdp->ConsumeBytes<uint8_t>(fdp->ConsumeIntegral<uint8_t>()));

  arc::keymaster::MakeExportKeyRequest(input);
}

void fuzzAttestKey(FuzzedDataProvider* fdp) {
  auto input = arc::mojom::AttestKeyRequest::New(
      fdp->ConsumeBytes<uint8_t>(fdp->ConsumeIntegral<uint8_t>()),
      consumeKeyParameters(fdp));

  arc::keymaster::MakeAttestKeyRequest(input);
}

void fuzzUpgradeKeyRequest(FuzzedDataProvider* fdp) {
  auto input = arc::mojom::UpgradeKeyRequest::New(
      fdp->ConsumeBytes<uint8_t>(fdp->ConsumeIntegral<uint8_t>()),
      consumeKeyParameters(fdp));

  arc::keymaster::MakeUpgradeKeyRequest(input);
}

void fuzzBeginOperation(FuzzedDataProvider* fdp) {
  auto input = arc::mojom::BeginRequest::New(
      static_cast<arc::mojom::KeyPurpose>(fdp->ConsumeIntegral<uint32_t>()),
      fdp->ConsumeBytes<uint8_t>(fdp->ConsumeIntegral<uint8_t>()),
      consumeKeyParameters(fdp));

  arc::keymaster::MakeBeginOperationRequest(input);
}

void fuzzUpdateOperation(FuzzedDataProvider* fdp) {
  auto input = arc::mojom::UpdateRequest::New(
      fdp->ConsumeIntegral<uint64_t>(), consumeKeyParameters(fdp),
      fdp->ConsumeBytes<uint8_t>(fdp->ConsumeIntegral<uint8_t>()));

  arc::keymaster::MakeUpdateOperationRequest(input);
}

void fuzzFinishOperation(FuzzedDataProvider* fdp) {
  auto input = arc::mojom::FinishRequest::New(
      fdp->ConsumeIntegral<uint64_t>(), consumeKeyParameters(fdp),
      fdp->ConsumeBytes<uint8_t>(fdp->ConsumeIntegral<uint8_t>()),
      fdp->ConsumeBytes<uint8_t>(fdp->ConsumeIntegral<uint8_t>()));

  arc::keymaster::MakeFinishOperationRequest(input);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  static Environment env;

  FuzzedDataProvider fdp(data, size);

  while (fdp.remaining_bytes()) {
    switch (fdp.ConsumeIntegralInRange<uint8_t>(0, 8)) {
      case 0:
        fuzzGetKeyCharacteristics(&fdp);
        break;
      case 1:
        fuzzGenerateKey(&fdp);
        break;
      case 2:
        fuzzImportKey(&fdp);
        break;
      case 3:
        fuzzExportKey(&fdp);
        break;
      case 4:
        fuzzAttestKey(&fdp);
        break;
      case 5:
        fuzzUpgradeKeyRequest(&fdp);
        break;
      case 6:
        fuzzBeginOperation(&fdp);
        break;
      case 7:
        fuzzUpdateOperation(&fdp);
        break;
      case 8:
        fuzzFinishOperation(&fdp);
        break;
    }
  }

  return 0;
}
