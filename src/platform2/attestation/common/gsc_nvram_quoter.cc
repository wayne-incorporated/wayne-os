// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "attestation/common/gsc_nvram_quoter.h"

#include <string>
#include <vector>

#include <base/check_op.h>
#include <base/logging.h>
#include <trunks/tpm_utility.h>
extern "C" {
#include <trunks/cr50_headers/virtual_nvmem.h>
}

#include "attestation/common/tpm_utility.h"

namespace attestation {

namespace {

struct NvramQuoteMetadata {
  NVRAMQuoteType type;
  const char* name;
  uint32_t index;
};

constexpr NvramQuoteMetadata kNvramQuoteMetadata[] = {
    {BOARD_ID, "BOARD_ID", VIRTUAL_NV_INDEX_BOARD_ID},
    {SN_BITS, "SN_BITS", VIRTUAL_NV_INDEX_SN_DATA},
    {RSA_PUB_EK_CERT, "RSA_PUB_EK_CERT",
     trunks::kRsaEndorsementCertificateIndex},
    {RSU_DEVICE_ID, "RSU_DEVICE_ID", VIRTUAL_NV_INDEX_RSU_DEV_ID},
};

constexpr bool VerifyMedataListOrder() {
  for (int i = 0; i < std::size(kNvramQuoteMetadata); ++i) {
    if (i != static_cast<int>(kNvramQuoteMetadata[i].type)) {
      return false;
    }
  }
  return true;
}

static_assert(VerifyMedataListOrder(),
              "List order should be aligned with enum in protobuf message");

std::string NvramQuoteTypeToString(NVRAMQuoteType type) {
  // No boundarty check, for the caller is responsible for that.
  return kNvramQuoteMetadata[type].name;
}

}  // namespace

GscNvramQuoter::GscNvramQuoter(TpmUtility& tpm_utility)
    : tpm_utility_(tpm_utility) {}

std::vector<NVRAMQuoteType> GscNvramQuoter::GetListForIdentity() const {
  return {BOARD_ID, SN_BITS};
}

std::vector<NVRAMQuoteType> GscNvramQuoter::GetListForVtpmEkCertificate()
    const {
  return {SN_BITS};
}

std::vector<NVRAMQuoteType> GscNvramQuoter::GetListForEnrollmentCertificate()
    const {
  return {BOARD_ID, SN_BITS, RSU_DEVICE_ID};
}

bool GscNvramQuoter::Certify(NVRAMQuoteType type,
                             const std::string& signing_key_blob,
                             Quote& quote) {
  CHECK_LT(static_cast<uint32_t>(type), std::size(kNvramQuoteMetadata))
      << "Unexpected type: " << static_cast<uint32_t>(type) << ".";
  const uint32_t nv_index =
      kNvramQuoteMetadata[static_cast<uint32_t>(type)].index;
  uint16_t nv_size;

  if (!tpm_utility_.GetNVDataSize(nv_index, &nv_size)) {
    LOG(ERROR) << __func__ << ": Failed to obtain NV data size for "
               << NvramQuoteTypeToString(type) << ".";
    return false;
  }

  std::string certified_value;
  std::string signature;

  if (!tpm_utility_.CertifyNV(nv_index, nv_size, signing_key_blob,
                              &certified_value, &signature)) {
    LOG(WARNING) << __func__ << ": Failed to certify "
                 << NvramQuoteTypeToString(type) << " NV data of size "
                 << nv_size << " at index " << std::hex << std::showbase
                 << nv_index << ".";
    return false;
  }
  quote.set_quote(signature);
  quote.set_quoted_data(certified_value);
  return true;
}

}  // namespace attestation
