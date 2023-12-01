// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "trunks/openssl_utility.h"

#include <base/check.h>
#include <base/logging.h>
#include <libhwsec-foundation/utility/crypto.h>
#include <openssl/bn.h>
#include <openssl/ec.h>

#include "trunks/tpm_generated.h"

namespace {

// Converts an ECC point |coordinate| in the OpenSSL BIGNUM format to the
// TPM2B_ECC_PARAMETER format and pads the result to |coord_size| bytes. If
// succeeded, stores the result in |param| and returns true; otherwise, returns
// false.
bool BignumCoordinateToEccParameter(const BIGNUM& coordinate,
                                    size_t coord_size,
                                    trunks::TPM2B_ECC_PARAMETER* param) {
  if (coord_size > MAX_ECC_KEY_BYTES) {
    LOG(ERROR) << "Coordinate size is too large: " << coord_size;
    return false;
  }

  int key_size = BN_num_bytes(&coordinate);
  if (key_size > coord_size) {
    LOG(ERROR) << "Coordinate size is larger than expected: " << key_size
               << " vs. " << coord_size;
    return false;
  }

  memset(param->buffer, 0, sizeof(trunks::BYTE) * MAX_ECC_KEY_BYTES);
  unsigned char* start_pos =
      reinterpret_cast<unsigned char*>(param->buffer) + coord_size - key_size;
  if (BN_bn2bin(&coordinate, start_pos) != key_size) {
    LOG(ERROR) << "BN_bn2bin() doesn't write a correct size: "
               << hwsec_foundation::utility::GetOpensslError();
    return false;
  }

  param->size = coord_size;
  return true;
}

}  // namespace

namespace trunks {

bool TpmToOpensslEccPoint(const TPMS_ECC_POINT& point,
                          const EC_GROUP& ec_group,
                          EC_POINT* ec_point) {
  CHECK(ec_point);

  hwsec_foundation::utility::ScopedBN_CTX ctx;
  BIGNUM* x = BN_CTX_get(ctx.get());
  BIGNUM* y = BN_CTX_get(ctx.get());
  if (!x || !y) {
    LOG(ERROR) << "Failed to create bignums for x or y when converting to "
               << "openssl ECC point: "
               << hwsec_foundation::utility::GetOpensslError();
    return false;
  }

  if (!BN_bin2bn(reinterpret_cast<const unsigned char*>(point.x.buffer),
                 point.x.size, x) ||
      !BN_bin2bn(reinterpret_cast<const unsigned char*>(point.y.buffer),
                 point.y.size, y) ||
      !EC_POINT_set_affine_coordinates_GFp(&ec_group, ec_point, x, y,
                                           ctx.get())) {
    LOG(ERROR) << "Failed to convert TPMS_ECC_POINT to OpenSSL EC_POINT: "
               << hwsec_foundation::utility::GetOpensslError();
    return false;
  }

  return true;
}

bool OpensslToTpmEccPoint(const EC_GROUP& ec_group,
                          const EC_POINT& point,
                          size_t coord_size,
                          TPMS_ECC_POINT* ecc_point) {
  CHECK(ecc_point);

  hwsec_foundation::utility::ScopedBN_CTX ctx;
  BIGNUM* x = BN_CTX_get(ctx.get());
  BIGNUM* y = BN_CTX_get(ctx.get());
  if (!x || !y) {
    LOG(ERROR) << "Failed to create bignums for x or y when converting to TPM "
               << "ECC point: " << hwsec_foundation::utility::GetOpensslError();
    return false;
  }

  if (!EC_POINT_get_affine_coordinates_GFp(&ec_group, &point, x, y,
                                           ctx.get())) {
    LOG(ERROR) << "Failed to get X and Y from OpenSSL EC_POINT: "
               << hwsec_foundation::utility::GetOpensslError();
    return false;
  }

  if (!BignumCoordinateToEccParameter(*x, coord_size, &ecc_point->x) ||
      !BignumCoordinateToEccParameter(*y, coord_size, &ecc_point->y)) {
    LOG(ERROR) << "Bad EC_POINT coordinate value.";
    return false;
  }

  return true;
}

}  // namespace trunks
