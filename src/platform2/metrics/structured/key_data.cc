// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "metrics/structured/key_data.h"

#include <memory>
#include <optional>
#include <utility>

#include <base/check.h>
#include <base/check_op.h>
#include <base/logging.h>
#include <base/notreached.h>
#include <base/rand_util.h>
#include <base/strings/strcat.h>
#include <base/strings/string_number_conversions.h>
#include <base/time/time.h>
#include <base/unguessable_token.h>
#include <crypto/hmac.h>
#include <crypto/sha2.h>

#include "metrics/structured/structured_events.h"

namespace metrics {
namespace structured {
namespace {

// The expected size of a key, in bytes.
constexpr size_t kKeySize = 32;

// The default maximum number of days before rotating keys.
constexpr int kDefaultRotationPeriod = 90;

// Generates a key, which is the string representation of
// base::UnguessableToken, and is of size |kKeySize| bytes.
std::string GenerateKey() {
  const std::string key = base::UnguessableToken::Create().ToString();
  DCHECK_EQ(key.size(), kKeySize);
  return key;
}

std::string HashToHex(const uint64_t hash) {
  return base::HexEncode(&hash, sizeof(uint64_t));
}

}  // namespace

KeyData::KeyData(const std::string& path)
    : proto_(std::make_unique<PersistentProto<KeyDataProto>>(path)) {}

KeyData::~KeyData() = default;

//---------------
// Key management
//---------------

std::optional<std::string> KeyData::ValidateAndGetKey(
    const uint64_t project_name_hash) {
  const int now = (base::Time::Now() - base::Time::UnixEpoch()).InDays();
  KeyProto& key = (*(proto_.get()->get()->mutable_keys()))[project_name_hash];

  // Generate or rotate key.
  const int last_rotation = key.last_rotation();
  if (key.key().empty() || last_rotation == 0) {
    // If the key is empty, generate a new one. Set the last rotation to a
    // uniformly selected day between today and |kDefaultRotationPeriod| days
    // ago, to uniformly distribute users amongst rotation cohorts.
    const int rotation_seed = base::RandInt(0, kDefaultRotationPeriod - 1);
    UpdateKey(&key, now - rotation_seed, kDefaultRotationPeriod);
  } else if (now - last_rotation > kDefaultRotationPeriod) {
    // If the key is outdated, generate a new one. Update the last rotation such
    // that the user stays in the same cohort.
    const int new_last_rotation =
        now - (now - last_rotation) % kDefaultRotationPeriod;
    UpdateKey(&key, new_last_rotation, kDefaultRotationPeriod);
  }

  // Return the key unless it's the wrong size, in which case return nullopt.
  const std::string key_string = key.key();
  if (key_string.size() != kKeySize)
    return std::nullopt;
  return key_string;
}

void KeyData::UpdateKey(KeyProto* key,
                        const int last_rotation,
                        const int rotation_period) {
  key->set_key(GenerateKey());
  key->set_last_rotation(last_rotation);
  key->set_rotation_period(rotation_period);
  proto_->Write();
}

//----------------
// IDs and hashing
//----------------

uint64_t KeyData::Id(const uint64_t project_name_hash) {
  // Retrieve the key for |project_name_hash|.
  const std::optional<std::string> key = ValidateAndGetKey(project_name_hash);
  if (!key) {
    NOTREACHED();
    return 0u;
  }

  // Compute and return the hash.
  uint64_t hash;
  crypto::SHA256HashString(key.value(), &hash, sizeof(uint64_t));
  return hash;
}

uint64_t KeyData::HmacMetric(const uint64_t project_name_hash,
                             const uint64_t metric_name_hash,
                             const std::string& value) {
  // Retrieve the key for |project_name_hash|.
  const std::optional<std::string> key = ValidateAndGetKey(project_name_hash);
  if (!key) {
    NOTREACHED();
    return 0u;
  }

  // Initialize the HMAC.
  crypto::HMAC hmac(crypto::HMAC::HashAlgorithm::SHA256);
  CHECK(hmac.Init(key.value()));

  // Compute and return the digest.
  const std::string salted_value =
      base::StrCat({HashToHex(metric_name_hash), value});
  uint64_t digest;
  CHECK(hmac.Sign(salted_value, reinterpret_cast<uint8_t*>(&digest),
                  sizeof(digest)));
  return digest;
}

}  // namespace structured
}  // namespace metrics
