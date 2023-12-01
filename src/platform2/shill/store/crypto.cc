// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/store/crypto.h"

#include <optional>
#include <string_view>
#include <utility>

#include <base/logging.h>
#include <base/strings/string_util.h>

#include "shill/logging.h"

namespace shill {

namespace {

constexpr char kRot47Id[] = "rot47:";

// ROT47 is self-reciprocal.
std::string Rot47(std::string_view input) {
  const int kRotSize = 94;
  const int kRotHalf = kRotSize / 2;
  const char kRotMin = '!';
  const char kRotMax = kRotMin + kRotSize - 1;

  std::string output;
  output.reserve(input.size());
  for (auto ch : input) {
    if (kRotMin <= ch && ch <= kRotMax) {
      int rot = ch + kRotHalf;
      ch = (rot > kRotMax) ? rot - kRotSize : rot;
    }
    output.push_back(ch);
  }
  return output;
}

}  // namespace

namespace Crypto {

std::string Encrypt(const std::string& plaintext) {
  return std::string(kRot47Id) + Rot47(plaintext);
}

std::optional<std::string> Decrypt(const std::string& ciphertext) {
  if (!base::StartsWith(ciphertext, kRot47Id, base::CompareCase::SENSITIVE)) {
    LOG(ERROR) << "Cannot decrypt non-ROT47 ciphertext";
    return std::nullopt;
  }

  std::string_view to_decrypt = ciphertext;
  to_decrypt.remove_prefix(sizeof(kRot47Id) - 1);
  return Rot47(std::move(to_decrypt));
}

}  // namespace Crypto

}  // namespace shill
