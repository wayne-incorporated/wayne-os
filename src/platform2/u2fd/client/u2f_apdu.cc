// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "u2fd/client/u2f_apdu.h"

#include <array>
#include <map>
#include <optional>
#include <utility>

#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <trunks/cr50_headers/u2f.h>

#include "u2fd/client/util.h"

namespace u2f {

namespace {

// All U2F APDUs have a CLA value of 0.
constexpr uint8_t kApduCla = 0;

// Chrome sends a REGISTER message with the following bogus app ID
// and challenge parameters to cause USB devices to flash their
// LED.

const std::array<uint8_t, 32> kChromeBogusAppId = {
    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41};

const std::array<uint8_t, 32> kChromeBogusChallenge = {
    0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
    0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
    0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42};

}  // namespace

//
// U2fCommandApdu Implementation.
//
//////////////////////////////////////////////////////////////////////

// Parses raw APDU strings.
class U2fCommandApdu::Parser {
 public:
  explicit Parser(const std::string& apdu_raw)
      : apdu_raw_(apdu_raw), pos_(apdu_raw.cbegin()) {}

  std::optional<U2fCommandApdu> Parse(uint16_t* u2f_status) {
    if (ParseHeader(u2f_status) && ParseLc() && ParseBody() && ParseLe()) {
      return apdu_;
    } else {
      VLOG(2) << "Failed to parse APDU: "
              << base::HexEncode(apdu_raw_.data(), apdu_raw_.size());
      return std::nullopt;
    }
  }

 private:
  bool ParseHeader(uint16_t* u2f_status) {
    static constexpr uint8_t kApduHeaderSize = 4;

    if (Remaining() < kApduHeaderSize) {
      return false;
    }

    if (Consume() != kApduCla) {
      if (u2f_status) {
        *u2f_status = U2F_SW_CLA_NOT_SUPPORTED;
      }
      return false;
    }

    // We checked we have enough data left, so these will not fail.
    apdu_.header_.ins_ = static_cast<U2fIns>(Consume());
    apdu_.header_.p1_ = Consume();
    apdu_.header_.p2_ = Consume();

    return true;
  }

  bool ParseLc() {
    lc_ = 0;

    // No Lc.
    if (Remaining() == 0)
      return true;

    lc_ = Consume();

    if (lc_ == 0 && Remaining() > 2) {
      // Extended Lc.
      lc_ = Consume() << 8;
      lc_ |= Consume();
    }

    return true;
  }

  bool ParseBody() {
    if (lc_ == 0)
      return true;

    if (Remaining() < lc_)
      return false;

    apdu_.data_.append(pos_, pos_ + lc_);
    pos_ += lc_;

    return true;
  }

  bool ParseLe() {
    if (Remaining() == 0) {
      apdu_.max_response_length_ = 0;
      return true;
    }

    apdu_.max_response_length_ = Consume();

    if (Remaining() > 0) {
      apdu_.max_response_length_ = apdu_.max_response_length_ << 8 | Consume();
      if (apdu_.max_response_length_ == 0)
        apdu_.max_response_length_ = 65536;
    }

    return true;
  }

  uint8_t Consume() {
    uint8_t val = *pos_;
    ++pos_;
    return val;
  }

  size_t Remaining() { return apdu_raw_.cend() - pos_; }

  const std::string& apdu_raw_;
  std::string::const_iterator pos_;

  uint16_t lc_;

  U2fCommandApdu apdu_;
};

std::optional<U2fCommandApdu> U2fCommandApdu::ParseFromString(
    const std::string& apdu_raw, uint16_t* u2f_status) {
  *u2f_status = 0;
  return U2fCommandApdu::Parser(apdu_raw).Parse(u2f_status);
}

U2fCommandApdu U2fCommandApdu::CreateForU2fIns(U2fIns ins) {
  U2fCommandApdu apdu;
  apdu.header_.ins_ = ins;
  return apdu;
}

namespace {

void AppendLc(std::string* apdu, size_t lc) {
  if (lc == 0)
    return;

  if (lc < 256) {
    apdu->append(1, lc);
  } else {
    apdu->append(1, lc >> 8);
    apdu->append(1, lc & 0xff);
  }
}

void AppendLe(std::string* apdu, size_t lc, size_t le) {
  if (le == 0)
    return;

  if (le < 256) {
    apdu->append(1, le);
  } else if (le == 256) {
    apdu->append(1, 0);
  } else {
    if (lc == 0)
      apdu->append(1, 0);

    if (le == 65536)
      le = 0;

    apdu->append(1, le >> 8);
    apdu->append(1, le & 0xff);
  }
}

}  // namespace

std::string U2fCommandApdu::ToString() const {
  std::string apdu;

  apdu.push_back(kApduCla);
  apdu.push_back(static_cast<uint8_t>(header_.ins_));
  apdu.push_back(header_.p1_);
  apdu.push_back(header_.p2_);

  AppendLc(&apdu, data_.size());

  apdu.append(data_);

  AppendLe(&apdu, data_.size(), max_response_length_);

  return apdu;
}

//
// Helper for parsing U2F command APDU request body.
//
//////////////////////////////////////////////////////////////////////

bool ParseApduBody(
    const std::string& body,
    std::map<std::pair<int, int>, std::vector<uint8_t>*> fields) {
  for (const auto& field : fields) {
    int field_start = field.first.first;
    int field_length = field.first.second;

    if (field_start < 0 || (field_start + field_length) > body.size())
      return false;

    util::AppendSubstringToVector(body, field_start, field_length,
                                  field.second);
  }
  return true;
}

//
// U2fRegisterRequestApdu Implementation.
//
//////////////////////////////////////////////////////////////////////

std::optional<U2fRegisterRequestApdu> U2fRegisterRequestApdu::FromCommandApdu(
    const U2fCommandApdu& apdu, uint16_t* u2f_status) {
  // Request body for U2F_REGISTER APDUs are in the following format:
  //
  // Byte(s)  | Description
  // --------------------------
  //  0 - 31  | Challenge
  // 32 - 64  | App ID

  *u2f_status = 0;

  U2fRegisterRequestApdu reg_apdu;
  if (!ParseApduBody(apdu.Body(), {{{0, 32}, &reg_apdu.challenge_},
                                   {{32, 32}, &reg_apdu.app_id_}})) {
    LOG(WARNING) << "Received invalid U2F_REGISTER APDU: "
                 << base::HexEncode(apdu.Body().data(), apdu.Body().size());
    if (u2f_status) {
      *u2f_status = U2F_SW_WRONG_LENGTH;
    }
    return std::nullopt;
  }

  // We require that P1 be set to 0x03 (though may optionally have the
  // G2F_ATTEST bit set), implying a test of user presence, and that presence
  // should be consumed.
  if ((apdu.P1() & ~G2F_ATTEST) != U2F_AUTH_ENFORCE) {
    LOG(WARNING) << "Received register APDU with invalid P1 value: " << std::hex
                 << apdu.P1();
    return std::nullopt;
  }

  reg_apdu.g2f_attestation_ = apdu.P1() & G2F_ATTEST;

  return reg_apdu;
}

bool U2fRegisterRequestApdu::IsChromeDummyWinkRequest() const {
  return std::equal(app_id_.begin(), app_id_.end(), kChromeBogusAppId.begin(),
                    kChromeBogusAppId.end()) &&
         std::equal(challenge_.begin(), challenge_.end(),
                    kChromeBogusChallenge.begin(), kChromeBogusChallenge.end());
}

//
// U2fAuthenticateRequest Implementation.
//
//////////////////////////////////////////////////////////////////////

std::optional<U2fAuthenticateRequestApdu>
U2fAuthenticateRequestApdu::FromCommandApdu(const U2fCommandApdu& apdu,
                                            uint16_t* u2f_status) {
  *u2f_status = 0;

  // The P1 field must be set to a value of 0x03 or 0x07, indicating
  // respectively a request to authenticate with user presence, or a request
  // merely trying to determine whether the key handle is owned by this U2F
  // device, in which case no user presence is required and authentication
  // should not be performed.
  if (apdu.P1() != U2F_AUTH_ENFORCE && apdu.P1() != U2F_AUTH_CHECK_ONLY) {
    LOG(WARNING) << "Received authenticate APDU with invalid P1 value: "
                 << std::hex << apdu.P1();
    return std::nullopt;
  }

  // Request body for U2F_AUTHENTICATE APDUs are in the following format:
  //
  // Byte(s)  | Description
  // --------------------------
  //  0 - 31  | Challenge
  // 32 - 63  | App ID
  // 64       | Key Handle Length
  // 65 - end | Key Handle
  //
  constexpr int kApduFixedFieldsSize = 65;
  int body_size = apdu.Body().size();
  int kh_length = body_size - kApduFixedFieldsSize;

  U2fAuthenticateRequestApdu auth_apdu;
  if (body_size < kApduFixedFieldsSize || kh_length != apdu.Body()[64] ||
      !ParseApduBody(apdu.Body(),
                     {{{0, 32}, &auth_apdu.challenge_},
                      {{32, 32}, &auth_apdu.app_id_},
                      {{65, kh_length}, &auth_apdu.key_handle_}})) {
    LOG(WARNING) << "Received invalid U2F_AUTHENTICATE APDU: "
                 << base::HexEncode(apdu.Body().data(), apdu.Body().size());
    if (u2f_status) {
      *u2f_status = U2F_SW_WRONG_LENGTH;
    }
    return std::nullopt;
  }

  auth_apdu.auth_check_only_ = apdu.P1() == U2F_AUTH_CHECK_ONLY;

  return auth_apdu;
}

//
// U2fResponseApdu Implementation.
//
//////////////////////////////////////////////////////////////////////

bool U2fResponseApdu::ToString(std::string* out) const {
  out->append(data_.begin(), data_.end());
  out->push_back(sw1_);
  out->push_back(sw2_);
  return true;
}

}  // namespace u2f
