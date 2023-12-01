// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef U2FD_CLIENT_U2F_APDU_H_
#define U2FD_CLIENT_U2F_APDU_H_

#include <stdint.h>

#include <optional>
#include <string>
#include <vector>

#include "u2fd/client/u2f_client_export.h"
#include "u2fd/client/util.h"

// Classes for dealing with command and response APDUs, as described in the "U2F
// Raw Message Formats" specification.

namespace u2f {

// INS codes used in U2F Command APDUs.
enum class U2F_CLIENT_EXPORT U2fIns : uint8_t {
  kU2fRegister = 1,      // U2F_REGISTER
  kU2fAuthenticate = 2,  // U2F_AUTHENTICATE
  kU2fVersion = 3,       // U2F_VERSION

  // TODO(crbug.com/1218246) Change UMA enum name kU2fCommand if new enums are
  // added to avoid data discontinuity.
  kInsInvalid = 0xff,
};

// Represents a command APDU.
class U2F_CLIENT_EXPORT U2fCommandApdu {
 public:
  // Fixed-size header of a command APDU.
  struct Header {
    U2fIns ins_;
    uint8_t p1_;
    uint8_t p2_;
  };

  // Attempts to parse the specified string as an APDU, and returns a valid
  // U2fCommandApdu if successful, or std::nullopt otherwise. If unsuccessful,
  // and u2f_status is not null, populates it with a U2F status code indicating
  // the type of failure, if an appropriate code is available, or 0 otherwise.
  static std::optional<U2fCommandApdu> ParseFromString(
      const std::string& apdu_raw, uint16_t* u2f_status);

  // Creates an 'empty' APDU for the command with the specified INS command
  // code.
  static U2fCommandApdu CreateForU2fIns(U2fIns ins);

  // Returns the INS command code for this APDU.
  U2fIns Ins() const { return header_.ins_; }
  // Returns the P1 parameter for this APDU.
  uint8_t P1() const { return header_.p1_; }
  // Returns the P2 parameter for this APDU.
  uint8_t P2() const { return header_.p2_; }
  // Returns the request body for this APDU.
  const std::string& Body() const { return data_; }
  // Returns the max response length for this APDU.
  uint32_t MaxResponseLength() const { return max_response_length_; }
  // Serializes this APDU to a string.
  std::string ToString() const;

 protected:
  Header header_;
  std::string data_;
  uint32_t max_response_length_;

 private:
  // Private constructor, use factory methods above.
  U2fCommandApdu() = default;
  // Internal parser class called by ParseFromString().
  class Parser;
  friend class Parser;
};

// Represents an APDU for a U2F_REGISTER request.
class U2F_CLIENT_EXPORT U2fRegisterRequestApdu {
 public:
  // Attempt to parse the body of the specified APDU as a U2F_REGISTER request.
  // Returns a valid U2fRegisterRequestApdu if successful, or std::nullopt
  // otherwise. If unsuccessful, and u2f_status is not null, populates it with
  // a U2F status code indicating the type of failure, if an appropriate code
  // is available, or 0 otherwise.
  static std::optional<U2fRegisterRequestApdu> FromCommandApdu(
      const U2fCommandApdu& apdu, uint16_t* u2f_status);

  // Whether the request response should use the G2F attestation certificate (if
  // available).
  bool UseG2fAttestation() const { return g2f_attestation_; }

  // Whether the request is a 'bogus' request sent by Chrome, solely to cause a
  // USB device to flash its LED.
  bool IsChromeDummyWinkRequest() const;

  // Accessors for the request fields.
  const std::vector<uint8_t>& GetAppId() const { return app_id_; }
  const std::vector<uint8_t>& GetChallenge() const { return challenge_; }

 private:
  bool g2f_attestation_;
  std::vector<uint8_t> app_id_;
  std::vector<uint8_t> challenge_;
};

class U2F_CLIENT_EXPORT U2fAuthenticateRequestApdu {
 public:
  // Attempt to parse the body of the specified APDU as a U2F_AUTHENTICATE
  // request. Returns a valid U2fRegisterRequestApdu if successful, or
  // std::nullopt otherwise. If unsuccessful, and u2f_status is not null,
  // populates it with a U2F status code indicating the type of failure,
  // if an appropriate code is available, or 0 otherwise.
  static std::optional<U2fAuthenticateRequestApdu> FromCommandApdu(
      const U2fCommandApdu& apdu, uint16_t* u2f_status);

  // Returns true if the APDU is for a U2F_AUTHENTICATE check-only
  // request. Check-only requests should verify whether the specified key handle
  // is owned by this U2F device, but not perform any authentication.
  bool IsAuthenticateCheckOnly() const { return auth_check_only_; }

  // Accessors for the request fields.
  const std::vector<uint8_t>& GetAppId() const { return app_id_; }
  const std::vector<uint8_t>& GetChallenge() const { return challenge_; }
  const std::vector<uint8_t>& GetKeyHandle() const { return key_handle_; }

 private:
  bool auth_check_only_;
  std::vector<uint8_t> app_id_;
  std::vector<uint8_t> challenge_;
  std::vector<uint8_t> key_handle_;
};

// Represents a response APDU. Provides methods for building  nd serializing a
// response.
class U2F_CLIENT_EXPORT U2fResponseApdu {
 public:
  // Constructs an empty response.
  U2fResponseApdu() = default;

  // Serialize the response to the specified string.
  bool ToString(std::string* out) const;

  // Methods to append data to the response.
  void AppendByte(uint8_t byte) { data_.push_back(byte); }
  void AppendBytes(const std::vector<uint8_t>& bytes) {
    util::AppendToVector(bytes, &data_);
  }
  void AppendString(const std::string& string) {
    util::AppendToVector(string, &data_);
  }
  template <typename T>
  void AppendObject(const T& obj) {
    util::AppendToVector(obj, &data_);
  }

  // Sets the return status for the response.
  void SetStatus(uint16_t sw) {
    sw1_ = sw >> 8;
    sw2_ = static_cast<uint8_t>(sw);
  }

  uint16_t GetStatus() { return (static_cast<uint16_t>(sw1_) << 8) | sw2_; }

 private:
  std::vector<uint8_t> data_;
  uint8_t sw1_;
  uint8_t sw2_;
};

}  // namespace u2f

#endif  // U2FD_CLIENT_U2F_APDU_H_
