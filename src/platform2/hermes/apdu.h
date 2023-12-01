// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef HERMES_APDU_H_
#define HERMES_APDU_H_

#include <cstdint>
#include <initializer_list>
#include <vector>

namespace hermes {

enum ApduClass : uint8_t {
  CLA_STORE_DATA = 0x80,
};

enum ApduInstruction : uint8_t {
  INS_GET_MORE_RESPONSE = 0xC0,
  INS_STORE_DATA = 0xE2,
};

// P1 byte based on the length of the data field P3 in a transport command.
constexpr uint8_t kApduP1MoreBlocks = 0x11;
constexpr uint8_t kApduP1LastBlock = 0x91;

// Class representing a smart card command APDU as defined in ISO 7816. Users
// need only provide this class with the APDU data. Fragmentation and creation
// of the in-memory APDU structure is taken care of internally.
//
// This class can generate extended length APDUs. Whether or not a particular
// card supports extended length APDUs, however, is outside the scope of this
// class.
//
// APDUs will be generated of the appropriate case, depending on the presence or
// absence of various fields. As per ISO 7816:
//                             +--------+
//   Case 1 (no data, no Le):  | Header |
//                             +--------+----------+
//   Case 2 (no data, Le):     | Header | Le field |
//                             +--------+----------+------------+
//   Case 3 (data, no Le):     | Header | Lc field | Data field |
//                             +--------+----------+------------+----------+
//   Case 4 (data, Le):        | Header | Lc field | Data field | Le field |
//                             +--------+----------+------------+----------+
class CommandApdu {
 public:
  CommandApdu(uint8_t cls,
              uint8_t instruction,
              bool is_extended_length = false,
              uint16_t le = 0);

  CommandApdu(CommandApdu&&) = default;
  CommandApdu(const CommandApdu&) = delete;
  explicit CommandApdu(const std::vector<uint8_t>& data);
  CommandApdu& operator=(const CommandApdu&) = delete;

  CommandApdu& operator=(CommandApdu&&) = default;

  // Add data to the APDU.
  // May only be called prior to any calls of |GetNextFragment|.
  void AddData(const std::initializer_list<uint8_t>& data);
  void AddData(const std::vector<uint8_t>& data);

  // Prepare the next APDU fragment.
  // |fragment| will be set to the start of the fragment, and the return value
  // represents the size of the fragment.
  // Note that accessing data beyond the size of the fragment is undefined, and
  // that the fragment data will no longer be valid after a subsequent call to
  // |GetNextFragment|.
  size_t GetNextFragment(uint8_t** fragment);

  bool HasMoreFragments() const;

  uint8_t cls_;

 private:
  // Create an Lc field if it doesn't already exist.
  void EnsureLcExists();

  bool is_apdu_ready_ = false;
  bool is_extended_length_;
  bool has_more_fragments_;
  uint8_t current_fragment_;
  uint16_t le_;
  size_t current_index_;
  size_t max_data_size_;
  std::vector<uint8_t> data_;
};

// Class representing a smart card response APDU.
class ResponseApdu {
 public:
  ResponseApdu() = default;

  ResponseApdu(ResponseApdu&&) = default;
  ResponseApdu(const ResponseApdu&) = delete;
  ResponseApdu& operator=(const ResponseApdu&) = delete;

  ResponseApdu& operator=(ResponseApdu&&) = default;

  // Add an entire received response APDU to this class. The response payload
  // will be added the existing payload, and the sw1 & sw2 values will be
  // updated.
  void AddData(const std::vector<uint8_t>& data);
  void AddData(const uint8_t* data, size_t data_len);
  void AddStatusBytes(uint8_t sw1, uint8_t sw2);
  // Release ownership of the data buffer. The payload data (without sw1 and
  // sw2) will be returned, and the ResponseApdu will revert to its default
  // state with an empty data buffer.
  std::vector<uint8_t> Release();
  std::vector<uint8_t> ReleaseStatusBytes();

  // Create a GetMoreResponse APDU command using the current sw2 value.
  CommandApdu CreateGetMoreCommand(bool use_extended_length, uint8_t cls) const;

  bool IsSuccessful() const;
  bool WaitingForNextFragment() const;
  bool MorePayloadIncoming() const;

 private:
  enum Sw1Status : uint8_t {
    STATUS_MORE_RESPONSE = 0x61,
    STATUS_OK = 0x90,
  };

  std::vector<uint8_t> data_;
};

}  // namespace hermes

#endif  // HERMES_APDU_H_
