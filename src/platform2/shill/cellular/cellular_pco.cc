// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/cellular/cellular_pco.h"

#include <utility>

#include <base/memory/ptr_util.h>
#include <base/strings/stringprintf.h>

namespace shill {

// Protocol Configuration Options (PCO) is an information element with an
// identifier (IEI) 0x27 and contains between 3 and 253 octets. See 3GPP TS
// 24.008 for more details on PCO.
//
// NOTE: The standard uses one-based indexing, but to better correlate to the
//       code, zero-based indexing is used in the description hereinafter.
//
//   Octet  | Value
//  --------+--------------------------------------------
//     0    | PCO IEI (= 0x27)
//     1    | Length of PCO contents (= total length - 2)
//     2    | bit 7      : ext
//          | bit 6 to 3 : spare (= 0b0000)
//          | bit 2 to 0 : Configuration protocol
//   3 to 4 | Element 1 ID
//     5    | Length of element 1 contents
//   6 to m | Element 1 contents
//    ...   |

namespace {

constexpr size_t kPcoHeaderLength = 3;
constexpr size_t kElementHeaderLength = 3;
constexpr size_t kMaxPcoContentLength = 250;
constexpr size_t kMinNumOfOctets = kPcoHeaderLength;
constexpr size_t kMaxNumOfOctets = kPcoHeaderLength + kMaxPcoContentLength;
constexpr uint8_t kPcoIei = 0x27;

}  // namespace

std::unique_ptr<CellularPco> CellularPco::CreateFromRawData(
    const std::vector<uint8_t>& raw_data) {
  if (raw_data.size() < kMinNumOfOctets || raw_data.size() > kMaxNumOfOctets)
    return nullptr;

  if (raw_data[0] != kPcoIei)
    return nullptr;

  if (raw_data[1] != raw_data.size() - 2)
    return nullptr;

  std::vector<Element> elements;
  const uint8_t* data_ptr = raw_data.data() + kPcoHeaderLength;
  size_t data_length = raw_data.size() - kPcoHeaderLength;
  while (data_length > 0) {
    if (data_length < kElementHeaderLength)
      return nullptr;

    uint16_t element_id = (data_ptr[0] << 8) | data_ptr[1];
    size_t element_length = data_ptr[2];
    data_ptr += kElementHeaderLength;
    data_length -= kElementHeaderLength;

    if (data_length < element_length)
      return nullptr;

    elements.emplace_back(
        element_id, std::vector<uint8_t>(data_ptr, data_ptr + element_length));
    data_ptr += element_length;
    data_length -= element_length;
  }

  return base::WrapUnique(new CellularPco(std::move(elements)));
}

CellularPco::CellularPco(std::vector<Element> elements)
    : elements_(std::move(elements)) {}

CellularPco::~CellularPco() = default;

const CellularPco::Element* CellularPco::FindElement(
    uint16_t element_id) const {
  for (const Element& element : elements_) {
    if (element.id == element_id)
      return &element;
  }
  return nullptr;
}

}  // namespace shill
