// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_CELLULAR_CELLULAR_PCO_H_
#define SHILL_CELLULAR_CELLULAR_PCO_H_

#include <stdint.h>

#include <memory>
#include <utility>
#include <vector>

namespace shill {

// A class that encapsulates elements extracted from the raw data of Protocol
// Configuration Options (PCO) structure.
class CellularPco {
 public:
  struct Element {
    Element(uint16_t id, std::vector<uint8_t> data)
        : id(id), data(std::move(data)) {}

    uint16_t id;
    std::vector<uint8_t> data;
  };

  // Parses the provided raw data representing a PCO structure and returns a
  // CellularPco object that encapsulates the elements found in the PCO
  // structure. Returns nullptr for an incomplete or malformed PCO structure.
  static std::unique_ptr<CellularPco> CreateFromRawData(
      const std::vector<uint8_t>& raw_data);

  ~CellularPco();

  // Returns a pointer to the element with the provided element identifier if
  // it's found in the PCO structure, or nullptr otherwise. The element is
  // owned by this CellularPco object and thus the returned pointer remains
  // valid until the CellularPco object is destructed.
  const Element* FindElement(uint16_t element_id) const;

 private:
  // Used by CreateFromRawData to construct a CellularPco object with the
  // elements extracted from a PCO structure.
  explicit CellularPco(std::vector<Element> elements);
  CellularPco(const CellularPco&) = delete;
  CellularPco& operator=(const CellularPco&) = delete;

  const std::vector<Element> elements_;
};

}  // namespace shill

#endif  // SHILL_CELLULAR_CELLULAR_PCO_H_
