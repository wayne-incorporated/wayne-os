// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BIOD_BIOMETRICS_MANAGER_RECORD_H_
#define BIOD_BIOMETRICS_MANAGER_RECORD_H_

#include <string>
#include <vector>

namespace biod {

// Represents a record previously registered with this BiometricsManager in an
// EnrollSession. These objects can be retrieved with GetRecords.
class BiometricsManagerRecord {
 public:
  virtual ~BiometricsManagerRecord() = default;
  virtual const std::string& GetId() const = 0;
  virtual std::string GetUserId() const = 0;
  virtual std::string GetLabel() const = 0;
  virtual std::vector<uint8_t> GetValidationVal() const = 0;

  // Returns true on success.
  virtual bool SetLabel(std::string label) = 0;

  // Returns true on success.
  virtual bool Remove() = 0;
};

}  //  namespace biod

#endif  // BIOD_BIOMETRICS_MANAGER_RECORD_H_
