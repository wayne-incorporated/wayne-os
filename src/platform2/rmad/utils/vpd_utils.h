// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RMAD_UTILS_VPD_UTILS_H_
#define RMAD_UTILS_VPD_UTILS_H_

#include <map>
#include <string>
#include <vector>

namespace rmad {

class VpdUtils {
 public:
  VpdUtils() = default;
  virtual ~VpdUtils() = default;

  // Get the serial number of the device from vpd.
  virtual bool GetSerialNumber(std::string* serial_number) const = 0;

  // Get custom-label-tag of the device from vpd. Old devices should set
  // |use_legacy| to true to use the old tag for backward compatibility with the
  // factory branch.
  virtual bool GetCustomLabelTag(std::string* custom_label_tag,
                                 bool use_legacy) const = 0;

  // Get the region of the device from vpd.
  virtual bool GetRegion(std::string* region) const = 0;

  // Get values from |entries| of the device from vpd and save it to
  // |calibbias|. If there are any errors, leave |calibbias| untouched.
  // Return true if it succeeds for all entries, otherwise return false.
  virtual bool GetCalibbias(const std::vector<std::string>& entries,
                            std::vector<int>* calibbias) const = 0;

  // Get the registration codes from vpd.
  virtual bool GetRegistrationCode(std::string* ubind,
                                   std::string* gbind) const = 0;

  // Get the stable device secret of the device from vpd.
  // Return true if it succeeds, otherwise return false.
  virtual bool GetStableDeviceSecret(
      std::string* stable_device_secret) const = 0;

  // Save the serial number in the cache until flush is called and set to vpd.
  // Return true if it succeeds, otherwise return false.
  virtual bool SetSerialNumber(const std::string& serial_number) = 0;

  // Save custom-label-tag in the cache until flush is called and set to vpd.
  // Return true if it succeeds, otherwise return false. Old devices should set
  // |use_legacy| to true to use the old tag for backward compatibility with the
  // factory branch.
  virtual bool SetCustomLabelTag(const std::string& custom_label_tag,
                                 bool use_legacy) = 0;

  // Save the region tag in the cache until flush is called and set to vpd.
  // Return true if it succeeds, otherwise return false.
  virtual bool SetRegion(const std::string& region) = 0;

  // Save |calibbias| to |entries| of the device in the cache until flush is
  // called and set to vpd.
  // Return true if it succeeds, otherwise return false.
  virtual bool SetCalibbias(const std::map<std::string, int>& calibbias) = 0;

  // Save the registration codes.
  virtual bool SetRegistrationCode(const std::string& ubind,
                                   const std::string& gbind) = 0;

  // Save the stable device secret in the cache until flush is called and set to
  // vpd. Return true if it succeeds, otherwise return false.
  virtual bool SetStableDeviceSecret(
      const std::string& stable_device_secret) = 0;

  // Remove custom-label-tag from the cache and the vpd.
  // Return true if it succeeds, otherwise return false.
  virtual bool RemoveCustomLabelTag() = 0;

  // Since setting the value to vpd requires a lot of overhead, we cache all
  // (key, value) pairs and then flush it all at once.
  virtual bool FlushOutRoVpdCache() = 0;
  virtual bool FlushOutRwVpdCache() = 0;

  // Clear all values in the cache.
  virtual void ClearRoVpdCache() = 0;
  virtual void ClearRwVpdCache() = 0;
};

}  // namespace rmad

#endif  // RMAD_UTILS_VPD_UTILS_H_
