// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#include <string>
#include <vector>

#include "crypto/random.h"
#include "shill/device.h"
#include "shill/mac_address.h"
#include "shill/store/store_interface.h"

namespace shill {

void MACAddress::Clear() {
  is_set_ = false;
  // Reset expiration time.
  expiration_time_ = kNotExpiring;
}

bool MACAddress::IsExpired(base::Time now) const {
  // We assume == is still not expired to be on the safe side.
  return (expiration_time_ != kNotExpiring) && (now > expiration_time_);
}

bool MACAddress::Load(const StoreInterface* storage, const std::string& id) {
  std::string mac_str;
  if (!storage->GetString(id, kStorageMACAddress, &mac_str) || !Set(mac_str)) {
    return false;
  }
  uint64_t expiration_time;
  if (storage->GetUint64(id, kStorageMACAddressExpiry, &expiration_time)) {
    expiration_time_ = base::Time::FromDeltaSinceWindowsEpoch(
        base::Microseconds(expiration_time));
  }
  return true;
}

void MACAddress::Randomize() {
  crypto::RandBytes(address_.data(), address_.size());

  address_[0] &= ~kMulicastMacBit;  // Set unicast address.
  address_[0] |= kLocallyAdministratedMacBit;
  is_set_ = true;
  // Reset expiration time.
  expiration_time_ = kNotExpiring;
}

bool MACAddress::Set(const std::string& str) {
  const auto addr = Device::MakeHardwareAddressFromString(str);
  if (addr.size() != address_.size()) {
    return false;
  }
  std::copy_n(addr.begin(), address_.size(), address_.begin());
  is_set_ = true;
  return true;
}

bool MACAddress::Save(StoreInterface* storage, const std::string& id) const {
  if (!is_set_) {
    return false;
  }
  storage->SetString(id, kStorageMACAddress, ToString());
  storage->SetUint64(
      id, kStorageMACAddressExpiry,
      expiration_time_.ToDeltaSinceWindowsEpoch().InMicroseconds());
  return true;
}

std::string MACAddress::ToString() const {
  if (!is_set_) {
    return "<UNSET>";
  }
  const std::vector<uint8_t> addr(address_.begin(), address_.end());
  return Device::MakeStringFromHardwareAddress(addr);
}

std::ostream& operator<<(std::ostream& os, const MACAddress& addr) {
  os << addr.ToString();
  return os;
}

}  // namespace shill
