// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#ifndef SHILL_MAC_ADDRESS_H_
#define SHILL_MAC_ADDRESS_H_

#include <array>
#include <string>
#include <base/time/time.h>

#include "linux/if_ether.h"

namespace shill {

class StoreInterface;

// MACAddress class encapsulates MAC address, providing means for
// keeping it, accessing, setting and randomizing.
class MACAddress {
 public:
  // Multicast address bit.
  static constexpr uint8_t kMulicastMacBit = 0x01;
  // Locally administered bit.
  static constexpr uint8_t kLocallyAdministratedMacBit = 0x02;
  // Default expiration time for RandomizedMACAddress.
  static constexpr base::TimeDelta kDefaultExpirationTime = base::Hours(24);
  // Set expiration time to this constant to disable expiration.
  static constexpr base::Time kNotExpiring = base::Time();

  // It does not clear the address itself, but clears is_set flag.
  void Clear();

  bool is_set() const { return is_set_; }

  // Returns is true if address has expired.
  bool IsExpired(base::Time now) const;

  // Returns true if the address has a chance to expire.
  bool will_expire() const { return expiration_time_ != kNotExpiring; }

  // Loads MACAddress-related data from store.
  bool Load(const StoreInterface* storage, const std::string& id);

  // Randomize address stored.
  void Randomize();

  // Saves MACAddress-related data to store.
  bool Save(StoreInterface* storage, const std::string& id) const;

  // Set stored address to match particular string in aa:bb:cc:dd:ee:ff
  // notation. Returns false if given string was incorrect.
  bool Set(const std::string& str);

  // Sets expiration time of the address.
  void set_expiration_time(base::Time when) { expiration_time_ = when; }

  // Returns address in aa:bb:cc:dd:ee:ff string notation.
  std::string ToString() const;

  // Convenient operator for logging.
  friend std::ostream& operator<<(std::ostream& os, const MACAddress& addr);

  MACAddress() = default;

 private:
  static constexpr char kStorageMACAddress[] = "WiFi.MACAddress";
  static constexpr char kStorageMACAddressExpiry[] = "WiFi.MACAddress.Expiry";
  friend bool operator==(const MACAddress& a1, const MACAddress& a2);

  std::array<uint8_t, ETH_ALEN> address_;
  bool is_set_ = false;
  base::Time expiration_time_ = kNotExpiring;

  MACAddress(const MACAddress&) = delete;
  MACAddress(const MACAddress&&) = delete;
  MACAddress& operator=(const MACAddress&) = delete;
  MACAddress&& operator=(const MACAddress&&) = delete;
};

inline bool operator==(const MACAddress& a1, const MACAddress& a2) {
  return a1.is_set_ == a2.is_set_ && a1.address_ == a2.address_ &&
         a1.expiration_time_ == a2.expiration_time_;
}

}  // namespace shill

#endif  // SHILL_MAC_ADDRESS_H_
