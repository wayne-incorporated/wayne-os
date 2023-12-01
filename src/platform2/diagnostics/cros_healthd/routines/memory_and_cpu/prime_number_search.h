// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_ROUTINES_MEMORY_AND_CPU_PRIME_NUMBER_SEARCH_H_
#define DIAGNOSTICS_CROS_HEALTHD_ROUTINES_MEMORY_AND_CPU_PRIME_NUMBER_SEARCH_H_

#include <bitset>
#include <cstdint>

namespace diagnostics {

class PrimeNumberSearch {
 public:
  explicit PrimeNumberSearch(uint64_t max_num);
  PrimeNumberSearch(const PrimeNumberSearch&) = delete;
  PrimeNumberSearch& operator=(const PrimeNumberSearch&) = delete;
  virtual ~PrimeNumberSearch() = default;

  virtual bool IsPrime(uint64_t num) const;

  // Executes prime number search task. Returns true if searching is completed
  // without any error, false otherwise.
  bool Run();

  // Largest number that routine will calculate prime numbers up to.
  static constexpr uint64_t kMaxPrimeNumber = 1000000;

 private:
  const uint64_t max_num_ = 0;
  std::bitset<kMaxPrimeNumber + 1> prime_sieve_ =
      std::bitset<kMaxPrimeNumber + 1>().set();
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_ROUTINES_MEMORY_AND_CPU_PRIME_NUMBER_SEARCH_H_
