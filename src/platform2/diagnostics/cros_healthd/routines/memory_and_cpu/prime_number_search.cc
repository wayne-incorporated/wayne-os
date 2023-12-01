// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_healthd/routines/memory_and_cpu/prime_number_search.h"

#include <cmath>

#include <base/logging.h>
#include <base/stl_util.h>

namespace diagnostics {

PrimeNumberSearch::PrimeNumberSearch(uint64_t max_num) : max_num_(max_num) {
  // Create a Sieve of Eratosthenes. This creates a bitfield of prime numbers
  // from 0 - |max_number|.
  // https://en.wikipedia.org/wiki/Sieve_of_Eratosthenes
  for (uint64_t i = 2;
       i <= static_cast<uint64_t>(std::sqrt(static_cast<double>(max_num_)));
       i++) {
    if (prime_sieve_[i]) {
      for (uint64_t j = (i * i); j <= max_num_; j += i)
        prime_sieve_[j] = 0;
    }
  }
}

bool PrimeNumberSearch::Run() {
  for (uint64_t num = 2; num <= max_num_; num++) {
    bool sieve_prime = prime_sieve_[num];
    bool func_prime = IsPrime(num);

    if (sieve_prime != func_prime) {
      LOG(ERROR) << "prime number mismatch: " << num
                 << ". sieve: " << sieve_prime << " IsPrime(): " << func_prime;
      return false;
    }
  }

  return true;
}

bool PrimeNumberSearch::IsPrime(uint64_t num) const {
  if (num == 0 || num == 1)
    return false;

  uint64_t sqrt_root =
      static_cast<uint64_t>(std::sqrt(static_cast<double>(num)));
  for (uint64_t divisor = 2; divisor <= sqrt_root; divisor++)
    if (num % divisor == 0)
      return false;

  return true;
}

}  // namespace diagnostics
