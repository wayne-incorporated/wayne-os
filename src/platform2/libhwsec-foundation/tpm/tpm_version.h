// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_FOUNDATION_TPM_TPM_VERSION_H_
#define LIBHWSEC_FOUNDATION_TPM_TPM_VERSION_H_

#include <optional>

#include <base/logging.h>

#include "libhwsec-foundation/hwsec-foundation_export.h"

#if !defined(USE_TPM1) || !defined(USE_TPM2) || !defined(USE_TPM_DYNAMIC)
#error "Don't include this file w/o defining the value of TPM types"
#endif

namespace hwsec_foundation::tpm {

enum class TPMVer {
  kUnknown = 0,
  kTPM1 = 1,
  kTPM2 = 2,
  kNoTPM = 3,
};

#if USE_TPM_DYNAMIC

HWSEC_FOUNDATION_EXPORT TPMVer
RuntimeTPMVer(std::optional<TPMVer> set_cache_for_testing = std::nullopt);

#else

inline constexpr TPMVer RuntimeTPMVer() {
#if USE_TPM1
  return TPMVer::kTPM1;
#elif USE_TPM2
  return TPMVer::kTPM2;
#else
  return TPMVer::kNoTPM;
#endif
}

#endif

}  // namespace hwsec_foundation::tpm

/**
 * These macros could help the caller switching between
 * build-time code path and run-time code path.
 *
 * The example usage of these macros:
 *
 * TPM_SELECT_BEGIN;
 * TPM1_SECTION({
 *    singleton_ = new TpmImpl();
 *    LOG(INFO) << "Use TPM1";
 * });
 * TPM2_SECTION({
 *    singleton_ = new Tpm2Impl();
 *    LOG(INFO) << "Use TPM2";
 * });
 * NO_TPM_SECTION({
 *    LOG(INFO) << "No TPM";
 * });
 * OTHER_TPM_SECTION();
 * TPM_SELECT_END;
 */

#define TPM_SELECT_BEGIN switch (::hwsec_foundation::tpm::RuntimeTPMVer()) {
#define OTHER_TPM_SECTION(block) \
  default: {                     \
    block                        \
  }
#define TPM_SELECT_END }

#if USE_TPM_DYNAMIC || USE_TPM1
#define TPM1_SECTION(block)                      \
  case ::hwsec_foundation::tpm::TPMVer::kTPM1: { \
    block                                        \
  } break;
#else
#define TPM1_SECTION(block)
#endif

#if USE_TPM_DYNAMIC || USE_TPM2
#define TPM2_SECTION(block)                      \
  case ::hwsec_foundation::tpm::TPMVer::kTPM2: { \
    block                                        \
  } break;
#else
#define TPM2_SECTION(block)
#endif

#if USE_TPM_DYNAMIC || (!USE_TPM1 && !USE_TPM2)
#define NO_TPM_SECTION(block)                     \
  case ::hwsec_foundation::tpm::TPMVer::kNoTPM: { \
    block                                         \
  } break;
#else
#define NO_TPM_SECTION(block)
#endif

/**
 * These macros could help the unittest environment selecting the TPM version.
 */

#if USE_TPM_DYNAMIC

#define SET_DEFAULT_TPM_FOR_TESTING       \
  ::hwsec_foundation::tpm::RuntimeTPMVer( \
      ::hwsec_foundation::tpm::TPMVer::kTPM2);
#define SET_TPM1_FOR_TESTING              \
  ::hwsec_foundation::tpm::RuntimeTPMVer( \
      ::hwsec_foundation::tpm::TPMVer::kTPM1);
#define SET_TPM2_FOR_TESTING              \
  ::hwsec_foundation::tpm::RuntimeTPMVer( \
      ::hwsec_foundation::tpm::TPMVer::kTPM2);
#define SET_NO_TPM_FOR_TESTING            \
  ::hwsec_foundation::tpm::RuntimeTPMVer( \
      ::hwsec_foundation::tpm::TPMVer::kNoTPM);

#elif USE_TPM1

#define SET_DEFAULT_TPM_FOR_TESTING
#define SET_TPM1_FOR_TESTING
#define SET_TPM2_FOR_TESTING                                         \
  static_assert(false,                                               \
                "Shouldn't set testing TPM to 2.0 when USE_TPM1 is " \
                "true");
#define SET_NO_TPM_FOR_TESTING \
  static_assert(false,         \
                "Shouldn't set testing TPM to null when USE_TPM1 is true");

#elif USE_TPM2

#define SET_DEFAULT_TPM_FOR_TESTING
#define SET_TPM1_FOR_TESTING                                         \
  static_assert(false,                                               \
                "Shouldn't set testing TPM to 1.0 when USE_TPM2 is " \
                "true");
#define SET_TPM2_FOR_TESTING
#define SET_NO_TPM_FOR_TESTING \
  static_assert(false,         \
                "Shouldn't set testing TPM to null when USE_TPM2 is true");

#else  // NO_TPM

#define SET_DEFAULT_TPM_FOR_TESTING
#define SET_TPM1_FOR_TESTING                                       \
  static_assert(false,                                             \
                "Shouldn't set testing TPM to 1.0 when no TPM is " \
                "enable");
#define SET_TPM2_FOR_TESTING                                       \
  static_assert(false,                                             \
                "Shouldn't set testing TPM to 2.0 when no TPM is " \
                "enable");
#define SET_NO_TPM_FOR_TESTING

#endif

#endif  // LIBHWSEC_FOUNDATION_TPM_TPM_VERSION_H_
