// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_ERROR_TPM_ERROR_H_
#define LIBHWSEC_ERROR_TPM_ERROR_H_

#include <memory>
#include <string>
#include <utility>

#include <base/strings/stringprintf.h>
#include <brillo/errors/error.h>
#include <libhwsec-foundation/error/error.h>

#include "libhwsec/error/tpm_retry_action.h"
#include "libhwsec/hwsec_export.h"

/* The most important function of TPM error is representing a TPM retry action.
 *
 * MakeStatus<TPM1Error>/MakeStatus<TPM2Error> converts the raw error code from
 * the daemon to a Status object.
 *
 * For example:
 *   StatusChain<TPM1Error> status = MakeStatus<TPM1Error>(
 *       Tspi_TPM_CreateEndorsementKey(tpm_handle, local_key_handle, NULL));
 *
 * And it could also creating software based TPM error.
 *
 * For example:
 *   StatusChain<TPMError> status =
 *       MakeStatus<TPMError>("Failed to get trunks context",
 *                            TPMRetryAction::kNoRetry);
 *
 * Using Wrap() could wrap a TPM error into a new TPM error, and it
 * would transfer the retry action to the new TPM error (due to Wrap
 * overload).
 *
 * For example:
 *   if (StatusChain<TPMErrorBase> status = GetPublicKeyBlob(...))) {
 *     return MakeStatus<TPMError>("Failed to get TPM public key hash")
 *        .Wrap(std::move(status));
 *   }
 *
 * And it could also overwrite the original retry action.
 *
 * For example:
 *   if (StatusChain<TPM2Error> status = MakeStatus<TPM2Error>(...)) {
 *     return MakeStatus<TPMError>(
 *        "Error ...", TPMRetryAction::kNoRetry).Wrap(std::move(status));
 *   }
 *
 * It can also be used with status_macros helpers. For more info see
 * `platform2/libhwsec-foundation/error/status_macros.h`.
 *
 * RETURN_IF_ERROR(
 *     MakeStatus<TPM1Error>(
 *         Tspi_TPM_CreateEndorsementKey(tpm_handle, local_key_handle, NULL),
 *     AsStatusChain<TPMError>("Failed to create endorsement key")));
 */

namespace hwsec {

namespace unified_tpm_error {

typedef int64_t UnifiedError;

// Note on the unified error code:
// The unified error code unifies error code from various TPM versions,
// furthermore, it also unifies error code from the generic TPMError (that
// contains a string) and the TPM-related errors on Cryptohome side. For all
// valid values of unified error code, it is expected that it'll map one to
// one to one of those errors above.

// For the encoding of the unified error code, TPM 1.2 and TPM 2.0 error code
// already coexist in the same error space, so they will remain intact, except
// the extra kUnifiedErrorBit.
// For the other error codes, such as those from elliptic curve, tpm_manager,
// or the generic variant of TPMError, they'll be mapped into the later 3072
// error codes of the trunks layer.

// A layer in TPM error encoding is a 4096 error code allocation with the same
// 12-15 bit. There's already 1 layer allocated to trunks (0x7000), but trunks
// doesn't need the entire 4096 error code encoding space, and thus the later
// 3072 of them is allocated to TPMError and related.
// The allocation is as below: (base is kTrunksErrorBase)
// base+0x000 to base+0x3FF       Allocated to trunks.
// base+0x800 to base+0x87F       Allocated to tpm_manager error.
// base+0x880 to base+0x8FF       Allocated to tpm_manager/nvram error.
// base+0x900 to base+0x97F       Allocated to elliptic curve and related.
// base+0xC00 to base+0xFFF       Allocated to hashed TPMError.

// When reporting the unified error code, bit 16 (0x10000) is set to indicate
// that it's a unified error code.

inline constexpr UnifiedError kUnifiedErrorMask = 0x0FFFFLL;
inline constexpr UnifiedError kUnifiedErrorBit = 0x10000LL;

inline constexpr int64_t kUnifiedErrorLayerMask = 0x0F000LL;

// Note: This is enforced by static_assert in tpm2_error_test.cc
inline constexpr UnifiedError kHwsecTpmErrorBase = (7 << 12);

// Note: All the *Max entries below are inclusive.

inline constexpr UnifiedError kUnifiedErrorTpmManagerBase =
    kHwsecTpmErrorBase + 0x800;
inline constexpr UnifiedError kUnifiedErrorTpmManagerMax =
    kHwsecTpmErrorBase + 0x87F;

inline constexpr UnifiedError kUnifiedErrorNvramBase =
    kHwsecTpmErrorBase + 0x880;
inline constexpr UnifiedError kUnifiedErrorNvramMax =
    kHwsecTpmErrorBase + 0x8FF;

inline constexpr UnifiedError kUnifiedErrorECBase = kHwsecTpmErrorBase + 0x900;
inline constexpr UnifiedError kUnifiedErrorECMax = kHwsecTpmErrorBase + 0x97F;

inline constexpr UnifiedError kUnifiedErrorHashedTpmErrorBase =
    kHwsecTpmErrorBase + 0xC00;
inline constexpr UnifiedError kUnifiedErrorHashedTpmErrorMax =
    kHwsecTpmErrorBase + 0xFFF;
inline constexpr UnifiedError kUnifiedErrorHashedTpmErrorMask = 0x3FF;

}  // namespace unified_tpm_error

// A base class for TPM errors.
class HWSEC_EXPORT TPMErrorBase : public hwsec_foundation::status::Error {
 public:
  using MakeStatusTrait = hwsec_foundation::status::ForbidMakeStatus;
  // TPMErrorBase is the base of all TPM-related error in libhwsec.
  using BaseErrorType = TPMErrorBase;

  explicit TPMErrorBase(std::string message) : Error(message) {}
  ~TPMErrorBase() override = default;

  // Returns what the action should do after this error happen.
  virtual TPMRetryAction ToTPMRetryAction() const = 0;

  // Returns a unified error code.
  virtual unified_tpm_error::UnifiedError UnifiedErrorCode() const = 0;

  // If there's any hashing that is used to derive the unified error code, then
  // this method print out the original content before hashing so that we can
  // discover what the hashed unified error code was when we're debugging.
  virtual void LogUnifiedErrorCodeMapping() const = 0;
};

// A TPM error which contains error message and retry action. Doesn't contain
// an error code on its own.
class HWSEC_EXPORT TPMError : public TPMErrorBase {
 public:
  // Overload MakeStatus to prevent issuing un-actioned TPMErrors. Attempting to
  // create a StatusChain<TPMError> without an action will create a stub object
  // that caches the message and waits for the Wrap call with an appropriate
  // Status to complete the definition and construct a proper TPMError. That
  // intends to ensure that all TPMError object propagated contain an action
  // either explicitly specified or inherited from a specific tpm-type dependent
  // error object.
  struct MakeStatusTrait : public hwsec_foundation::status::AlwaysNotOk {
    class Unactioned {
     public:
      explicit Unactioned(std::string error_message)
          : error_message_(error_message) {}

      // Wrap will convert the stab into the appropriate Status type.
      [[clang::return_typestate(unconsumed)]] auto Wrap(
          hwsec_foundation::status::StatusChain<TPMErrorBase> status
          [[clang::param_typestate(unconsumed)]]) && {
        using hwsec_foundation::status::NewStatus;
        return NewStatus<TPMError>(error_message_, status->ToTPMRetryAction())
            .Wrap(std::move(status));
      }

     private:
      const std::string error_message_;
    };

    class Unmessaged {
     public:
      explicit Unmessaged(TPMRetryAction action) : action_(action) {}

      // Wrap will convert the stab into the appropriate Status type.
      [[clang::return_typestate(unconsumed)]] auto Wrap(
          brillo::ErrorPtr err) && {
        using hwsec_foundation::status::NewStatus;
        std::string result;
        if (err) {
          result = base::StringPrintf(
              "BrilloError(%s, %s, %s)", err->GetDomain().c_str(),
              err->GetCode().c_str(), err->GetMessage().c_str());
        } else {
          result = "BrilloError(null)";
        }
        return NewStatus<TPMError>(std::move(result), action_);
      }

     private:
      const TPMRetryAction action_;
    };

    // Returns a stub that doesn't convert to Status. The stub will wait for a
    // Wrap.
    auto operator()(std::string error_message) {
      return Unactioned(error_message);
    }

    // Returns a stub that doesn't convert to Status. The stub will wait for a
    // Wrap.
    auto operator()(TPMRetryAction action) { return Unmessaged(action); }

    // If we get action as an argument - create the Status directly.
    [[clang::return_typestate(unconsumed)]] auto operator()(
        std::string error_message, TPMRetryAction action) {
      using hwsec_foundation::status::NewStatus;
      return NewStatus<TPMError>(error_message, action);
    }
  };

  TPMError(std::string error_message, TPMRetryAction action)
      : TPMErrorBase(error_message), retry_action_(action) {}
  ~TPMError() override = default;

  TPMRetryAction ToTPMRetryAction() const override { return retry_action_; }
  unified_tpm_error::UnifiedError UnifiedErrorCode() const override {
    return CalculateUnifiedErrorCode(ToString());
  }

  void LogUnifiedErrorCodeMapping() const override;

 private:
  static unified_tpm_error::UnifiedError CalculateUnifiedErrorCode(
      const std::string& msg);

  const TPMRetryAction retry_action_;
};

}  // namespace hwsec

#endif  // LIBHWSEC_ERROR_TPM_ERROR_H_
