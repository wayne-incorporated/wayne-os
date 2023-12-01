// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "hermes/lpa_util.h"

#include <map>
#include <string>

#include <base/strings/stringprintf.h>
#include <brillo/errors/error_codes.h>
#include <brillo/map_utils.h>
#include <chromeos/dbus/service_constants.h>
#include <google-lpa/lpa/card/euicc_card.h>
#include <google-lpa/lpa/core/lpa.h>
#include <google-lpa/lpa/smdx/smdp_client.h>

namespace hermes {

namespace {

constexpr int kOuterErrorBase = 100000;
constexpr int kInnerErrorMax = 1000;

struct InnerError {
  const char* error_code_;
  const char* error_message_;
};

const std::map<int, const char*>& GetOuterErrorMap() {
  static std::map<int, const char*> err_map{
      {0, ""},
      {lpa::core::Lpa::kSetTestModeError, "Lpa SetTestModeError: "},
      {lpa::core::Lpa::kGetEidError, "Lpa GetEid: "},
      {lpa::core::Lpa::kGetInstalledProfilesError,
       "Lpa GetInstalledProfiles: "},
      {lpa::core::Lpa::kEnableProfileError, "Lpa EnableProfile: "},
      {lpa::core::Lpa::kDisableProfileError, "Lpa DisableProfile: "},
      {lpa::core::Lpa::kSetProfileNicknameError, "Lpa SetProfileNickname: "},
      {lpa::core::Lpa::kDeleteProfileError, "Lpa DeleteProfile: "},
      {lpa::core::Lpa::kResetMemoryError, "Lpa ResetMemory: "},
      {lpa::core::Lpa::kDownloadProfileError, "Lpa DownloadProfile: "},
      {lpa::core::Lpa::kGetProfileFromActivationCodeError,
       "Lpa GetProfileFromActivationCode: "},
      {lpa::core::Lpa::kGetDefaultProfileFromSmdpError,
       "Lpa GetDefaultProfileFromSmdp: "},
      {lpa::core::Lpa::kSendNotificationsError, "Lpa SendNotifications: "},
      {lpa::core::Lpa::kGetPendingProfilesError, "Lpa GetPendingProfiles: "},
  };
  return err_map;
}

const std::map<int, const char*>& GetMidErrorMap() {
  static std::map<int, const char*> err_map{
      {0, ""},
      {lpa::card::EuiccCard::kGetEidError, "EuiccCard GetEid: "},
      {lpa::card::EuiccCard::kGetProfilesInfoError,
       "EuiccCard GetProfilesInfo: "},
      {lpa::card::EuiccCard::kEnableProfileError, "EuiccCard EnableProfile: "},
      {lpa::card::EuiccCard::kDisableProfileError,
       "EuiccCard DisableProfile: "},
      {lpa::card::EuiccCard::kDeleteProfileError, "EuiccCard DeleteProfile: "},
      {lpa::card::EuiccCard::kSetNicknameError, "EuiccCard SetNickname: "},
      {lpa::card::EuiccCard::kGetEuiccConfiguredAddressesError,
       "EuiccCard GetEuiccConfiguredAddresses: "},
      {lpa::card::EuiccCard::kSetDefaultSmdpAddressError,
       "EuiccCard SetDefaultSmdpAddress: "},
      {lpa::card::EuiccCard::kGetRatError, "EuiccCard GetRat: "},
      {lpa::card::EuiccCard::kResetMemoryError, "EuiccCard ResetMemory: "},
      {lpa::card::EuiccCard::kGetEuiccChallengeError,
       "EuiccCard GetEuiccChallenge: "},
      {lpa::card::EuiccCard::kGetEuiccInfo1Error, "EuiccCard GetEuiccInfo1: "},
      {lpa::card::EuiccCard::kGetEuiccInfo2Error, "EuiccCard GetEuiccInfo2: "},
      {lpa::card::EuiccCard::kAuthenticateServerError,
       "EuiccCard AuthenticateServer: "},
      {lpa::card::EuiccCard::kPrepareDownloadError,
       "EuiccCard PrepareDownload: "},
      {lpa::card::EuiccCard::kLoadBoundProfilePackageError,
       "EuiccCard LoadBoundProfilePackage: "},
      {lpa::card::EuiccCard::kCancelSessionError, "EuiccCard CancelSession: "},
      {lpa::card::EuiccCard::kListNotificationsError,
       "EuiccCard ListNotifications: "},
      {lpa::card::EuiccCard::kRetrieveNotificationListError,
       "EuiccCard RetrieveNotificationList: "},
      {lpa::card::EuiccCard::kRetrieveNotificationError,
       "EuiccCard RetrieveNotification: "},
      {lpa::card::EuiccCard::kRemoveNotificationFromListError,
       "EuiccCard RemoveNotificationFromList: "},
      {lpa::smdp::SmdpClient::kInitiateAuthenticationError,
       "Smdp InitiateAuthentication: "},
      {lpa::smdp::SmdpClient::kAuthenticateClientError,
       "Smdp AuthenticateClient: "},
      {lpa::smdp::SmdpClient::kGetBoundProfilePackageError,
       "Smdp GetBoundProfilePackage: "},
      {lpa::smdp::SmdpClient::kCancelSessionError, "Smdp CancelSession: "},
      {lpa::smdp::SmdpClient::kHandleNotificationError,
       "Smdp HandleNotification: "},
  };
  return err_map;
}

const std::map<int, InnerError>& GetInnerErrorMap() {
  static std::map<int, InnerError> err_map{
      {lpa::core::Lpa::kWrongState,
       {kErrorWrongState, "Invalid state for requested method"}},
      {lpa::core::Lpa::kIccidNotFound, {kErrorInvalidIccid, "Invalid iccid"}},
      {lpa::core::Lpa::kProfileAlreadyEnabled,
       {kErrorAlreadyEnabled,
        "Requested method provided an already-enabled profile"}},
      {lpa::core::Lpa::kProfileAlreadyDisabled,
       {kErrorAlreadyDisabled, "Requested method provided a disabled profile"}},
      {lpa::core::Lpa::kNeedConfirmationCode,
       {kErrorNeedConfirmationCode, "Need confirmation code"}},
      {lpa::core::Lpa::kInvalidActivationCode,
       {kErrorInvalidActivationCode, "Invalid activation code"}},
      {lpa::core::Lpa::kFailedToSendNotifications,
       {kErrorSendNotificationFailure, "Failed to send notifications"}},
      {lpa::core::Lpa::kNoOpForTestingProfile,
       {kErrorTestProfileInProd, "Non-test mode cannot use test profile"}},
      {lpa::card::EuiccCard::kNoResponses,
       {kErrorNoResponse, "No response from eUICC"}},
      {lpa::card::EuiccCard::kMalformedResponse,
       {kErrorMalformedResponse, "Malformed response from eUICC"}},
      {lpa::card::EuiccCard::kSendApduError,
       {kErrorSendApduFailure, "Failed to send APDU to eUICC"}},
      {lpa::card::EuiccCard::kInvalidIccid,
       {kErrorInvalidIccid, "Invalid iccid"}},
      {lpa::card::EuiccCard::kBadRequest,
       {kErrorBadRequest, "Bad eUICC request"}},
      {lpa::smdp::SmdpClient::kMalformedResponse,
       {kErrorMalformedResponse, "Malformed response"}},
      {lpa::smdp::SmdpClient::kSendHttpsError,
       {kErrorSendHttpsFailure, "Error sending HTTPS"}},
      {lpa::smdp::SmdpClient::kBadNotification,
       {kErrorBadNotification, "Bad notification"}},
  };
  return err_map;
}

const std::map<int, InnerError>& GetInnerErrorMapForAuthenticateServer() {
  constexpr int kPreviouslySeenInvalidActivationCode = 4;
  static std::map<int, InnerError> err_map{
      {lpa::card::EuiccCard::kNoResponses,
       {kErrorNoResponse, "No response from eUICC"}},
      {kPreviouslySeenInvalidActivationCode,
       {kErrorMalformedResponse,
        "Malformed response from eUICC. Invalid activation code may have been "
        "reused"}},
      {lpa::card::EuiccCard::kSendApduError,
       {kErrorSendApduFailure, "Failed to send APDU to eUICC"}},
  };
  return err_map;
}

}  // namespace

brillo::ErrorPtr LpaErrorToBrillo(const base::Location& location, int error) {
  int lpa_inner_code = error % kInnerErrorMax;
  if (lpa_inner_code == lpa::core::Lpa::kNoError) {
    return nullptr;
  }

  int lpa_outer_mod = error % kOuterErrorBase;
  int lpa_outer_code = error - lpa_outer_mod;
  std::string error_message = brillo::GetOrDefault(
      GetOuterErrorMap(), lpa_outer_code, "Lpa UnknownMethod: ");

  int lpa_mid_code = lpa_outer_mod - lpa_inner_code;
  error_message +=
      brillo::GetOrDefault(GetMidErrorMap(), lpa_mid_code, "UnknownMid: ");

  const auto& error_map =
      lpa_mid_code == lpa::card::EuiccCard::kAuthenticateServerError
          ? GetInnerErrorMapForAuthenticateServer()
          : GetInnerErrorMap();
  const auto& inner_error = brillo::GetOrDefault(
      error_map, lpa_inner_code, {kErrorUnknown, "Unknown error"});

  error_message +=
      base::StringPrintf("%s (%d)", inner_error.error_message_, lpa_inner_code);

  return brillo::Error::Create(location, brillo::errors::dbus::kDomain,
                               inner_error.error_code_, error_message);
}

}  // namespace hermes
