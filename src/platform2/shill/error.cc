// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/error.h"

#include <utility>

#include <base/check.h>
#include <base/files/file_path.h>
#include <base/logging.h>
#include <brillo/errors/error.h>
#include <brillo/errors/error_codes.h>
#include <chromeos/dbus/service_constants.h>

#include "shill/logging.h"

namespace shill {

namespace {

struct Info {
  const char* dbus_result;  // Error type name
  const char* message;      // Default error type message
};

const Info kInfos[Error::kNumErrors] = {
    {kErrorResultSuccess, "Success (no error)"},
    {kErrorResultFailure, "Operation failed (no other information)"},
    {kErrorResultAlreadyConnected, "Already connected"},
    {kErrorResultAlreadyExists, "Already exists"},
    {kErrorResultIllegalOperation, "Illegal operation"},
    {kErrorResultIncorrectPin, "Incorrect PIN"},
    {kErrorResultInProgress, "In progress"},
    {kErrorResultInternalError, "Internal error"},
    {kErrorResultInvalidApn, "Invalid APN"},
    {kErrorResultInvalidArguments, "Invalid arguments"},
    {kErrorResultInvalidNetworkName, "Invalid network name"},
    {kErrorResultInvalidPassphrase, "Invalid passphrase"},
    {kErrorResultInvalidProperty, "Invalid property"},
    {kErrorResultNoCarrier, "No carrier"},
    {kErrorResultNotConnected, "Not connected"},
    {kErrorResultNotFound, "Not found"},
    {kErrorResultNotImplemented, "Not implemented"},
    {kErrorResultNotOnHomeNetwork, "Not on home network"},
    {kErrorResultNotRegistered, "Not registered"},
    {kErrorResultNotSupported, "Not supported"},
    {kErrorResultOperationAborted, "Operation aborted"},
    {kErrorResultOperationTimeout, "Operation timeout"},
    {kErrorResultPassphraseRequired, "Passphrase required"},
    {kErrorResultPermissionDenied, "Permission denied"},
    {kErrorResultPinBlocked, "SIM PIN is blocked"},
    {kErrorResultPinRequired, "SIM PIN is required"},
    {kErrorResultTechnologyNotAvailable, "Technology not available"},
    {kErrorResultWepNotSupported, "WEP not supported"},
    {kErrorResultWrongState, "Wrong state"},
};

}  // namespace

Error::Error() {
  Reset();
}

Error::Error(Type type) {
  Populate(type);
}

Error::Error(Type type, base::StringPiece message) {
  Populate(type, message);
}

Error::Error(Type type,
             base::StringPiece message,
             base::StringPiece detailed_error_type) {
  Populate(type, message, detailed_error_type);
}

Error::Error(Type type,
             base::StringPiece message,
             const base::Location& location) {
  Populate(type, message, location);
}

Error::Error(const Error&) = default;

Error& Error::operator=(const Error&) = default;

Error::~Error() = default;

void Error::Populate(Type type) {
  Populate(type, GetDefaultMessage(type));
}

void Error::Populate(Type type, base::StringPiece message) {
  CHECK(type < kNumErrors) << "Error type out of range: " << type;
  type_ = type;
  message_ = message;
}

void Error::Populate(Type type,
                     base::StringPiece message,
                     base::StringPiece detailed_error_type) {
  CHECK(type < kNumErrors) << "Error type out of range: " << type;
  type_ = type;
  message_ = message;
  detailed_error_type_ = detailed_error_type;
}

void Error::Populate(Type type,
                     base::StringPiece message,
                     const base::Location& location) {
  CHECK(type < kNumErrors) << "Error type out of range: " << type;
  type_ = type;
  message_ = message;
  location_ = location;
}

void Error::Log() const {
  LogMessage(location_, type_, message_);
}

void Error::Reset() {
  Populate(kSuccess);
}

bool Error::ToChromeosError(brillo::ErrorPtr* error) const {
  if (IsFailure()) {
    brillo::Error::AddTo(error, location_, brillo::errors::dbus::kDomain,
                         kInfos[type_].dbus_result, message_);
    return true;
  }
  return false;
}

bool Error::ToChromeosErrorNoLog(brillo::ErrorPtr* error) const {
  if (IsFailure()) {
    if (error) {
      *error = brillo::Error::CreateNoLog(
          location_, brillo::errors::dbus::kDomain, kInfos[type_].dbus_result,
          message_, std::move(*error));
    }
    return true;
  }
  return false;
}

bool Error::ToDetailedError(brillo::ErrorPtr* error) const {
  if (IsFailure()) {
    brillo::Error::AddTo(error, location_, brillo::errors::shill::kDomain,
                         detailed_error_type_, detailed_message_);
    return true;
  }
  return false;
}

bool Error::ToDetailedErrorNoLog(brillo::ErrorPtr* error) const {
  if (IsFailure()) {
    if (error) {
      *error = brillo::Error::CreateNoLog(
          location_, brillo::errors::shill::kDomain, detailed_error_type_,
          detailed_message_, std::move(*error));
    }
    return true;
  }
  return false;
}

// static
std::string Error::GetDBusResult(Type type) {
  CHECK(type < kNumErrors) << "Error type out of range: " << type;
  return kInfos[type].dbus_result;
}

// static
std::string Error::GetDefaultMessage(Type type) {
  CHECK(type < kNumErrors) << "Error type out of range: " << type;
  return kInfos[type].message;
}

// static
void Error::LogMessage(const base::Location& from_here,
                       Type type,
                       base::StringPiece message) {
  // Since Chrome OS devices do not support certain features, errors returning
  // kNotSupported when those features are requested are expected and should be
  // logged as a WARNING. Prefer using the more specific kNotImplemented error
  // for missing functionality that should be implemented.
  if (type == Error::kNotSupported) {
    LOG(WARNING) << GetLocationAsString(from_here) << message;
  } else {
    LOG(ERROR) << GetLocationAsString(from_here) << message;
  }
}

// static
void Error::PopulateAndLog(const base::Location& from_here,
                           Error* error,
                           Type type,
                           base::StringPiece message) {
  LogMessage(from_here, type, message);
  if (error) {
    error->Populate(type, message, from_here);
  }
}

// static
std::string Error::GetLocationAsString(const base::Location& location) {
  if (!location.has_source_info())
    return "";
  const std::string file_name =
      base::FilePath(location.file_name()).BaseName().value();
  return "[" + file_name + "(" + std::to_string(location.line_number()) +
         ")]: ";
}

std::ostream& operator<<(std::ostream& stream, const Error& error) {
  stream << error.GetDBusResult(error.type()) << ": " << error.message();
  return stream;
}

}  // namespace shill
