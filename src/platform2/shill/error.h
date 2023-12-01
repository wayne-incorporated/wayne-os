// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_ERROR_H_
#define SHILL_ERROR_H_

#include <memory>
#include <string>

#include <base/location.h>
#include <base/strings/string_piece.h>

namespace brillo {
class Error;
using ErrorPtr = std::unique_ptr<Error>;
}  // namespace brillo

namespace shill {

class Error {
 public:
  enum Type {
    kSuccess = 0,      // No error.
    kOperationFailed,  // failure, otherwise unspecified
    kAlreadyConnected,
    kAlreadyExists,
    kIllegalOperation,
    kIncorrectPin,
    kInProgress,
    kInternalError,
    kInvalidApn,
    kInvalidArguments,
    kInvalidNetworkName,
    kInvalidPassphrase,
    kInvalidProperty,
    kNoCarrier,
    kNotConnected,
    kNotFound,
    kNotImplemented,
    kNotOnHomeNetwork,
    kNotRegistered,
    kNotSupported,
    kOperationAborted,
    kOperationTimeout,
    kPassphraseRequired,
    kPermissionDenied,
    kPinBlocked,
    kPinRequired,
    kTechnologyNotAvailable,
    kWepNotSupported,
    kWrongState,
    kNumErrors,
  };

  Error();                    // Success by default.
  explicit Error(Type type);  // Uses the default message for |type|.
  Error(Type type, base::StringPiece message);
  Error(Type type,
        base::StringPiece message,
        base::StringPiece detailed_error_type);
  Error(Type type, base::StringPiece message, const base::Location& location);
  Error(const Error&);
  Error& operator=(const Error&);

  ~Error();

  void Populate(Type type);  // Uses the default message for |type|.
  void Populate(Type type, base::StringPiece message);
  void Populate(Type type,
                base::StringPiece message,
                base::StringPiece detailed_error_type);
  void Populate(Type type,
                base::StringPiece message,
                const base::Location& location);

  void Log() const;

  void Reset();

  // Sets the Chromeos |error| and returns true if Error represents failure.
  // Leaves error unchanged, and returns false otherwise.
  bool ToChromeosError(brillo::ErrorPtr* error) const;
  bool ToChromeosErrorNoLog(brillo::ErrorPtr* error) const;

  bool ToDetailedError(brillo::ErrorPtr* error) const;
  bool ToDetailedErrorNoLog(brillo::ErrorPtr* error) const;

  Type type() const { return type_; }
  const std::string& message() const { return message_; }
  const base::Location& location() const { return location_; }

  bool IsSuccess() const { return type_ == kSuccess; }
  bool IsFailure() const { return !IsSuccess(); }

  static std::string GetDBusResult(Type type);
  static std::string GetDefaultMessage(Type type);

  static void LogMessage(const base::Location& from_here,
                         Type type,
                         base::StringPiece message);

  // Log an error message from |from_here|.  If |error| is non-NULL, also
  // populate it.
  static void PopulateAndLog(const base::Location& from_here,
                             Error* error,
                             Type type,
                             base::StringPiece message);

  static std::string GetLocationAsString(const base::Location& location);

  // Note: This error message is used in tast tests.
  static constexpr char kServiceNotFoundMsg[] =
      "Matching service was not found";

 private:
  Type type_;
  std::string message_;
  // For frontend we need a user friendly error message, but for effective
  // diagnostics we also need the actual error reported by the underlying
  // connectivity module which could be reported through UMA or
  // structured metrics.
  std::string detailed_error_type_;
  std::string detailed_message_;
  base::Location location_;
};

// stream operator provided to facilitate logging
std::ostream& operator<<(std::ostream& stream, const shill::Error& error);

}  // namespace shill

#endif  // SHILL_ERROR_H_
