// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef HERMES_SMDP_INTERFACE_H_
#define HERMES_SMDP_INTERFACE_H_

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include <base/functional/callback.h>
#include <base/values.h>

namespace hermes {

// Provides an interface through which the LPD can communicate with the SM-DP
// server. This is responsible for opening, maintaining, and closing a HTTPS
// connection to the server.
class SmdpInterface {
 public:
  using InitiateAuthenticationCallback = base::OnceCallback<void(
      const std::string& transaction_id,
      const std::vector<uint8_t>& server_signed1,
      const std::vector<uint8_t>& server_signature1,
      const std::vector<uint8_t>& euicc_ci_pk_id_to_be_used,
      const std::vector<uint8_t>& server_certificate)>;
  using AuthenticateClientCallback =
      base::OnceCallback<void(const std::string& transaction_id,
                              const std::vector<uint8_t>& profile_metadata,
                              const std::vector<uint8_t>& smdp_signed2,
                              const std::vector<uint8_t>& smdp_signature2,
                              const std::vector<uint8_t>& public_key)>;
  using GetBoundProfilePackageCallback = base::OnceCallback<void(
      const std::string& transaction_id,
      const std::vector<uint8_t>& bound_profile_package)>;
  using ErrorCallback =
      base::OnceCallback<void(const std::vector<uint8_t>& error_data)>;

  virtual ~SmdpInterface() = default;

  // First, establishes a connection to the SM-DP+ server over which
  // the ES8+ secure channel will be tunneled, then sends server the eSIM
  // challenge and info1 to begin the Authentication procedure. |callback| is
  // called upon server's response, or |error_callback| is called on server
  // error.
  //
  // Parameters
  //    challenge - eSIM challenge as returned by Esim.GetEuiccChallenge
  //    info1 - eSIM info1 as returned by Esim.GetEuiccInfo
  virtual void InitiateAuthentication(
      const std::vector<uint8_t>& info1,
      const std::vector<uint8_t>& challenge,
      InitiateAuthenticationCallback data_callback,
      ErrorCallback error_callback) = 0;

  virtual void AuthenticateClient(const std::string& transaction_id,
                                  const std::vector<uint8_t>& data,
                                  AuthenticateClientCallback data_callback,
                                  ErrorCallback error_callback) = 0;

  virtual void GetBoundProfilePackage(
      const std::string& transaction_id,
      const std::vector<uint8_t>& data,
      GetBoundProfilePackageCallback data_callback,
      ErrorCallback error_callback) = 0;
};

}  // namespace hermes

#endif  // HERMES_SMDP_INTERFACE_H_
