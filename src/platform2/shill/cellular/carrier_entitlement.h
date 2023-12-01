// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_CELLULAR_CARRIER_ENTITLEMENT_H_
#define SHILL_CELLULAR_CARRIER_ENTITLEMENT_H_

#include <memory>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include <base/cancelable_callback.h>
#include <base/json/json_string_value_serializer.h>
#include <base/memory/weak_ptr.h>
#include <brillo/http/http_transport.h>
#include "base/time/time.h"

#include "shill/cellular/mobile_operator_mapper.h"
#include "shill/data_types.h"
#include "shill/event_dispatcher.h"
#include "shill/net/ip_address.h"

namespace shill {

class EventDispatcher;
class Metrics;

// The CarrierEntitlement class implements the carrier entitlement check
// functionality in shill, which is responsible for connecting to a remote
// server and checking if a user is allowed to use the cellular connection for
// tethering/hotspot on carriers that require this verification.
// The entitlement check is configured on a carrier by setting the value
// |mhs_entitlement_url| in the modb. Any parameters that need to be sent in
// the request, such as the imsi, can be configured in |mhs_entitlement_param|.
// If a carrier doesn't have a |mhs_entitlement_url|
// value, the entitlement check passes automatically.
class CarrierEntitlement {
 public:
  enum class Result {
    kAllowed,
    kUserNotAllowedToTether,
    kUnrecognizedUser,
    kGenericError
  };

  explicit CarrierEntitlement(EventDispatcher* dispatcher,
                              Metrics* metrics,
                              base::RepeatingCallback<void(Result)> check_cb);
  CarrierEntitlement(const CarrierEntitlement&) = delete;
  CarrierEntitlement& operator=(const CarrierEntitlement&) = delete;

  virtual ~CarrierEntitlement();

  // Performs an entitlement check if required by the carrier and triggers
  // |check_cb|.
  // If an entitlement check is not required by the carrier, |result| will be
  // set to |kAllowed|, otherwise it will run the entitlement check
  // corresponding to the carrier and return |kAllowed| in the callback if and
  // only if the device is allowed to tether.
  // TODO(b/287083906): Evaluate passing the Network object to reduce the
  // number of arguments.
  void Check(const IPAddress& src_address,
             const std::vector<IPAddress>& dns_list,
             const std::string& interface_name,
             const MobileOperatorMapper::EntitlementConfig& config);

  // Reset the cached entitlement check value.
  void Reset();

  // The time between background entitlement checks.
  static constexpr base::TimeDelta kBackgroundCheckPeriod = base::Hours(24);

  // Error codes returned by server.
  static constexpr char kServerCodeUserNotAllowedToTether[] = "1000";
  static constexpr char kServerCodeHttpSyntaxError[] = "1001";
  static constexpr char kServerCodeUnrecognizedUser[] = "1003";
  static constexpr char kServerCodeInternalError[] = "5000";

  // Entitlement check parameter keys
  static constexpr char kImsiProperty[] = "imsi";

 private:
  friend class CarrierEntitlementTest;

  // Time to wait for HTTP request.
  static constexpr base::TimeDelta kHttpRequestTimeout = base::Seconds(10);

  // Callback used to return data read from the HTTP HttpRequest.
  void HttpRequestSuccessCallback(
      brillo::http::RequestID request_id,
      std::unique_ptr<brillo::http::Response> response);

  // Callback used to return the error from the HTTP HttpRequest.
  void HttpRequestErrorCallback(brillo::http::RequestID request_id,
                                const brillo::Error* error);

  void CheckInternal(const IPAddress& src_address,
                     const std::vector<IPAddress>& dns_list,
                     const std::string& interface_name,
                     bool user_triggered);

  void PostBackgroundCheck();
  // Builds the request content
  std::unique_ptr<base::Value> BuildContentPayload(const Stringmap& params);

  void SendResult(Result result);

  EventDispatcher* dispatcher_;
  Metrics* metrics_;
  base::RepeatingCallback<void(Result)> check_cb_;
  MobileOperatorMapper::EntitlementConfig config_;
  std::shared_ptr<brillo::http::Transport> transport_;
  brillo::http::RequestID request_id_;
  bool request_in_progress_;
  base::CancelableOnceClosure background_check_cancelable;
  std::vector<IPAddress> last_dns_list_;
  std::string last_interface_name_;
  IPAddress last_src_address_;
  Result last_result_ = Result::kGenericError;
  base::WeakPtrFactory<CarrierEntitlement> weak_ptr_factory_;
};

}  // namespace shill

#endif  // SHILL_CELLULAR_CARRIER_ENTITLEMENT_H_
