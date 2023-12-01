// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_NETWORK_DHCP_CONTROLLER_H_
#define SHILL_NETWORK_DHCP_CONTROLLER_H_

#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <base/cancelable_callback.h>
#include <base/files/file_path.h>
#include <base/memory/weak_ptr.h>
#include <base/time/time.h>
#include <gtest/gtest_prod.h>  // for FRIEND_TEST

#include "shill/ipconfig.h"
#include "shill/mockable.h"
#include "shill/net/shill_time.h"
#include "shill/store/key_value_store.h"
#include "shill/technology.h"

namespace shill {

class ControlInterface;
class DHCPProvider;
class DHCPProxyInterface;
class EventDispatcher;
class Metrics;
class ProcessManager;

// This class provides a DHCP client instance for the device |device_name|.
//
// The DHPCConfig instance asks the DHCP client to create a lease file
// containing the name |lease_file_suffix|.  If this suffix is the same as
// |device_name|, the lease is considered to be ephemeral, and the lease
// file is removed whenever this DHCPController instance is no longer needed.
// Otherwise, the lease file persists and will be re-used in future attempts.
// If |hostname| is not empty, it will be used in the DHCP request as DHCP
// option 12. This asks the DHCP server to register this hostname on our
// behalf, for purposes of administration or creating a dynamic DNS entry.
class DHCPController {
 public:
  // Called when the IPConfig got from DHCP is updated. |properties| contains
  // all the parameters we get from DHCP. |new_lease_acquired| indicates whether
  // or not a DHCP lease was acquired from the server.
  using UpdateCallback = base::RepeatingCallback<void(
      const IPConfig::Properties& properties, bool new_lease_acquired)>;
  // Called when DHCP process ended without getting a lease. |is_voluntary|
  // indicates whether that was a voluntary stop per option 108, or because of a
  // failure.
  using DropCallback = base::RepeatingCallback<void(bool is_voluntary)>;

  enum ReleaseReason { kReleaseReasonDisconnect, kReleaseReasonStaticIP };

  enum class ClientEventReason {
    kUnknown,
    kBound,
    kFail,
    kGatewayArp,
    kNak,
    kRebind,
    kReboot,
    kRenew
  };
  enum class ClientStatus { kUnknown, kIPv6Preferred };

  DHCPController(ControlInterface* control_interface,
                 EventDispatcher* dispatcher,
                 DHCPProvider* provider,
                 const std::string& device_name,
                 const std::string& lease_file_suffix,
                 bool arp_gateway,
                 bool enable_rfc_8925,
                 const std::string& hostname,
                 Technology technology,
                 Metrics* metrics);
  DHCPController(const DHCPController&) = delete;
  DHCPController& operator=(const DHCPController&) = delete;

  virtual ~DHCPController();

  // Registers callbacks for DHCP events.
  mockable void RegisterCallbacks(UpdateCallback update_callback,
                                  DropCallback drop_callback);

  // Request, renew and release IP configuration. Return true on success, false
  // otherwise. The default implementation always returns false indicating a
  // failure.  ReleaseIP is advisory: if we are no longer connected, it is not
  // possible to properly vacate the lease on the remote server.  Also,
  // depending on the configuration of the specific IPConfig subclass, we may
  // end up holding on to the lease so we can resume to the network lease
  // faster.
  mockable bool RequestIP();
  mockable bool RenewIP();
  mockable bool ReleaseIP(ReleaseReason reason);

  // If |proxy_| is not initialized already, sets it to a new D-Bus proxy to
  // |service|.
  void InitProxy(const std::string& service);

  // Processes an Event signal from dhcpcd.
  mockable void ProcessEventSignal(ClientEventReason reason,
                                   const KeyValueStore& configuration);
  // Processes a StatusChanged signal from dhcpcd.
  mockable void ProcessStatusChangedSignal(ClientStatus status);

  // Returns the time left (in seconds) till the current DHCP lease is to be
  // renewed in |time_left|. Returns nullopt if an error occurs (i.e. current
  // lease has already expired or no current DHCP lease), true otherwise.
  mockable std::optional<base::TimeDelta> TimeToLeaseExpiry();

  std::string device_name() const { return device_name_; }

  void set_root_for_testing(base::FilePath path) { root_ = path; }

 protected:
  // On we get a new IP config properties via DHCP. The second parameter
  // indicates whether this is an authoritative confirmation.
  void OnIPConfigUpdated(const IPConfig::Properties& properties,
                         bool new_lease_acquired);

  // Notifies registered listeners that the configuration process has failed.
  void NotifyFailure();

  // Notifies registered listeners that the lease has expired.
  void NotifyUpdate(bool new_lease_acquired);

  void set_is_lease_active(bool active) { is_lease_active_ = active; }

  // Return true if the lease file is ephermeral, which means the lease file
  // should be deleted during cleanup.
  bool IsEphemeralLease() const;

  // Cleans up remaining state from a running client, if any, including freeing
  // its GPid, exit watch callback, and state files.
  void CleanupClientState();

  // Return true if we should treat acquisition timeout as failure.
  bool ShouldFailOnAcquisitionTimeout() const;

  // Return true if we should keep the lease on disconnect.
  bool ShouldKeepLeaseOnDisconnect() const;

  // Updates |current_lease_expiration_time_| by adding |new_lease_duration| to
  // the current time.
  void UpdateLeaseExpirationTime(uint32_t new_lease_duration);

  // Resets |current_lease_expiration_time_| to its default value.
  void ResetLeaseExpirationTime();

  // Return the list of flags used to start dhcpcd.
  virtual std::vector<std::string> GetFlags();

  base::FilePath root() const { return root_; }

 private:
  friend class DHCPControllerTest;
  FRIEND_TEST(DHCPControllerCallbackTest, ProcessEventSignalFail);
  FRIEND_TEST(DHCPControllerCallbackTest, ProcessAcquisitionTimeout);
  FRIEND_TEST(DHCPControllerCallbackTest, RequestIPTimeout);
  FRIEND_TEST(DHCPControllerCallbackTest, StartTimeout);
  FRIEND_TEST(DHCPControllerCallbackTest, StoppedDuringFailureCallback);
  FRIEND_TEST(DHCPControllerCallbackTest, StoppedDuringSuccessCallback);
  FRIEND_TEST(DHCPControllerTest, InitProxy);
  FRIEND_TEST(DHCPControllerTest, KeepLeaseOnDisconnect);
  FRIEND_TEST(DHCPControllerTest, ReleaseIP);
  FRIEND_TEST(DHCPControllerTest, ReleaseIPStaticIPWithLease);
  FRIEND_TEST(DHCPControllerTest, ReleaseIPStaticIPWithoutLease);
  FRIEND_TEST(DHCPControllerTest, ReleaseLeaseOnDisconnect);
  FRIEND_TEST(DHCPControllerTest, RenewIP);
  FRIEND_TEST(DHCPControllerTest, RequestIP);
  FRIEND_TEST(DHCPControllerTest, Restart);
  FRIEND_TEST(DHCPControllerTest, RestartNoClient);
  FRIEND_TEST(DHCPControllerTest, StartFail);
  FRIEND_TEST(DHCPControllerTest, StartWithoutLeaseSuffix);
  FRIEND_TEST(DHCPControllerTest, Stop);
  FRIEND_TEST(DHCPControllerTest, StopDuringRequestIP);
  FRIEND_TEST(DHCPProviderTest, CreateController);
  FRIEND_TEST(DHCPProviderTest, BindAndUnbind);

  // Starts dhcpcd, returns true on success and false otherwise.
  bool Start();

  // Stops dhcpcd if running.
  void Stop(const char* reason);

  // Stops dhcpcd if already running and then starts it. Returns true on success
  // and false otherwise.
  bool Restart();

  // Called when the dhcpcd client process exits.
  void OnProcessExited(int exit_status);

  // Initialize a callback that will invoke ProcessAcquisitionTimeout if we
  // do not get a lease in a reasonable amount of time.
  void StartAcquisitionTimeout();
  // Cancel callback created by StartAcquisitionTimeout. One-liner included
  // for symmetry.
  void StopAcquisitionTimeout();
  // Called if we do not get a DHCP lease in a reasonable amount of time.
  // Informs upper layers of the failure.
  void ProcessAcquisitionTimeout();

  // Initialize a callback that will invoke ProcessExpirationTimeout if we
  // do not renew a lease in a |lease_duration|.
  void StartExpirationTimeout(base::TimeDelta lease_duration);
  // Cancel callback created by StartExpirationTimeout. One-liner included
  // for symmetry.
  void StopExpirationTimeout();
  // Called if we do not renew a DHCP lease by the time the lease expires.
  // Informs upper layers of the expiration and restarts the DHCP client.
  void ProcessExpirationTimeout(base::TimeDelta lease_duration);

  // Kills DHCP client process.
  void KillClient();

  // These two functions invoke corresponding callbacks and are executed via
  // PostTask(), so it can be guaranteed that callbacks will not be invoked when
  // this object has been destroyed, and the listener can safely destroy this
  // object in the callback.
  void InvokeUpdateCallback(const IPConfig::Properties properties,
                            bool new_lease_acquired);
  void InvokeDropCallback(bool is_failure);

  ControlInterface* control_interface_;

  DHCPProvider* provider_;

  // The name of interface which this DHCP instance is running on.
  std::string device_name_;

  // DHCP lease file suffix, used to differentiate the lease of one interface
  // or network from another.
  std::string lease_file_suffix_;

  // The technology of device which DHCP is running on.
  Technology technology_;

  // The PID of the spawned DHCP client. May be 0 if no client has been spawned
  // yet or the client has died.
  int pid_;

  // Whether a lease has been acquired from the DHCP server or gateway ARP.
  bool is_lease_active_;

  // Specifies whether to supply an argument to the DHCP client to validate
  // the acquired IP address using an ARP request to the gateway IP address.
  bool arp_gateway_;

  // Specifies whether request option 108 to prefer IPv6-only on a capable
  // network.
  bool enable_rfc_8925_;

  // Whether it is valid to retain the lease acquired via gateway ARP.
  bool is_gateway_arp_active_;

  // Hostname to be used in DHCP request.
  std::string hostname_;

  // The proxy for communicating with the DHCP client.
  std::unique_ptr<DHCPProxyInterface> proxy_;

  // Called if we fail to get a DHCP lease in a timely manner.
  base::CancelableOnceClosure lease_acquisition_timeout_callback_;

  // Time to wait for a DHCP lease. Represented as field so that it
  // can be overridden in tests.
  base::TimeDelta lease_acquisition_timeout_;

  std::optional<struct timeval> current_lease_expiration_time_;

  // Called if a DHCP lease expires.
  base::CancelableOnceClosure lease_expiration_callback_;

  // Callbacks registered by RegisterCallbacks().
  UpdateCallback update_callback_;
  DropCallback drop_callback_;

  // Root file path, used for testing.
  base::FilePath root_;

  base::WeakPtrFactory<DHCPController> weak_ptr_factory_;
  EventDispatcher* dispatcher_;
  ProcessManager* process_manager_;
  Metrics* metrics_;
  Time* time_;
};

}  // namespace shill

#endif  // SHILL_NETWORK_DHCP_CONTROLLER_H_
