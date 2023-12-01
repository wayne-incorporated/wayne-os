// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_DEVICE_INFO_H_
#define SHILL_DEVICE_INFO_H_

#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <base/cancelable_callback.h>
#include <base/files/file_path.h>
#include <base/functional/callback.h>
#include <base/memory/weak_ptr.h>
#include <chromeos/patchpanel/dbus/client.h>
#include <gtest/gtest_prod.h>  // for FRIEND_TEST

#include "shill/net/byte_string.h"
#include "shill/net/ip_address.h"
#include "shill/net/shill_time.h"
#include "shill/net/sockets.h"
#include "shill/refptr_types.h"
#include "shill/technology.h"

namespace shill {

class EventDispatcher;
class Manager;
class Metrics;
class NetlinkManager;
class Nl80211Message;
class RoutingTable;
class RTNLHandler;
class RTNLListener;
class RTNLMessage;
class Sockets;

class DeviceInfo {
 public:
  // Type of callback function triggered when an RTNL link add event occurs.
  // First parameter is link name and second parameter interface index.
  using LinkReadyCallback = base::OnceCallback<void(const std::string&, int)>;

  explicit DeviceInfo(Manager* manager);
  DeviceInfo(const DeviceInfo&) = delete;
  DeviceInfo& operator=(const DeviceInfo&) = delete;

  virtual ~DeviceInfo();

  virtual void BlockDevice(const std::string& device_name);
  virtual void AllowDevice(const std::string& device_name);
  virtual bool IsDeviceBlocked(const std::string& device_name);
  void Start();
  void Stop();

  std::vector<std::string> GetUninitializedTechnologies() const;

  // Adds |device| to this DeviceInfo instance so that we can handle its link
  // messages, and registers it with the manager.
  virtual void RegisterDevice(const DeviceRefPtr& device);

  // Deregister the Device instance (if any) from interested parties like
  // Manager and Metrics, and remove the Info corresponding to this
  // interface. No-op if there is no Info for this interface index.
  void DeregisterDevice(int interface_index);

  virtual DeviceRefPtr GetDevice(int interface_index) const;

  virtual bool GetMacAddress(int interface_index, ByteString* address) const;

  // Queries the kernel for a MAC address for |interface_index|.  Returns an
  // empty ByteString on failure.
  virtual ByteString GetMacAddressFromKernel(int interface_index) const;

  // Query IDs that identify the adapter (e.g. PCI IDs). Returns |false| if
  // there was an error. Even if there was an error (say, when probing the
  // |subsystem_id|), the method will still set the IDs it managed to detect,
  // even it could not probe successfully all the IDs. IDs that could not be
  // probed are left untouched.
  bool GetWiFiHardwareIds(int interface_index,
                          int* vendor_id,
                          int* product_id,
                          int* subsystem_id) const;

  virtual bool GetFlags(int interface_index, unsigned int* flags) const;
  virtual bool GetByteCounts(int interface_index,
                             uint64_t* rx_bytes,
                             uint64_t* tx_bytes) const;

  virtual bool CreateTunnelInterface(LinkReadyCallback callback);
  virtual int OpenTunnelInterface(const std::string& interface_name) const;

  // Creates a wireguard interface in the kernel with name |interface_name|.
  // Returns true if we send the message to the kernel successfully.
  // |link_ready_callback| will be invoked when the created link is ready,
  // otherwise |failure_callback| will be invoked if the kernel rejects our
  // request.
  virtual bool CreateWireGuardInterface(const std::string& interface_name,
                                        LinkReadyCallback link_ready_callback,
                                        base::OnceClosure failure_callback);

  // Creates a XFRM interface in the kernel with name |interface_name|, index of
  // the underlying interface |underlying_if_index| and the XFRM interface
  // identifier |xfrm_if_id|. See the following link for more details about
  // these two parameters:
  // https://wiki.strongswan.org/projects/strongswan/wiki/RouteBasedVPN#XFRM-Interfaces-on-Linux.
  // Returns true if we send the message to the kernel successfully.
  // |link_ready_callback| will be invoked when the created link is ready,
  // otherwise |failure_callback| will be invoked if the kernel rejects our
  // request.
  virtual bool CreateXFRMInterface(const std::string& interface_name,
                                   int underlying_if_index,
                                   int xfrm_if_id,
                                   LinkReadyCallback link_ready_callback,
                                   base::OnceClosure failure_callback);

  virtual VirtualDevice* CreatePPPDevice(Manager* manager,
                                         const std::string& ifname,
                                         int ifindex);

  virtual bool DeleteInterface(int interface_index) const;
  virtual void AddVirtualInterfaceReadyCallback(
      const std::string& interface_name, LinkReadyCallback callback);

  // Returns the interface index for |interface_name| or -1 if unknown.
  virtual int GetIndex(const std::string& interface_name) const;

  // Gets the real user ID of the given |user_name| and returns it via |uid|.
  // Returns true on success.
  virtual bool GetUserId(const std::string& user_name, uid_t* uid) const;

  // Notifies this object that patchpanel::Client is ready in Manager. Registers
  // neighbor connected events handler via manager_->patchpanel_client().
  void OnPatchpanelClientReady();

  Manager* manager() const { return manager_; }

 private:
  friend class DeviceInfoDelayedCreationTest;
  friend class DeviceInfoMockedGetUserId;
  friend class DeviceInfoTechnologyTest;
  friend class DeviceInfoTest;
  FRIEND_TEST(CellularTest, StartLinked);
  FRIEND_TEST(DeviceInfoTest, DeviceRemovedEvent);
  FRIEND_TEST(DeviceInfoTest, GetUninitializedTechnologies);
  FRIEND_TEST(DeviceInfoTest, HasSubdir);  // For HasSubdir.
  FRIEND_TEST(DeviceInfoTest, StartStop);
  FRIEND_TEST(DeviceInfoMockedGetUserId,
              AddRemoveAllowedInterface);  // For rtnl_handler_, routing_table_.
  FRIEND_TEST(DeviceInfoTest, CreateDeviceTunnel);  // For pending_links_.

  struct Info {
    Info();

    DeviceRefPtr device;
    std::string name;
    ByteString mac_address;
    unsigned int flags;
    uint64_t rx_bytes;
    uint64_t tx_bytes;

    // This flag indicates that a link add RTNL message has been received for
    // this interface. This is used to behave differently for the first link add
    // message received for this interface index; |device| is unsuitable because
    // some interfaces may undergo delayed Device creation.
    bool received_add_link;

    Technology technology;
  };

  // Create a Device object for the interface named |linkname|, with a
  // string-form MAC address |address|, whose kernel interface index
  // is |interface_index| and detected technology is |technology|.
  virtual DeviceRefPtr CreateDevice(const std::string& link_name,
                                    const std::string& address,
                                    int interface_index,
                                    Technology technology);

  // Return the ARP type (ARPHRD_* from <net/if_arp.h>) of interface
  // |iface_name|.
  int GetDeviceArpType(const std::string& iface_name) const;
  // Return the FilePath for a given |path_name| in the device sysinfo for
  // a specific interface |iface_name|.
  base::FilePath GetDeviceInfoPath(const std::string& iface_name,
                                   const std::string& path_name) const;
  // Return the contents of the device info file |path_name| for interface
  // |iface_name| in output parameter |contents_out|.  Returns true if file
  // read succeeded, false otherwise.
  bool GetDeviceInfoContents(const std::string& iface_name,
                             const std::string& path_name,
                             std::string* contents_out) const;

  // Return the filepath for the target of the device info symbolic link
  // |path_name| for interface |iface_name| in output parameter |path_out|.
  // Returns true if symbolic link read succeeded, false otherwise.
  bool GetDeviceInfoSymbolicLink(const std::string& iface_name,
                                 const std::string& path_name,
                                 base::FilePath* path_out) const;
  // Return the path of the lower device, if any
  bool GetLowerDeviceInfoPath(const std::string& iface_name,
                              base::FilePath* path_out) const;
  // Classify the device named |iface_name| with RTNL kind |kind|, and return
  // an identifier indicating its type.
  virtual Technology GetDeviceTechnology(
      const std::string& iface_name,
      const std::optional<std::string>& kind) const;
  // Checks the device specified by |iface_name| to see if it's a modem device.
  // This method assumes that |iface_name| has already been determined to be
  // using the cdc_ether / cdc_ncm driver.
  bool IsCdcEthernetModemDevice(const std::string& iface_name) const;
  // Query the IDs that identify the WiFi adapter of integrated chipsets like
  // the ones included in some Qualcomm SoCs.
  // To be compatible with the IDs of PCIe adapters, we set the vendor ID to the
  // value 0x0000 (Metrics::kWiFiIntegratedAdapterVendorId) that is not assigned
  // by the PCI-SIG. Integrated adapters are identified by the tuple
  // (Metrics::kWiFiIntegratedAdapterVendorId, product_id, subsystem_id).
  // Returns true if an integrated adapter was detected, false otherwise.
  bool GetIntegratedWiFiHardwareIds(const std::string& iface_name,
                                    int* vendor_id,
                                    int* product_id,
                                    int* subsystem_id) const;
  // Returns true if |base_dir| has a subdirectory named |subdir|.
  // |subdir| can be an immediate subdirectory of |base_dir| or can be
  // several levels deep.
  static bool HasSubdir(const base::FilePath& base_dir,
                        const base::FilePath& subdir);

  // Returns true and sets |link_name| to the interface name contained
  // in |msg| if one is provided.  Returns false otherwise.
  bool GetLinkNameFromMessage(const RTNLMessage& msg, std::string* link_name);

  // Returns true if |msg| pertains to a blocked device whose link name
  // is now different from the name it was assigned before.
  bool IsRenamedBlockedDevice(const RTNLMessage& msg);

  void AddLinkMsgHandler(const RTNLMessage& msg);
  void DelLinkMsgHandler(const RTNLMessage& msg);
  void LinkMsgHandler(const RTNLMessage& msg);

  const Info* GetInfo(int interface_index) const;
  void DelayDeviceCreation(int interface_index);
  void DelayedDeviceCreationTask();
  void RetrieveLinkStatistics(int interface_index, const RTNLMessage& msg);
  void RequestLinkStatistics();

  // Use nl80211 to get information on |interface_index|.
  void GetWiFiInterfaceInfo(int interface_index);
  void OnWiFiInterfaceInfoReceived(const Nl80211Message& message);
  void RecordDarkResumeWakeReason(const std::string& wake_reason);

  // Returns whether a device with name |interface_name| is guest.
  bool IsGuestDevice(const std::string& interface_name) const;

  void OnNeighborReachabilityEvent(
      const patchpanel::Client::NeighborReachabilityEvent& event);

  // Callback registered in CreateWireGuardInterface() and
  // CreateXFRMInterface(). Invoked by RTNLHandler, to notify the
  // acknowledgement from the kernel for the adding link request.
  void OnCreateInterfaceResponse(const std::string& interface_name,
                                 base::OnceClosure failure_callback,
                                 int32_t error);

  void set_sockets_for_test(std::unique_ptr<Sockets> sockets) {
    sockets_ = std::move(sockets);
  }

  Manager* manager_;
  EventDispatcher* dispatcher_ = nullptr;
  Metrics* metrics_ = nullptr;

  std::map<int, Info> infos_;           // Maps interface index to Info.
  std::map<std::string, int> indices_;  // Maps interface name to index.

  std::unique_ptr<RTNLListener> link_listener_;
  std::set<std::string> blocked_list_;
  base::FilePath device_info_root_;

  // Keep track of devices that require a delayed call to CreateDevice().
  base::CancelableOnceClosure delayed_devices_callback_;
  std::set<int> delayed_devices_;

  // Maintain a callback for the periodic link statistics poll task.
  base::CancelableOnceClosure request_link_statistics_callback_;

  // Maintain the list of callbacks awaiting link ready event.
  // Used by VPNServices for tunnel (through calling CreateTunnel with
  // callback) and ppp (through direct registering callback).
  // Callback are one-time and will be removed once triggered.
  // Keys of the map are names of the link concerned.
  std::map<std::string, LinkReadyCallback> pending_links_;

  // Cache copy of singleton pointers.
  RoutingTable* routing_table_;
  RTNLHandler* rtnl_handler_;
  NetlinkManager* netlink_manager_;

  // A member of the class so that a mock can be injected for testing.
  std::unique_ptr<Sockets> sockets_;

  Time* time_;
  base::WeakPtrFactory<DeviceInfo> weak_factory_{this};
};

}  // namespace shill

#endif  // SHILL_DEVICE_INFO_H_
