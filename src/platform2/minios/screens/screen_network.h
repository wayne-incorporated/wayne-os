// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MINIOS_SCREENS_SCREEN_NETWORK_H_
#define MINIOS_SCREENS_SCREEN_NETWORK_H_

#include <algorithm>
#include <memory>
#include <string>
#include <vector>

#include <gtest/gtest_prod.h>

#include "minios/key_reader.h"
#include "minios/network_manager_interface.h"
#include "minios/screens/screen_base.h"

namespace minios {

// The internal states of `ScreenNetwork`.
enum class NetworkState {
  kDropdownClosed = 0,
  kDropdownOpen = 1,
  kGetPassword = 2,
  kWaitForConnection = 3,
};

class ScreenNetwork : public ScreenBase,
                      public NetworkManagerInterface::Observer {
 public:
  ScreenNetwork(std::shared_ptr<DrawInterface> draw_utils,
                std::shared_ptr<NetworkManagerInterface> network_manager,
                KeyReader* key_reader,
                ScreenControllerInterface* screen_controller);

  ~ScreenNetwork();

  ScreenNetwork(const ScreenNetwork&) = delete;
  ScreenNetwork& operator=(const ScreenNetwork&) = delete;

  void Show() override;
  void Reset() override;
  void OnKeyPress(int key_changed) override;
  ScreenType GetType() override;
  std::string GetName() override;
  bool MoveForward(brillo::ErrorPtr* error) override;
  bool MoveBackward(brillo::ErrorPtr* error) override;

  // `NetworkManagerInterface::Observer` overrides.
  // Updates the list of networks stored by the UI to show in the drop down.
  void OnGetNetworks(
      const std::vector<NetworkManagerInterface::NetworkProperties>& networks,
      brillo::Error* error) override;

  // Attempts to connect, shows error screen on failure.
  void OnConnect(const std::string& ssid, brillo::Error* error) override;

  // Hook for programmatic seeding of network credentials.
  void SeedCredentials(const std::string& ssid,
                       const std::string& password = "");

  void SetIndexForTest(int index) { index_ = index; }
  void SetStateForTest(NetworkState state);
  NetworkState GetStateForTest() { return state_; }

 private:
  // Updates buttons with current selection.
  void ShowButtons();

  // Get user password using the keyboard layout stored in locale. Users can use
  // the tab key to toggle showing the password.
  void GetPassword();

  // Changes UI with instructions to wait for screen. This screen is
  // automatically changed when `OnConnect` returns.
  void WaitForConnection();

  // Shows network menu drop down button on the screen. Button is
  // highlighted if it is currently selected. Selecting this button directs to
  // the expanded network dropdown.
  void ShowCollapsedNetworkDropDown(bool is_selected);

  // Shows a list of all available networks.
  void ShowNetworkDropdown(int current_index);

  // Helper function for finding the button index for an ssid.
  bool GetNetworkIndex(const std::string& ssid, int* index) const;

  // Initiate a scan for available networks.
  void GetNetworks();

  // Connect to the a network using the provided credentials.
  void Connect(const std::string& ssid, const std::string& password);

  std::shared_ptr<NetworkManagerInterface> network_manager_;

  KeyReader* key_reader_;

  std::vector<NetworkManagerInterface::NetworkProperties> networks_;

  // The network the user has chosen.
  NetworkManagerInterface::NetworkProperties chosen_network_;

  // Pre-seeded network credentials.
  std::string ssid_;
  std::string password_;

  // Number of items in the network dropdown.
  int items_per_page_;

  // Current internal state.
  NetworkState state_;
};

}  // namespace minios

#endif  // MINIOS_SCREENS_SCREEN_NETWORK_H_
