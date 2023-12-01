// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_ETHERNET_VIRTIO_ETHERNET_H_
#define SHILL_ETHERNET_VIRTIO_ETHERNET_H_

#include <string>

#include "shill/ethernet/ethernet.h"

namespace shill {

class VirtioEthernet : public Ethernet {
 public:
  VirtioEthernet(Manager* manager,
                 const std::string& link_name,
                 const std::string& address,
                 int interface_index);
  VirtioEthernet(const VirtioEthernet&) = delete;
  VirtioEthernet& operator=(const VirtioEthernet&) = delete;

  ~VirtioEthernet() override;

  void Start(EnabledStateChangedCallback callback) override;
};

}  // namespace shill

#endif  // SHILL_ETHERNET_VIRTIO_ETHERNET_H_
