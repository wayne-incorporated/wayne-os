// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TRUNKS_CSME_MEI_CLIENT_FACTORY_H_
#define TRUNKS_CSME_MEI_CLIENT_FACTORY_H_

#include <array>
#include <memory>
#include <string>

#include <linux/uuid.h>

#include "trunks/csme/mei_client.h"
#include "trunks/trunks_export.h"

namespace trunks {
namespace csme {

// `MeiClientFactory` creates `MeiClient` with the type selected according to
// the confguration setup. See `mei_selection.md` for more information.
class TRUNKS_EXPORT MeiClientFactory {
 public:
  // Constructs the factory with the customized socket config path and character
  // device path.
  MeiClientFactory(const std::string& socket_config_path,
                   const std::string& char_device_path);
  MeiClientFactory();
  ~MeiClientFactory() = default;

  MeiClientFactory(MeiClientFactory&&) = delete;
  MeiClientFactory& operator=(MeiClientFactory&&) = delete;

  // The following group of factory functions creates the instances of
  // `MeiClient` with corresponding MEI GUIDs and the connection type
  // configuration.
  //
  // Creates an `MeiClient` instance for pinweaver core.
  std::unique_ptr<MeiClient> CreateMeiClientForPinWeaverCore();
  // Creates an `MeiClient` instance for pinweaver provision.
  std::unique_ptr<MeiClient> CreateMeiClientForPinWeaverProvision();
  // Creates an `MeiClient` instance for pinweaver tpm tunnel.
  std::unique_ptr<MeiClient> CreateMeiClientForPinWeaverTpmTunnel();

 private:
  std::unique_ptr<MeiClient> CreateMeiClient(const std::string path,
                                             const uuid_le& guid);

  // The ways connecting to MEI.
  enum class MeiConnectionType {
    // Not determined yet.
    kUnknown,
    // Character device driver; typically it means /dev/mei0.
    kCharacterDevice,
    // Sokcet-based connection. Used for emulator case.
    kSocket,
  };

  void DetermineMeiConnectionType();
  MeiConnectionType GetMeiConnectionType();
  bool ReadSocketConfig();

  // The function type of MEI clients.
  enum class MeiFunctionType {
    kCore = 0,
    kProvision = 1,
    kTpmTunnel = 2,
    kSize = 3,
  };

  std::string GetMeiPath(MeiFunctionType function_type);
  std::string GetCoreMeiPath();
  std::string GetProvisionMeiPath();
  std::string GetTpmTunnelMeiPath();

  const std::string socket_config_path_;
  const std::string char_device_path_;
  std::array<std::string, static_cast<int>(MeiFunctionType::kSize)>
      socket_paths_;
  MeiConnectionType mei_client_type_ = MeiConnectionType::kUnknown;
};

}  // namespace csme
}  // namespace trunks

#endif  // TRUNKS_CSME_MEI_CLIENT_FACTORY_H_
