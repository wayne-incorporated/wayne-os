// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "trunks/csme/mei_client_factory.h"

#include <memory>
#include <string>

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <linux/uuid.h>

#include "trunks/csme/mei_client.h"
#include "trunks/csme/mei_client_char_device.h"
#include "trunks/csme/mei_client_socket.h"

namespace trunks {
namespace csme {

namespace {

constexpr uuid_le kCoreGuid = UUID_LE(
    0x989e0b6f, 0xda76, 0x45d7, 0x92, 0x99, 0xa4, 0x07, 0x9d, 0x7e, 0x22, 0xb1);
constexpr uuid_le kProvisionGuid = UUID_LE(
    0x168dbc9c, 0xf757, 0x4eed, 0xa2, 0xd8, 0x94, 0xa3, 0xb7, 0x0f, 0x26, 0xc2);
constexpr uuid_le kTpmTunnelGuid = UUID_LE(
    0xa6103662, 0x23a6, 0x4315, 0xa5, 0x3b, 0x74, 0x9d, 0x91, 0xca, 0xee, 0x17);

constexpr char kDefaultMeiDevicePath[] = "/dev/mei0";
constexpr char kDefaultSocketConfigPath[] = "/run/pinweaver_socket.config";

}  // namespace

MeiClientFactory::MeiClientFactory(const std::string& socket_config_path,
                                   const std::string& char_device_path)
    : socket_config_path_(socket_config_path),
      char_device_path_(char_device_path) {}

MeiClientFactory::MeiClientFactory()
    : socket_config_path_(kDefaultSocketConfigPath),
      char_device_path_(kDefaultMeiDevicePath) {}

std::unique_ptr<MeiClient> MeiClientFactory::CreateMeiClient(
    const std::string path, const uuid_le& guid) {
  switch (GetMeiConnectionType()) {
    case MeiConnectionType::kUnknown:
      LOG(FATAL) << __func__ << ": Unknown connection type.";
      break;
    case MeiConnectionType::kSocket:
#if !USE_CSME_EMULATOR
      LOG(FATAL) << __func__ << ": socket-based connection is not allowed.";
#endif
      return std::unique_ptr<MeiClient>(new MeiClientSocket(path, guid));
    case MeiConnectionType::kCharacterDevice:
      return std::unique_ptr<MeiClient>(new MeiClientCharDevice(path, guid));
  }
  return nullptr;
}

std::unique_ptr<MeiClient> MeiClientFactory::CreateMeiClientForPinWeaverCore() {
  return CreateMeiClient(GetCoreMeiPath(), kCoreGuid);
}

std::unique_ptr<MeiClient>
MeiClientFactory::CreateMeiClientForPinWeaverProvision() {
  return CreateMeiClient(GetProvisionMeiPath(), kProvisionGuid);
}

std::unique_ptr<MeiClient>
MeiClientFactory::CreateMeiClientForPinWeaverTpmTunnel() {
  return CreateMeiClient(GetTpmTunnelMeiPath(), kTpmTunnelGuid);
}

MeiClientFactory::MeiConnectionType MeiClientFactory::GetMeiConnectionType() {
  DetermineMeiConnectionType();
  return mei_client_type_;
}

std::string MeiClientFactory::GetMeiPath(
    MeiClientFactory::MeiFunctionType function_type) {
  switch (GetMeiConnectionType()) {
    case MeiConnectionType::kUnknown:
      LOG(DFATAL) << __func__ << ": Unknown Mei client type.";
      return "";
    case MeiConnectionType::kCharacterDevice:
      return char_device_path_;
    case MeiConnectionType::kSocket:
      return socket_paths_[static_cast<int>(function_type)];
  }
}

std::string MeiClientFactory::GetCoreMeiPath() {
  return GetMeiPath(MeiFunctionType::kCore);
}

std::string MeiClientFactory::GetProvisionMeiPath() {
  return GetMeiPath(MeiFunctionType::kProvision);
}

std::string MeiClientFactory::GetTpmTunnelMeiPath() {
  return GetMeiPath(MeiFunctionType::kTpmTunnel);
}

void MeiClientFactory::DetermineMeiConnectionType() {
  if (mei_client_type_ != MeiConnectionType::kUnknown) {
    return;
  }
  if (ReadSocketConfig()) {
    mei_client_type_ = MeiConnectionType::kSocket;
  } else {
    mei_client_type_ = MeiConnectionType::kCharacterDevice;
  }
}

bool MeiClientFactory::ReadSocketConfig() {
  const base::FilePath config_path(socket_config_path_);
  if (!base::PathExists(config_path)) {
    return false;
  }
  std::string config_str;
  if (!base::ReadFileToString(config_path, &config_str)) {
    LOG(ERROR) << __func__ << ": Failed to read socket config at "
               << socket_config_path_;
    return false;
  }
  int index = 0;
  for (std::string& s : socket_paths_) {
    s.clear();
  }
  while (index < socket_paths_.size()) {
    size_t pos = config_str.find('\n');
    if (pos == std::string::npos) {
      socket_paths_[index] = config_str;
    } else {
      socket_paths_[index] = config_str.substr(0, pos);
      config_str = config_str.substr(pos + 1);
    }
    index += 1;
  }
  for (const std::string& s : socket_paths_) {
    if (s.empty()) {
      LOG(ERROR) << __func__ << ": Empty path.";
      return false;
    }
  }
  return true;
}

}  // namespace csme
}  // namespace trunks
