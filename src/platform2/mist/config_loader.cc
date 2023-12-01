// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "mist/config_loader.h"

#include <fcntl.h>

#include <utility>

#include <base/files/file_path.h>
#include <base/files/scoped_file.h>
#include <base/logging.h>
#include <base/posix/eintr_wrapper.h>
#include <google/protobuf/io/zero_copy_stream_impl.h>
#include <google/protobuf/text_format.h>

#include "mist/proto_bindings/config.pb.h"
#include "mist/proto_bindings/usb_modem_info.pb.h"

namespace mist {

namespace {

const char kDefaultConfigFile[] = "/usr/share/mist/default.conf";

}  // namespace

ConfigLoader::ConfigLoader() = default;

ConfigLoader::~ConfigLoader() = default;

bool ConfigLoader::LoadDefaultConfig() {
  return LoadConfig(base::FilePath(kDefaultConfigFile));
}

bool ConfigLoader::LoadConfig(const base::FilePath& file_path) {
  int fd = HANDLE_EINTR(open(file_path.MaybeAsASCII().c_str(), O_RDONLY));
  if (fd == -1) {
    PLOG(ERROR) << "Could not open config file '" << file_path.MaybeAsASCII()
                << "'";
    return false;
  }

  base::ScopedFD scoped_fd(fd);
  google::protobuf::io::FileInputStream file_stream(fd);

  auto config = std::make_unique<Config>();
  if (!google::protobuf::TextFormat::Parse(&file_stream, config.get())) {
    LOG(ERROR) << "Could not parse config file '" << file_path.MaybeAsASCII()
               << "'";
    return false;
  }

  config_ = std::move(config);
  return true;
}

const UsbModemInfo* ConfigLoader::GetUsbModemInfo(uint16_t vendor_id,
                                                  uint16_t product_id) const {
  if (!config_)
    return nullptr;

  for (int i = 0; i < config_->usb_modem_info_size(); ++i) {
    const UsbModemInfo& usb_modem_info = config_->usb_modem_info(i);
    const UsbId& usb_id = usb_modem_info.initial_usb_id();
    if (usb_id.vendor_id() == vendor_id && usb_id.product_id() == product_id)
      return &usb_modem_info;
  }

  return nullptr;
}

}  // namespace mist
