// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MIST_CONFIG_LOADER_H_
#define MIST_CONFIG_LOADER_H_

#include <stdint.h>

#include <memory>

#include <base/files/file_path.h>
#include <gtest/gtest_prod.h>

namespace mist {

class Config;
class UsbModemInfo;

// A configuration file loader, which loads information about USB modems
// supported by mist from a configuration file based on the text format of
// protocol buffers. The protocol buffers for the configuration file are defined
// in proto/*.proto.
class ConfigLoader {
 public:
  ConfigLoader();
  ConfigLoader(const ConfigLoader&) = delete;
  ConfigLoader& operator=(const ConfigLoader&) = delete;

  virtual ~ConfigLoader();

  // Loads the default configuration. Returns true on success.
  virtual bool LoadDefaultConfig();

  // Loads a configuration from |config_file|. Returns true on success.
  virtual bool LoadConfig(const base::FilePath& config_file);

  // Returns the info of the USB modem with its vendor ID equal to |vendor_id|
  // and its product ID equal to |product_id| from the loaded configuration.
  // Returns NULL if no matching USB modem is found. The returned UsbModemInfo
  // object becomes invalid, and thus should not be held, beyond the lifetime
  // of the loaded configuration held by |config_|.
  virtual const UsbModemInfo* GetUsbModemInfo(uint16_t vendor_id,
                                              uint16_t product_id) const;

 private:
  FRIEND_TEST(ConfigLoaderTest, GetUsbModemInfo);
  FRIEND_TEST(ConfigLoaderTest, LoadEmptyConfigFile);
  FRIEND_TEST(ConfigLoaderTest, LoadInvalidConfigFile);
  FRIEND_TEST(ConfigLoaderTest, LoadNonExistentConfigFile);
  FRIEND_TEST(ConfigLoaderTest, LoadValidConfigFile);

  std::unique_ptr<Config> config_;
};

}  // namespace mist

#endif  // MIST_CONFIG_LOADER_H_
