// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef INSTALLER_EFIVAR_H_
#define INSTALLER_EFIVAR_H_

#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <base/files/file_path.h>
#include <base/memory/free_deleter.h>

#include "installer/inst_util.h"

// All the efi variables we're writing want the same set of attributes,
// according to the UEFI spec v2.9 section 3.3, Table 3-1 "Global Variables".
extern const uint32_t kBootVariableAttributes;

// Indicates that the int is an errno passed back from libefivar.
using EfiVarError = int;

// Interface to allow testing.
class EfiVarInterface {
 public:
  using Bytes = std::unique_ptr<uint8_t, base::FreeDeleter>;

  virtual ~EfiVarInterface() = default;

  virtual bool EfiVariablesSupported() = 0;

  virtual std::optional<std::string> GetNextVariableName() = 0;

  virtual bool GetVariable(const std::string& name,
                           Bytes& data,
                           size_t* data_size) = 0;

  virtual std::optional<EfiVarError> SetVariable(
      const std::string& name,
      uint32_t attributes,
      std::vector<uint8_t>& data) = 0;

  virtual bool DelVariable(const std::string& name) = 0;

  virtual bool GenerateFileDevicePathFromEsp(
      const base::FilePath& device_path,
      PartitionNum esp_partition,
      const base::FilePath& boot_file,
      std::vector<uint8_t>& efidp_data) = 0;

  // These three don't do filesystem access, they just operate on data
  // returned by GetVariable, so no need for virtual.
  std::string LoadoptDesc(uint8_t* const data, size_t data_size);
  std::vector<uint8_t> LoadoptPath(uint8_t* const data, size_t data_size);
  bool LoadoptCreate(uint32_t loadopt_attributes,
                     std::vector<uint8_t>& efidp_data,
                     std::string& description,
                     std::vector<uint8_t>* data);
};

// Non-testing implementation. Moderately thin wrappers around libefivar, using
// C++ amenities rather than raw pointers that you have to free.
class EfiVarImpl : public EfiVarInterface {
 public:
  bool EfiVariablesSupported() override;

  std::optional<std::string> GetNextVariableName() override;

  bool GetVariable(const std::string& name,
                   Bytes& data,
                   size_t* data_size) override;

  std::optional<EfiVarError> SetVariable(const std::string& name,
                                         uint32_t attributes,
                                         std::vector<uint8_t>& data) override;

  bool DelVariable(const std::string& name) override;

  bool GenerateFileDevicePathFromEsp(const base::FilePath& device_path,
                                     PartitionNum esp_partition,
                                     const base::FilePath& boot_file,
                                     std::vector<uint8_t>& efidp_data) override;
};

#endif  // INSTALLER_EFIVAR_H_
