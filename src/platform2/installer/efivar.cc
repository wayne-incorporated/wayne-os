// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "installer/efivar.h"

#include <cstring>
#include <optional>

#include <base/logging.h>
#include <base/strings/string_number_conversions.h>

// TODO(tbrandston): upstream extern "C" to efivar.
// https://github.com/rhboot/efivar/issues/205
extern "C" {
#include "efivar/efiboot.h"
}

namespace {
bool IsEfiGlobalGUID(const efi_guid_t* guid) {
  const efi_guid_t global = EFI_GLOBAL_GUID;
  return memcmp(guid, &global, sizeof(global)) == 0;
}

// Wrapper around the libefivar error logging interface.
//
// libefivar stores a list of errors that it encounters, and lets you access
// them by index. The list is cleared when certain calls succeed, but successive
// errors can accumulate.
//
// This accumulation can make for confusing logs if we only clear these logs
// after libefivar functions return failure.
// For example, GenerateFileDevicePathFromEsp may produce a pair of errors like:
// ./util.h:325:get_file rc=1 could not open file "/sys/devices/pci0000:00/..."
// but efi_generate_file_device_path_from_esp still returns success. If we don't
// clear those errors they'll show up the next time we look at logged errors,
// which will be after an unrelated call.
//
// To simplify logging and clearing, and ensure that all returns will clear,
// this wrapper logs all errors and clears the list on destruction. Instantiate
// a local instance in each function that calls a libefivar function.
class EfiLogWrapper {
 public:
  explicit EfiLogWrapper(const std::string& source) : source_(source) {
    // Clear any errors encountered before construction to avoid confusion.
    efi_error_clear();
  }

  ~EfiLogWrapper() {
    // Log all errors upon destruction.
    LogEfiErrors();
    efi_error_clear();
  }

  // Log all libefivar errors.
  void LogEfiErrors() {
    uint32_t index = 0;

    char* filename = nullptr;
    char* function = nullptr;
    int line = 0;
    char* message = nullptr;
    int error = 0;

    while (true) {
      int rc =
          efi_error_get(index, &filename, &function, &line, &message, &error);

      if (rc == -1) {
        LOG(ERROR) << "programmer error, invalid args.";
        return;
      } else if (rc == 0) {
        // No more errors, for now.
        break;
      }

      // We don't know here whether it should be treated as a warning or an
      // error, so we'll call everything a warning and let further logging
      // clarify.
      LOG(WARNING) << source_ << "triggered efi error " << index << ": "
                   << filename << ":" << line << ":" << function << " rc=" << rc
                   << " " << message << ": " << std::strerror(error);
      index += 1;
    }
  }

  // Get the errno stored in the libefivar log at index 0.
  // This is the first one encountered and the most likely to be relevant.
  std::optional<EfiVarError> GetFirstErrno() {
    const uint32_t idx = 0;
    char* file = nullptr;
    char* func = nullptr;
    int line = 0;
    char* message = nullptr;
    int error_num = 0;

    if (efi_error_get(idx, &file, &func, &line, &message, &error_num) == 1) {
      return error_num;
    }

    return std::nullopt;
  }

 private:
  // Where this was instantiated, to help clarify where errors are coming from.
  std::string source_;
};

}  // namespace

const uint32_t kBootVariableAttributes = EFI_VARIABLE_BOOTSERVICE_ACCESS |
                                         EFI_VARIABLE_RUNTIME_ACCESS |
                                         EFI_VARIABLE_NON_VOLATILE;

std::string EfiVarInterface::LoadoptDesc(uint8_t* const data,
                                         size_t data_size) {
  EfiLogWrapper log_wrapper(__func__);
  efi_load_option* load_opt = reinterpret_cast<efi_load_option*>(data);

  // Memory returned by efi_loadopt_desc doesn't need to be freed.
  // Internally it frees the previously loaded description each time you
  // load a new one.
  const unsigned char* unsigned_desc = efi_loadopt_desc(load_opt, data_size);

  // Store the unsigned chars in signed chars for ease of use outside this api.
  return reinterpret_cast<const char*>(unsigned_desc);
}

std::vector<uint8_t> EfiVarInterface::LoadoptPath(uint8_t* const data,
                                                  size_t data_size) {
  EfiLogWrapper log_wrapper(__func__);
  efi_load_option* load_opt = reinterpret_cast<efi_load_option*>(data);

  // This path_data is just a pointer into `data`, not separately allocated.
  efidp path_data = efi_loadopt_path(load_opt, data_size);
  const ssize_t path_data_size = efi_loadopt_pathlen(load_opt, data_size);

  // Copy the path data into a vector.
  return std::vector<uint8_t>(
      reinterpret_cast<uint8_t*>(path_data),
      reinterpret_cast<uint8_t*>(path_data) + path_data_size);
}

bool EfiVarInterface::LoadoptCreate(uint32_t loadopt_attributes,
                                    std::vector<uint8_t>& efidp_data,
                                    std::string& description,
                                    std::vector<uint8_t>* data) {
  EfiLogWrapper log_wrapper(__func__);
  efidp device_path = reinterpret_cast<efidp>(efidp_data.data());
  unsigned char* description_data =
      reinterpret_cast<unsigned char*>(description.data());

  // Passing a size of 0 will simply return the sum of the lengths of the
  // relevant arguments, which tells us how much space to allocate.
  const ssize_t entry_data_size =
      efi_loadopt_create(nullptr, 0, loadopt_attributes, device_path,
                         efidp_data.size(), description_data,
                         // optional, for EDD10 or something?
                         nullptr, 0);

  data->resize(entry_data_size);

  const ssize_t rv = efi_loadopt_create(
      data->data(), entry_data_size, loadopt_attributes, device_path,
      efidp_data.size(), description_data, nullptr, 0);

  if (rv < 0) {
    LOG(ERROR) << "Error formatting data for efi variable.\n"
               << "attributes: " << loadopt_attributes << "\n"
               << "efidp_data: "
               << base::HexEncode(efidp_data.data(), efidp_data.size()) << "\n"
               << "description: " << description << "\n";

    return false;
  }

  return true;
}

bool EfiVarImpl::EfiVariablesSupported() {
  return efi_variables_supported();
}

std::optional<std::string> EfiVarImpl::GetNextVariableName() {
  EfiLogWrapper log_wrapper(__func__);

  efi_guid_t* guid = nullptr;
  char* name = nullptr;
  int rc = 0;

  // efi_get_next_variable_name repeatedly returns the same static char[].
  // efi_get_next_variable_name returns 1 if an entry is found.
  while ((rc = efi_get_next_variable_name(&guid, &name)) > 0) {
    // NULL is not expected but guard against it.
    if (!name || !guid)
      return std::nullopt;
    if (!IsEfiGlobalGUID(guid))
      continue;
    return std::string(name);
  }

  return std::nullopt;
}

bool EfiVarImpl::GetVariable(const std::string& name,
                             Bytes& data,
                             size_t* data_size) {
  EfiLogWrapper log_wrapper(__func__);

  // efi_get_variable will malloc some space and store it in `data`,
  // so we have to make sure it gets freed.
  uint8_t* data_ptr;

  // All the variables we manage have well defined attributes by the efi spec,
  // so we can safely ignore these -- if they're somehow different we'd want to
  // fix them.
  uint32_t ignored_attributes;

  if (efi_get_variable(EFI_GLOBAL_GUID, name.c_str(), &data_ptr, data_size,
                       &ignored_attributes) < 0) {
    LOG(ERROR) << "Error getting '" << name << "'";
    // Okay to return without freeing data if ret < 0 (at least in the
    // current (v37) efivar implementation ...).
    return false;
  }

  // Pass data out, ensuring it gets freed when it's no longer needed.
  data.reset(data_ptr);

  return true;
}

std::optional<EfiVarError> EfiVarImpl::SetVariable(const std::string& name,
                                                   uint32_t attributes,
                                                   std::vector<uint8_t>& data) {
  EfiLogWrapper log_wrapper(__func__);

  if (efi_set_variable(EFI_GLOBAL_GUID, name.c_str(), data.data(), data.size(),
                       attributes,
                       // mode
                       0644) < 0) {
    LOG(ERROR) << "Error setting '" << name
               << "' data: " << base::HexEncode(data.data(), data.size());
    return log_wrapper.GetFirstErrno();
  }

  return std::nullopt;
}

bool EfiVarImpl::DelVariable(const std::string& name) {
  EfiLogWrapper log_wrapper(__func__);
  if (efi_del_variable(EFI_GLOBAL_GUID, name.c_str()) < 0) {
    LOG(ERROR) << "Error deleting '" << name << "'";
    return false;
  }

  return true;
}

bool EfiVarImpl::GenerateFileDevicePathFromEsp(
    const base::FilePath& device_path,
    PartitionNum esp_partition,
    const base::FilePath& boot_file,
    std::vector<uint8_t>& efidp_data) {
  EfiLogWrapper log_wrapper(__func__);

  // Check how much capacity we'll need in efidp by passing null/0 first.
  const ssize_t required_size = efi_generate_file_device_path_from_esp(
      nullptr, 0, device_path.value().c_str(), esp_partition.Value(),
      boot_file.value().c_str(), EFIBOOT_ABBREV_HD);

  if (required_size < 0) {
    LOG(ERROR) << "Could not generate device path. "
               << "efi_generate_file_device_path_from_esp returned: "
               << required_size;
    return false;
  }

  efidp_data.resize(required_size);

  const ssize_t rv = efi_generate_file_device_path_from_esp(
      efidp_data.data(), required_size, device_path.value().c_str(),
      esp_partition.Value(), boot_file.value().c_str(), EFIBOOT_ABBREV_HD);

  if (rv < 0) {
    LOG(ERROR) << "Could not generate device path. "
               << "efi_generate_file_device_path_from_esp returned: " << rv;
    return false;
  }

  return true;
}
