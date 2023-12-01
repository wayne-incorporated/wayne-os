// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "arc/setup/arc_property_util.h"

#include <algorithm>
#include <memory>
#include <tuple>
#include <vector>

#include <base/command_line.h>
#include <base/files/file_enumerator.h>
#include <base/files/file_util.h>
#include <base/json/json_reader.h>
#include <base/logging.h>
#include <base/process/launch.h>
#include <base/strings/strcat.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <base/time/time.h>
#include <brillo/dbus/dbus_method_invoker.h>
#include <brillo/files/file_util.h>
#include <brillo/files/safe_fd.h>
#include <cdm_oemcrypto/proto_bindings/client_information.pb.h>
#include <chromeos/dbus/service_constants.h>
#include <chromeos-config/libcros_config/cros_config.h>
#include <dbus/message.h>
#include <re2/re2.h>

constexpr char kCdmManufacturerProp[] = "ro.vendor.cdm.manufacturer";
constexpr char kCdmDeviceProp[] = "ro.vendor.cdm.device";
constexpr char kCdmModelProp[] = "ro.vendor.cdm.model";

namespace arc {
namespace {

enum class ExtraProps {
  kNone,

  // Add CDM properties for HW DRM.
  kCdm,

  // ro.soc.manufacturer and .model, parsed from /proc/cpuinfo.
  kX86Soc,

  // ro.soc.manufacturer and .model, parsed from /sys/bus/soc/devices.
  kArmSoc,
};

// The path in the chromeos-config database where Android properties will be
// looked up.
constexpr char kCrosConfigPropertiesPath[] = "/arc/build-properties";

// Android property name used to store the board name.
constexpr char kBoardPropertyPrefix[] = "ro.product.board=";

// Android property name for custom key used for Play Auto Install selection.
constexpr char kOEMKey1PropertyPrefix[] = "ro.oem.key1=";

// Configuration property name of an optional string that contains a comma-
// separated list of regions to include in the OEM key property.
constexpr char kPAIRegionsPropertyName[] = "pai-regions";

// Prefix of Android property to enable debugging features.
constexpr char kDebuggablePropertyPrefix[] = "ro.debuggable=";

// Maximum length of an Android property value.
constexpr int kAndroidMaxPropertyLength = 91;

bool FindProperty(const std::string& line_prefix_to_find,
                  std::string* out_prop,
                  const std::string& line) {
  if (base::StartsWith(line, line_prefix_to_find,
                       base::CompareCase::SENSITIVE)) {
    *out_prop = line.substr(line_prefix_to_find.length());
    return true;
  }
  return false;
}

bool TruncateAndroidProperty(const std::string& line, std::string* truncated) {
  // If line looks like key=value, cut value down to the max length of an
  // Android property.  Since Android P or above, only non ro.* properties
  // have the explicit limit.
  size_t eq_pos = line.find('=');
  if (eq_pos == std::string::npos) {
    *truncated = line;
    return true;
  }
  if (base::StartsWith(line, "ro.")) {
    *truncated = line;
    return true;
  }

  std::string val = line.substr(eq_pos + 1);
  base::TrimWhitespaceASCII(val, base::TRIM_ALL, &val);
  if (val.length() <= kAndroidMaxPropertyLength) {
    *truncated = line;
    return true;
  }

  const std::string key = line.substr(0, eq_pos);
  LOG(WARNING) << "Truncating property " << key << " value: " << val;

  val = val.substr(0, kAndroidMaxPropertyLength);
  *truncated = key + "=" + val;
  return true;
}

// Computes the value of ro.oem.key1 based on the build-time ro.product.board
// value and the device's region of origin.
std::string ComputeOEMKey(brillo::CrosConfigInterface* config,
                          const std::string& board) {
  std::string regions;
  if (!config->GetString(kCrosConfigPropertiesPath, kPAIRegionsPropertyName,
                         &regions)) {
    // No region list found, just use the board name as before.
    return board;
  }

  std::string region_code;
  if (!base::GetAppOutput({"cros_region_data", "region_code"}, &region_code)) {
    LOG(WARNING) << "Failed to get region code";
    return board;
  }

  // Remove trailing newline.
  region_code.erase(std::remove(region_code.begin(), region_code.end(), '\n'),
                    region_code.end());

  // Allow wildcard configuration to indicate that all regions should be
  // included.
  if (regions.compare("*") == 0 && region_code.length() >= 2)
    return board + "_" + region_code;

  // Check to see if region code is in the list of regions that should be
  // included in the property.
  const std::vector<std::string> region_vector =
      base::SplitString(regions, ",", base::WhitespaceHandling::TRIM_WHITESPACE,
                        base::SplitResult::SPLIT_WANT_NONEMPTY);
  for (const auto& region : region_vector) {
    if (region_code.compare(region) == 0)
      return board + "_" + region_code;
  }

  return board;
}

bool IsComment(const std::string& line) {
  return base::StartsWith(
      base::TrimWhitespaceASCII(line, base::TrimPositions::TRIM_LEADING), "#",
      base::CompareCase::SENSITIVE);
}

bool ExpandPropertyContents(const std::string& content,
                            brillo::CrosConfigInterface* config,
                            scoped_refptr<::dbus::Bus> bus,
                            std::string* expanded_content,
                            bool filter_non_ro_props,
                            ExtraProps extra_props,
                            bool debuggable) {
  const std::vector<std::string> lines = base::SplitString(
      content, "\n", base::WhitespaceHandling::KEEP_WHITESPACE,
      base::SplitResult::SPLIT_WANT_ALL);

  std::string new_properties;
  for (std::string line : lines) {
    // Since Chrome only expands ro. properties at runtime, skip processing
    // non-ro lines here for R+. For P, we cannot do that because the
    // expanded property files will directly replace the original ones via
    // bind mounts.
    if (filter_non_ro_props &&
        !base::StartsWith(line, "ro.", base::CompareCase::SENSITIVE)) {
      if (!IsComment(line) && line.find('{') != std::string::npos) {
        // The non-ro property has substitution(s).
        LOG(ERROR) << "Found substitution(s) in a non-ro property: " << line;
        return false;
      }
      continue;
    }

    // First expand {property} substitutions in the string.  The insertions
    // may contain substitutions of their own, so we need to repeat until
    // nothing more is found.
    bool inserted;
    do {
      inserted = false;
      size_t match_start = line.find('{');
      size_t prev_match = 0;  // 1 char past the end of the previous {} match.
      std::string expanded;
      // Find all of the {} matches on the line.
      while (match_start != std::string::npos) {
        expanded += line.substr(prev_match, match_start - prev_match);

        size_t match_end = line.find('}', match_start);
        if (match_end == std::string::npos) {
          LOG(ERROR) << "Unmatched { found in line: " << line;
          return false;
        }

        const std::string keyword =
            line.substr(match_start + 1, match_end - match_start - 1);
        std::string replacement;
        if (config->GetString(kCrosConfigPropertiesPath, keyword,
                              &replacement)) {
          expanded += replacement;
          inserted = true;
        } else {
          LOG(ERROR) << "Did not find a value for " << keyword
                     << " while expanding " << line;
          return false;
        }

        prev_match = match_end + 1;
        match_start = line.find('{', match_end);
      }
      if (prev_match != std::string::npos)
        expanded += line.substr(prev_match);
      line = expanded;
    } while (inserted);

    {
      // Replace ro.debuggable value with |debuggable| flag.
      const std::string prefix(kDebuggablePropertyPrefix);
      std::string value;
      if (FindProperty(prefix, &value, line)) {
        line = prefix + (debuggable ? "1" : "0");
      }
    }

    std::string truncated;
    if (!TruncateAndroidProperty(line, &truncated)) {
      LOG(ERROR) << "Unable to truncate property: " << line;
      return false;
    }

    new_properties += truncated + "\n";

    // Special-case ro.product.board to compute ro.oem.key1 at runtime, as it
    // can depend upon the device region.
    std::string property;
    if (FindProperty(kBoardPropertyPrefix, &property, line)) {
      std::string oem_key_property = ComputeOEMKey(config, property);
      new_properties +=
          std::string(kOEMKey1PropertyPrefix) + oem_key_property + "\n";
    }
  }

  switch (extra_props) {
    case ExtraProps::kNone:
      break;

    case ExtraProps::kCdm: {
      // We need to make a D-Bus call to the cdm-oemcrypto daemon to get these
      // properties and then append them to the contents on success. The daemon
      // we are talking to has already had it's D-Bus service advertisement
      // waited on by Chrome (or a timeout occurred waiting for it). The 10
      // second timeout is more than enough to cover the amount of time it
      // would take the daemon to process this request (it should be very
      // fast). This timeout also should be shorter than the default D-Bus
      // timeout used by upstart to launch the script which is 30 seconds. In
      // the event the daemon did not startup correctly, then the D-Bus call
      // should return immediately.
      auto proxy = bus->GetObjectProxy(
          cdm_oemcrypto::kCdmFactoryDaemonServiceName,
          dbus::ObjectPath(cdm_oemcrypto::kCdmFactoryDaemonServicePath));
      constexpr int kDbusTimeoutMsec = 10000;
      brillo::ErrorPtr error;
      std::unique_ptr<::dbus::Response> response =
          brillo::dbus_utils::CallMethodAndBlockWithTimeout(
              kDbusTimeoutMsec, proxy,
              cdm_oemcrypto::kCdmFactoryDaemonServiceInterface,
              cdm_oemcrypto::kGetClientInformation, &error);
      if (response) {
        dbus::MessageReader reader(response.get());
        chromeos::cdm::ClientInformation client_info;
        if (reader.PopArrayOfBytesAsProto(&client_info)) {
          new_properties += std::string(kCdmManufacturerProp) + "=" +
                            client_info.manufacturer() + "\n";
          new_properties +=
              std::string(kCdmModelProp) + "=" + client_info.model() + "\n";
          new_properties +=
              std::string(kCdmDeviceProp) + "=" + client_info.make() + "\n";
        } else {
          DLOG(WARNING) << "Failed reading proto response";
        }
      } else {
        LOG(WARNING) << "Failed getting client information from cdm-oemcrypto";
      }
      break;
    }

    case ExtraProps::kArmSoc:
      AppendArmSocProperties(base::FilePath("/sys/bus/soc/devices"), config,
                             &new_properties);
      break;

    case ExtraProps::kX86Soc:
      AppendX86SocProperties(base::FilePath("/proc/cpuinfo"), &new_properties);
      break;
  }

  *expanded_content = new_properties;
  return true;
}

bool ExpandPropertyFile(const base::FilePath& input,
                        const base::FilePath& output,
                        brillo::CrosConfigInterface* config,
                        scoped_refptr<::dbus::Bus> bus,
                        bool append,
                        ExtraProps extra_props,
                        bool debuggable) {
  std::string content;
  std::string expanded;
  if (!base::ReadFileToString(input, &content)) {
    PLOG(ERROR) << "Failed to read " << input;
    return false;
  }
  if (!ExpandPropertyContents(content, config, bus, &expanded,
                              /*filter_non_ro_props=*/append, extra_props,
                              debuggable)) {
    return false;
  }
  if (append && base::PathExists(output)) {
    if (!base::AppendToFile(output, expanded)) {
      PLOG(ERROR) << "Failed to append to " << output;
      return false;
    }
  } else {
    if (!base::WriteFile(output, expanded)) {
      PLOG(ERROR) << "Failed to write to " << output;
      return false;
    }
  }
  return true;
}

// Reads the contents of a file with SafeFD and returns the results, or an empty
// string if an error occurs.
template <class StringPieceType>
StringPieceType SafelyReadFile(const base::FilePath& path,
                               std::vector<char>* buffer) {
  auto [fd, err] =
      brillo::SafeFD::Root().first.OpenExistingFile(path, O_RDONLY);
  if (brillo::SafeFD::IsError(err)) {
    LOG(ERROR) << "Cannot open file for reading: " << path << ": "
               << static_cast<int>(err);
    return "";
  }

  std::tie(*buffer, err) = fd.ReadContents();
  if (brillo::SafeFD::IsError(err)) {
    LOG(ERROR) << "Error reading contents of: " << path << ": "
               << static_cast<int>(err);
    return "";
  }

  return {&buffer->front(), buffer->size()};
}

}  // namespace

static bool ParseOneSocinfo(const base::FilePath& soc_dir_path,
                            std::string* dest) {
  auto machine_path = soc_dir_path.Append("machine");
  auto family_path = soc_dir_path.Append("family");
  auto soc_id_path = soc_dir_path.Append("soc_id");
  std::string machine = "";
  std::string family = "";
  std::string soc_id = "";

  // Different socinfo drivers expose different attributes.
  // For simplicity we'll just end up with a empty string for any
  // ones not present.
  //
  // NOTE: Use base::ReadFileToString() instead of SafelyReadFile() below
  // on purpose because Linux sysfs expects symlink traversal.
  if (base::PathExists(machine_path)) {
    if (!base::ReadFileToString(machine_path, &machine))
      PLOG(ERROR) << "Failed to read " << machine_path;
  }
  if (base::PathExists(family_path)) {
    if (!base::ReadFileToString(family_path, &family))
      PLOG(ERROR) << "Failed to read " << family_path;
  }
  if (base::PathExists(soc_id_path)) {
    if (!base::ReadFileToString(soc_id_path, &soc_id))
      PLOG(ERROR) << "Failed to read " << soc_id_path;
  }

  // There can be SoC-specif socinfo drivers in the kernel that have a
  // table mapping IDs to nice names and avoids us having to have our own
  // table here. For instance, Qualcomm SoCs have a driver for this. See
  // "drivers/soc/qcom/socinfo.c" in the Linux kernel sources.
  // That's how we get family = "Snapdragon" and machine = "SC7180".
  //
  // If we're running on an ARM SoC without a nice driver then we can fall
  // back to something that just exposes what the firmware tells us. There
  // we'll see something like family = "jep106:0070" and
  // soc_id = "jep106:0070:7180". If we're running on an ARM SoC that only
  // has what the firmware exposes then we'll need a table here for each
  // SoC.
  //
  // NOTES:
  // - On ARM devices /proc/cpuinfo _doesn't_ have details about the CPU model.
  // - The "socinfo" drivers in the Linux kernel are somewhat recent but is
  //   the official suggested way to get this info. A technique that used to
  //   be used was to assume that "/proc/device-tree/compatible" had an entry
  //   describing the SoC, but though we usually include the SoC there by
  //   convention there is actually no requirement for it and future boards
  //   might not include this info.
  std::string manufacturer;
  if (family == "Snapdragon\n" && machine != "") {
    manufacturer = "Qualcomm";
  } else if (family == "jep106:0426\n") {
    manufacturer = "Mediatek";
    machine = soc_id;
    constexpr base::StringPiece mtk_prefix("jep106:0426:");
    machine.replace(0, mtk_prefix.length(), "MT");
  } else {
    return false;
  }

  *dest += "ro.soc.manufacturer=" + manufacturer + "\n";

  // machine already has a trailing newline.
  *dest += base::StrCat({"ro.soc.model=", machine});

  return true;
}

void AppendArmSocProperties(const base::FilePath& sysfs_socinfo_devices_path,
                            brillo::CrosConfigInterface* config,
                            std::string* dest) {
  const std::string soc_pattern("*");

  base::FileEnumerator soc_dir_it(sysfs_socinfo_devices_path, false,
                                  base::FileEnumerator::FileType::DIRECTORIES,
                                  soc_pattern);

  for (auto soc_dir_path = soc_dir_it.Next(); !soc_dir_path.empty();
       soc_dir_path = soc_dir_it.Next()) {
    if (ParseOneSocinfo(soc_dir_path, dest))
      return;
  }

  std::string platform;

  if (!config->GetString("/identity", "platform-name", &platform)) {
    LOG(ERROR) << "Cannot get platform name";
  } else {
    LOG(INFO) << "Cannot find SoC info from " << sysfs_socinfo_devices_path
              << "; attempting to use platform->CPU mapping for: " << platform;

    // Platform names:
    //   Trogdor: also matches Strongbad and Homestar.
    //   Kukui: also matches Jacuzzi.
    // These devices do not have recent-enough firmware and/or kernels to have
    // a populated /sys/bus/soc/devices.
    if (platform == "Kukui") {
      *dest += "ro.soc.manufacturer=Mediatek\n";
      *dest += "ro.soc.model=MT8183\n";
    } else if (platform == "Trogdor") {
      *dest += "ro.soc.manufacturer=Qualcomm\n";
      *dest += "ro.soc.model=SC7180\n";
    } else {
      LOG(ERROR) << "Unexpected platform: " << platform;
    }
  }
}

void AppendX86SocProperties(const base::FilePath& cpuinfo_path,
                            std::string* dest) {
  std::vector<char> buffer;
  auto cpuinfo = SafelyReadFile<re2::StringPiece>(cpuinfo_path, &buffer);

  std::string model_field;
  re2::RE2 model_field_re("model name[ \t]*:(.*)\n");
  if (!re2::RE2::PartialMatch(cpuinfo, model_field_re, &model_field)) {
    LOG(ERROR) << "cannot find model name in cpuinfo: "
               << cpuinfo.substr(0, 2048);
    return;
  }

  std::string model;
  base::StringPiece manufacturer;
  if (re2::RE2::PartialMatch(
          model_field, R"(Intel\(R\) (?:Celeron\(R\)|Core\(TM\)) ([^ ]+) CPU)",
          &model) ||

      re2::RE2::PartialMatch(
          model_field, R"(Intel\(R\) Celeron\(R\)(?: CPU)? +([^ ]+)(?: +@|$))",
          &model) ||

      // This one is tricky because the trailing "@ <clock frequency>" is
      // optional.
      re2::RE2::PartialMatch(
          model_field,
          R"(Intel\(R\) Pentium\(R\) (?:Gold|Silver|CPU) ([^ ]+)(?: @|$))",
          &model) ||

      re2::RE2::PartialMatch(model_field,
                             R"(Intel\(R\) Pentium\(R\) Silver ([^ ]+) CPU @)",
                             &model) ||

      // 11th Gen starts calling out the generation no. explicitly.
      re2::RE2::PartialMatch(
          model_field, R"(11th Gen Intel\(R\) Core\(TM\) ([^ ]+) @)", &model) ||

      // 12th+13th Gens don't have trailing clock freq in field.
      // For i5-1245U, the "C" in Core is missing.
      // 13th Gen may have CoreT rather than Core(TM).
      re2::RE2::PartialMatch(model_field,
                             R"(1[23]th Gen Intel\(R\) C?ore[()TM]+ ([^ ]+)$)",
                             &model) ||

      // Alderlake-N series.
      re2::RE2::PartialMatch(model_field, R"(Intel\(R\) (N[0-9]+)$)", &model) ||
      re2::RE2::PartialMatch(
          model_field, R"(Intel\(R\) Core\(TM\) (i3-N[0-9]+)$)", &model)) {
    manufacturer = "Intel";
  } else if (base::EndsWith(model_field, "Genuine Intel(R) 0000")) {
    model = "0000-FixMe";
    manufacturer = "Intel";
  } else if (re2::RE2::PartialMatch(model_field, R"(Intel\(R\).*Xeon\(R\))")) {
    // Xeon CPUs should only occur when ChromeOS is running in a VM, not on a
    // physical device.
    model = "Unknown-Xeon";
    manufacturer = "Intel";
  } else if (
      // Some Ryzen CPU models have a watt value, some do not.
      // The "Ryzen # " portion is part of the ro.soc.model value.
      // There are various kinds of GPUs, so don't match more than
      // "with Radeon ".
      re2::RE2::PartialMatch(
          model_field,
          R"(AMD (Ryzen [3-9] [A-Z0-9]+) (?:[0-9]+W )?with Radeon )", &model) ||

      // Simpler AMD model names missing Ryzen name and a watt value.
      re2::RE2::PartialMatch(model_field,
                             R"(AMD(?: Athlon Gold| Athlon Silver)?)"
                             R"( ([0-9A-Za-z]+) with Radeon Graphics)",
                             &model) ||

      re2::RE2::PartialMatch(model_field,
                             R"(AMD ([-0-9A-Za-z]+) RADEON R[45],)", &model)) {
    manufacturer = "AMD";
  } else {
    LOG(ERROR) << "Unknown CPU in '" << model_field << "'; won't set ro.soc.*";
    return;
  }

  *dest += base::StrCat({"ro.soc.manufacturer=", manufacturer, "\n",
                         "ro.soc.model=", model, "\n"});
}

bool ExpandPropertyContentsForTesting(const std::string& content,
                                      brillo::CrosConfigInterface* config,
                                      bool debuggable,
                                      std::string* expanded_content) {
  return ExpandPropertyContents(content, config, nullptr, expanded_content,
                                /*filter_non_ro_props=*/true, ExtraProps::kNone,
                                debuggable);
}

bool TruncateAndroidPropertyForTesting(const std::string& line,
                                       std::string* truncated) {
  return TruncateAndroidProperty(line, truncated);
}

bool ExpandPropertyFileForTesting(const base::FilePath& input,
                                  const base::FilePath& output,
                                  brillo::CrosConfigInterface* config) {
  return ExpandPropertyFile(input, output, config, nullptr, /*append=*/false,
                            ExtraProps::kNone, /*debuggable=*/false);
}

bool ExpandPropertyFiles(const base::FilePath& source_path,
                         const base::FilePath& dest_path,
                         bool single_file,
                         bool hw_oemcrypto_support,
                         bool include_soc_props,
                         bool debuggable,
                         scoped_refptr<::dbus::Bus> bus) {
  brillo::CrosConfig config;
  if (single_file)
    brillo::DeleteFile(dest_path);

  ExtraProps soc_props_type = ExtraProps::kNone;
  if (include_soc_props) {
#if defined(ARCH_CPU_ARM_FAMILY)
    soc_props_type = ExtraProps::kArmSoc;
#else
    soc_props_type = ExtraProps::kX86Soc;
#endif
  }

  // default.prop may not exist. Silently skip it if not found.
  for (const auto& tuple :
       // The order has to match the one in PropertyLoadBootDefaults() in
       // system/core/init/property_service.cpp.
       // Note: Our vendor image doesn't have /vendor/default.prop although
       // PropertyLoadBootDefaults() tries to open it.
       {std::tuple<const char*, bool, ExtraProps>{"default.prop", true,
                                                  ExtraProps::kNone},
        {"build.prop", false, ExtraProps::kNone},
        {"system_ext_build.prop", true, ExtraProps::kNone},
        {"vendor_build.prop", false, soc_props_type},
        {"odm_build.prop", true, ExtraProps::kNone},
        {"product_build.prop", true,
         hw_oemcrypto_support ? ExtraProps::kCdm : ExtraProps::kNone}}) {
    const char* file = std::get<0>(tuple);
    const bool is_optional = std::get<1>(tuple);
    const ExtraProps extra_props = std::get<2>(tuple);

    const base::FilePath source_file = source_path.Append(file);
    if (is_optional && !base::PathExists(source_file))
      continue;

    if (!ExpandPropertyFile(source_file,
                            single_file ? dest_path : dest_path.Append(file),
                            &config, bus,
                            /*append=*/single_file, extra_props, debuggable)) {
      LOG(ERROR) << "Failed to expand " << source_file;
      return false;
    }
  }
  return true;
}

}  // namespace arc
