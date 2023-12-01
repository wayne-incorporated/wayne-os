// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <sysexits.h>

#include <base/check.h>
#include <base/command_line.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_util.h>
#include <brillo/syslog_logging.h>

#include "libhwsec/client/command_helpers.h"
#include "libhwsec/factory/factory.h"
#include "libhwsec/factory/factory_impl.h"
#include "libhwsec/frontend/client/frontend.h"
#include "libhwsec-foundation/crypto/secure_blob_util.h"
#include "libhwsec-foundation/status/status_chain_macros.h"

using hwsec::ClientArgs;

namespace {

constexpr char kUsage[] =
    "Usage: libhwsec_client <command> [<args>]\nCommands:\n";

template <typename... Args>
struct Help {
  static constexpr char kName[] = "help";
  static constexpr char kArgs[] = "";
  static constexpr char kDesc[] = R"(
      Print this help message.
)";

  static int Run(const ClientArgs& args) {
    PrintUsage();
    return EX_USAGE;
  }

  static void PrintUsage() {
    printf("%s", kUsage);
    (hwsec::PrintCommandUsage<Args>(), ...);
  }
};

struct GetRandom {
  static constexpr char kName[] = "get_random";
  static constexpr char kArgs[] = "<N>";
  static constexpr char kDesc[] = R"(
      Gets |N| random bytes and prints them as a hex-encoded string.
)";

  static int Run(const ClientArgs& args) {
    if (args.size() != 1) {
      hwsec::PrintCommandUsage<GetRandom>();
      return EX_USAGE;
    }

    size_t size = 0;
    if (!base::StringToSizeT(args[0], &size)) {
      LOG(ERROR) << "Failed to convert size.";
      return EX_USAGE;
    }

    ASSIGN_OR_RETURN(
        brillo::Blob data,
        hwsec::FactoryImpl().GetClientFrontend()->GetRandomBlob(size),
        _.LogError().As(EXIT_FAILURE));

    puts(hwsec_foundation::BlobToHex(data).c_str());
    return EXIT_SUCCESS;
  }
};

struct IsSrkRocaVulnerable {
  static constexpr char kName[] = "is_srk_roca_vulnerable";
  static constexpr char kArgs[] = "";
  static constexpr char kDesc[] = R"(
      Output "true" when the SRK is ROCA vulnerable, otherwise output "false".
)";

  static int Run(const ClientArgs& args) {
    if (args.size() != 0) {
      hwsec::PrintCommandUsage<IsSrkRocaVulnerable>();
      return EX_USAGE;
    }

    ASSIGN_OR_RETURN(
        bool is_srk_roca_vulnerable,
        hwsec::FactoryImpl().GetClientFrontend()->IsSrkRocaVulnerable(),
        _.LogError().As(EXIT_FAILURE));

    puts(is_srk_roca_vulnerable ? "true" : "false");
    return EXIT_SUCCESS;
  }
};

struct GetVersionInfo {
  static constexpr char kName[] = "get_version_info";
  static constexpr char kArgs[] = "";
  static constexpr char kDesc[] = R"(
      Prints TPM software and hardware version information.
)";

  static int Run(const ClientArgs& args) {
    if (args.size() != 0) {
      hwsec::PrintCommandUsage<GetVersionInfo>();
      return EX_USAGE;
    }

    hwsec::FactoryImpl factory;
    std::unique_ptr<const hwsec::ClientFrontend> hwsec =
        factory.GetClientFrontend();

    ASSIGN_OR_RETURN(uint32_t family, hwsec->GetFamily(),
                     _.LogError().As(EXIT_FAILURE));

    ASSIGN_OR_RETURN(uint64_t spec_level, hwsec->GetSpecLevel(),
                     _.LogError().As(EXIT_FAILURE));

    ASSIGN_OR_RETURN(uint32_t manufacturer, hwsec->GetManufacturer(),
                     _.LogError().As(EXIT_FAILURE));

    ASSIGN_OR_RETURN(uint32_t tpm_model, hwsec->GetTpmModel(),
                     _.LogError().As(EXIT_FAILURE));

    ASSIGN_OR_RETURN(uint64_t firmware_version, hwsec->GetFirmwareVersion(),
                     _.LogError().As(EXIT_FAILURE));

    ASSIGN_OR_RETURN(brillo::Blob vendor_specific, hwsec->GetVendorSpecific(),
                     _.LogError().As(EXIT_FAILURE));

    std::string vendor_specific_str = base::ToLowerASCII(
        base::HexEncode(vendor_specific.data(), vendor_specific.size()));

    printf("tpm_family %08" PRIx32
           "\n"
           "spec_level %016" PRIx64
           "\n"
           "vendor %08" PRIx32
           "\n"
           "tpm_model %08" PRIx32
           "\n"
           "firmware_version %016" PRIx64
           "\n"
           "vendor_specific %s\n",
           family, spec_level, manufacturer, tpm_model, firmware_version,
           vendor_specific_str.c_str());
    return EXIT_SUCCESS;
  }
};

struct GetIfxFieldUpgradeInfo {
  static constexpr char kName[] = "get_ifx_field_upgrade_info";
  static constexpr char kArgs[] = "";
  static constexpr char kDesc[] = R"(
      Prints status info pertaining to firmware updates on Infineon TPMs.
)";

  static int Run(const ClientArgs& args) {
    if (args.size() != 0) {
      hwsec::PrintCommandUsage<GetIfxFieldUpgradeInfo>();
      return EX_USAGE;
    }

    ASSIGN_OR_RETURN(
        hwsec::IFXFieldUpgradeInfo info,
        hwsec::FactoryImpl().GetClientFrontend()->GetIFXFieldUpgradeInfo(),
        _.LogError().As(EXIT_FAILURE));

    printf("max_data_size %u\n", info.max_data_size);
    PrintIFXFirmwarePackage(info.bootloader, "bootloader");
    PrintIFXFirmwarePackage(info.firmware[0], "fw0");
    PrintIFXFirmwarePackage(info.firmware[1], "fw1");
    printf("status %04x\n", info.status);
    PrintIFXFirmwarePackage(info.process_fw, "process_fw");
    printf("field_upgrade_counter %u\n", info.field_upgrade_counter);

    return EXIT_SUCCESS;
  }

  static void PrintIFXFirmwarePackage(
      const hwsec::IFXFieldUpgradeInfo::FirmwarePackage& firmware_package,
      const char* prefix) {
    printf("%s_package_id %08x\n", prefix, firmware_package.package_id);
    printf("%s_version %08x\n", prefix, firmware_package.version);
    printf("%s_stale_version %08x\n", prefix, firmware_package.stale_version);
  }
};

#define COMMAND_LIST \
  GetRandom, IsSrkRocaVulnerable, GetVersionInfo, GetIfxFieldUpgradeInfo

using Usage = Help<Help<>, COMMAND_LIST>;

}  // namespace

int main(int argc, char** argv) {
  base::CommandLine::Init(argc, argv);
  brillo::InitLog(brillo::kLogToStderr);

  base::CommandLine* cl = base::CommandLine::ForCurrentProcess();
  std::vector<std::string> cmd_args = cl->GetArgs();

  hwsec::ClientArgs args(cmd_args.data(), cmd_args.size());

  if (args.empty()) {
    return Usage::Run(args);
  }

  return hwsec::MatchCommands<Usage, COMMAND_LIST>::Run(args);
}
