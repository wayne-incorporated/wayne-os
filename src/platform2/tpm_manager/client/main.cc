// Copyright 2015 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stdio.h>
#include <stdlib.h>
#include <sysexits.h>

#include <memory>
#include <string>

#include <base/check.h>
#include <base/command_line.h>
#include <base/files/file_util.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/task/single_thread_task_runner.h>
#include <brillo/daemons/daemon.h>
#include <brillo/syslog_logging.h>
#include <crypto/sha2.h>
#include <tpm_manager/proto_bindings/tpm_manager.pb.h>
#include <tpm_manager-client/tpm_manager/dbus-proxies.h>

#include "tpm_manager/common/print_tpm_manager_proto.h"

namespace {
constexpr base::TimeDelta kDefaultTimeout = base::Minutes(2);
}  // namespace

namespace tpm_manager {

constexpr char kGetTpmStatusCommand[] = "status";
constexpr char kGetVersionInfoCommand[] = "get_version_info";
constexpr char kGetSupportedFeatures[] = "get_supported_features";
constexpr char kGetDictionaryAttackInfoCommand[] = "get_da_info";
constexpr char kGetRoVerificationStatusCommand[] = "get_ro_verification_status";
constexpr char kResetDictionaryAttackLockCommand[] = "reset_da_lock";
constexpr char kTakeOwnershipCommand[] = "take_ownership";
constexpr char kRemoveOwnerDependencyCommand[] = "remove_dependency";
constexpr char kClearStoredOwnerPasswordCommand[] = "clear_owner_password";
constexpr char kDefineSpaceCommand[] = "define_space";
constexpr char kDestroySpaceCommand[] = "destroy_space";
constexpr char kWriteSpaceCommand[] = "write_space";
constexpr char kReadSpaceCommand[] = "read_space";
constexpr char kLockSpaceCommand[] = "lock_space";
constexpr char kListSpacesCommand[] = "list_spaces";
constexpr char kGetSpaceInfoCommand[] = "get_space_info";

constexpr char kDependencySwitch[] = "dependency";
constexpr char kIndexSwitch[] = "index";
constexpr char kSizeSwitch[] = "size";
constexpr char kAttributesSwitch[] = "attributes";
constexpr char kPasswordSwitch[] = "password";
constexpr char kBindToPCR0Switch[] = "bind_to_pcr0";
constexpr char kFileSwitch[] = "file";
constexpr char kUseOwnerSwitch[] = "use_owner_authorization";
constexpr char kNonsensitiveSwitch[] = "nonsensitive";
constexpr char kIgnoreCacheSwitch[] = "ignore_cache";
constexpr char kLockRead[] = "lock_read";
constexpr char kLockWrite[] = "lock_write";

constexpr char kUsage[] = R"(
Usage: tpm_manager_client <command> [<arguments>]
Commands:
  status
      Prints TPM status information.
  get_version_info
      Prints TPM version information.
  get_supported_features
      Prints TPM supported features.
  get_da_info
      Prints TPM dictionary attack information.
  get_ro_verification_status
      Prints whether last reboot was triggered by RO verification
  reset_da_lock
      Resets dictionary attack lock
  take_ownership
      Takes ownership of the Tpm with a random password.
  remove_dependency --dependency=<owner_dependency>
      Removes the named Tpm owner dependency. E.g. \"Nvram\" or \"Attestation\".
  clear_owner_password
      Clears stored owner password if all dependencies have been removed.
  define_space --index=<index> --size=<size> [--attributes=<attribute_list>]
               [--password=<password>] [--bind_to_pcr0]
      Defines an NV space. The attribute format is a '|' separated list of:
          PERSISTENT_WRITE_LOCK: Allow write lock; stay locked until destroyed.
          BOOT_WRITE_LOCK: Allow write lock; stay locked until next boot.
          BOOT_READ_LOCK: Allow read lock; stay locked until next boot.
          WRITE_AUTHORIZATION: Require authorization to write.
          READ_AUTHORIZATION: Require authorization to read.
          WRITE_EXTEND: Allow only extend operations, not direct writes.
          GLOBAL_LOCK: Engage write lock when the global lock is engaged.
          PLATFORM_READ: Allow read with 'platform' authorization. Used by FWMP.
          PLATFORM_WRITE: Allow write only with 'platform' authorization. This
                          is similar to the TPM 1.2 'physical presence' notion.
          OWNER_WRITE: Allow write only with TPM owner authorization.
          OWNER_READ: Allow read only with TPM owner authorization.
      This command requires that owner authorization is available. If a password
      is given it will be required only as specified by the attributes. E.g. if
      READ_AUTHORIZATION is not listed, then the password will not be required
      in order to read. Similarly, if the --bind_to_pcr0 option is given, the
      current PCR0 value will be required only as specified by the attributes.
  destroy_space --index=<index>
      Destroys an NV space. This command requires that owner authorization is
      available.
  write_space --index=<index> --file=<input_file> [--password=<password>]
              [--use_owner_authorization]
      Writes data from a file to an NV space. Any existing data will be
      overwritten.
  read_space --index=<index> --file=<output_file> [--password=<password>]
             [--use_owner_authorization]
      Reads the entire contents of an NV space to a file.
  lock_space --index=<index> [--lock_read] [--lock_write]
             [--password=<password>] [--use_owner_authorization]
      Locks an NV space for read and / or write.
  list_spaces
      Prints a list of all defined index values.
  get_space_info --index=<index>
      Prints public information about an NV space.
)";

constexpr char kKnownNVRAMSpaces[] = R"(
NVRAM Index Reference:
 TPM 1.2 (32-bit values)
  0x00001007 - Chrome OS Firmware Version Rollback Protection
  0x00001008 - Chrome OS Kernel Version Rollback Protection
  0x00001009 - Chrome OS Firmware Backup
  0x0000100A - Chrome OS Firmware Management Parameters
  0x0000100B - Chrome OS Firmware Recovery Hash Space
  0x20000004 - Chrome OS Install Attributes (aka LockBox)
  0x10000001 - Standard TPM_NV_INDEX_DIR (Permanent)
  0x1000F000 - Endorsement Certificate (Permanent)
  0x30000001 - Endorsement Authority Certificate (Permanent)
  0x0000F004 - Standard Test Index (for testing TPM_NV_DefineSpace)

 TPM 2.0 (24-bit values)
  0x400000 and following - Reserved for Firmware
  0x800000 and following - Reserved for Software
  0xC00000 and following - Endorsement Certificates
)";

bool ReadFileToString(const std::string& filename, std::string* data) {
  return base::ReadFileToString(base::FilePath(filename), data);
}

bool WriteStringToFile(const std::string& data, const std::string& filename) {
  int result =
      base::WriteFile(base::FilePath(filename), data.data(), data.size());
  return (result != -1 && static_cast<size_t>(result) == data.size());
}

uint32_t StringToUint32(const std::string& s) {
  return strtoul(s.c_str(), nullptr, 0);
}

uint32_t StringToNvramIndex(const std::string& s) {
  return StringToUint32(s);
}

std::string GetAuthValueFromPassword(const std::string& password) {
  // For NULL password auth, we should pass a Empty Buffer as authorization
  // value to TPM. Otherwise, we use SHA256(password) to transform the
  // variable-length password to fixed-length authorization value.
  if (password.empty())
    return "";
  else
    return crypto::SHA256HashString(password);
}

using ClientLoopBase = brillo::Daemon;
class ClientLoop : public ClientLoopBase {
 public:
  ClientLoop() = default;
  ClientLoop(const ClientLoop&) = delete;
  ClientLoop& operator=(const ClientLoop&) = delete;

  ~ClientLoop() override = default;

 protected:
  int OnInit() override {
    int exit_code = ClientLoopBase::OnInit();
    if (exit_code != EX_OK) {
      LOG(ERROR) << "Error initializing tpm_manager_client.";
      return exit_code;
    }

    dbus::Bus::Options options;
    options.bus_type = dbus::Bus::SYSTEM;
    bus_ = base::MakeRefCounted<dbus::Bus>(options);
    CHECK(bus_->Connect()) << "Failed to connect to system D-Bus";

    std::unique_ptr<org::chromium::TpmNvramProxy> nvram_proxy =
        std::make_unique<org::chromium::TpmNvramProxy>(bus_);
    std::unique_ptr<org::chromium::TpmManagerProxy> ownership_proxy =
        std::make_unique<org::chromium::TpmManagerProxy>(bus_);
    tpm_nvram_ = std::move(nvram_proxy);
    tpm_ownership_ = std::move(ownership_proxy);
    exit_code = ScheduleCommand();
    if (exit_code == EX_USAGE) {
      printf("%s%s", kUsage, kKnownNVRAMSpaces);
    }
    return exit_code;
  }

  void OnShutdown(int* exit_code) override {
    tpm_nvram_.reset();
    tpm_ownership_.reset();
    if (bus_) {
      bus_->ShutdownAndBlock();
    }
    ClientLoopBase::OnShutdown(exit_code);
  }

 private:
  // Posts tasks on to the message loop based on command line flags.
  int ScheduleCommand() {
    base::OnceClosure task;
    base::CommandLine* command_line = base::CommandLine::ForCurrentProcess();
    if (command_line->HasSwitch("help") || command_line->HasSwitch("h") ||
        command_line->GetArgs().size() == 0) {
      return EX_USAGE;
    }
    std::string command = command_line->GetArgs()[0];
    if (command == kGetTpmStatusCommand) {
      if (!command_line->HasSwitch(kNonsensitiveSwitch)) {
        task = base::BindOnce(&ClientLoop::HandleGetTpmStatus,
                              weak_factory_.GetWeakPtr(),
                              command_line->HasSwitch(kIgnoreCacheSwitch));
      } else {
        task = base::BindOnce(&ClientLoop::HandleGetTpmNonsensitiveStatus,
                              weak_factory_.GetWeakPtr(),
                              command_line->HasSwitch(kIgnoreCacheSwitch));
      }

    } else if (command == kGetVersionInfoCommand) {
      task = base::BindOnce(&ClientLoop::HandleGetVersionInfo,
                            weak_factory_.GetWeakPtr());
    } else if (command == kGetSupportedFeatures) {
      task = base::BindOnce(&ClientLoop::HandleGetSupportedFeatures,
                            weak_factory_.GetWeakPtr());
    } else if (command == kGetDictionaryAttackInfoCommand) {
      task = base::BindOnce(&ClientLoop::HandleGetDictionaryAttackInfo,
                            weak_factory_.GetWeakPtr());
    } else if (command == kGetRoVerificationStatusCommand) {
      task = base::BindOnce(&ClientLoop::HandleGetRoVerificationStatus,
                            weak_factory_.GetWeakPtr());
    } else if (command == kResetDictionaryAttackLockCommand) {
      task = base::BindOnce(&ClientLoop::HandleResetDictionaryAttackLock,
                            weak_factory_.GetWeakPtr());
    } else if (command == kTakeOwnershipCommand) {
      task = base::BindOnce(&ClientLoop::HandleTakeOwnership,
                            weak_factory_.GetWeakPtr());
    } else if (command == kRemoveOwnerDependencyCommand) {
      if (!command_line->HasSwitch(kDependencySwitch)) {
        return EX_USAGE;
      }
      task = base::BindOnce(
          &ClientLoop::HandleRemoveOwnerDependency, weak_factory_.GetWeakPtr(),
          command_line->GetSwitchValueASCII(kDependencySwitch));
    } else if (command == kClearStoredOwnerPasswordCommand) {
      task = base::BindOnce(&ClientLoop::HandleClearStoredOwnerPassword,
                            weak_factory_.GetWeakPtr());
    } else if (command == kDefineSpaceCommand) {
      if (!command_line->HasSwitch(kIndexSwitch) ||
          !command_line->HasSwitch(kSizeSwitch)) {
        return EX_USAGE;
      }
      task = base::BindOnce(
          &ClientLoop::HandleDefineSpace, weak_factory_.GetWeakPtr(),
          StringToNvramIndex(command_line->GetSwitchValueASCII(kIndexSwitch)),
          StringToUint32(command_line->GetSwitchValueASCII(kSizeSwitch)),
          command_line->GetSwitchValueASCII(kAttributesSwitch),
          command_line->GetSwitchValueASCII(kPasswordSwitch),
          command_line->HasSwitch(kBindToPCR0Switch));
    } else if (command == kDestroySpaceCommand) {
      if (!command_line->HasSwitch(kIndexSwitch)) {
        return EX_USAGE;
      }
      task = base::BindOnce(
          &ClientLoop::HandleDestroySpace, weak_factory_.GetWeakPtr(),
          StringToNvramIndex(command_line->GetSwitchValueASCII(kIndexSwitch)));
    } else if (command == kWriteSpaceCommand) {
      if (!command_line->HasSwitch(kIndexSwitch) ||
          !command_line->HasSwitch(kFileSwitch)) {
        return EX_USAGE;
      }
      task = base::BindOnce(
          &ClientLoop::HandleWriteSpace, weak_factory_.GetWeakPtr(),
          StringToNvramIndex(command_line->GetSwitchValueASCII(kIndexSwitch)),
          command_line->GetSwitchValueASCII(kFileSwitch),
          command_line->GetSwitchValueASCII(kPasswordSwitch),
          command_line->HasSwitch(kUseOwnerSwitch));
    } else if (command == kReadSpaceCommand) {
      if (!command_line->HasSwitch(kIndexSwitch) ||
          !command_line->HasSwitch(kFileSwitch)) {
        return EX_USAGE;
      }
      task = base::BindOnce(
          &ClientLoop::HandleReadSpace, weak_factory_.GetWeakPtr(),
          StringToNvramIndex(command_line->GetSwitchValueASCII(kIndexSwitch)),
          command_line->GetSwitchValueASCII(kFileSwitch),
          command_line->GetSwitchValueASCII(kPasswordSwitch),
          command_line->HasSwitch(kUseOwnerSwitch));
    } else if (command == kLockSpaceCommand) {
      if (!command_line->HasSwitch(kIndexSwitch)) {
        return EX_USAGE;
      }
      task = base::BindOnce(
          &ClientLoop::HandleLockSpace, weak_factory_.GetWeakPtr(),
          StringToNvramIndex(command_line->GetSwitchValueASCII(kIndexSwitch)),
          command_line->HasSwitch(kLockRead),
          command_line->HasSwitch(kLockWrite),
          command_line->GetSwitchValueASCII(kPasswordSwitch),
          command_line->HasSwitch(kUseOwnerSwitch));
    } else if (command == kListSpacesCommand) {
      task = base::BindOnce(&ClientLoop::HandleListSpaces,
                            weak_factory_.GetWeakPtr());
    } else if (command == kGetSpaceInfoCommand) {
      if (!command_line->HasSwitch(kIndexSwitch)) {
        return EX_USAGE;
      }
      task = base::BindOnce(
          &ClientLoop::HandleGetSpaceInfo, weak_factory_.GetWeakPtr(),
          StringToNvramIndex(command_line->GetSwitchValueASCII(kIndexSwitch)));
    } else {
      // Command line arguments did not match any valid commands.
      return EX_USAGE;
    }
    base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
        FROM_HERE, std::move(task));
    return EX_OK;
  }

  // Template to print reply protobuf.
  template <typename ProtobufType>
  void PrintReplyAndQuit(const ProtobufType& reply) {
    printf("Message Reply: %s\n", GetProtoDebugString(reply).c_str());
    Quit();
  }

  void PrintErrorAndQuit(brillo::Error* error) {
    printf("Error: %s\n", error->GetMessage().c_str());
    Quit();
  }

  void HandleGetTpmStatus(bool ignore_cache) {
    GetTpmStatusRequest request;
    request.set_ignore_cache(ignore_cache);
    tpm_ownership_->GetTpmStatusAsync(
        request,
        base::BindOnce(&ClientLoop::PrintReplyAndQuit<GetTpmStatusReply>,
                       weak_factory_.GetWeakPtr()),
        base::BindOnce(&ClientLoop::PrintErrorAndQuit,
                       weak_factory_.GetWeakPtr()),
        kDefaultTimeout.InMilliseconds());
  }

  void HandleGetTpmNonsensitiveStatus(bool ignore_cache) {
    GetTpmNonsensitiveStatusRequest request;
    request.set_ignore_cache(ignore_cache);
    tpm_ownership_->GetTpmNonsensitiveStatusAsync(
        request,
        base::BindOnce(
            &ClientLoop::PrintReplyAndQuit<GetTpmNonsensitiveStatusReply>,
            weak_factory_.GetWeakPtr()),
        base::BindOnce(&ClientLoop::PrintErrorAndQuit,
                       weak_factory_.GetWeakPtr()),
        kDefaultTimeout.InMilliseconds());
  }

  void HandleGetVersionInfo() {
    GetVersionInfoRequest request;
    tpm_ownership_->GetVersionInfoAsync(
        request,
        base::BindOnce(&ClientLoop::PrintReplyAndQuit<GetVersionInfoReply>,
                       weak_factory_.GetWeakPtr()),
        base::BindOnce(&ClientLoop::PrintErrorAndQuit,
                       weak_factory_.GetWeakPtr()),
        kDefaultTimeout.InMilliseconds());
  }

  void HandleGetSupportedFeatures() {
    GetSupportedFeaturesRequest request;
    tpm_ownership_->GetSupportedFeaturesAsync(
        request,
        base::BindOnce(
            &ClientLoop::PrintReplyAndQuit<GetSupportedFeaturesReply>,
            weak_factory_.GetWeakPtr()),
        base::BindOnce(&ClientLoop::PrintErrorAndQuit,
                       weak_factory_.GetWeakPtr()),
        kDefaultTimeout.InMilliseconds());
  }

  void HandleGetDictionaryAttackInfo() {
    GetDictionaryAttackInfoRequest request;
    tpm_ownership_->GetDictionaryAttackInfoAsync(
        request,
        base::BindOnce(
            &ClientLoop::PrintReplyAndQuit<GetDictionaryAttackInfoReply>,
            weak_factory_.GetWeakPtr()),
        base::BindOnce(&ClientLoop::PrintErrorAndQuit,
                       weak_factory_.GetWeakPtr()),
        kDefaultTimeout.InMilliseconds());
  }

  void HandleGetRoVerificationStatus() {
    GetRoVerificationStatusRequest request;
    tpm_ownership_->GetRoVerificationStatusAsync(
        request,
        base::BindOnce(
            &ClientLoop::PrintReplyAndQuit<GetRoVerificationStatusReply>,
            weak_factory_.GetWeakPtr()),
        base::BindOnce(&ClientLoop::PrintErrorAndQuit,
                       weak_factory_.GetWeakPtr()),
        kDefaultTimeout.InMilliseconds());
  }

  void HandleResetDictionaryAttackLock() {
    ResetDictionaryAttackLockRequest request;
    tpm_ownership_->ResetDictionaryAttackLockAsync(
        request,
        base::BindOnce(
            &ClientLoop::PrintReplyAndQuit<ResetDictionaryAttackLockReply>,
            weak_factory_.GetWeakPtr()),
        base::BindOnce(&ClientLoop::PrintErrorAndQuit,
                       weak_factory_.GetWeakPtr()),
        kDefaultTimeout.InMilliseconds());
  }

  void HandleTakeOwnership() {
    TakeOwnershipRequest request;
    tpm_ownership_->TakeOwnershipAsync(
        request,
        base::BindOnce(&ClientLoop::PrintReplyAndQuit<TakeOwnershipReply>,
                       weak_factory_.GetWeakPtr()),
        base::BindOnce(&ClientLoop::PrintErrorAndQuit,
                       weak_factory_.GetWeakPtr()),
        kDefaultTimeout.InMilliseconds());
  }

  void HandleRemoveOwnerDependency(const std::string& owner_dependency) {
    RemoveOwnerDependencyRequest request;
    request.set_owner_dependency(owner_dependency);
    tpm_ownership_->RemoveOwnerDependencyAsync(
        request,
        base::BindOnce(
            &ClientLoop::PrintReplyAndQuit<RemoveOwnerDependencyReply>,
            weak_factory_.GetWeakPtr()),
        base::BindOnce(&ClientLoop::PrintErrorAndQuit,
                       weak_factory_.GetWeakPtr()),
        kDefaultTimeout.InMilliseconds());
  }

  void HandleClearStoredOwnerPassword() {
    ClearStoredOwnerPasswordRequest request;
    tpm_ownership_->ClearStoredOwnerPasswordAsync(
        request,
        base::BindOnce(
            &ClientLoop::PrintReplyAndQuit<ClearStoredOwnerPasswordReply>,
            weak_factory_.GetWeakPtr()),
        base::BindOnce(&ClientLoop::PrintErrorAndQuit,
                       weak_factory_.GetWeakPtr()),
        kDefaultTimeout.InMilliseconds());
  }

  bool DecodeAttribute(const std::string& attribute_str,
                       NvramSpaceAttribute* attribute) {
    if (attribute_str == "PERSISTENT_WRITE_LOCK") {
      *attribute = NVRAM_PERSISTENT_WRITE_LOCK;
      return true;
    }
    if (attribute_str == "BOOT_WRITE_LOCK") {
      *attribute = NVRAM_BOOT_WRITE_LOCK;
      return true;
    }
    if (attribute_str == "BOOT_READ_LOCK") {
      *attribute = NVRAM_BOOT_READ_LOCK;
      return true;
    }
    if (attribute_str == "WRITE_AUTHORIZATION") {
      *attribute = NVRAM_WRITE_AUTHORIZATION;
      return true;
    }
    if (attribute_str == "READ_AUTHORIZATION") {
      *attribute = NVRAM_READ_AUTHORIZATION;
      return true;
    }
    if (attribute_str == "WRITE_EXTEND") {
      *attribute = NVRAM_WRITE_EXTEND;
      return true;
    }
    if (attribute_str == "GLOBAL_LOCK") {
      *attribute = NVRAM_GLOBAL_LOCK;
      return true;
    }
    if (attribute_str == "PLATFORM_READ") {
      *attribute = NVRAM_PLATFORM_READ;
      return true;
    }
    if (attribute_str == "PLATFORM_WRITE") {
      *attribute = NVRAM_PLATFORM_WRITE;
      return true;
    }
    if (attribute_str == "OWNER_WRITE") {
      *attribute = NVRAM_OWNER_WRITE;
      return true;
    }
    if (attribute_str == "OWNER_READ") {
      *attribute = NVRAM_OWNER_READ;
      return true;
    }
    LOG(ERROR) << "Unrecognized attribute: " << attribute_str;
    return false;
  }

  void HandleDefineSpace(uint32_t index,
                         size_t size,
                         const std::string& attributes,
                         const std::string& password,
                         bool bind_to_pcr0) {
    DefineSpaceRequest request;
    request.set_index(index);
    request.set_size(size);
    std::string::size_type pos = 0;
    std::string::size_type next_pos = 0;
    while (next_pos != std::string::npos) {
      next_pos = attributes.find('|', pos);
      std::string attribute_str;
      if (next_pos == std::string::npos) {
        attribute_str = attributes.substr(pos);
      } else {
        attribute_str = attributes.substr(pos, next_pos - pos);
      }
      if (!attribute_str.empty()) {
        NvramSpaceAttribute attribute;
        if (!DecodeAttribute(attribute_str, &attribute)) {
          Quit();
          return;
        }
        request.add_attributes(attribute);
      }
      pos = next_pos + 1;
    }
    request.set_authorization_value(GetAuthValueFromPassword(password));
    request.set_policy(bind_to_pcr0 ? NVRAM_POLICY_PCR0 : NVRAM_POLICY_NONE);
    tpm_nvram_->DefineSpaceAsync(
        request,
        base::BindOnce(&ClientLoop::PrintReplyAndQuit<DefineSpaceReply>,
                       weak_factory_.GetWeakPtr()),
        base::BindOnce(&ClientLoop::PrintErrorAndQuit,
                       weak_factory_.GetWeakPtr()),
        kDefaultTimeout.InMilliseconds());
  }

  void HandleDestroySpace(uint32_t index) {
    DestroySpaceRequest request;
    request.set_index(index);
    tpm_nvram_->DestroySpaceAsync(
        request,
        base::BindOnce(&ClientLoop::PrintReplyAndQuit<DestroySpaceReply>,
                       weak_factory_.GetWeakPtr()),
        base::BindOnce(&ClientLoop::PrintErrorAndQuit,
                       weak_factory_.GetWeakPtr()),
        kDefaultTimeout.InMilliseconds());
  }

  void HandleWriteSpace(uint32_t index,
                        const std::string& input_file,
                        const std::string& password,
                        bool use_owner_authorization) {
    WriteSpaceRequest request;
    request.set_index(index);
    std::string data;
    if (!ReadFileToString(input_file, &data)) {
      LOG(ERROR) << "Failed to read input file.";
      Quit();
      return;
    }
    request.set_data(data);
    request.set_authorization_value(GetAuthValueFromPassword(password));
    request.set_use_owner_authorization(use_owner_authorization);
    tpm_nvram_->WriteSpaceAsync(
        request,
        base::BindOnce(&ClientLoop::PrintReplyAndQuit<WriteSpaceReply>,
                       weak_factory_.GetWeakPtr()),
        base::BindOnce(&ClientLoop::PrintErrorAndQuit,
                       weak_factory_.GetWeakPtr()),
        kDefaultTimeout.InMilliseconds());
  }

  void HandleReadSpaceReply(const std::string& output_file,
                            const ReadSpaceReply& reply) {
    if (!WriteStringToFile(reply.data(), output_file)) {
      LOG(ERROR) << "Failed to write output file.";
    }
    LOG(INFO) << "Message Reply: " << GetProtoDebugString(reply);
    Quit();
  }

  void HandleReadSpace(uint32_t index,
                       const std::string& output_file,
                       const std::string& password,
                       bool use_owner_authorization) {
    ReadSpaceRequest request;
    request.set_index(index);
    request.set_authorization_value(GetAuthValueFromPassword(password));
    request.set_use_owner_authorization(use_owner_authorization);
    tpm_nvram_->ReadSpaceAsync(
        request,
        base::BindOnce(&ClientLoop::HandleReadSpaceReply,
                       weak_factory_.GetWeakPtr(), output_file),
        base::BindOnce(&ClientLoop::PrintErrorAndQuit,
                       weak_factory_.GetWeakPtr()),
        kDefaultTimeout.InMilliseconds());
  }

  void HandleLockSpace(uint32_t index,
                       bool lock_read,
                       bool lock_write,
                       const std::string& password,
                       bool use_owner_authorization) {
    LockSpaceRequest request;
    request.set_index(index);
    request.set_lock_read(lock_read);
    request.set_lock_write(lock_write);
    request.set_authorization_value(GetAuthValueFromPassword(password));
    request.set_use_owner_authorization(use_owner_authorization);
    tpm_nvram_->LockSpaceAsync(
        request,
        base::BindOnce(&ClientLoop::PrintReplyAndQuit<LockSpaceReply>,
                       weak_factory_.GetWeakPtr()),
        base::BindOnce(&ClientLoop::PrintErrorAndQuit,
                       weak_factory_.GetWeakPtr()),
        kDefaultTimeout.InMilliseconds());
  }

  void HandleListSpaces() {
    printf("%s\n", kKnownNVRAMSpaces);
    ListSpacesRequest request;
    tpm_nvram_->ListSpacesAsync(
        request,
        base::BindOnce(&ClientLoop::PrintReplyAndQuit<ListSpacesReply>,
                       weak_factory_.GetWeakPtr()),
        base::BindOnce(&ClientLoop::PrintErrorAndQuit,
                       weak_factory_.GetWeakPtr()),
        kDefaultTimeout.InMilliseconds());
  }

  void HandleGetSpaceInfo(uint32_t index) {
    GetSpaceInfoRequest request;
    request.set_index(index);
    tpm_nvram_->GetSpaceInfoAsync(
        request,
        base::BindOnce(&ClientLoop::PrintReplyAndQuit<GetSpaceInfoReply>,
                       weak_factory_.GetWeakPtr()),
        base::BindOnce(&ClientLoop::PrintErrorAndQuit,
                       weak_factory_.GetWeakPtr()),
        kDefaultTimeout.InMilliseconds());
  }

  scoped_refptr<dbus::Bus> bus_;

  // IPC proxy interfaces.
  std::unique_ptr<org::chromium::TpmNvramProxyInterface> tpm_nvram_;
  std::unique_ptr<org::chromium::TpmManagerProxyInterface> tpm_ownership_;

  // Declared last so that weak pointers will be destroyed first.
  base::WeakPtrFactory<ClientLoop> weak_factory_{this};
};

}  // namespace tpm_manager

int main(int argc, char* argv[]) {
  base::CommandLine::Init(argc, argv);
  brillo::InitLog(brillo::kLogToStderr);
  tpm_manager::ClientLoop loop;
  return loop.Run();
}
