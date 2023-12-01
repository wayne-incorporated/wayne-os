// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "vm_tools/concierge/ssh_keys.h"

#include <utility>
#include <vector>

#include <base/command_line.h>
#include <base/files/file_enumerator.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/process/launch.h>
#include <base/strings/string_util.h>

#include "vm_tools/common/naming.h"

namespace vm_tools {
namespace concierge {

namespace {
// Daemon store base path.
constexpr char kCryptohomeRoot[] = "/run/daemon-store/crosvm";

// Dir name that all ssh keys are stored under.
constexpr char kSshKeysDir[] = "sshkeys";

// Filename used for the host keys in the ssh key dir.
constexpr char kHostKeyFilename[] = "host_key";

// Separator between the encoded vm and container name in the filename. This
// also prevents a well-chosen vm/container name from colliding with 'host_key'.
constexpr char kVmContainerSeparator[] = "-";

// Filename extension for the public variant of a key.
constexpr char kPubKeyExt[] = ".pub";

// Generated SSH key file will never be larger than this.
constexpr size_t kMaxKeyFileSize = 1024;

// Timeout when we are launching the keygen process. It will hang indefinitely
// if the target files exist (we protect against that, but better to be safe).
constexpr base::TimeDelta kKeyGenProcessTimeout = base::Seconds(10);

// Returns the file path to where the host private key is stored. To get the
// public key version, just add the extension kPubKeyExt to this.
base::FilePath GetHostKeyPath(const std::string& cryptohome_id) {
  return base::FilePath(kCryptohomeRoot)
      .Append(cryptohome_id)
      .Append(kSshKeysDir)
      .Append(kHostKeyFilename);
}

// Returns the file path to where the guest private key is stored. To get the
// public key version, just add the extension kPubKeyExt to this.
base::FilePath GetGuestKeyPath(const std::string& cryptohome_id,
                               const std::string& vm_name,
                               const std::string& container_name) {
  std::string encoded_vm = GetEncodedName(vm_name);
  std::string encoded_container = GetEncodedName(container_name);

  return base::FilePath(kCryptohomeRoot)
      .Append(cryptohome_id)
      .Append(kSshKeysDir)
      .Append(encoded_vm + kVmContainerSeparator + encoded_container);
}

// Reads in the contents of the specified file path and returns it as a string,
// returns an empty string if there was any kind of failure.
std::string LoadKeyFromPath(const base::FilePath& path) {
  // To better distinguish between error cases and non-existent keys for logging
  // purposes.
  if (!base::PathExists(path)) {
    return "";
  }
  std::string key;
  if (!base::ReadFileToStringWithMaxSize(path, &key, kMaxKeyFileSize)) {
    PLOG(ERROR) << "Failed reading SSH key from: " << path.value();
    return "";
  }
  return key;
}

// Generates an SSH key pair with the output being written to the specified
// |path|. The public key will have a .pub extension added to it at that same
// path. Returns true on success and false otherwise.
bool GenerateKeyPair(const base::FilePath& path) {
  // First we need to ensure the output paths are empty, there is no option to
  // have ssh-keygen overwrite the targets.
  if (!base::DeleteFile(path) ||
      !base::DeleteFile(path.AddExtension(kPubKeyExt))) {
    PLOG(ERROR) << "Failed ensuring SSH keys don't exist before creation at "
                << "path: " << path.value();
    return false;
  }

  // Ensure our output directory exists.
  base::FilePath parent_dir = path.DirName();
  if (!base::DirectoryExists(parent_dir)) {
    base::File::Error dir_error;
    if (!base::CreateDirectoryAndGetError(parent_dir, &dir_error)) {
      LOG(ERROR) << "Failed to create crosvm_sshkeys directory in "
                 << parent_dir << ": " << base::File::ErrorToString(dir_error);
      return false;
    }
  }

  std::vector<std::string> args = {
      "ssh-keygen",                // Executable for key generation.
      "-t",         "ed25519",     // Elliptic curve keys.
      "-N",         "",            // No passphrase.
      "-C",         "",            // No comment.
      "-q",                        // Quiet mode.
      "-f",         path.value(),  // Output file path for private key.
  };
  base::Process process =
      base::LaunchProcess(std::move(args), base::LaunchOptions());
  int exit_code;
  if (!process.WaitForExitWithTimeout(kKeyGenProcessTimeout, &exit_code)) {
    LOG(ERROR) << "Timed out waiting for keygen process to finish";
    return false;
  }
  if (exit_code != 0) {
    LOG(ERROR) << "SSH key generation failed with exit code: " << exit_code;
    return false;
  }
  return true;
}

}  // namespace

std::string GetHostSshPublicKey(const std::string& cryptohome_id) {
  base::FilePath key_path = GetHostKeyPath(cryptohome_id);
  base::FilePath pub_key_path = key_path.AddExtension(kPubKeyExt);
  std::string pub_key = LoadKeyFromPath(pub_key_path);
  if (!pub_key.empty()) {
    return pub_key;
  }
  LOG(INFO) << "Host SSH keys do not exist, generate the key pair for them";
  if (!GenerateKeyPair(key_path)) {
    LOG(ERROR) << "Failed generating host ssh keys";
    return "";
  }
  pub_key = LoadKeyFromPath(pub_key_path);
  return pub_key;
}

std::string GetHostSshPrivateKey(const std::string& cryptohome_id) {
  base::FilePath key_path = GetHostKeyPath(cryptohome_id);
  std::string priv_key = LoadKeyFromPath(key_path);
  if (!priv_key.empty()) {
    return priv_key;
  }
  LOG(INFO) << "Host SSH keys do not exist, generate the key pair for them";
  if (!GenerateKeyPair(key_path)) {
    LOG(ERROR) << "Failed generating host ssh keys";
    return "";
  }
  priv_key = LoadKeyFromPath(key_path);
  return priv_key;
}

std::string GetGuestSshPublicKey(const std::string& cryptohome_id,
                                 const std::string& vm_name,
                                 const std::string& container_name) {
  base::FilePath key_path =
      GetGuestKeyPath(cryptohome_id, vm_name, container_name);
  base::FilePath pub_key_path = key_path.AddExtension(kPubKeyExt);
  std::string pub_key = LoadKeyFromPath(pub_key_path);
  if (!pub_key.empty()) {
    return pub_key;
  }
  LOG(INFO) << "Guest SSH keys do not exist for " << vm_name << ":"
            << container_name << ", generate the key pair for them";
  if (!GenerateKeyPair(key_path)) {
    LOG(ERROR) << "Failed generating guest ssh keys";
    return "";
  }
  pub_key = LoadKeyFromPath(pub_key_path);
  return pub_key;
}

std::string GetGuestSshPrivateKey(const std::string& cryptohome_id,
                                  const std::string& vm_name,
                                  const std::string& container_name) {
  base::FilePath key_path =
      GetGuestKeyPath(cryptohome_id, vm_name, container_name);
  std::string priv_key = LoadKeyFromPath(key_path);
  if (!priv_key.empty()) {
    return priv_key;
  }
  LOG(INFO) << "Guest SSH keys do not exist for " << vm_name << ":"
            << container_name << ", generate the key pair for them";
  if (!GenerateKeyPair(key_path)) {
    LOG(ERROR) << "Failed generating guest ssh keys";
    return "";
  }
  priv_key = LoadKeyFromPath(key_path);
  return priv_key;
}

bool EraseGuestSshKeys(const std::string& cryptohome_id,
                       const std::string& vm_name) {
  // Look in the generated key directory for all keys that have the prefix
  // associated with this |vm_name| and erase them.
  bool rv = true;
  std::string encoded_vm = GetEncodedName(vm_name);
  std::string target_prefix = encoded_vm + kVmContainerSeparator;
  base::FilePath search_path =
      base::FilePath(kCryptohomeRoot).Append(cryptohome_id).Append(kSshKeysDir);
  base::FileEnumerator file_enum(search_path, false,
                                 base::FileEnumerator::FILES);
  for (base::FilePath enum_path = file_enum.Next(); !enum_path.empty();
       enum_path = file_enum.Next()) {
    if (base::StartsWith(enum_path.BaseName().value(), target_prefix,
                         base::CompareCase::SENSITIVE)) {
      // Found an ssh key for this VM, delete it.
      if (!base::DeleteFile(enum_path)) {
        PLOG(ERROR) << "Failed deleting generated SSH key for VM: "
                    << enum_path.value();
        rv = false;
      }
    }
  }
  return rv;
}

}  // namespace concierge
}  // namespace vm_tools
