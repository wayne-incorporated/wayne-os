// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VM_TOOLS_CONCIERGE_SSH_KEYS_H_
#define VM_TOOLS_CONCIERGE_SSH_KEYS_H_

#include <string>

namespace vm_tools {
namespace concierge {

// Gets the public key for the host (Chrome OS) for usage in the authorized
// hosts file in a container. If the key does not exist yet it will be generated
// as part of this call. Returns the empty string if there is any kind of
// failure.
std::string GetHostSshPublicKey(const std::string& cryptohome_id);

// Gets the private key for the host (Chrome OS) for usage by SSH in SFTP
// mounting. If the key does not exist yet it will be generated as part of this
// call. Returns the empty string if there is any kind of failure.
std::string GetHostSshPrivateKey(const std::string& cryptohome_id);

// Gets the public key for the guest (container) for usage by Chrome OS in its
// known hosts. If the key does not exist yet it will be generated as part of
// this call. Returns the empty string if there is any kind of failure.
std::string GetGuestSshPublicKey(const std::string& cryptohome_id,
                                 const std::string& vm_name,
                                 const std::string& container_name);

// Gets the private key for the guest (container) for usage by the container as
// its identity in SSH for SFTP mounting. If the key does not exist yet it will
// be generated as part of this call. Returns the empty string if there is any
// kind of failure.
std::string GetGuestSshPrivateKey(const std::string& cryptohome_id,
                                  const std::string& vm_name,
                                  const std::string& container_name);

// Erases all of the SSH keys generated for the specified |vm_name|. Should be
// called when a VM disk image is destroyed. Returns false if there were any
// failures deleting the keys, true otherwise.
bool EraseGuestSshKeys(const std::string& cryptohome_id,
                       const std::string& vm_name);

}  // namespace concierge
}  // namespace vm_tools

#endif  // VM_TOOLS_CONCIERGE_SSH_KEYS_H_
