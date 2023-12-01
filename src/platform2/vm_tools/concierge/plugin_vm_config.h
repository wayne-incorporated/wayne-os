// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
#ifndef VM_TOOLS_CONCIERGE_PLUGIN_VM_CONFIG_H_
#define VM_TOOLS_CONCIERGE_PLUGIN_VM_CONFIG_H_

namespace vm_tools {
namespace concierge {
namespace pvm {

// Path to the Parallels binaries and other assets.
constexpr char kApplicationDir[] =
    "/run/imageloader/pita/package/root/opt/pita";

// Name of the runtime directory both inside and outside of jails.
constexpr char kRuntimeDir[] = "/run/pvm";

namespace dispatcher {

// Path to VM images, as seen from the dispatcher jail.
constexpr char kImageDir[] = "/run/pvm-images";

// Path to the dispatcher socket, should be the same from inside
// and outside of jails.
constexpr char kSocketPath[] = "/run/pvm/vmplugin_dispatcher.socket";

}  // namespace dispatcher

namespace helper {

constexpr char kCommand[] = "prlctl";
constexpr char kPolicyPath[] = "policy/pvm_helper.policy";

}  // namespace helper

namespace plugin {

// Name of the plugin VM binary.
constexpr char kCommand[] = "prl_vm_app";

// Name of the sub-directory containing plugin's seccomp policy.
constexpr char kPolicyDir[] = "policy";

// Name of directory used by Parallels software to locate components
// inside jail when not using relative paths.
constexpr char kPitaDir[] = "/opt/pita";

// Name of the directory holding ISOs inside the jail.
constexpr char kIsoDir[] = "/iso";

// Name we give VM installation media, as seen from inside jail.
constexpr char kInstallIsoPath[] = "/iso/install.iso";

// Name of the Parallels Tools media, as seen from inside jail.
constexpr char kToolsIsoPath[] = "/opt/pita/tools/prl-tools-win.iso";

// Name of the stateful directory inside the jail.
constexpr char kStatefulDir[] = "/pvm";

}  // namespace plugin

}  // namespace pvm
}  // namespace concierge
}  // namespace vm_tools

#endif  // VM_TOOLS_CONCIERGE_PLUGIN_VM_CONFIG_H_
