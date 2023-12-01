#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright 2017 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""A command-line utility to access the Chrome OS model configuration.

Cros config is broken into two tools, cros_config and cros_config_host. This is
the latter; it is the build side version of cros_config. It is used by the build
system to access configuration details for for a Chrome OS device.
"""

from __future__ import print_function

import argparse
import json
import os
import sys


# pylint: disable=wrong-import-position
this_dir = os.path.dirname(__file__)
sys.path.insert(0, this_dir)
from libcros_config_host import CrosConfig  # pylint: disable=import-error


sys.path.pop(0)


def DumpConfig(config):
    """Dumps all of the config to stdout

    Args:
        config: A CrosConfig instance
    """
    result = config.GetFullConfig()
    output = json.dumps(result, sort_keys=True, indent=2)
    print(output)


def ListModels(config):
    """Prints all models in a config to stdout, one per line.

    Args:
        config: A CrosConfig instance
    """
    for model_name in config.GetModelList():
        print(model_name)


def GetProperty(device, path, prop):
    """Prints a property from the config tree for all models in the list models.

    Args:
        device: DeviceConfig instance for the lookup.
        path: The path (relative to a device) for the node containing the
            property.
        prop: The property to get (by name).
    """
    print(device.GetProperty(path, prop))


def GetFirmwareUris(config):
    """Prints space-separated firmware uris for all models in models.

    Args:
        config: A CrosConfig instance
    """
    print(" ".join(config.GetFirmwareUris()))


def GetTouchFirmwareFiles(config):
    """Print a list of touch firmware files across all models

    The output is one line for the firmware file and one line for the symlink,
    e.g.:
       ${FILESDIR}/wacom/4209.hex
       /opt/google/touch/firmware/wacom/4209.hex
       /lib/firmware/wacom_firmware_reef.bin

    Args:
        config: A CrosConfig instance
    """
    for files in config.GetTouchFirmwareFiles():
        print(files.source)
        print(files.dest)
        print(files.symlink)


def GetDetachableBaseFirmwareFiles(config):
    """Prints a list of detachable base firmware files across all models.

    The output is one line for the firmware file and one line for the symlink,
    e.g.:
       ${FILESDIR}/detachable_base/firmware/masterball.fw
       /opt/google/detachable_base/firmware/masterball.fw
       /lib/firmware/masterball.fw

    Args:
        config: A CrosConfig instance
    """
    for files in config.GetDetachableBaseFirmwareFiles():
        print(files.source)
        print(files.dest)
        print(files.symlink)


def GetArcFiles(config):
    """Print a list of arc++ files across all models

    The output is one line for the source file (typically relative to
    ${FILESDIR}) and one line for the install file, e.g.:
       astronaut/arc++/board_hardware_features
       /usr/sbin/astronaut/board_hardware_features

    Args:
        config: A CrosConfig instance
    """
    for files in config.GetArcFiles():
        print(files.source)
        print(files.dest)


def GetArcCodecFiles(config):
    """Print a list of arc media codec files across all models

    The output is one line for the source file (typically relative to
    ${FILESDIR}) and one line for the install file, e.g.:
       media_codecs_c2.xml
       /etc/media_codecs_c2.xml
       media_codecs_c2_performance.xml
       /etc/media_codecs_c2_performance.xml

    Args:
        config: A CrosConfig instance
    """
    for files in config.GetArcCodecFiles():
        print(files.source)
        print(files.dest)


def GetAudioFiles(config):
    """Print a list of audio files across all models

    The output is one line for the source file and one line for the install
    file, e.g.:
       ucm-config/bxtda7219max.reef.BASKING/bxtda7219max.reef.BASKING.conf
       /usr/share/alsa/ucm/bxtda7219max.basking/bxtda7219max.basking.conf

    Args:
        config: A CrosConfig instance
    """
    for files in config.GetAudioFiles():
        print(files.source)
        print(files.dest)


def GetBluetoothFiles(config):
    """Print a list of bluetooth files across all devices

    The output is one line for the source file and one line for the install
    file, e.g.:
       bluetooth/main.conf
       /etc/bluetooth/main.conf

    Args:
        config: A CrosConfig instance
    """
    for files in config.GetBluetoothFiles():
        print(files.source)
        print(files.dest)


def GetCameraFiles(config):
    """Print a list of camera files across all devices

    The output is one line for the source file and one line for the install
    file, e.g.:
      sw_build_config/.../camera_config_${design}.json
      /etc/camera/camera_config_${design}.json

    Args:
        config: A CrosConfig instance
    """
    for files in config.GetCameraFiles():
        print(files.source)
        print(files.dest)


def GetFirmwareBuildTargets(config, target_type):
    """Lists all firmware build-targets of the given type, for all models.

    Args:
        config: A CrosConfig instance to load data from.
        target_type: A string name for what target type to get build-targets
        for.
    """
    for target in config.GetFirmwareBuildTargets(target_type):
        print(target)


def GetFingerprintFirmwareROVersion(config, fpmcu):
    """Get the read-only versions of the fingerprint firmware for this board.

    cros_config_schema validates there is only one value for "ro-version" in the
    fingerprint object containing a "board" (fpmcu). This function finds and
    prints the value of the first "ro-version".

    Args:
        config: A CrosConfig instance.
        fpmcu: "FPMCU board".

    Returns:
        Exit code: 0 always since the ro-version does not have to be specified.
    """
    devices = config.GetDeviceConfigs()
    for device in devices:
        identity = device.GetProperties("/fingerprint")
        board = identity.get("board")
        if board == fpmcu:
            ro_version = identity.get("ro-version")
            if ro_version is not None:
                print(ro_version)
                return 0

    return 0


def GetThermalFiles(config):
    """Print a list of thermal files across all models

    The output is one line for the source file (typically relative to
    ${FILESDIR}) and one line for the install file, e.g.:
       astronaut/dptf.dv
       /etc/dptf/astronaut/dptf.dv

    Args:
        config: A CrosConfig instance
    """
    for files in config.GetThermalFiles():
        print(files.source)
        print(files.dest)


def GetIntelWifiSarFiles(config):
    """Print a list of intel wifi sar files across all models

    The output is one line for the source file
    and one line for the install file, e.g.:

       proj/sw_build_config/.../generated/wifi/wifi_sar_6.hex
       /firmware/cbfs-rw-raw/proj/wifi_sar_6.hex

    Args:
        config: A CrosConfig instance
    """
    for files in config.GetIntelWifiSarFiles():
        print(files.source)
        print(files.dest)


def GetProximitySensorFiles(config):
    """Print a list of proximity sensor configuration files across all models

    The output is one line for the source file
    and one line for the install file, e.g.:

        villager/sw_build_config/.../semtech_config_wifi_cellular-1.json
        /usr/share/chromeos-assets/.../semtech_config_wifi_cellular-1.json

    Args:
        config: A CrosConfig instance
    """
    for files in config.GetProximitySensorFiles():
        print(files.source)
        print(files.dest)


def FileTree(config, root):
    """Print a tree showing all files installed for this config

    The output is a tree structure printed one directory/file per line. Each
    file is shown with its size, or missing it if is not present.

    Args:
        config: A CrosConfig instance
        root: Path to the root directory for the board (e.g. '/build/reef-uni')
    """
    tree = config.GetFileTree()
    config.ShowTree(tree, root)


def GetFirmwareBuildCombinations(config, targets):
    """Print the firmware build combinations for requested targets

    Args:
        config: A CrosConfig instance
        targets: List of names of the build targets to get combinations for
    """
    d = config.GetFirmwareBuildCombinations(targets)
    for name, target_values in d.items():
        print(name)
        for value in target_values:
            if value:
                print(value)
            else:
                print()


def GetWallpaperFiles(config):
    """Get the wallpaper files needed for installation

    Args:
        config: A CrosConfig instance

    Returns:
        List of wallpaper filenames (sorted)
    """
    for fname in config.GetWallpaperFiles():
        print(fname)


def GetAutobrightnessFiles(config):
    """Print a list of autobrightness files across all models

    The output is one line for the source file (typically relative to
    ${FILESDIR}) and one line for the install file, e.g.:
       kohaku/autobrightness/model_params.json
       usr/share/chromeos-assets/autobrightness/kohaku/model_params.json

    Args:
        config: A CrosConfig instance
    """
    for files in config.GetAutobrightnessFiles():
        print(files.source)
        print(files.dest)


def GetFirmwareRecoveryInput(config, build_target_name, build_target_value):
    """Print the recovery input method for firmware config

    Args:
        config: A CrosConfig instance
        build_target_name: Build target name (e.g. "depthcharge")
        build_target_value: Build target for the associated name
    """
    print(
        config.GetFirmwareRecoveryInput(build_target_name, build_target_value)
    )


def GetKeyValuePairs(config, key_path, key_name, value_path, value_name):
    """Print the key-value pairs that exist for the given paths

    Args:
        config: A CrosConfig instance
        key_path: Path to property to use as the key (e.g. "/firmware")
        key_name: Name of property to use as the key (e.g. "image-name")
        value_path: Path to property to use as the value
        value_name: Path to property to use as the value
    """
    d = config.GetKeyValuePairs(key_path, key_name, value_path, value_name)
    for name, value in d.items():
        print(name)
        print(value)


def GetKeyValue(
    config,
    key_path,
    key_name,
    key_match,
    value_path,
    value_name,
    ignore_unset=False,
):
    """Print the unique value for a key in a key-value pair.

    Args:
        config: A CrosConfig instance
        key_path: Path to property to use as the key (e.g. "/firmware")
        key_name: Name of property to use as the key (e.g. "image-name")
        key_match: Value of key in kv pair
        value_path: Path to property to use as the value
        value_name: Path to property to use as the value
        ignore_unset: Ignore a device in the config if the value for a
            particular path is not set. This is useful when trying to resolve
            conflicts between a value and configs that don't set a value.
    """
    value = config.GetKeyValue(
        key_path, key_name, key_match, value_path, value_name, ignore_unset
    )
    if value:
        print(value)
    else:
        print()


def GetParser(description):
    """Returns an ArgumentParser structured for the cros_config_host CLI.

    Args:
        description: A description of the entire script, and it's purpose in
                     life.

    Returns:
        An ArgumentParser structured for the cros_config_host CLI.
    """
    parser = argparse.ArgumentParser(description)
    parser.add_argument(
        "-c",
        "--config",
        help="Override the model config file path. Use - for " "stdin.",
    )
    parser.add_argument(
        "-m",
        "--model",
        type=str,
        help="Which model to run the subcommand on. Defaults to "
        "CROS_CONFIG_MODEL environment variable.",
    )
    subparsers = parser.add_subparsers(dest="subcommand")
    subparsers.add_parser(
        "dump-config",
        help="Dumps all of the config via the respective API calls to stdout.",
    )
    # Parser: list-models
    subparsers.add_parser(
        "list-models",
        help="Lists all models in the Cros Configuration Database.",
        epilog="Each model will be printed on its own line.",
    )
    # Parser: get
    get_parser = subparsers.add_parser(
        "get",
        help="Gets a model property at the given path, with the given name.",
    )
    get_parser.add_argument(
        "path",
        help="Relative path (within the model) to the property's parent node",
    )
    get_parser.add_argument(
        "prop",
        help="The name of the property to get within the node at <path>.",
    )
    # Parser: get-touch-firmware-files
    subparsers.add_parser(
        "get-touch-firmware-files",
        help="Lists groups of touch firmware files in sequence: first line is "
        "firmware file, second line is symlink name for /lib/firmware",
    )
    # Parser: get-detachable-base-firmware-files
    subparsers.add_parser(
        "get-detachable-base-firmware-files",
        help="Lists groups of detachable base firmware files in sequence: "
        "first line is firmware file, second line is symlink name for "
        "/lib/firmware",
    )
    subparsers.add_parser(
        "get-firmware-uris",
        help="Lists AP firmware URIs for models. These URIs can be used to "
        "fetch firmware files for the chromeos-firmware-xxx ebuilds.",
    )
    # Parser: get-arc-files
    subparsers.add_parser(
        "get-arc-files",
        help="Lists pairs of arc++ files in sequence: first line is "
        "the relative source file, second line is the full install pathname",
    )
    # Parser: get-arc-codec-files
    subparsers.add_parser(
        "get-arc-codec-files",
        help="Lists pairs of arc media codec files in sequence: first line is "
        "the relative source file, second line is the full install pathname",
    )
    # Parser: get-audio-files
    subparsers.add_parser(
        "get-audio-files",
        help="Lists pairs of audio files in sequence: first line is "
        "the source file, second line is the full install pathname",
    )
    # Parser: get-bluetooth-files
    subparsers.add_parser(
        "get-bluetooth-files",
        help="Lists pairs of bluetooth files in sequence: first line is "
        "the source file, second line is the full install pathname",
    )
    # Parser: get-camera-files
    subparsers.add_parser(
        "get-camera-files",
        help="Lists pairs of camera files in sequence: first line is "
        "the source file, second line is the full install pathname",
    )
    # Parser: get-firmware-build-targets
    build_target_parser = subparsers.add_parser(
        "get-firmware-build-targets",
        help="Lists firmware build-targets for the given type, for all models.",
        epilog="Each build-target will be printed on its own line.",
    )
    build_target_parser.add_argument(
        "type",
        help="The build-targets type to get (ex. coreboot, ec, depthcharge)",
    )
    # Parser: get-fpmcu-firmware-ro-version
    fpmcu_firmware_ro_parser = subparsers.add_parser(
        "get-fpmcu-firmware-ro-version",
        help="Get the fingerprint firmware RO version for this device.",
    )
    fpmcu_firmware_ro_parser.add_argument("fpmcu", help='FPMCU "board"')
    # Parser: get-thermal-files
    subparsers.add_parser(
        "get-thermal-files",
        help="Lists pairs of thermal files in sequence: first line is "
        "the relative source file, second line is the full install pathname",
    )
    # Parser: get-intel-wifi-sar-files
    subparsers.add_parser(
        "get-intel-wifi-sar-files",
        help="Lists pairs of intel wifi sar files in sequence: first line is "
        "the relative source file, second line is the full install pathname",
    )
    # Parser: get-proximity-sensor-files
    subparsers.add_parser(
        "get-proximity-sensor-files",
        help="Lists pairs of proximity sensor configuration files in sequence: "
        "first line is the relative source file, "
        "second line is the full install pathname",
    )
    # Parser: file-tree
    file_tree_parser = subparsers.add_parser(
        "file-tree",
        help="Shows all files installed by the BSP in a tree structure",
    )
    file_tree_parser.add_argument(
        "root", help="Part to the root directory for this board"
    )
    # Parser: write-target-dirs
    subparsers.add_parser(
        "write-target-dirs",
        help="Writes out a list of target directories for each PropFile "
        "element",
    )
    # Parser: get-firmware-build-combinations
    build_combination_parser = subparsers.add_parser(
        "get-firmware-build-combinations",
        help="Lists firmware build combinations for the given types, for all "
        "models.",
    )
    build_combination_parser.add_argument(
        "components",
        help="Comma-separated list of firmware components to get combinations "
        "for.",
    )
    # Parser: get-wallpaper-files
    subparsers.add_parser(
        "get-wallpaper-files",
        help="Gets a list of wallpaper files which are used in the config",
    )
    # Parser: get-autobrightness-files
    subparsers.add_parser(
        "get-autobrightness-files",
        help="Lists pairs of autobrightness files in sequence: first line "
        "is the relative source pathname, second line is the full install "
        "pathname",
    )
    # Parser: get-firmware-recovery-input
    firmware_recovery_input_parser = subparsers.add_parser(
        "get-firmware-recovery-input",
        help="Gets the recovery input method for the given build target",
    )
    firmware_recovery_input_parser.add_argument(
        "build_target_name", help="Build target name"
    )
    firmware_recovery_input_parser.add_argument(
        "build_target_value", help="Build target value"
    )
    # Parser: get-key-value-pairs
    key_value_pairs_input_parser = subparsers.add_parser(
        "get-key-value-pairs",
        help="Lists combinations of (key,value) pairs when given an input of "
        "(key property path, value property path).",
    )
    key_value_pairs_input_parser.add_argument(
        "key_property_path", help="Config path of key"
    )
    key_value_pairs_input_parser.add_argument(
        "key_property_name", help="Config name of key"
    )
    key_value_pairs_input_parser.add_argument(
        "value_property_path", help="Config path of value"
    )
    key_value_pairs_input_parser.add_argument(
        "value_property_name", help="Config name of value"
    )
    # Parser: get-key-value
    key_value_input_parser = subparsers.add_parser(
        "get-key-value",
        help="Lists a key-value pairs's value for the given key.",
    )
    key_value_input_parser.add_argument(
        "key_property_path", help="Config path of key"
    )
    key_value_input_parser.add_argument(
        "key_property_name", help="Config name of key"
    )
    key_value_input_parser.add_argument(
        "key_property_match", help="Key to match against"
    )
    key_value_input_parser.add_argument(
        "value_property_path", help="Config path of value"
    )
    key_value_input_parser.add_argument(
        "value_property_name", help="Config name of value"
    )
    key_value_input_parser.add_argument(
        "--ignore-unset",
        action="store_true",
        help="Ignore key-value pairs " "where the value is not set",
    )
    return parser


def main(argv=None):
    """Chrome OS Configuration for Host

    This Python script is used on the host (primary purpose is being called from
    the shell during building). It is broken into a sub-command tree that allows
    for traversal of models and access to their properties within.
    """
    parser = GetParser(__doc__)
    # Parse argv
    if argv is None:
        argv = sys.argv[1:]
    opts = parser.parse_args(argv)

    if not opts.model and "CROS_CONFIG_MODEL" in os.environ:
        opts.model = os.environ["CROS_CONFIG_MODEL"]

    config = CrosConfig(opts.config, model_filter_regex=opts.model)
    # Get all models we are invoking on (if any).
    if opts.model and not config.GetDeviceConfigs():
        print("Unknown model '%s'" % opts.model, file=sys.stderr)
        return
    # Main command branch
    if opts.subcommand == "list-models":
        ListModels(config)
    elif opts.subcommand == "dump-config":
        DumpConfig(config)
    elif opts.subcommand == "get":
        if not opts.model:
            print(
                "You must specify --model for this command. See --help for "
                "more info.",
                file=sys.stderr,
            )
            return
        # There are multiple configs per model.
        # TODO(b/235382291): It's not correct to just pick the first one, since
        # different SKUs have different configs.
        model = config.GetDeviceConfigs()[0]
        GetProperty(model, opts.path, opts.prop)
    elif opts.subcommand == "get-touch-firmware-files":
        GetTouchFirmwareFiles(config)
    elif opts.subcommand == "get-detachable-base-firmware-files":
        GetDetachableBaseFirmwareFiles(config)
    elif opts.subcommand == "get-firmware-uris":
        GetFirmwareUris(config)
    elif opts.subcommand == "get-arc-files":
        GetArcFiles(config)
    elif opts.subcommand == "get-arc-codec-files":
        GetArcCodecFiles(config)
    elif opts.subcommand == "get-audio-files":
        GetAudioFiles(config)
    elif opts.subcommand == "get-bluetooth-files":
        GetBluetoothFiles(config)
    elif opts.subcommand == "get-camera-files":
        GetCameraFiles(config)
    elif opts.subcommand == "get-firmware-build-targets":
        GetFirmwareBuildTargets(config, opts.type)
    elif opts.subcommand == "get-fpmcu-firmware-ro-version":
        return GetFingerprintFirmwareROVersion(config, opts.fpmcu)
    elif opts.subcommand == "get-thermal-files":
        GetThermalFiles(config)
    elif opts.subcommand == "get-intel-wifi-sar-files":
        GetIntelWifiSarFiles(config)
    elif opts.subcommand == "get-proximity-sensor-files":
        GetProximitySensorFiles(config)
    elif opts.subcommand == "file-tree":
        FileTree(config, opts.root)
    elif opts.subcommand == "get-firmware-build-combinations":
        GetFirmwareBuildCombinations(config, opts.components.split(","))
    elif opts.subcommand == "get-wallpaper-files":
        GetWallpaperFiles(config)
    elif opts.subcommand == "get-autobrightness-files":
        GetAutobrightnessFiles(config)
    elif opts.subcommand == "get-firmware-recovery-input":
        GetFirmwareRecoveryInput(
            config, opts.build_target_name, opts.build_target_value
        )
    elif opts.subcommand == "get-key-value-pairs":
        GetKeyValuePairs(
            config,
            opts.key_property_path,
            opts.key_property_name,
            opts.value_property_path,
            opts.value_property_name,
        )
    elif opts.subcommand == "get-key-value":
        GetKeyValue(
            config,
            key_path=opts.key_property_path,
            key_name=opts.key_property_name,
            key_match=opts.key_property_match,
            value_path=opts.value_property_path,
            value_name=opts.value_property_name,
            ignore_unset=opts.ignore_unset,
        )


if __name__ == "__main__":
    sys.exit(main())
