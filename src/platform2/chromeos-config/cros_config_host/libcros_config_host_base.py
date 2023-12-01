# -*- coding: utf-8 -*-
# Copyright 2018 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Base impl of the Chrome OS Configuration access library."""

from __future__ import print_function

from collections import namedtuple
from collections import OrderedDict
import os
import sys


# pylint: disable=wrong-import-position
this_dir = os.path.dirname(__file__)
sys.path.insert(0, this_dir)
# pylint: disable=import-error
from cros_config_schema import GetValidSchemaProperties
from cros_config_schema import ValidationError


# pylint: enable=import-error


sys.path.pop(0)

# Represents a single symbolic link firmware file which needs to be installed:
#   source: source filename of firmware file. This is installed in a
#       directory in the root filesystem
#   dest: destination filename of firmware file in the root filesystem. This is
#       in /opt/google/touch/firmware
#   symlink: name of symbolic link to put in LIB_FIRMWARE to point to the target
#       firmware. This is where Linux finds the firmware at runtime.
SymlinkedFile = namedtuple("SymlinkedFile", ["source", "dest", "symlink"])

# Represents a single file which needs to be installed:
#   source: Source filename within ${FILESDIR}
#   dest: Destination filename in the root filesystem
BaseFile = namedtuple("BaseFile", ["source", "dest"])

# Represents information needed to create firmware for a model:
#   model: Name of model (e.g 'reef'). Also used as the signature ID for signing
#   shared_model: Name of model containing the shared firmware used by this
#       model, or None if this model has its own firmware images
#   key_id: Key ID used to sign firmware for this model (e.g. 'REEF')
#   have_image: True if we need to generate a setvars.sh file for this model.
#       If this is False it indicates that the model will never be detected at
#       run-time since it is a zero-touch whitelabel model. The signature ID
#       will be obtained from the customization_id in VPD when needed. Signing
#       instructions should still be generated for this model.
#   bios_build_target: Build target to use to build the BIOS, or None if none
#   ec_build_target: Build target to use to build the EC (either CrOS EC or
#       zephyr EC), or None if none
#   main_image_uri: URI to use to obtain main firmware image (e.g.
#       'bcs://Caroline.2017.21.1.tbz2')
#   main_rw_image_uri: URI to use to obtain main firmware RW image (e.g.
#       'bcs://Caroline.2017.21.1.tbz2')
#   ec_image_uri: URI to use to obtain the EC (Embedded Controller) firmware
#       image
#   ec_rw_image_uri: URI to use to obtain the EC RW firmware image
#   pd_image_uri: URI to use to obtain the PD (Power Delivery controller)
#       firmware image
#   sig_id: Signature ID to put in the setvars.sh file. This is normally the
#       same as the model, since that is what we use for signature ID. But for
#       zero-touch whitelabel this is 'sig-id-in-customization-id' since we do
#       not know the signature ID until we look up in VPD.
#   brand-code: Uniquely identifies a given brand (see go/chromeos-rlz)
FirmwareInfo = namedtuple(
    "FirmwareInfo",
    [
        "model",
        "shared_model",
        "key_id",
        "have_image",
        "bios_build_target",
        "ec_build_target",
        "main_image_uri",
        "main_rw_image_uri",
        "ec_image_uri",
        "ec_rw_image_uri",
        "pd_image_uri",
        "sig_id",
        "brand_code",
    ],
)

# Represents the firmware image for a model:
#   type\: one of 'ap', 'ap_rw', 'ec', 'ec_rw', 'pd'.
#   build_target: The build target for given firmware image.
#   image_uri: The BCS image URI.
FirmwareImage = namedtuple(
    "FirmwareImage", ["type", "build_target", "image_uri"]
)

# Represents the signer data for a device.
#   key_id: The key ID of the device.
#   sig_id: Teh signature ID of the device.
DeviceSignerInfo = namedtuple("DeviceSignerInfo", ["key_id", "sig_id"])


class PathComponent(object):
    """A component in a directory/file tree

    Attributes:
        name: Name this component
        children: Dict of children:
            key: Name of child
            value: PathComponent object for child
    """

    def __init__(self, name):
        self.name = name
        self.children = dict()

    def AddPath(self, path):
        parts = path.split("/", 1)
        part = parts[0]
        rest = parts[1] if len(parts) > 1 else ""
        child = self.children.get(part)
        if not child:
            child = PathComponent(part)
            self.children[part] = child
        if rest:
            child.AddPath(rest)

    def ShowTree(self, base_path, path="", indent=0):
        """Show a tree of file paths

        This shows a component and all its children. Nodes can either be
        directories or files. Each file is shown with its size, or 'missing'
        if not found.

        Args:
            base_path: Base path where the actual files can be found
            path: Path of this component relative to the root (e.g. 'etc/cras/)
            indent: Indent level we are up to (0 = first)
        """
        path = os.path.join(path, self.name)
        fname = os.path.join(base_path, path)
        if os.path.isdir(fname):
            status = ""
        elif os.path.exists(fname):
            status = os.stat(fname).st_size
        else:
            status = "missing"
        print(
            "%-10s%s%s%s"
            % (
                status,
                "   " * indent,
                str(self.name),
                self.children and "/" or "",
            )
        )
        for child in sorted(self.children.keys()):
            self.children[child].ShowTree(base_path, path, indent + 1)


class DeviceConfig(object):
    """Configuration for a unique Device/SKU/Product combination.

    Provides an abstraction layer between DTS/JSON for accessing config for a
    unique Device/SKU/Product instance.
    """

    def GetName(self):
        """Returns the name of the config.

        Returns:
            Name of the config
        """

    def GetProperties(self, path):
        """Returns a map of properties at the given config path.

        Args:
            path: Path to the config desired.

        Returns:
            A map of properties at the given config path.
        """

    def GetProperty(self, path, name):
        """Returns the name value at a given path.

        Args:
            path: Path to the config desired.
            name: Property desired.

        Returns:
            Requested value or empty string if not present.
        """

    def GetFirmwareConfig(self):
        """Returns a map hierarchy of the firmware config."""
        return {}

    def GetFirmwareUris(self):
        """Returns a list of (string) firmware URIs.

        Generates and returns a list of firmeware URIs for this device. These
        URIs can be used to pull down remote firmware packages.

        Returns:
            A list of (string) full firmware URIs, or an empty list on failure.
        """
        firmware = self.GetFirmwareConfig()
        if not firmware:
            return []

        if "bcs-overlay" not in firmware:
            return []
        # Strip "overlay-" from bcs_overlay
        bcs_overlay = firmware["bcs-overlay"][8:]
        ebuild_name = bcs_overlay.split("-")[0]
        valid_images = [
            p
            for n, p in firmware.items()
            if n.endswith("-image") and p.startswith("bcs://")
        ]
        # Strip "bcs://" from bcs_from images (to get the file names only)
        file_names = [p[6:] for p in valid_images]
        uri_format = (
            "gs://chromeos-binaries/HOME/bcs-{bcs}/overlay-{bcs}/"
            "chromeos-base/chromeos-firmware-{ebuild_name}/{fname}"
        )
        uris = [
            uri_format.format(
                bcs=bcs_overlay,
                model=self.GetName(),
                fname=fname,
                ebuild_name=ebuild_name,
            )
            for fname in file_names
        ]
        return sorted(uris)

    def GetTouchFirmwareFiles(self):
        """Get a list of unique touch firmware files

        Returns:
            List of SymlinkedFile objects representing the touch firmware
            referenced by this model
        """

    def GetDetachableBaseFirmwareFiles(self):
        """Get a list of unique detachable base firmware files

        Returns:
            List of SymlinkedFile objects representing the detachable base
            firmware referenced by this model
        """

    def GetArcFiles(self):
        """Get a list of arc++ files for this device

        Returns:
            List of BaseFile objects representing the arc++ files needed.
        """

    def GetArcCodecFiles(self):
        """Get a list of arc media codec files for this device

        Returns:
            List of BaseFile objects representing the arc codec files needed.
        """

    def GetAudioFiles(self):
        """Get a list of audio files

        Returns:
            List of BaseFile objects representing the audio files referenced
            by this device.
        """

    def GetBluetoothFiles(self):
        """Get a list of bluetooth config files

        Returns:
            List of BaseFile objects representing the bluetooth files
            referenced by this device.
        """

    def GetCameraFiles(self):
        """Get a list of camera config files

        Returns:
            List of BaseFile objects representing the camera files referenced
            by this device.
        """

    def GetThermalFiles(self):
        """Get a list of thermal files

        Returns:
            List of BaseFile objects representing the thermal files referenced
            by this device.
        """

    def GetProximitySensorFiles(self):
        """Get a list of proximity sensor configuration files

        Returns:
            List of BaseFile objects representing the configuration files for
            this device proximity sensors, especially the semtech ones.
        """

    def GetIntelWifiSarFiles(self):
        """Get a list of intel wifi sar files

        Returns:
            List of BaseFile objects representing the intel wifi sar filesi
            referenced for this device.
        """

    def GetFirmwareInfo(self):
        """Gets the FirmewareInfo instance for a given device.

        Returns:
            Returns the FirmwareInfo instance.
        """

    def GetFirmwareConfigs(self):
        """Gets unique firmware configs for all devices.

        Returns:
            Dictionary of FirmwareImage objects grouped by config name.
        """

    def GetFirmwareConfigsByDevice(self):
        """Gets firmware config name for all devices.

        Returns:
            Dictionary of firmware config names grouped by device.
        """

    def GetDeviceSignerInfo(self):
        """Gets firmware signer info for all devices.

        Returns:
            Dictionary of DeviceSignerInfo grouped by device.
        """

    def GetWallpaperFiles(self):
        """Get a set of wallpaper files used for this model"""

    def GetAutobrightnessFiles(self):
        """Get a list of autobrightness files

        Returns:
            List of BaseFile objects representing the autobrightness files
            referenced by this device.
        """


class CrosConfigBaseImpl(object):
    """The ChromeOS Configuration API for the host."""

    def GetConfig(self, name):
        """Gets a (DeviceConfig) instance by name.

        Returns:
            (DeviceConfig) instance if found, else None
        """
        for device in self.GetDeviceConfigs():
            if device.GetName() == name:
                return device
        return None

    def GetDeviceConfigs(self):
        """Returns a list of (DeviceConfig) instances.

        Returns:
            A list of (DeviceConfig) instances.
        """

    def GetFullConfig(self):
        """Returns a full dict of every config returned from every API.

        Returns:
            Dictionary that maps method call onto return config.
        """
        result = {}
        result["ListModels"] = self.GetModelList()
        result["GetFirmwareUris"] = self.GetFirmwareUris()
        result["GetTouchFirmwareFiles"] = self.GetTouchFirmwareFiles()
        result[
            "GetDetachableBaseFirmwareFiles"
        ] = self.GetDetachableBaseFirmwareFiles()
        result["GetArcFiles"] = self.GetArcFiles()
        result["GetArcCodecFiles"] = self.GetArcCodecFiles()
        result["GetAudioFiles"] = self.GetAudioFiles()
        bluetooth_files = self.GetBluetoothFiles()
        if bluetooth_files:
            result["GetBluetoothFiles"] = bluetooth_files
        result["GetCameraFiles"] = self.GetCameraFiles()
        result["GetThermalFiles"] = self.GetThermalFiles()
        result["GetIntelWifiSarFiles"] = self.GetIntelWifiSarFiles()
        result["GetProximitySensorFiles"] = self.GetProximitySensorFiles()
        result["GetFirmwareInfo"] = self.GetFirmwareInfo()
        for target in ["coreboot", "ec"]:
            result[
                "GetFirmwareBuildTargets_%s" % target
            ] = self.GetFirmwareBuildTargets(target)
        result[
            "GetFirmwareBuildCombinations"
        ] = self.GetFirmwareBuildCombinations(["coreboot", "ec"])
        for target_name in ["depthcharge", "bmpblk"]:
            for target_value in self.GetFirmwareBuildTargets(target_name):
                result[
                    "GetFirmwareRecoveryInput_%s_%s"
                    % (target_name, target_value)
                ] = self.GetFirmwareRecoveryInput(target_name, target_value)
        result["GetWallpaperFiles"] = self.GetWallpaperFiles()
        result["GetAutobrightnessFiles"] = self.GetAutobrightnessFiles()

        schema_properties = GetValidSchemaProperties()
        for device in self.GetDeviceConfigs():
            value_map = {}
            for path in schema_properties:
                for schema_property in schema_properties[path]:
                    prop_value = device.GetProperty(path, schema_property)
                    # Only dump populated values; this makes it so the config
                    # dumps # don't need to be updated when new schema
                    # attributes are added.
                    if prop_value:
                        value_map[
                            "%s::%s" % (path, schema_property)
                        ] = prop_value
            result["GetProperty_%s" % device.GetName()] = value_map
        return result

    def GetFirmwareUris(self):
        """Returns a list of (string) firmware URIs.

        Generates and returns a list of firmeware URIs for all device. These
        URIs can be used to pull down remote firmware packages.

        Returns:
            A list of (string) full firmware URIs, or an empty list on failure.
        """
        uris = set()
        for device in self.GetDeviceConfigs():
            uris.update(set(device.GetFirmwareUris()))
        return sorted(list(uris))

    def _GetFiles(self, func_name):
        """Get a list of unique files for all devices.

        Args:
            func_name: name of method to invoke on a DeviceConfig to retrieve
              files.

        Returns:
            list of files sorted by source.
        """
        file_set = set()
        for device in self.GetDeviceConfigs():
            for files in getattr(device, func_name)():
                file_set.add(files)

        return sorted(file_set, key=lambda files: files.source)

    def GetTouchFirmwareFiles(self):
        """Get a list of unique touch firmware files for all devices

        These files may come from ${FILESDIR} or from a tar file in BCS.

        Returns:
            List of SymlinkedFile objects representing all the touch firmware
            referenced by all devices
        """
        return self._GetFiles("GetTouchFirmwareFiles")

    def GetDetachableBaseFirmwareFiles(self):
        """Get a list of unique detachable base firmware files for all devices

        These files may come from ${FILESDIR} or from a tar file in BCS.

        Returns:
            List of SymlinkedFile objects representing all the detachable base
            firmware referenced by all devices
        """
        return self._GetFiles("GetDetachableBaseFirmwareFiles")

    def GetBcsUri(self, overlay, path):
        """Form a valid BCS URI for downloading files.

        Args:
            overlay: Name of overlay (e.g. 'reef-private')
            path: Path to file in overlay (e.g. 'chromeos-base/'
            'chromeos-touch-firmware-reef/'
            'chromeos-touch-firmware-reef-1.0-r9.tbz2')

        Returns:
            Valid BCS URI to download from
        """
        if not overlay.startswith("overlay"):
            return None
        # Strip "overlay-" from bcs_overlay.
        bcs_overlay = overlay[8:]
        return (
            "gs://chromeos-binaries/HOME/bcs-%(bcs)s/overlay-%(bcs)s/%(path)s"
            % {
                "bcs": bcs_overlay,
                "path": path,
            }
        )

    def GetArcFiles(self):
        """Get a list of unique Arc++ files for all devices

        Returns:
            List of BaseFile objects representing all the arc++ files
            referenced by all devices
        """
        return self._GetFiles("GetArcFiles")

    def GetArcCodecFiles(self):
        """Get a list of unique Arc++ files for all devices

        Returns:
            List of BaseFile objects representing all the arc++ files
            referenced by all devices
        """
        return self._GetFiles("GetArcCodecFiles")

    def GetAudioFiles(self):
        """Get a list of unique audio files for all models

        Returns:
            List of BaseFile objects representing all the audio files
            referenced by all models
        """
        return self._GetFiles("GetAudioFiles")

    def GetBluetoothFiles(self):
        """Get a list of unique bluetooth files for all devices

        Returns:
            List of BaseFile objects representing all the bluetooth files
            referenced by all devices
        """
        return self._GetFiles("GetBluetoothFiles")

    def GetCameraFiles(self):
        """Get a list of unique camera files for all devices

        Returns:
            List of BaseFile objects representing all the camera files
            referenced by all devices
        """
        return self._GetFiles("GetCameraFiles")

    def _GetFirmwareGroupingName(self, config):
        """Gets the name of group of firmware build targets

        Historically this maps to the name of the coreboot build target.

        Args:
            config: config object that contains /firmware node

        Returns:
            A string of the firmware group name
        """
        # Use coreboot as key if it exist to support historical use case of
        # grouping firmware build targets by coreboot name
        key = config.GetProperty("/firmware/build-targets", "coreboot")
        if key:
            return key
        # Otherwise use the image-name. There are very few cases of having an
        # image-name without also having a coreboot image
        return config.GetProperty("/firmware", "image-name")

    def _GetFirmwareFilter(self):
        """Get the name of firmware build targets to filter on

        Extract the comma-separated list of firmware targets from the FW_NAME
        environment variable.

        Returns:
            A list of firmware build targets
        """
        fw_name = os.getenv("FW_NAME")
        if fw_name:
            return [s.strip() for s in fw_name.split(",")]
        return []

    def GetFirmwareBuildTargets(self, target_type):
        """Returns all firmware build-targets of the given target type.

        Args:
            target_type: A string type for the build-targets to return

        Returns:
            A list of all build-targets of the given type, for all models.
        """
        firmware_filter = self._GetFirmwareFilter()
        build_targets = []
        for device in self.GetDeviceConfigs():
            device_targets = device.GetProperties("/firmware/build-targets")
            # Skip nodes with no build targets
            if not device_targets:
                continue

            key = self._GetFirmwareGroupingName(device)

            if firmware_filter and key not in firmware_filter:
                continue
            if target_type in device_targets:
                build_targets.append(device_targets[target_type])
            if target_type == "ec":
                for ec_extra in ("base",):
                    if ec_extra in device_targets:
                        build_targets.append(device_targets[ec_extra])
                if "ec-extras" in device_targets:
                    for extra_target in device_targets["ec-extras"]:
                        build_targets.append(extra_target)
        return sorted(set(build_targets))

    def GetFirmwareBuildCombinations(self, components):
        """Get named firmware build combinations for all devices.

        Args:
            components: List of firmware components to get target combinations
            for.

        Returns:
            OrderedDict containing firmware combinations
                key: combination name
                value: list of firmware targets for specified types

        Raises:
            ValueError if a collision is encountered for named combinations.
        """
        firmware_filter = self._GetFirmwareFilter()

        combos = OrderedDict()
        for device in self.GetDeviceConfigs():
            device_targets = device.GetProperties("/firmware/build-targets")
            # Skip device_targetss with no build targets
            if not device_targets:
                continue
            targets = [device_targets.get(c) for c in components]

            key = self._GetFirmwareGroupingName(device)

            if firmware_filter and key not in firmware_filter:
                continue

            if key in combos and targets != combos[key]:
                raise ValueError(
                    "Colliding firmware combinations found for key %s: "
                    "%s, %s" % (key, targets, combos[key])
                )
            combos[key] = targets
        return OrderedDict(sorted(combos.items()))

    def GetThermalFiles(self):
        """Get a list of unique thermal files for all models

        Returns:
            List of BaseFile objects representing all the audio files
            referenced by all devices
        """
        return self._GetFiles("GetThermalFiles")

    def GetProximitySensorFiles(self):
        """Get a list of unique proximity sensor files for all models

        Returns:
            List of BaseFile objects representing all the proximity sensor files
            referenced by all devices
        """
        return self._GetFiles("GetProximitySensorFiles")

    def GetIntelWifiSarFiles(self):
        """Get a list of unique intel wifi sar files for all models

        Returns:
            List of BaseFile objects representing all the intel wifi sar files
            referenced by all devices
        """
        return self._GetFiles("GetIntelWifiSarFiles")

    def ShowTree(self, base_path, tree):
        print("%-10s%s" % ("Size", "Path"))
        tree.ShowTree(base_path)

    def GetFileTree(self):
        """Get a tree of all files installed by the config

        This looks at all available config that installs files in the root and
        returns them as a tree structure. This can be passed to ShowTree(),
        which is the only feature currently implemented which uses this tree.

        Returns:
            PathComponent object containing the root component
        """
        paths = set()
        for item in self.GetAudioFiles():
            paths.add(item.dest)
        for item in self.GetTouchFirmwareFiles():
            paths.add(item.dest)
            paths.add(item.symlink)
        root = PathComponent("")
        for path in paths:
            root.AddPath(path[1:])

        return root

    def GetModelList(self):
        """Return a list of models

        Returns:
            List of model names, each a string
        """
        return sorted(
            set([device.GetName() for device in self.GetDeviceConfigs()])
        )

    def GetFirmwareInfo(self):
        firmware_info = OrderedDict()
        for name in self.GetModelList():
            for device in self.GetDeviceConfigs():
                if device.GetName() == name:
                    firmware_info.update(device.GetFirmwareInfo())
        return firmware_info

    def GetWallpaperFiles(self):
        """Get a list of wallpaper files used for all models"""
        wallpapers = set()
        for device in self.GetDeviceConfigs():
            wallpapers |= device.GetWallpaperFiles()
        return sorted(wallpapers)

    def GetAutobrightnessFiles(self):
        """Get a list of unique autobrightness files for all models

        Returns:
            List of BaseFile objects representing all the autobrightness files
            referenced by all devices
        """
        return self._GetFiles("GetAutobrightnessFiles")

    def GetFirmwareRecoveryInput(self, build_target_name, build_target_value):
        """Gets the recovery input method for the given build target.

        If the device config does not specify the firmware recovery input,
        it will be inferred from the form factor.
        If no recovery input is found, an empty string is returned

        Args:
            build_target_name: Build target name (e.g. "depthcharge")
            build_target_value: Build target for the associated name

        Returns:
            Recovery input method string. Empty string if not determinable from
            config.

        Raises:
            ValidationError if single build_target_value target is paired with
            multiple recovery inputs
        """
        # Try to retrieve recovery-input first
        methods = OrderedDict()
        for device in self.GetDeviceConfigs():
            key = device.GetProperties(
                "/firmware/build-targets/%s" % build_target_name
            )
            # Skip targets that aren't specified in the JSON or don't match
            # target
            if not key or key != build_target_value:
                continue

            recovery_input = device.GetProperties(
                "/hardware-properties/recovery-input"
            )
            if recovery_input:
                if key in methods and recovery_input != methods[key]:
                    raise ValidationError(
                        "Colliding recovery input found for "
                        "build_target_value target %s: %s, %s"
                        % (key, recovery_input, methods[key])
                    )
                methods[key] = recovery_input

        if build_target_value in methods:
            return methods[build_target_value]

        # recovery-input not set, auto-generate based on form factor
        for device in self.GetDeviceConfigs():
            key = device.GetProperties(
                "/firmware/build-targets/%s" % build_target_name
            )
            # Skip targets that aren't specified in the JSON or don't match
            # target
            if not key or key != build_target_value:
                continue

            form_factor = device.GetProperties(
                "/hardware-properties/form-factor"
            )
            # Make sure that `mapping` is consistent with `recovery_input`
            # in src/config/util/hw_topology.star
            mapping = {
                "CLAMSHELL": "KEYBOARD",
                "CONVERTIBLE": "KEYBOARD",
                "DETACHABLE": "KEYBOARD",
                "CHROMEBASE": "RECOVERY_BUTTON",
                "CHROMEBOX": "RECOVERY_BUTTON",
                "CHROMEBIT": "RECOVERY_BUTTON",
                "CHROMESLATE": "KEYBOARD",
            }
            if form_factor and form_factor in mapping:
                generated_recovery = mapping[form_factor]
                if key in methods and generated_recovery != methods[key]:
                    raise ValidationError(
                        "Colliding recovery input found for "
                        "build_target_value target %s: %s, %s"
                        % (key, generated_recovery, methods[key])
                    )
                methods[key] = generated_recovery

        if build_target_value in methods:
            return methods[build_target_value]

        # No found or generated config
        return ""

    def GetKeyValuePairs(self, key_path, key_name, value_path, value_name):
        """A dictionary of key-value pairs for the given config paths.

        This will check for consistency across kv pairs, a 1:1 mapping of
        key to value must occur in the config.
        If no pairs are found, an empty dict is returned.

        Args:
            key_path: Path to property to use as the key (e.g. "/firmware")
            key_name: Name of property to use as the key (e.g. "image-name")
            value_path: Path to property to use as the value
            value_name: Path to property to use as the value

        Returns:
            dict of key-value pairs

        Raises:
            ValidationError if conflicting values are found for a key
        """
        pairs = OrderedDict()
        for device in self.GetDeviceConfigs():
            key = device.GetProperty(key_path, key_name)
            value = device.GetProperty(value_path, value_name)

            if not key:
                continue

            if key in pairs and pairs.get(key, value) != value:
                raise ValueError(
                    f"Colliding key-value pair found for key {key}: "
                    f"{value}, {pairs[key]}"
                )
            else:
                pairs[key] = value

        return pairs

    def GetKeyValue(
        self,
        key_path,
        key_name,
        key_match,
        value_path,
        value_name,
        ignore_unset=False,
    ):
        """A unique value of a given config path for a matching key

        This will check for consistency across kv pairs, a 1:1 mapping of
        key to value must occur in the config.
        If no pairs are found, None is returned.

        Args:
            key_path: Path to property to use as the key (e.g. "/firmware")
            key_name: Name of property to use as the key (e.g. "image-name")
            key_match: Only key-value pairs where the key matches this value
                will be considered.
            value_path: Path to property to use as the value
            value_name: Path to property to use as the value
            ignore_unset: Ignore key-value pairs if the value isn't set. The
                key-value pair may be used on devices which do not specify this
                property.

        Returns:
            value

        Raises:
            ValidationError if conflicting values are found for the key
        """
        values = OrderedDict()
        for device in self.GetDeviceConfigs():
            key = device.GetProperty(key_path, key_name)
            value = device.GetProperty(value_path, value_name)

            # Skip targets that aren't specified in the JSON or don't match
            if not key or key != key_match:
                continue
            if ignore_unset and not value:
                continue

            if key in values and values.get(key, value) != value:
                raise ValueError(
                    f"Colliding key-value pair found for key {key}: "
                    f"{value}, {values[key]}"
                )
            else:
                values[key_match] = value

        if key_match in values:
            return values[key_match]

        # Not found
        return None
