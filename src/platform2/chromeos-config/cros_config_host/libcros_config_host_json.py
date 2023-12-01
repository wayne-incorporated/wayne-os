# -*- coding: utf-8 -*-
# Copyright 2017 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Chrome OS Configuration access library.

Provides build-time access to the model configuration on the host. It is used
for reading from the model configuration. Consider using cros_config_host.py
for CLI access to this library.
"""

from __future__ import print_function

from collections import OrderedDict
import copy
import json
import os
import sys


# pylint: disable=wrong-import-position
this_dir = os.path.dirname(__file__)
sys.path.insert(0, this_dir)
# pylint: disable=import-error
from cros_config_schema import GetValidSchemaProperties
from cros_config_schema import TransformConfig
from libcros_config_host_base import BaseFile
from libcros_config_host_base import CrosConfigBaseImpl
from libcros_config_host_base import DeviceConfig
from libcros_config_host_base import DeviceSignerInfo
from libcros_config_host_base import FirmwareImage
from libcros_config_host_base import FirmwareInfo
from libcros_config_host_base import SymlinkedFile


# pylint: enable=import-error


sys.path.pop(0)


class DeviceConfigJson(DeviceConfig):
    """JSON specific impl of DeviceConfig

    Attributes:
        _config: Root dictionary element for a given config.
    """

    def __init__(self, config):
        self._schema_properties = GetValidSchemaProperties()
        self._config = config
        self.firmware_info = OrderedDict()

    def GetName(self):
        return str(self._config["name"])

    def GetProperties(self, path):
        result = self._config
        if path != "/":
            for path_token in path[1:].split("/"):  # Burn the first '/' char
                if path_token in result:
                    result = result[path_token]
                else:
                    return {}
        return result

    def GetProperty(self, path, name):
        schema_props = self._schema_properties.get(path, None)
        if not schema_props or not name in schema_props:
            raise Exception(
                "Property not present in schema: %s:%s" % (path, name)
            )
        props = self.GetProperties(path)
        if props and name in props:
            return str(props[name])
        return ""

    def GetPropertiesStr(self, path):
        """Get the string representation of the properties."""
        return json.dumps(self.GetProperties(path), sort_keys=True)

    def GetValue(self, source, name):
        return source.get(name, None)

    def _GetFiles(self, path):
        result = []
        file_region = self.GetProperties(path)
        if file_region and "files" in file_region:
            for item in file_region["files"]:
                if "build-path" in item:
                    result.append(
                        BaseFile(item["build-path"], item["system-path"])
                    )
                else:
                    result.append(BaseFile(item["source"], item["destination"]))
        return result

    def _GetSymlinkedFiles(self, path):
        result = []
        items = self.GetProperties(path)
        if items and "files" in items:
            for item in items["files"]:
                result.append(
                    SymlinkedFile(
                        item["source"], item["destination"], item["symlink"]
                    )
                )

        return result

    def _GetSystemFileV2(self, path):
        return self._GetSystemFilesV2([path])

    def _GetSystemFilesV2(self, paths):
        result = []
        for path in paths:
            config = self.GetProperties(path)
            if config:
                result.append(
                    BaseFile(config["build-path"], config["system-path"])
                )
        return result

    def GetFirmwareConfig(self):
        firmware = self.GetProperties("/firmware")
        if not firmware or self.GetValue(firmware, "no-firmware"):
            return {}
        return firmware

    def GetFirmwareInfo(self):
        return self.firmware_info

    def GetTouchFirmwareFiles(self):
        return self._GetSymlinkedFiles("/touch")

    def GetDetachableBaseFirmwareFiles(self):
        return self._GetSymlinkedFiles("/detachable-base")

    def GetArcFiles(self):
        return self._GetSystemFilesV2(
            ["/arc/hardware-features", "/arc/media-profiles"]
        )

    def GetArcCodecFiles(self):
        return self._GetSystemFilesV2(
            ["/arc/media-codecs", "/arc/media-codecs-performance"]
        )

    def GetAudioFiles(self):
        return self._GetFiles("/audio/main")

    def GetBluetoothFiles(self):
        return self._GetSystemFileV2("/bluetooth/config")

    def GetCameraFiles(self):
        return self._GetSystemFileV2("/camera/config-file")

    def GetThermalFiles(self):
        return self._GetFiles("/thermal")

    def GetIntelWifiSarFiles(self):
        return self._GetSystemFileV2("/wifi/sar-file")

    def GetWallpaperFiles(self):
        result = set()
        wallpaper = self.GetValue(self._config, "wallpaper")
        if wallpaper:
            result.add(wallpaper)
        return result

    def GetProximitySensorFiles(self):
        files = []
        configs = self.GetProperties("/proximity-sensor/semtech-config")
        for config in configs:
            item = config["file"]
            files.append(BaseFile(item["build-path"], item["system-path"]))
        return files

    def GetAutobrightnessFiles(self):
        return self._GetSystemFileV2("/power/autobrightness/config-file")


class CrosConfigJson(CrosConfigBaseImpl):
    """JSON specific impl of CrosConfig

    Attributes:
        _json: Root json for the entire config.
        _configs: List of DeviceConfigJson instances
    """

    def __init__(self, infile, model_filter_regex=None):
        """Constructor for JSON specific implementation of CrosConfig

        Args:
            infile: File-like object with JSON configuration
            model_filter_regex: Only returns configs that match the filter.
        """
        self._json = json.loads(
            TransformConfig(
                infile.read(), model_filter_regex=model_filter_regex
            )
        )
        self._configs = []
        for config in self._json["chromeos"]["configs"]:
            self._configs.append(DeviceConfigJson(config))

        # TODO(shapiroc): This is mess and needs considerable rework on the fw
        # side to cleanup, but for now, we're sticking with it in order to
        # finish migration to YAML.
        fw_by_model = {}
        processed = set()
        for config in self._configs:
            fw = config.GetFirmwareConfig()
            # For partial configs (public vs private), we need to support the
            # name for cases where identity isn't specified.
            brand_code = config.GetProperty("/", "brand-code")
            if fw:
                image_name = fw.get("image-name")
                name = config.GetName()
                identity = (
                    name,
                    image_name,
                    config.GetPropertiesStr("/identity"),
                )
                if identity in processed:
                    continue

                firmware_name = image_name or name

                fw_str = json.dumps(fw, sort_keys=True)
                if fw_str not in fw_by_model:
                    # Use the explicit name of the firmware, else use the
                    # calculated firmware name. This supports equivalence
                    # testing with DT since it allowed naming firmware images.
                    fw_by_model[fw_str] = fw.get("name", firmware_name)

                shared_model = fw_by_model[fw_str]

                build_config = config.GetProperties("/firmware/build-targets")
                if build_config:
                    bios_build_target = config.GetValue(
                        build_config, "coreboot"
                    )
                    ec_build_target = config.GetValue(build_config, "ec")
                    if not ec_build_target:
                        ec_build_target = config.GetValue(
                            build_config, "zephyr-ec"
                        )
                else:
                    bios_build_target, ec_build_target = None, None

                main_image_uri = config.GetValue(fw, "main-ro-image") or ""
                main_rw_image_uri = config.GetValue(fw, "main-rw-image") or ""
                ec_image_uri = config.GetValue(fw, "ec-ro-image") or ""
                ec_rw_image_uri = config.GetValue(fw, "ec-rw-image") or ""
                pd_image_uri = config.GetValue(fw, "pd-ro-image") or ""

                fw_signer_config = config.GetProperties("/firmware-signing")
                key_id = config.GetValue(fw_signer_config, "key-id")
                sig_in_customization_id = config.GetValue(
                    fw_signer_config, "sig-id-in-customization-id"
                )

                have_image = True

                if sig_in_customization_id:
                    sig_id = "sig-id-in-customization-id"
                    brand_code = ""
                else:
                    sig_id = config.GetValue(fw_signer_config, "signature-id")
                    processed.add(identity)

                info = FirmwareInfo(
                    firmware_name,
                    shared_model,
                    key_id,
                    have_image,
                    bios_build_target,
                    ec_build_target,
                    main_image_uri,
                    main_rw_image_uri,
                    ec_image_uri,
                    ec_rw_image_uri,
                    pd_image_uri,
                    sig_id,
                    brand_code,
                )
                config.firmware_info[firmware_name] = info

                if sig_in_customization_id:
                    for wl_config in self._configs:
                        wl_firmware_name = wl_config.GetFirmwareConfig().get(
                            "image-name", wl_config.GetName()
                        )
                        if wl_firmware_name == firmware_name:
                            wl_brand_code = wl_config.GetProperty(
                                "/", "brand-code"
                            )
                            wl_identity_str = wl_config.GetPropertiesStr(
                                "/identity"
                            )
                            wl_identity = name, image_name, wl_identity_str
                            processed.add(wl_identity)
                            fw_signer_config = wl_config.GetProperties(
                                "/firmware-signing"
                            )
                            wl_key_id = wl_config.GetValue(
                                fw_signer_config, "key-id"
                            )
                            wl_sig_id = wl_config.GetValue(
                                fw_signer_config, "signature-id"
                            )
                            wl_fw_info = copy.deepcopy(info)
                            # Firmware info associated with model name should
                            # be kept with have_image=True so following
                            # process will generate one firmware entry for
                            # this model.
                            if wl_sig_id == firmware_name:
                                wl_config.firmware_info[
                                    wl_sig_id
                                ] = wl_fw_info._replace(
                                    brand_code=wl_brand_code
                                )
                            else:
                                wl_config.firmware_info[
                                    wl_sig_id
                                ] = wl_fw_info._replace(
                                    model=wl_sig_id,
                                    key_id=wl_key_id,
                                    have_image=False,
                                    sig_id=wl_sig_id,
                                    brand_code=wl_brand_code,
                                )

    def GetDeviceConfigs(self):
        return self._configs

    def GetFirmwareConfigs(self):
        result = dict()
        for value in self.GetFirmwareInfo().values():
            fw_images = []
            ap_build_target = value.bios_build_target
            ec_build_target = value.ec_build_target
            if value.main_image_uri:
                fw_images.append(
                    FirmwareImage(
                        type="ap",
                        build_target=ap_build_target,
                        image_uri=value.main_image_uri,
                    )
                )
            if value.main_rw_image_uri:
                fw_images.append(
                    FirmwareImage(
                        type="ap_rw",
                        build_target=ap_build_target,
                        image_uri=value.main_rw_image_uri,
                    )
                )
            if value.ec_image_uri:
                fw_images.append(
                    FirmwareImage(
                        type="ec",
                        build_target=ec_build_target,
                        image_uri=value.ec_image_uri,
                    )
                )
            if value.ec_rw_image_uri:
                fw_images.append(
                    FirmwareImage(
                        type="ec_rw",
                        build_target=ec_build_target,
                        image_uri=value.ec_rw_image_uri,
                    )
                )
            if value.pd_image_uri:
                fw_images.append(
                    FirmwareImage(
                        type="pd",
                        build_target=ec_build_target,
                        image_uri=value.pd_image_uri,
                    )
                )

            result[value.shared_model] = fw_images

        return result

    def GetFirmwareConfigsByDevice(self):
        return {
            value.model: value.shared_model or value.model
            for value in self.GetFirmwareInfo().values()
        }

    def GetDeviceSignerInfo(self):
        return {
            value.model: DeviceSignerInfo(
                key_id=value.key_id, sig_id=value.sig_id
            )
            for value in self.GetFirmwareInfo().values()
            if value.key_id
        }
