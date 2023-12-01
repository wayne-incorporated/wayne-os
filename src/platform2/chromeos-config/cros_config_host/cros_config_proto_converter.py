#!/usr/bin/env python3
# Copyright 2020 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Transforms config from /config/proto/api proto format to platform JSON."""

# pylint: disable=too-many-lines

import argparse
from collections import namedtuple
import collections.abc
import functools
import glob
import itertools
import json
import os
import pathlib
import pprint
import re
import sys

# pylint: disable=import-error
from chromiumos.config.api import component_pb2
from chromiumos.config.api import device_brand_pb2
from chromiumos.config.api import proximity_config_pb2
from chromiumos.config.api import topology_pb2
from chromiumos.config.api.software import brand_config_pb2
from chromiumos.config.api.software import ui_config_pb2
from chromiumos.config.payload import config_bundle_pb2
from chromiumos.config.test import fake_config as fake_config_mod
from google.protobuf import json_format
from google.protobuf import wrappers_pb2
from lxml import etree


# pylint: enable=import-error


Config = namedtuple(
    "Config",
    [
        "program",
        "hw_design",
        "odm",
        "hw_design_config",
        "device_brand",
        "device_signer_config",
        "oem",
        "sw_config",
        "brand_config",
    ],
)

ConfigFiles = namedtuple(
    "ConfigFiles",
    [
        "arc_hw_features",
        "arc_media_profiles",
        "touch_fw",
        "dptf_map",
        "camera_map",
        "wifi_sar_map",
        "proximity_map",
    ],
)

CAMERA_CONFIG_DEST_PATH_TEMPLATE = "/etc/camera/camera_config_{}.json"
CAMERA_CONFIG_SOURCE_PATH_TEMPLATE = (
    "sw_build_config/platform/chromeos-config/camera/camera_config_{}.json"
)

DTD_FILE = "media_profiles.dtd"
DPTF_PATH = "sw_build_config/platform/chromeos-config/thermal"
DPTF_FILE = "dptf.dv"

PROXIMITY_SEMTECH_CONFIG_TEMPLATE = "semtech_config_{}.json"

TOUCH_PATH = "sw_build_config/platform/chromeos-config/touch"
WALLPAPER_BASE_PATH = "/usr/share/chromeos-assets/wallpaper"

XML_DECLARATION = b'<?xml version="1.0" encoding="utf-8"?>\n'


def parse_args(argv):
    """Parse the available arguments.

    Invalid arguments or -h cause this function to print a message and exit.

    Args:
        argv: List of string arguments (excluding program name / argv[0])

    Returns:
        argparse.Namespace object containing the attributes.
    """
    parser = argparse.ArgumentParser(
        description="Converts source proto config into platform JSON config."
    )
    parser.add_argument(
        "-c",
        "--project_configs",
        "--project-configs",
        nargs="+",
        type=str,
        help="Space delimited list of source protobinary project config files.",
    )
    parser.add_argument(
        "-p",
        "--program_config",
        "--program-config",
        type=str,
        help="Path to the source program-level protobinary file",
    )
    parser.add_argument(
        "-o", "--output", type=str, help="Output file that will be generated"
    )
    parser.add_argument(
        "--dtd-path",
        default=pathlib.Path(__file__).parent / DTD_FILE,
        type=pathlib.Path,
        help="Path to media_profiles.dtd. Defaults to the script's cwd.",
    )
    parser.add_argument(
        "--regen",
        action="store_true",
        help="Shortcut to regenerate all generated files in test_data.",
    )
    return parser.parse_args(argv)


def _upsert(field, target, target_name, suffix=None):
    """Updates or inserts `field` within `target`.

    If `target_name` already exists within `target` an update is performed,
    otherwise, an insert is performed.
    """
    if field or field == 0:
        if suffix is not None:
            field += suffix
        if target_name in target:
            target[target_name].update(field)
        else:
            target[target_name] = field


def _build_arc(config, config_files):
    build_properties = {
        "device": "%s_cheets" % config.program.name.lower(),
        "marketing-name": config.device_brand.brand_name,
        "metrics-tag": _get_model_name(config.hw_design.id),
        "product": config.program.name.lower(),
    }
    if config.oem:
        build_properties["oem"] = config.oem.name
    result = {"build-properties": build_properties}
    config_id = _get_formatted_config_id(config.hw_design_config)
    if config_id in config_files.arc_hw_features:
        result["hardware-features"] = config_files.arc_hw_features[config_id]
    if config_id in config_files.arc_media_profiles:
        result["media-profiles"] = config_files.arc_media_profiles[config_id]
    topology = config.hw_design_config.hardware_topology
    ppi = topology.screen.hardware_feature.screen.panel_properties.pixels_per_in
    # Only set for high resolution displays
    if ppi and ppi > 250:
        result["scale"] = ppi

    platform = config.program.platform
    if platform.HasField("arc_settings"):
        hw_features = config.hw_design_config.hardware_features
        suffix = (
            hw_features.soc.arc_media_codecs_suffix
            or platform.arc_settings.media_codecs_suffix
        )
        if suffix:
            suffix = f"_{suffix}"
        result["media-codecs"] = _file_v2(
            f"media_codecs_c2{suffix}.xml",
            f"/etc/media_codecs_c2{suffix}.xml",
        )
        result["media-codecs-performance"] = _file_v2(
            f"media_codecs_performance_c2{suffix}.xml",
            f"/etc/media_codecs_performance_c2{suffix}.xml",
        )
    return result


def _check_percentage_value(value: float, description: str):
    if not 0 <= value <= 100:
        raise Exception(
            "Value %.1f out of range [0, 100] for %s" % (value, description)
        )


def _check_nits_value(value: float, maximum: float, description: str):
    if not 0 <= value <= maximum:
        raise Exception(
            f"Value {value:.1f} out of range [0, {maximum:.1f}] for "
            f"{description}"
        )


def _check_increasing_sequence(values: [float], description: str):
    for lhs, rhs in zip(values, values[1:]):
        if lhs >= rhs:
            raise Exception(
                "Value %s is not strictly larger than previous value %s for %s"
                % (rhs, lhs, description)
            )


def _check_lux_threshold(
    lux_thresholds: [component_pb2.Component.LuxThreshold],
    description: str,
):
    _check_increasing_sequence(
        [
            lux_thresholds.increase_threshold
            for lux_thresholds in lux_thresholds[:-1]
        ],
        f"{description}.lux_increase_threshold",
    )
    _check_increasing_sequence(
        [
            lux_thresholds.decrease_threshold
            for lux_thresholds in lux_thresholds[1:]
        ],
        f"{description}.lux_decrease_threshold",
    )

    if lux_thresholds[0].decrease_threshold != -1:
        raise Exception(
            f"{description}[0].lux_decrease_threshold should be unset, \
            not {lux_thresholds[0].decrease_threshold}"
        )
    if lux_thresholds[-1].increase_threshold != -1:
        raise Exception(
            f"{description}[0].lux_decrease_threshold should be unset, \
            not {lux_thresholds[-1].increase_threshold}"
        )


def _check_als_steps(
    steps: [component_pb2.Component.AlsStep],
    max_screen_brightness_nits: float,
    description: str,
):
    sequence_in_percent = None
    for idx, step in enumerate(steps):
        if step.ac_backlight_nits and step.battery_backlight_nits:
            if sequence_in_percent is True:
                raise Exception(
                    "Als steps not specified in consistent units "
                    "(expected percent, got nits) for %s[%d]"
                    % (description, idx)
                )
            sequence_in_percent = False
            if not max_screen_brightness_nits:
                raise Exception(
                    "max_screen_brightness must be set for panel when "
                    "specifying brightness in nits"
                )
            _check_nits_value(
                step.ac_backlight_nits,
                max_screen_brightness_nits,
                "%s[%d].ac_backlight_nits" % (description, idx),
            )
            _check_nits_value(
                step.battery_backlight_nits,
                max_screen_brightness_nits,
                "%s[%d].battery_backlight_nits" % (description, idx),
            )
        elif step.ac_backlight_percent and step.battery_backlight_percent:
            if sequence_in_percent is False:
                raise Exception(
                    "Als steps not specified in consistent units "
                    "(expected nits, got percent) for %s[%d]"
                    % (description, idx)
                )
            sequence_in_percent = True
            _check_percentage_value(
                step.ac_backlight_percent,
                "%s[%d].ac_backlight_percent" % (description, idx),
            )
            _check_percentage_value(
                step.battery_backlight_percent,
                "%s[%d].battery_backlight_percent" % (description, idx),
            )
        else:
            raise Exception(
                "Als step battery and AC brightness given in different "
                "units for %s[%d]" % (description, idx)
            )

    if sequence_in_percent:
        _check_increasing_sequence(
            [step.ac_backlight_percent for step in steps],
            "%s.ac_backlight_percent" % description,
        )
        _check_increasing_sequence(
            [step.battery_backlight_percent for step in steps],
            "%s.battery_backlight_percent" % description,
        )
    else:
        _check_increasing_sequence(
            [step.ac_backlight_nits for step in steps],
            "%s.ac_backlight_nits" % description,
        )
        _check_increasing_sequence(
            [step.battery_backlight_nits for step in steps],
            "%s.battery_backlight_nits" % description,
        )

    _check_lux_threshold([step.lux_threshold for step in steps], description)


def _format_als_step(als_step: component_pb2.Component.AlsStep) -> str:
    ac_percent = ""
    battery_percent = ""

    if als_step.ac_backlight_nits:
        ac_percent = _format_power_pref_value(
            _brightness_nits_to_percent(
                als_step.ac_backlight_nits, als_step.max_screen_brightness
            )
        )
    else:
        ac_percent = _format_power_pref_value(als_step.ac_backlight_percent)

    if (
        als_step.battery_backlight_nits
        and als_step.battery_backlight_nits != als_step.ac_backlight_nits
    ):
        battery_percent = " %s" % _format_power_pref_value(
            _brightness_nits_to_percent(
                als_step.battery_backlight_nits, als_step.max_screen_brightness
            )
        )
    elif als_step.battery_backlight_percent != als_step.ac_backlight_percent:
        battery_percent = " %s" % _format_power_pref_value(
            als_step.battery_backlight_percent
        )

    return "%s%s %s %s" % (
        ac_percent,
        battery_percent,
        _format_power_pref_value(als_step.lux_threshold.decrease_threshold),
        _format_power_pref_value(als_step.lux_threshold.increase_threshold),
    )


def _format_kb_als_step(
    als_step: topology_pb2.HardwareFeatures.KbAlsStep,
) -> str:
    return " ".join(
        [
            _format_power_pref_value(als_step.backlight_percent),
            _format_power_pref_value(als_step.lux_threshold.decrease_threshold),
            _format_power_pref_value(als_step.lux_threshold.increase_threshold),
        ]
    )


def _build_charging_ports(ports: [topology_pb2.HardwareFeatures.UsbC]) -> str:
    overridden_indices = {}
    port_positions = set()
    for port in ports:
        if port.position == topology_pb2.HardwareFeatures.PortPosition.UNKNOWN:
            raise Exception(
                "Invalid port position %s"
                % topology_pb2.HardwareFeatures.PortPosition.Name(port.position)
            )

        if port.position in port_positions:
            raise Exception(
                "Duplicate port position %s"
                % topology_pb2.HardwareFeatures.PortPosition.Name(port.position)
            )
        port_positions.add(port.position)

        if port.HasField("index_override"):
            if port.index_override.value in overridden_indices:
                raise Exception(
                    "Duplicate port index_override %d"
                    % port.index_override.value
                )
            if port.index_override.value >= len(ports):
                raise Exception(
                    "Port index_override %d outside range [0, %d)"
                    % (port.index_override.value, len(ports))
                )
            overridden_indices[port.index_override.value] = port

    ordered_ports = []

    def handle_overridden_port():
        override = overridden_indices.get(len(ordered_ports), None)
        while override:
            ordered_ports.append(override)
            override = overridden_indices.get(len(ordered_ports), None)

    for port in ports:
        handle_overridden_port()

        if port.HasField("index_override"):
            continue

        ordered_ports.append(port)

    handle_overridden_port()

    return "\n".join(
        "CROS_USBPD_CHARGER%d %s"
        % (idx, topology_pb2.HardwareFeatures.PortPosition.Name(port.position))
        for idx, port in enumerate(ordered_ports)
    )


def _format_power_pref_value(value) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, collections.abc.Sequence):
        return "\n".join(_format_power_pref_value(x) for x in value)
    if isinstance(value, collections.abc.Mapping):
        return "\n".join(
            f"{_format_power_pref_value(k)} {_format_power_pref_value(v)}"
            for k, v in sorted(value.items())
        )
    if isinstance(value, bool):
        return str(int(value))
    if isinstance(
        value,
        (
            wrappers_pb2.DoubleValue,
            wrappers_pb2.FloatValue,
            wrappers_pb2.UInt32Value,
            wrappers_pb2.UInt64Value,
            wrappers_pb2.Int32Value,
            wrappers_pb2.Int64Value,
            wrappers_pb2.BoolValue,
            wrappers_pb2.StringValue,
            wrappers_pb2.BytesValue,
        ),
    ):
        return _format_power_pref_value(value.value)
    if isinstance(value, component_pb2.Component.AlsStep):
        return _format_als_step(value)
    if isinstance(value, topology_pb2.HardwareFeatures.KbAlsStep):
        return _format_kb_als_step(value)
    return str(value)


def _build_derived_platform_power_prefs(capabilities) -> dict:
    result = {}

    # Falsy values are filtered out, deferring to the equivalent powerd default
    # pref values. Dark resume is inverted; wrap it so False values are
    # forwarded.
    if capabilities.dark_resume:
        result["disable-dark-resume"] = wrappers_pb2.BoolValue(
            value=not capabilities.dark_resume
        )
    result["suspend-to-idle"] = capabilities.suspend_to_idle
    result["wake-on-dp"] = capabilities.wake_on_dp

    return result


def _build_derived_connectivity_power_prefs(config: Config) -> dict:
    present = topology_pb2.HardwareFeatures.PRESENT
    hw_features = config.hw_design_config.hardware_features
    form_factor = hw_features.form_factor.form_factor
    radio_type = proximity_config_pb2.ProximityConfig.Location.RadioType
    result = {}

    for radio in [radio_type.WIFI, radio_type.CELLULAR]:
        if radio == radio_type.WIFI:
            radio_string = "set-wifi-transmit-power-for"
        else:
            radio_string = "set-cellular-transmit-power-for"

        proximity = "-".join([radio_string, "proximity"])
        activity_proximity = "-".join([radio_string, "activity-proximity"])

        result[proximity] = False
        result[activity_proximity] = False
        if hw_features.HasField("proximity"):
            for sensor in hw_features.proximity.configs:
                for location in sensor.location:
                    if location.radio_type == radio:
                        result[proximity] = True
                        if sensor.WhichOneof("config") == "activity_config":
                            result[activity_proximity] = True

    if (
        hw_features.cellular.present == present
        and hw_features.cellular.HasField("dynamic_power_reduction_config")
    ):
        dpr_config = hw_features.cellular.dynamic_power_reduction_config
        result["set-cellular-transmit-power-for-tablet-mode"] = False
        if form_factor in (
            topology_pb2.HardwareFeatures.FormFactor.CONVERTIBLE,
            topology_pb2.HardwareFeatures.FormFactor.DETACHABLE,
        ):
            if dpr_config.tablet_mode:
                result["set-cellular-transmit-power-for-tablet-mode"] = True
        if (
            result["set-cellular-transmit-power-for-tablet-mode"]
            or result["set-cellular-transmit-power-for-proximity"]
            or result["set-cellular-transmit-power-for-activity-proximity"]
        ):
            if dpr_config.HasField("gpio"):
                result[
                    "set-cellular-transmit-power-dpr-gpio"
                ] = wrappers_pb2.UInt32Value(value=dpr_config.gpio)
            elif dpr_config.HasField("modem_manager"):
                result["use-modemmanager-for-dynamic-sar"] = True
                result[
                    "use-multi-power-level-dynamic-sar"
                ] = dpr_config.enable_multi_power_level_sar
                result[
                    "set-default-proximity-state-high"
                ] = dpr_config.enable_default_proximity_state_far
                result[
                    "set-cellular-transmit-power-level-mapping"
                ] = dpr_config.power_level_mapping
                result[
                    "set-cellular-regulatory-domain-mapping"
                ] = dpr_config.regulatory_domain_mapping
                if result["set-cellular-regulatory-domain-mapping"]:
                    result["use-regulatory-domain-for-dynamic-sar"] = True
    result[
        "set-wifi-transmit-power-for-tablet-mode"
    ] = hw_features.wifi.HasField("wifi_config")

    return result


def _build_derived_external_display_timeout_power_prefs(config: Config) -> dict:
    hw_features = config.hw_design_config.hardware_features
    result = {}

    if hw_features.usb_c.defer_external_display_timeout:
        result[
            "defer-external-display-timeout"
        ] = hw_features.usb_c.defer_external_display_timeout
    elif hw_features.usb_c.usb4:
        result["defer-external-display-timeout"] = 10

    return result


def _brightness_nits_to_percent(nits, max_screen_brightness):
    max_percent = 100
    max_brightness_steps = 16
    min_visible_percent = max_percent / max_brightness_steps

    linear_fraction = nits / max_screen_brightness
    percent = min_visible_percent + (max_percent - min_visible_percent) * pow(
        linear_fraction, 0.5
    )
    return round(percent, 1)


def _build_derived_panel_power_prefs(config: Config) -> dict:
    """Builds a partial 'power' property derived from hardware features."""
    present = topology_pb2.HardwareFeatures.PRESENT
    hw_features = config.hw_design_config.hardware_features

    result = {}

    if hw_features.screen.panel_properties.min_visible_backlight_level:
        result[
            "min-visible-backlight-level"
        ] = hw_features.screen.panel_properties.min_visible_backlight_level

    if hw_features.screen.panel_properties.HasField(
        "turn_off_screen_timeout_ms"
    ):
        result[
            "turn-off-screen-timeout-ms"
        ] = hw_features.screen.panel_properties.turn_off_screen_timeout_ms

    light_sensor = hw_features.light_sensor
    if light_sensor.lid_lightsensor == present:
        if hw_features.screen.panel_properties.als_steps:
            _check_als_steps(
                hw_features.screen.panel_properties.als_steps,
                hw_features.screen.panel_properties.max_screen_brightness,
                "hw_features.screen.panel_properties.als_steps",
            )
            result[
                "internal-backlight-als-steps"
            ] = hw_features.screen.panel_properties.als_steps
    else:
        panel_properties = hw_features.screen.panel_properties
        if panel_properties.no_als_battery_brightness:
            _check_percentage_value(
                panel_properties.no_als_battery_brightness,
                "screen.panel_properties.no_als_battery_brightness",
            )
            result[
                "internal-backlight-no-als-battery-brightness"
            ] = panel_properties.no_als_battery_brightness
        elif panel_properties.no_als_battery_brightness_nits:
            brightness_pct_calc = _brightness_nits_to_percent(
                panel_properties.no_als_battery_brightness_nits,
                panel_properties.max_screen_brightness,
            )
            result[
                "internal-backlight-no-als-battery-brightness"
            ] = brightness_pct_calc

        if hw_features.screen.panel_properties.no_als_ac_brightness:
            _check_percentage_value(
                hw_features.screen.panel_properties.no_als_ac_brightness,
                "screen.panel_properties.no_als_ac_brightness",
            )
            result[
                "internal-backlight-no-als-ac-brightness"
            ] = hw_features.screen.panel_properties.no_als_ac_brightness
        elif hw_features.screen.panel_properties.no_als_ac_brightness_nits:
            brightness_pct_calc = _brightness_nits_to_percent(
                hw_features.screen.panel_properties.no_als_ac_brightness_nits,
                hw_features.screen.panel_properties.max_screen_brightness,
            )
            result[
                "internal-backlight-no-als-ac-brightness"
            ] = brightness_pct_calc

    return result


def _build_derived_power_prefs(config: Config) -> dict:
    """Builds a partial 'power' property derived from hardware features."""
    present = topology_pb2.HardwareFeatures.PRESENT
    hw_features = config.hw_design_config.hardware_features

    form_factor = hw_features.form_factor.form_factor
    if (
        form_factor
        == topology_pb2.HardwareFeatures.FormFactor.FORM_FACTOR_UNKNOWN
    ):
        return {}

    result = {}

    result["external-display-only"] = form_factor in (
        topology_pb2.HardwareFeatures.FormFactor.CHROMEBIT,
        topology_pb2.HardwareFeatures.FormFactor.CHROMEBOX,
    )

    light_sensor = hw_features.light_sensor
    result["has-ambient-light-sensor"] = (
        light_sensor.lid_lightsensor,
        light_sensor.base_lightsensor,
    ).count(present)

    result["has-keyboard-backlight"] = hw_features.keyboard.backlight == present
    result["has-barreljack"] = hw_features.power_supply.barreljack == present

    if hw_features.keyboard.backlight_user_steps:
        _check_increasing_sequence(
            hw_features.keyboard.backlight_user_steps,
            "keyboard.backlight_user_steps",
        )
        if hw_features.keyboard.backlight_user_steps[0] != 0:
            raise Exception(
                "keyboard.backlight_user_steps starts at %.1f instead of 0.0"
                % hw_features.keyboard.backlight_user_steps[0]
            )

        result[
            "keyboard-backlight-user-steps"
        ] = hw_features.keyboard.backlight_user_steps

    if present in (light_sensor.lid_lightsensor, light_sensor.base_lightsensor):
        if hw_features.keyboard.als_steps:
            _check_lux_threshold(
                [step.lux_threshold for step in hw_features.keyboard.als_steps],
                "hw_features.keyboard.als_steps",
            )
            result[
                "keyboard-backlight-als-steps"
            ] = hw_features.keyboard.als_steps
    else:
        if hw_features.keyboard.no_als_brightness:
            _check_percentage_value(
                hw_features.keyboard.no_als_brightness,
                "hw_features.keyboard.no_als_brightness",
            )
            result[
                "keyboard-backlight-no-als-brightness"
            ] = hw_features.keyboard.no_als_brightness

    if hw_features.screen.panel_properties.min_visible_backlight_level:
        result[
            "min-visible-backlight-level"
        ] = hw_features.screen.panel_properties.min_visible_backlight_level

    if hw_features.screen.panel_properties.HasField(
        "turn_off_screen_timeout_ms"
    ):
        result[
            "turn-off-screen-timeout-ms"
        ] = hw_features.screen.panel_properties.turn_off_screen_timeout_ms

    result.update(_build_derived_panel_power_prefs(config))

    if len(hw_features.usb_c.ports) > 1:
        if len(hw_features.usb_c.ports) != hw_features.usb_c.count.value:
            raise Exception(
                "Only %d of %d USB-C ports have locations configured."
                % (len(hw_features.usb_c.ports), hw_features.usb_c.count.value)
            )

        result["charging-ports"] = _build_charging_ports(
            hw_features.usb_c.ports
        )

    result.update(
        _build_derived_platform_power_prefs(
            config.program.platform.capabilities
        )
    )
    result.update(_build_derived_connectivity_power_prefs(config))
    result.update(_build_derived_external_display_timeout_power_prefs(config))

    result["usb-min-ac-watts"] = hw_features.power_supply.usb_min_ac_watts

    return dict(
        (k, _format_power_pref_value(v)) for k, v in result.items() if v
    )


def _build_power(config: Config) -> dict:
    """Builds the 'power' property from cros_config_schema."""
    power_prefs_map = _build_derived_power_prefs(config)
    power_prefs = config.sw_config.power_config.preferences
    power_prefs_map.update(
        (x.replace("_", "-"), power_prefs[x]) for x in power_prefs
    )
    return power_prefs_map


# From drm_mode.h in libdrm.
_CONNECTOR_TYPES = {
    topology_pb2.HardwareFeatures.Screen.ConnectorType.CONNECTOR_TYPE_EDP: 14,
}


def _build_display(screen_topo: topology_pb2.HardwareFeatures.Screen) -> dict:
    """Builds a single object under /displays/N."""
    props = screen_topo.panel_properties
    result = {}

    if props.HasField("rounded_corners"):
        result["rounded-corners"] = {
            "top-left": props.rounded_corners.top_left.radius_px,
            "top-right": props.rounded_corners.top_right.radius_px,
            "bottom-left": props.rounded_corners.bottom_left.radius_px,
            "bottom-right": props.rounded_corners.bottom_right.radius_px,
        }

    if not result:
        return {}

    # We assume that eDP (type 14) is a resaonable default connector type.
    libdrm_connector_type = _CONNECTOR_TYPES.get(screen_topo.connector_type, 14)
    result["connector-type"] = libdrm_connector_type
    return result


def _build_displays(hw_topology: topology_pb2.HardwareFeatures) -> list:
    """Builds the /displays object."""
    displays = []

    # Boxster only understands one display, which does not map to what
    # cros_config is capable of encoding.  We can fix this later should we
    # require it.
    displays.append(_build_display(hw_topology.screen.hardware_feature.screen))

    return [x for x in displays if x]


def _build_resource(config: Config) -> dict:
    """Builds the 'resource' property for cros_config_schema."""

    return json_format.MessageToDict(
        config.sw_config.resource_config, including_default_value_fields=True
    )


def _overlay_presence(*values):
    for value in values:
        if value != topology_pb2.HardwareFeatures.UNKNOWN:
            return value
    return topology_pb2.HardwareFeatures.UNKNOWN


def _build_ash_flags(config: Config) -> dict:
    """Returns a dict of ash flags and features.

    Ash is the window manager and system UI for ChromeOS, see
    https://chromium.googlesource.com/chromium/src/+/HEAD/ash/.
    """
    # pylint: disable=too-many-branches,too-many-locals,too-many-statements

    # A map from flag name -> value. Value may be None for boolean flags.
    flags = {}

    # Sets of ash features to enable and disable, respectively.
    enabled_features = set()
    disabled_features = set()

    # Adds a flag name -> value pair to flags map. |value| may be None for
    # boolean flags.
    def _add_flag(name, value=None):
        flags[name] = value

    # Adds a feature name to the set of enabled features, removing it from the
    # set of disabled features if present.
    def _enable_feature(name):
        enabled_features.add(name)
        disabled_features.discard(name)

    # Adds a feature name to the set of disabled features, removing it from the
    # set of enabled features if present.
    def _disable_feature(name):
        disabled_features.add(name)
        enabled_features.discard(name)

    hw_features = config.hw_design_config.hardware_features
    if (
        hw_features.stylus.stylus
        == topology_pb2.HardwareFeatures.Stylus.INTERNAL
    ):
        _add_flag("has-internal-stylus")

    fp_loc = hw_features.fingerprint.location
    if hw_features.fingerprint.present:
        loc_name = topology_pb2.HardwareFeatures.Fingerprint.Location.Name(
            fp_loc
        )
        _add_flag(
            "fingerprint-sensor-location", loc_name.lower().replace("_", "-")
        )

    wallpaper = config.brand_config.wallpaper
    # If a wallpaper is set, the 'default-wallpaper-is-oem' flag needs to be
    # set.
    # If a wallpaper is not set, the 'default_[large|small].jpg' wallpapers
    # should still be set.
    if wallpaper:
        _add_flag("default-wallpaper-is-oem")
    else:
        wallpaper = "default"

    for size in ("small", "large"):
        _add_flag(
            f"default-wallpaper-{size}",
            f"{WALLPAPER_BASE_PATH}/{wallpaper}_{size}.jpg",
        )

        # For each size, also install 'guest' and 'child' wallpapers.
        for wallpaper_type in ("guest", "child"):
            _add_flag(
                f"{wallpaper_type}-wallpaper-{size}",
                f"{WALLPAPER_BASE_PATH}/{wallpaper_type}_{size}.jpg",
            )

    regulatory_label = config.brand_config.regulatory_label
    if regulatory_label:
        _add_flag("regulatory-label-dir", regulatory_label)

    if (
        config.brand_config.cloud_gaming_device
        or config.sw_config.ui_config.cloud_gaming_device
    ):
        _enable_feature("CloudGamingDevice")

    if (
        component_pb2.Component.DisplayPanel.SEAMLESS_REFRESH_RATE_SWITCHING
        in hw_features.screen.panel_properties.features
    ):
        _enable_feature("SeamlessRefreshRateSwitching")

    _add_flag(
        "arc-build-properties",
        {
            "device": "%s_cheets" % config.program.name.lower(),
            "firstApiLevel": "28",
        },
    )

    power_button = hw_features.power_button
    if power_button.edge:
        _add_flag(
            "ash-power-button-position",
            json.dumps(
                {
                    "edge": topology_pb2.HardwareFeatures.Button.Edge.Name(
                        power_button.edge
                    ).lower(),
                    # Starlark sometimes represents float literals strangely,
                    # e.g. changing 0.9 to 0.899999. Round to two digits here.
                    "position": round(power_button.position, 2),
                }
            ),
        )

    volume_button = hw_features.volume_button
    if volume_button.edge:
        _add_flag(
            "ash-side-volume-button-position",
            json.dumps(
                {
                    "region": topology_pb2.HardwareFeatures.Button.Region.Name(
                        volume_button.region
                    ).lower(),
                    "side": topology_pb2.HardwareFeatures.Button.Edge.Name(
                        volume_button.edge
                    ).lower(),
                }
            ),
        )

    form_factor = hw_features.form_factor.form_factor
    lid_accel = hw_features.accelerometer.lid_accelerometer
    if form_factor == topology_pb2.HardwareFeatures.FormFactor.CHROMEBASE:
        _add_flag("touchscreen-usable-while-screen-off")
        if lid_accel == topology_pb2.HardwareFeatures.PRESENT:
            _add_flag("supports-clamshell-auto-rotation")

    if config.sw_config.ui_config.extra_web_apps_dir:
        _add_flag(
            "extra-web-apps-dir", config.sw_config.ui_config.extra_web_apps_dir
        )

    if (
        hw_features.microphone_mute_switch.present
        == topology_pb2.HardwareFeatures.PRESENT
    ):
        _add_flag("enable-microphone-mute-switch-device")

    requisition = config.sw_config.ui_config.requisition
    if (
        requisition == ui_config_pb2.UiConfig.REQUISITION_MEETHW
        and form_factor == topology_pb2.HardwareFeatures.FormFactor.CHROMEBASE
    ):
        _add_flag("oobe-large-screen-special-scaling")
        _add_flag("enable-virtual-keyboard")

    touch = (
        config.hw_design_config.hardware_topology.touch.hardware_feature.touch
    )
    if touch.HasField("touch_slop_distance"):
        _add_flag("touch-slop-distance", touch.touch_slop_distance.value)

    if form_factor in (
        topology_pb2.HardwareFeatures.FormFactor.CONVERTIBLE,
        topology_pb2.HardwareFeatures.FormFactor.DETACHABLE,
        topology_pb2.HardwareFeatures.FormFactor.CHROMESLATE,
    ):
        _add_flag("enable-touchview")

    hevc_support = _overlay_presence(
        hw_features.soc.hevc_support, config.program.platform.hevc_support
    )
    hevc_action = lambda _: None
    if hevc_support == topology_pb2.HardwareFeatures.PRESENT:
        hevc_action = _enable_feature
    elif hevc_support == topology_pb2.HardwareFeatures.NOT_PRESENT:
        hevc_action = _disable_feature

    hevc_action("PlatformHEVCDecoderSupport")

    result = {
        "extra-ash-flags": sorted(
            [f"--{k}={v}" if v else f"--{k}" for k, v in flags.items()]
        ),
    }
    if disabled_features:
        result["ash-disabled-features"] = sorted(disabled_features)
    if enabled_features:
        result["ash-enabled-features"] = sorted(enabled_features)
    return result


def _build_ui(config: Config) -> dict:
    """Builds the 'ui' property from cros_config_schema."""
    result = _build_ash_flags(config)
    help_content_id = config.brand_config.help_content_id
    if help_content_id:
        result["help-content-id"] = help_content_id
    return result


def _build_keyboard(hw_topology):
    if not hw_topology.HasField("keyboard"):
        return None

    keyboard = hw_topology.keyboard.hardware_feature.keyboard
    result = {}
    if keyboard.backlight == topology_pb2.HardwareFeatures.PRESENT:
        result["backlight"] = True
    if keyboard.numeric_pad == topology_pb2.HardwareFeatures.PRESENT:
        result["numpad"] = True
    if (
        keyboard.mcu_type
        == topology_pb2.HardwareFeatures.Keyboard.KEYBOARD_MCU_PRISM
    ):
        result["mcutype"] = "prism_rgb_controller"

    return result


def _build_bluetooth(config):
    bt_flags = config.sw_config.bluetooth_config.flags
    # Convert to native map (from proto wrapper)
    bt_flags_map = dict(bt_flags)
    result = {}
    if bt_flags_map:
        result["flags"] = bt_flags_map
    return result


def _build_ath10k_config(ath10k_config):
    """Builds the wifi configuration for the ath10k driver.

    Args:
        ath10k_config: Ath10kConfig config.

    Returns:
        wifi configuration for the ath10k driver.
    """
    result = {}

    def power_chain(power):
        return {
            "limit-2g": power.limit_2g,
            "limit-5g": power.limit_5g,
        }

    result["tablet-mode-power-table-ath10k"] = power_chain(
        ath10k_config.tablet_mode_power_table
    )
    result["non-tablet-mode-power-table-ath10k"] = power_chain(
        ath10k_config.non_tablet_mode_power_table
    )
    return result


def _build_rtw88_config(rtw88_config):
    """Builds the wifi configuration for the rtw88 driver.

    Args:
        rtw88_config: Rtw88Config config.

    Returns:
        wifi configuration for the rtw88 driver.
    """
    result = {}

    def power_chain(power):
        return {
            "limit-2g": power.limit_2g,
            "limit-5g-1": power.limit_5g_1,
            "limit-5g-3": power.limit_5g_3,
            "limit-5g-4": power.limit_5g_4,
        }

    result["tablet-mode-power-table-rtw"] = power_chain(
        rtw88_config.tablet_mode_power_table
    )
    result["non-tablet-mode-power-table-rtw"] = power_chain(
        rtw88_config.non_tablet_mode_power_table
    )

    def offsets(offset):
        return {
            "offset-2g": offset.offset_2g,
            "offset-5g": offset.offset_5g,
        }

    result["geo-offsets-fcc"] = offsets(rtw88_config.offset_fcc)
    result["geo-offsets-eu"] = offsets(rtw88_config.offset_eu)
    result["geo-offsets-rest-of-world"] = offsets(rtw88_config.offset_other)
    return result


def _build_rtw89_config(rtw89_config):
    """Builds the wifi configuration for the rtw89 driver.

    Args:
        rtw89_config: Rtw89Config config.

    Returns:
        wifi configuration for the rtw89 driver.
    """
    result = {}

    def power_chain(power):
        return {
            "limit-2g": power.limit_2g,
            "limit-5g-1": power.limit_5g_1,
            "limit-5g-3": power.limit_5g_3,
            "limit-5g-4": power.limit_5g_4,
            "limit-6g-1": power.limit_6g_1,
            "limit-6g-2": power.limit_6g_2,
            "limit-6g-3": power.limit_6g_3,
            "limit-6g-4": power.limit_6g_4,
            "limit-6g-5": power.limit_6g_5,
            "limit-6g-6": power.limit_6g_6,
        }

    if rtw89_config.HasField("tablet_mode_power_table"):
        result["tablet-mode-power-table-rtw"] = power_chain(
            rtw89_config.tablet_mode_power_table
        )
    if rtw89_config.HasField("non_tablet_mode_power_table"):
        result["non-tablet-mode-power-table-rtw"] = power_chain(
            rtw89_config.non_tablet_mode_power_table
        )

    def offsets(offset):
        return {
            "offset-2g": offset.offset_2g,
            "offset-5g": offset.offset_5g,
            "offset-6g": offset.offset_6g,
        }

    if rtw89_config.HasField("offset_fcc"):
        result["geo-offsets-fcc"] = offsets(rtw89_config.offset_fcc)
    if rtw89_config.HasField("offset_eu"):
        result["geo-offsets-eu"] = offsets(rtw89_config.offset_eu)
    if rtw89_config.HasField("offset_other"):
        result["geo-offsets-rest-of-world"] = offsets(rtw89_config.offset_other)
    return result


def _build_intel_config(config, config_files):
    """Builds the wifi configuration for the intel driver.

    Args:
        config: Config namedtuple
        config_files: Map to look up the generated config files.

    Returns:
        wifi configuration for the intel driver.
    """
    coreboot_target = (
        config.sw_config.firmware_build_config.build_targets.coreboot
        + _calculate_image_name_suffix(config.hw_design_config)
    )
    wifi_sar_id = _extract_fw_config_value(
        config.hw_design_config, config.hw_design_config.hardware_topology.wifi
    )
    return config_files.wifi_sar_map.get((coreboot_target, wifi_sar_id))


def _build_mtk_config(mtk_config):
    """Builds the wifi configuration for the mtk driver.

    Args:
        mtk_config: MtkConfig config.

    Returns:
        wifi configuration for the mtk driver.
    """
    result = {}

    def power_chain(power):
        chain = {}
        chain["limit-2g"] = power.limit_2g
        chain["limit-5g-1"] = power.limit_5g_1
        chain["limit-5g-2"] = power.limit_5g_2
        chain["limit-5g-3"] = power.limit_5g_3
        chain["limit-5g-4"] = power.limit_5g_4
        # Ignore 6 GHz parameters that are 0, which is the protobuf 3 default
        # this is done to avoid inserting 0s where values should be unset.
        if power.limit_6g_1 != 0:
            # Don't allow partially configured 6GHz SAR tables.
            if (
                power.limit_6g_2 == 0
                or power.limit_6g_3 == 0
                or power.limit_6g_4 == 0
                or power.limit_6g_5 == 0
                or power.limit_6g_6 == 0
            ):
                raise Exception(
                    "6GHz SAR table partially and improperly set up.  Please add values for limits in all bands (1-6)."
                )
            chain["limit-6g-1"] = power.limit_6g_1
            chain["limit-6g-2"] = power.limit_6g_2
            chain["limit-6g-3"] = power.limit_6g_3
            chain["limit-6g-4"] = power.limit_6g_4
            chain["limit-6g-5"] = power.limit_6g_5
            chain["limit-6g-6"] = power.limit_6g_6
        else:
            # Don't allow partially configured 6GHz SAR tables.
            if (
                power.limit_6g_2 != 0
                or power.limit_6g_3 != 0
                or power.limit_6g_4 != 0
                or power.limit_6g_5 != 0
                or power.limit_6g_6 != 0
            ):
                raise Exception(
                    "6GHz SAR table partially and improperly set up.  Please add values for limits in all bands (1-6)."
                )
        return chain

    if mtk_config.HasField("tablet_mode_power_table"):
        result["tablet-mode-power-table-mtk"] = power_chain(
            mtk_config.tablet_mode_power_table
        )
    if mtk_config.HasField("non_tablet_mode_power_table"):
        result["non-tablet-mode-power-table-mtk"] = power_chain(
            mtk_config.non_tablet_mode_power_table
        )

    def geo_power_chain(power):
        chain = {}
        chain["limit-2g"] = power.limit_2g
        chain["limit-5g"] = power.limit_5g
        # Ignore 6 GHz parameters that are 0, which is the protobuf 3 default
        # this is done to avoid inserting 0s where values should be unset.
        if power.limit_6g != 0:
            chain["limit-6g"] = power.limit_6g
        chain["offset-2g"] = power.offset_2g
        chain["offset-5g"] = power.offset_5g
        # Ignore 6 GHz parameters that are 0, which is the protobuf 3 default
        # this is done to avoid inserting 0s where values should be unset.
        if power.offset_6g != 0:
            chain["offset-6g"] = power.offset_6g
        return chain

    if mtk_config.HasField("fcc_power_table"):
        result["fcc-power-table-mtk"] = geo_power_chain(
            mtk_config.fcc_power_table
        )
    if mtk_config.HasField("eu_power_table"):
        result["eu-power-table-mtk"] = geo_power_chain(
            mtk_config.eu_power_table
        )
    if mtk_config.HasField("other_power_table"):
        result["rest-of-world-power-table-mtk"] = geo_power_chain(
            mtk_config.other_power_table
        )

    return result


def _build_wifi(config, config_files):
    """Builds the wifi configuration.

    Args:
        config: Config namedtuple
        config_files: Map to look up the generated config files.

    Returns:
        wifi configuration.
    """
    if config.hw_design_config.hardware_features.wifi.HasField("wifi_config"):
        wifi_config = config.hw_design_config.hardware_features.wifi.wifi_config
    else:
        wifi_config = config.sw_config.wifi_config

    config_field = wifi_config.WhichOneof("wifi_config")
    if config_field == "ath10k_config":
        return _build_ath10k_config(wifi_config.ath10k_config)
    if config_field == "rtw88_config":
        return _build_rtw88_config(wifi_config.rtw88_config)
    if config_field == "intel_config":
        return _build_intel_config(config, config_files)
    if config_field == "mtk_config":
        return _build_mtk_config(wifi_config.mtk_config)
    if config_field == "rtw89_config":
        return _build_rtw89_config(wifi_config.rtw89_config)
    return {}


def _build_health_cached_vpd(health_config):
    if not health_config.HasField("cached_vpd"):
        return None

    cached_vpd = health_config.cached_vpd
    result = {}
    _upsert(cached_vpd.has_sku_number, result, "has-sku-number")
    return result


def _build_health_battery(health_config):
    if not health_config.HasField("battery"):
        return None

    battery = health_config.battery
    result = {}
    _upsert(battery.has_smart_battery_info, result, "has-smart-battery-info")
    return result


def _build_health_routines_fingerprint_diag(config):
    """Builds the health service routines fingerprint health configuration.

    Args:
        config: Fingerprint diag config namedtuple.

    Returns:
        fingerprint health routines configuration.
    """

    def _build_pixel_median(pixel_median):
        return {
            "cb-type1-lower": pixel_median.cb_type1_lower,
            "cb-type1-upper": pixel_median.cb_type1_upper,
            "cb-type2-lower": pixel_median.cb_type2_lower,
            "cb-type2-upper": pixel_median.cb_type2_upper,
            "icb-type1-lower": pixel_median.icb_type1_lower,
            "icb-type1-upper": pixel_median.icb_type1_upper,
            "icb-type2-lower": pixel_median.icb_type2_lower,
            "icb-type2-upper": pixel_median.icb_type2_upper,
        }

    def _build_detect_zones(detect_zones):
        result = []
        for detect_zone in detect_zones:
            zone = {
                "x1": detect_zone.x1,
                "y1": detect_zone.y1,
                "x2": detect_zone.x2,
                "y2": detect_zone.y2,
            }
            result.append(zone)
        return result

    return {
        "routine-enable": config.routine_enable,
        "max-pixel-dev": config.max_pixel_dev,
        "max-dead-pixels": config.max_dead_pixels,
        "pixel-median": _build_pixel_median(config.pixel_median),
        "num-detect-zone": config.num_detect_zone,
        "detect-zones": _build_detect_zones(config.detect_zones),
        "max-dead-pixels-in-detect-zone": config.max_dead_pixels_in_detect_zone,
        "max-reset-pixel-dev": config.max_reset_pixel_dev,
        "max-error-reset-pixels": config.max_error_reset_pixels,
    }


def _build_health_routines(health_config, hw_topo):
    """Builds the health service routines configuration.

    Args:
        health_config: Health Config namedtuple.
        hw_topo: Hardware topology.

    Returns:
        health routines configuration.
    """

    result = {}

    if health_config.HasField("routines"):
        routines = health_config.routines
        if routines.HasField("battery_health"):
            battery_health_result = {}
            _upsert(
                routines.battery_health.percent_battery_wear_allowed,
                battery_health_result,
                "percent-battery-wear-allowed",
            )
            _upsert(battery_health_result, result, "battery-health")
        if routines.HasField("nvme_wear_level"):
            nvme_wear_level_result = {}
            _upsert(
                routines.nvme_wear_level.wear_level_threshold,
                nvme_wear_level_result,
                "wear-level-threshold",
            )
            _upsert(nvme_wear_level_result, result, "nvme-wear-level")

    if hw_topo.HasField("fingerprint"):
        fingerprint = hw_topo.fingerprint.hardware_feature.fingerprint
        if fingerprint.HasField("fingerprint_diag"):
            _upsert(
                _build_health_routines_fingerprint_diag(
                    fingerprint.fingerprint_diag
                ),
                result,
                "fingerprint-diag",
            )

    return result


def _build_health(config: Config):
    """Builds the health configuration.

    Args:
        config: Config namedtuple

    Returns:
        health configuration.
    """
    if not config.sw_config.health_config:
        return None

    health_config = config.sw_config.health_config
    hw_topo = config.hw_design_config.hardware_topology
    result = {}
    _upsert(_build_health_cached_vpd(health_config), result, "cached-vpd")
    _upsert(_build_health_battery(health_config), result, "battery")
    _upsert(_build_health_routines(health_config, hw_topo), result, "routines")
    return result


def _build_ssfc_probeable_components(component_type_config):
    """Builds the probeable SSFC component list.

    Args:
        component_type_config: RMA SSFC Component Type Config namedtuple

    Returns:
        List of SSFC components.
    """
    if not component_type_config.probeable_components:
        return None

    probeable_components = component_type_config.probeable_components
    result = []

    for component in probeable_components:
        result.append(
            {
                "identifier": component.identifier,
                "value": component.value,
            }
        )

    return result


def _build_ssfc_component_type_configs(ssfc_config):
    """Builds the SSFC config list of each component type.

    Args:
        ssfc_config: RMA SSFC Config namedtuple

    Returns:
        List of SSFC configs.
    """
    if not ssfc_config.component_type_configs:
        return None

    component_type_configs = ssfc_config.component_type_configs
    result = []

    for component_type_config in component_type_configs:
        result.append(
            {
                "component-type": component_type_config.component_type,
                "default-value": component_type_config.default_value,
                "probeable-components": _build_ssfc_probeable_components(
                    component_type_config
                ),
            }
        )

    return result


def _build_ssfc_config(rma_config):
    """Builds the SSFC configuration.

    Args:
        rma_config: RMA Config namedtuple

    Returns:
        SSFC configuration.
    """
    if not rma_config.HasField("ssfc_config"):
        return None

    ssfc_config = rma_config.ssfc_config
    result = {}

    _upsert(ssfc_config.mask, result, "mask")
    _upsert(
        _build_ssfc_component_type_configs(ssfc_config),
        result,
        "component-type-configs",
    )

    return result


def _build_rma(config: Config):
    """Builds the RMA configuration.

    Args:
        config: Config namedtuple

    Returns:
        RMA configuration.
    """
    if not config.sw_config.rma_config:
        return None

    rma_config = config.sw_config.rma_config
    if not rma_config.enabled:
        return None

    result = {}
    _upsert(rma_config.enabled, result, "enabled")
    _upsert(rma_config.has_cbi, result, "has-cbi")
    _upsert(_build_ssfc_config(rma_config), result, "ssfc")
    return result


def _build_nnpalm(config: Config):
    """Builds the nnpalm configuration.

    Args:
        config: Config namedtuple

    Returns:
        nnpalm configuration.
    """
    if not config.sw_config.nnpalm_config:
        return None

    nnpalm_config = config.sw_config.nnpalm_config
    if not nnpalm_config.touch_compatible:
        return None

    result = {}
    _upsert(nnpalm_config.model, result, "model")
    _upsert(nnpalm_config.radius_polynomial, result, "radius-polynomial")
    _upsert(nnpalm_config.touch_compatible, result, "touch-compatible")
    return result


def _build_branding(config: Config):
    """Builds the branding configuration.

    Args:
        config: Config namedtuple

    Returns:
        branding configuration.
    """
    result = {}
    if config.device_brand.export_oem_info and config.oem:
        _upsert(config.oem.name, result, "oem-name")
    if config.device_brand:
        _upsert(config.device_brand.brand_name, result, "marketing-name")
    return result


def _build_pvs(config: Config) -> dict:
    """Builds the PVS configuration.

    Args:
        config: Config namedtuple

    Returns:
        PVS configuration
    """
    hw_design = config.hw_design
    result = {}
    if hw_design.program_id and hw_design.program_id.value:
        _upsert(hw_design.program_id.value.lower(), result, "program")
    if hw_design.id and hw_design.id.value:
        _upsert(hw_design.id.value.lower(), result, "project")
    return result


def _build_proximity(config, config_files):
    """Builds the proximity sensors configuration.

    Args:
        config: Config namedtuple
        config_files: Map to look up the generated config files.

    Returns:
        proximity sensors configuration.
    """
    design_name = _get_name_for_config(config.hw_design.id)
    design_config_id = config.hw_design_config.id.value.lower()
    return config_files.proximity_map.get((design_name, design_config_id))


def _build_fingerprint(hw_topology):
    if not hw_topology.HasField("fingerprint"):
        return None

    fp = hw_topology.fingerprint.hardware_feature.fingerprint
    result = {}
    if fp.present:
        location = fp.Location.DESCRIPTOR.values_by_number[fp.location].name
    else:
        location = "none"
    result["sensor-location"] = location.lower().replace("_", "-")
    if fp.board:
        result["board"] = fp.board
    if fp.ro_version:
        result["ro-version"] = fp.ro_version

    return result


def _build_hps(hw_topology):
    if not hw_topology.HasField("hps"):
        return None

    hps = hw_topology.hps.hardware_feature.hps
    result = {}
    if hps.present == topology_pb2.HardwareFeatures.PRESENT:
        result["has-hps"] = True

    return result


def _build_dgpu(hw_topology):
    if not hw_topology.HasField("dgpu"):
        return None

    dgpu = hw_topology.dgpu.hardware_feature.dgpu_config
    result = {}
    if dgpu.present == topology_pb2.HardwareFeatures.PRESENT:
        result["has-dgpu"] = True
        if dgpu.dgpu_type == topology_pb2.HardwareFeatures.Dgpu.DGPU_NV3050:
            result["dgpu-type"] = "nv3050"
        elif dgpu.dgpu_type == topology_pb2.HardwareFeatures.Dgpu.DGPU_NV4050:
            result["dgpu-type"] = "nv4050"
        else:
            result["dgpu-type"] = "unknown"

    return result


def _build_uwb(hw_topology):
    if not hw_topology.HasField("uwb"):
        return None

    uwb = hw_topology.uwb.hardware_feature.uwb_config
    result = {}
    if uwb.present == topology_pb2.HardwareFeatures.PRESENT:
        result["has-uwb"] = True

    return result


def _build_poe(hw_topology):
    if not hw_topology.HasField("poe"):
        return None

    poe = hw_topology.poe.hardware_feature.poe
    result = {}
    if poe.present == topology_pb2.HardwareFeatures.PRESENT:
        result["has-poe-peripheral-support"] = True

    return result


def _build_detachable_base(form_factor, detachable_base):
    if form_factor != topology_pb2.HardwareFeatures.FormFactor.DETACHABLE:
        return None

    result = {}
    ec_image_name = detachable_base.ec_image_name
    touch_image_name = detachable_base.touch_image_name
    db_fw_root = pathlib.PurePath("/lib/firmware/")
    db_fw_path = pathlib.PurePath("detachable_base/firmware/")
    db_tp_path = pathlib.PurePath("detachable_base/touch/")
    db_path_prefix = pathlib.PurePath("/opt/google")

    db_files = []

    if not ec_image_name:
        return None

    db_files.append(
        _file(
            db_fw_path.joinpath(f"{ec_image_name}.bin"),
            db_path_prefix.joinpath(db_fw_path, f"{ec_image_name}.bin"),
            db_fw_root.joinpath(f"{ec_image_name}.fw"),
        )
    )

    if touch_image_name:
        db_files.append(
            _file(
                db_tp_path.joinpath(f"{touch_image_name}.bin"),
                db_path_prefix.joinpath(db_tp_path, f"{touch_image_name}.bin"),
                db_fw_root.joinpath(f"{ec_image_name}-touch.fw"),
            )
        )
        _upsert(f"{ec_image_name}-touch.fw", result, "touch-image-name")

    _upsert(db_files, result, "files")
    _upsert(f"{ec_image_name}.fw", result, "ec-image-name")
    _upsert(detachable_base.usb_path, result, "usb-path")
    _upsert(detachable_base.product_id, result, "product-id")
    _upsert(detachable_base.vendor_id, result, "vendor-id")
    return result


def _build_hardware_properties(hw_topology):
    if not hw_topology.HasField("form_factor"):
        return None

    form_factor = (
        hw_topology.form_factor.hardware_feature.form_factor.form_factor
    )
    result = {}
    if form_factor in [
        topology_pb2.HardwareFeatures.FormFactor.CHROMEBIT,
        topology_pb2.HardwareFeatures.FormFactor.CHROMEBASE,
        topology_pb2.HardwareFeatures.FormFactor.CHROMEBOX,
    ]:
        result["psu-type"] = "AC_only"
    else:
        result["psu-type"] = "battery"

    result["has-backlight"] = form_factor not in [
        topology_pb2.HardwareFeatures.FormFactor.CHROMEBIT,
        topology_pb2.HardwareFeatures.FormFactor.CHROMEBOX,
    ]

    form_factor_names = {
        topology_pb2.HardwareFeatures.FormFactor.CLAMSHELL: "CLAMSHELL",
        topology_pb2.HardwareFeatures.FormFactor.CONVERTIBLE: "CONVERTIBLE",
        topology_pb2.HardwareFeatures.FormFactor.DETACHABLE: "DETACHABLE",
        topology_pb2.HardwareFeatures.FormFactor.CHROMEBASE: "CHROMEBASE",
        topology_pb2.HardwareFeatures.FormFactor.CHROMEBOX: "CHROMEBOX",
        topology_pb2.HardwareFeatures.FormFactor.CHROMEBIT: "CHROMEBIT",
        topology_pb2.HardwareFeatures.FormFactor.CHROMESLATE: "CHROMESLATE",
    }
    if form_factor in form_factor_names:
        result["form-factor"] = form_factor_names[form_factor]

    recovery_input_names = {
        topology_pb2.HardwareFeatures.FormFactor.KEYBOARD: "KEYBOARD",
        topology_pb2.HardwareFeatures.FormFactor.POWER_BUTTON: "POWER_BUTTON",
        topology_pb2.HardwareFeatures.FormFactor.RECOVERY_BUTTON: (
            "RECOVERY_BUTTON"
        ),
    }
    recovery_input = (
        hw_topology.form_factor.hardware_feature.form_factor.recovery_input
    )
    if recovery_input and recovery_input in recovery_input_names:
        _upsert(recovery_input_names[recovery_input], result, "recovery-input")

    privacy_screen = hw_topology.screen.hardware_feature.privacy_screen
    if privacy_screen.present == topology_pb2.HardwareFeatures.PRESENT:
        result["has-privacy-screen"] = True

    screen = hw_topology.screen.hardware_feature.screen
    if screen.touch_support == topology_pb2.HardwareFeatures.PRESENT:
        result["has-touchscreen"] = True

    hdmi = hw_topology.hdmi.hardware_feature.hdmi
    if hdmi.present == topology_pb2.HardwareFeatures.PRESENT:
        result["has-hdmi"] = True

    audio = hw_topology.audio.hardware_feature.audio
    if (
        audio.headphone_codec is not None
        and audio.headphone_codec
        != topology_pb2.HardwareFeatures.Audio.AUDIO_CODEC_UNKNOWN
    ):
        result["has-audio-jack"] = True

    if hw_topology.HasField("sd_reader"):
        result["has-sd-reader"] = True

    sensors = hw_topology.accelerometer_gyroscope_magnetometer.hardware_feature
    acc = sensors.accelerometer
    if acc.base_accelerometer == topology_pb2.HardwareFeatures.PRESENT:
        result["has-base-accelerometer"] = True
    if acc.lid_accelerometer == topology_pb2.HardwareFeatures.PRESENT:
        result["has-lid-accelerometer"] = True
    gyro = sensors.gyroscope
    if gyro.base_gyroscope == topology_pb2.HardwareFeatures.PRESENT:
        result["has-base-gyroscope"] = True
    if gyro.lid_gyroscope == topology_pb2.HardwareFeatures.PRESENT:
        result["has-lid-gyroscope"] = True
    magn = sensors.magnetometer
    if magn.base_magnetometer == topology_pb2.HardwareFeatures.PRESENT:
        result["has-base-magnetometer"] = True
    if magn.lid_magnetometer == topology_pb2.HardwareFeatures.PRESENT:
        result["has-lid-magnetometer"] = True
    light_sensor = sensors.light_sensor
    if light_sensor.base_lightsensor == topology_pb2.HardwareFeatures.PRESENT:
        result["has-base-light-sensor"] = True
    if light_sensor.lid_lightsensor == topology_pb2.HardwareFeatures.PRESENT:
        result["has-lid-light-sensor"] = True

    return result


def _build_storage(hw_topology):
    storage_type = (
        hw_topology.non_volatile_storage.hardware_feature.storage.storage_type
    )

    storage_type_names = {
        component_pb2.Component.Storage.StorageType.STORAGE_TYPE_UNKNOWN: (
            "STORAGE_TYPE_UNKNOWN"
        ),
        component_pb2.Component.Storage.StorageType.EMMC: "EMMC",
        component_pb2.Component.Storage.StorageType.NVME: "NVME",
        component_pb2.Component.Storage.StorageType.SATA: "SATA",
        component_pb2.Component.Storage.StorageType.UFS: "UFS",
        component_pb2.Component.Storage.StorageType.BRIDGED_EMMC: "BRIDGED_EMMC",
    }
    result = {}
    if storage_type in storage_type_names:
        result["storage-type"] = storage_type_names[storage_type]

    return result


def _build_stylus(hw_topology):
    stylus_category_names = {
        topology_pb2.HardwareFeatures.Stylus.STYLUS_UNKNOWN: "unknown",
        topology_pb2.HardwareFeatures.Stylus.NONE: "none",
        topology_pb2.HardwareFeatures.Stylus.INTERNAL: "internal",
        topology_pb2.HardwareFeatures.Stylus.EXTERNAL: "external",
    }
    stylus_category = hw_topology.stylus.hardware_feature.stylus.stylus
    result = {}
    if stylus_category in stylus_category_names:
        result["stylus-category"] = stylus_category_names[stylus_category]

    return result


def _fw_bcs_path(payload, ap_fw_suffix=""):
    if payload and payload.firmware_image_name:
        return "bcs://%s%s.%d.%d.%d.tbz2" % (
            payload.firmware_image_name,
            ap_fw_suffix.title(),
            payload.version.major,
            payload.version.minor,
            payload.version.patch,
        )

    return None


def _fw_build_target(payload):
    if payload:
        return payload.build_target_name

    return None


def _get_name_for_config(design_id):
    """Returns the name to use for config naming for a given design ID."""
    if design_id.HasField("config_design_id_override"):
        return design_id.config_design_id_override.value.lower()
    return design_id.value.lower()


def _get_model_name(design_id):
    """Returns the model name to use for a given design ID."""
    if design_id.HasField("model_name_design_id_override"):
        return design_id.model_name_design_id_override.value.lower()
    return design_id.value.lower()


def _calculate_image_name_suffix(hw_design_config):
    fw_config = hw_design_config.hardware_features.fw_config
    return "".join(
        f"_{customization}"
        for customization in sorted(fw_config.coreboot_customizations)
    )


def _build_firmware(config):
    """Returns firmware config, or None if no build targets."""
    fw_payload_config = config.sw_config.firmware
    fw_build_config = config.sw_config.firmware_build_config
    main_ro = fw_payload_config.main_ro_payload
    main_rw = fw_payload_config.main_rw_payload
    ec_ro = fw_payload_config.ec_ro_payload
    ec_rw = fw_payload_config.ec_rw_payload
    pd_ro = fw_payload_config.pd_ro_payload

    build_targets = {}

    _upsert(fw_build_config.build_targets.bmpblk, build_targets, "bmpblk")
    _upsert(
        fw_build_config.build_targets.depthcharge, build_targets, "depthcharge"
    )

    ap_fw_suffix = _calculate_image_name_suffix(config.hw_design_config)

    _upsert(
        fw_build_config.build_targets.coreboot,
        build_targets,
        "coreboot",
        suffix=ap_fw_suffix,
    )
    _upsert(fw_build_config.build_targets.ec, build_targets, "ec")
    _upsert(
        list(fw_build_config.build_targets.ec_extras),
        build_targets,
        "ec_extras",
    )
    _upsert(fw_build_config.build_targets.ish, build_targets, "ish")
    _upsert(
        fw_build_config.build_targets.libpayload, build_targets, "libpayload"
    )
    _upsert(fw_build_config.build_targets.zephyr_ec, build_targets, "zephyr-ec")

    if not build_targets:
        return None

    result = {
        "bcs-overlay": "overlay-%s-private" % config.program.name.lower(),
        "build-targets": build_targets,
    }

    hw_features = config.hw_design_config.hardware_features
    if hw_features.form_factor.HasField("detachable_ui"):
        result["detachable-ui"] = hw_features.form_factor.detachable_ui.value
    else:
        assume_on_ffs = [
            topology_pb2.HardwareFeatures.FormFactor.CHROMESLATE,
            topology_pb2.HardwareFeatures.FormFactor.DETACHABLE,
        ]
        if hw_features.form_factor.form_factor in assume_on_ffs:
            result["detachable-ui"] = True

    if main_ro and main_ro.firmware_image_name:
        _upsert(
            config.hw_design.id.value.lower(),
            result,
            "image-name",
            suffix=ap_fw_suffix,
        )

    _upsert(_fw_bcs_path(main_ro, ap_fw_suffix), result, "main-ro-image")
    _upsert(_fw_bcs_path(main_rw, ap_fw_suffix), result, "main-rw-image")
    _upsert(_fw_bcs_path(ec_ro), result, "ec-ro-image")
    _upsert(_fw_bcs_path(ec_rw), result, "ec-rw-image")
    _upsert(_fw_bcs_path(pd_ro), result, "pd-ro-image")

    _upsert(
        config.hw_design_config.hardware_features.fw_config.value,
        result,
        "firmware-config",
    )

    return result


def _build_fw_signing(config, whitelabel):
    if config.sw_config.firmware and config.device_signer_config:
        ap_fw_suffix = _calculate_image_name_suffix(config.hw_design_config)
        hw_design = config.hw_design.name.lower()
        if ap_fw_suffix:
            hw_design += ap_fw_suffix
        brand_scan_config = config.brand_config.scan_config
        if brand_scan_config and brand_scan_config.whitelabel_tag:
            signature_id = "%s-%s" % (
                hw_design,
                brand_scan_config.whitelabel_tag,
            )
        else:
            signature_id = hw_design

        result = {
            "key-id": config.device_signer_config.key_id,
            "signature-id": signature_id,
        }
        if whitelabel:
            result["sig-id-in-customization-id"] = True
        return result
    return {}


def _build_usb(config: Config):
    """Builds the usb configuration.

    Args:
        config: Config namedtuple

    Returns:
        usb configuration.
    """
    if not config.sw_config.usb_config:
        return None

    usb_config = config.sw_config.usb_config
    if not usb_config.HasField("typecd"):
        return None

    typecd = usb_config.typecd
    result = {}

    _upsert(typecd.dp_only, result, "mode-entry-dp-only")
    return result


def _file(source, destination, symlink=None):
    if not symlink:
        return {"destination": str(destination), "source": str(source)}

    return {
        "destination": str(destination),
        "source": str(source),
        "symlink": str(symlink),
    }


def _file_v2(build_path, system_path):
    return {"build-path": build_path, "system-path": system_path}


class _AudioConfigBuilder:
    """The audio config builder"""

    _ALSA_PATH = pathlib.PurePath("/usr/share/alsa/ucm")
    _CRAS_PATH = pathlib.PurePath("/etc/cras")
    _SOUND_CARD_INIT_PATH = pathlib.PurePath("/etc/sound_card_init")
    _MODULE_PATH = pathlib.PurePath("/etc/modprobe.d")
    _AUDIO_CONFIG_PATH = "audio"
    _CRAS_CONFIG_PATH = "cras-config"
    AudioConfigStructure = (
        topology_pb2.HardwareFeatures.Audio.AudioConfigStructure
    )
    Camera = topology_pb2.HardwareFeatures.Camera

    def __init__(self, config):
        self._config = config

        self._files = []
        self._ucm_suffixes = set()
        self._cras_suffixes = set()
        self._sound_card_init_confs = set()

    @property
    def _program_audio(self):
        return self._config.program.audio_config

    @property
    def _audio(self):
        return self._hw_features.audio

    @property
    def _design_name(self):
        return _get_name_for_config(self._config.hw_design.id)

    @property
    def _hw_features(self):
        return self._config.hw_design_config.hardware_features

    @staticmethod
    def _get_audio_enum_name(
        audio_enum: topology_pb2.HardwareFeatures.Audio, numeric_value: int
    ) -> str:
        """Get name from last underscore."""
        name = audio_enum.Name(numeric_value)
        if numeric_value != 0:
            # skip for unknown type
            _, _, name = name.rpartition("_")
        return name

    def _build_source_path(self, config_structure, config_path):
        if config_structure == self.AudioConfigStructure.COMMON:
            return pathlib.PurePath("common").joinpath(
                self._AUDIO_CONFIG_PATH, config_path
            )
        if config_structure == self.AudioConfigStructure.DESIGN:
            return pathlib.PurePath(self._design_name).joinpath(
                self._AUDIO_CONFIG_PATH, config_path
            )
        return None

    def _count_mics(self, facing):
        return sum(
            device.microphone_count.value
            for device in self._hw_features.camera.devices
            if device.facing == facing
        )

    def _build_suffix(self, card_config, config_type="ucm"):
        if config_type not in ("ucm", "cras"):
            raise Exception("Not supported config type.")

        suffix_format = getattr(
            self._program_audio, f"default_{config_type}_suffix"
        )
        if card_config.HasField(f"{config_type}_suffix"):
            suffix_format = getattr(card_config, f"{config_type}_suffix").value

        design_name = self._design_name
        if (
            getattr(card_config, f"{config_type}_config")
            == self.AudioConfigStructure.COMMON
        ):
            design_name = ""

        uf_mics = self._count_mics(self.Camera.FACING_FRONT)
        wf_mics = self._count_mics(self.Camera.FACING_BACK)
        mic_details = [(uf_mics, "uf"), (wf_mics, "wf")]
        suffix = suffix_format.format(
            headset_codec=self._get_audio_enum_name(
                topology_pb2.HardwareFeatures.Audio.AudioCodec,
                self._audio.headphone_codec,
            ).lower()
            if self._audio.headphone_codec
            else "",
            speaker_amp=self._get_audio_enum_name(
                topology_pb2.HardwareFeatures.Audio.Amplifier,
                self._audio.speaker_amp,
            ).lower()
            if self._audio.speaker_amp
            else "",
            design=design_name,
            camera_count=len(self._hw_features.camera.devices),
            mic_description="".join(
                f"{position[0]}{position[1]}" if position[0] else ""
                for position in mic_details
            ),
            total_mic_count=uf_mics + wf_mics,
            user_facing_mic_count=uf_mics,
            world_facing_mic_count=wf_mics,
        )
        return ".".join(
            [component for component in suffix.split(".") if component]
        )

    def _build_audio_card(self, card_config):
        ucm_suffix = self._build_suffix(card_config, "ucm")
        cras_suffix = self._build_suffix(card_config, "cras")
        card_with_suffix = ".".join([card_config.card_name, ucm_suffix]).strip(
            "."
        )
        card, _, card_suffix = card_config.card_name.partition(".")
        ucm_suffix = ".".join([card_suffix, ucm_suffix]).strip(".")
        self._ucm_suffixes.add(ucm_suffix)
        self._cras_suffixes.add(cras_suffix)

        ucm_config_source_directory = self._build_source_path(
            card_config.ucm_config, "ucm-config"
        )
        self._files.append(
            _file(
                ucm_config_source_directory.joinpath(
                    card_with_suffix, "HiFi.conf"
                ),
                self._ALSA_PATH.joinpath(card_with_suffix, "HiFi.conf"),
            )
        )
        self._files.append(
            _file(
                ucm_config_source_directory.joinpath(
                    card_with_suffix, f"{card_with_suffix}.conf"
                ),
                self._ALSA_PATH.joinpath(
                    card_with_suffix, f"{card_with_suffix}.conf"
                ),
            )
        )

        cras_config_with_suffix = self._CRAS_CONFIG_PATH
        design_name_with_suffix = self._design_name
        if cras_suffix:
            cras_config_with_suffix = f"{cras_config_with_suffix}.{cras_suffix}"
            design_name_with_suffix = f"{design_name_with_suffix}.{cras_suffix}"

        cras_config_source_path = self._build_source_path(
            card_config.cras_config, cras_config_with_suffix
        )
        if cras_config_source_path:
            card_settings = f"{card}.card_settings"
            self._files.append(
                _file(
                    cras_config_source_path / card_settings,
                    self._CRAS_PATH.joinpath(
                        design_name_with_suffix, card_settings
                    ),
                )
            )

        card_init_config_source_path = self._build_source_path(
            card_config.sound_card_init_config, "sound-card-init-config"
        )

        if card_init_config_source_path:
            speaker_amp = self._get_audio_enum_name(
                topology_pb2.HardwareFeatures.Audio.Amplifier,
                self._audio.speaker_amp,
            )
            sound_card_init_conf = f"{self._design_name}.{speaker_amp}.yaml"
            self._files.append(
                _file(
                    card_init_config_source_path.joinpath(sound_card_init_conf),
                    self._SOUND_CARD_INIT_PATH.joinpath(sound_card_init_conf),
                )
            )
            self._sound_card_init_confs.add(sound_card_init_conf)
        else:
            self._sound_card_init_confs.add(None)

    @staticmethod
    def _select_from_set(values, description):
        if not values:
            return None
        if len(values) == 1:
            return next(iter(values))
        values -= set([None, ""])
        if len(values) == 1:
            return next(iter(values))
        raise Exception(f'Inconsistent values for "{description}": {values}')

    def build(self):
        """Builds the audio configuration."""
        if (
            not self._hw_features.audio
            or not self._hw_features.audio.card_configs
        ):
            return {}

        program_name = self._config.program.name.lower()

        for card_config in itertools.chain(
            self._audio.card_configs, self._program_audio.card_configs
        ):
            self._build_audio_card(card_config)

        cras_config_with_suffix = self._CRAS_CONFIG_PATH
        design_name_with_suffix = self._design_name

        cras_suffix = self._select_from_set(self._cras_suffixes, "cras-suffix")
        if cras_suffix:
            design_name_with_suffix = f"{design_name_with_suffix}.{cras_suffix}"
            cras_config_with_suffix = f"{cras_config_with_suffix}.{cras_suffix}"

        cras_config_source_path = self._build_source_path(
            self._audio.cras_config, cras_config_with_suffix
        )
        if cras_config_source_path:
            for filename in ["dsp.ini", "board.ini", "apm.ini"]:
                self._files.append(
                    _file(
                        cras_config_source_path.joinpath(filename),
                        self._CRAS_PATH.joinpath(
                            design_name_with_suffix, filename
                        ),
                    )
                )

        if self._program_audio.has_module_file:
            module_name = f"alsa-{program_name}.conf"
            self._files.append(
                _file(
                    self._build_source_path(
                        self.AudioConfigStructure.COMMON, "alsa-module-config"
                    ).joinpath(module_name),
                    self._MODULE_PATH.joinpath(module_name),
                )
            )

        result = {
            "main": {
                "cras-config-dir": design_name_with_suffix,
                "files": self._files,
            }
        }

        ucm_suffix = self._select_from_set(self._ucm_suffixes, "ucm-suffix")
        if ucm_suffix:
            result["main"]["ucm-suffix"] = ucm_suffix

        sound_card_init_conf = self._select_from_set(
            self._sound_card_init_confs, "sound-card-init-conf"
        )
        if sound_card_init_conf:
            result["main"]["sound-card-init-conf"] = sound_card_init_conf
            result["main"][
                "speaker-amp"
            ] = topology_pb2.HardwareFeatures.Audio.Amplifier.Name(
                self._audio.speaker_amp
            )

        return result


def _build_audio(config):
    # pylint: disable=too-many-locals
    # pylint: disable=too-many-branches
    if not config.sw_config.audio_configs:
        builder = _AudioConfigBuilder(config)
        return builder.build()

    alsa_path = "/usr/share/alsa/ucm"
    cras_path = "/etc/cras"
    sound_card_init_path = "/etc/sound_card_init"
    design_name = config.hw_design.name.lower()
    program_name = config.program.name.lower()
    files = []
    ucm_suffix = None
    sound_card_init_conf = None
    audio_pb = topology_pb2.HardwareFeatures.Audio
    hw_feature = config.hw_design_config.hardware_features

    for audio in config.sw_config.audio_configs:
        card = audio.card_name
        card_with_suffix = audio.card_name

        if audio.cras_custom_name:
            design_name = audio.cras_custom_name

        if audio.ucm_suffix:
            # TODO: last ucm_suffix wins.
            ucm_suffix = audio.ucm_suffix
            card_with_suffix += "." + audio.ucm_suffix
        if audio.ucm_file:
            files.append(
                _file(
                    audio.ucm_file,
                    "%s/%s/HiFi.conf" % (alsa_path, card_with_suffix),
                )
            )
        if audio.ucm_master_file:
            files.append(
                _file(
                    audio.ucm_master_file,
                    "%s/%s/%s.conf"
                    % (alsa_path, card_with_suffix, card_with_suffix),
                )
            )
        if audio.card_config_file:
            files.append(
                _file(
                    audio.card_config_file,
                    "%s/%s/%s" % (cras_path, design_name, card),
                )
            )
        if audio.dsp_file:
            files.append(
                _file(
                    audio.dsp_file, "%s/%s/dsp.ini" % (cras_path, design_name)
                )
            )
        if audio.module_file:
            files.append(
                _file(
                    audio.module_file,
                    "/etc/modprobe.d/alsa-%s.conf" % program_name,
                )
            )
        if audio.board_file:
            files.append(
                _file(
                    audio.board_file,
                    "%s/%s/board.ini" % (cras_path, design_name),
                )
            )
        if audio.sound_card_init_file:
            sound_card_init_conf = design_name + ".yaml"
            files.append(
                _file(
                    audio.sound_card_init_file,
                    "%s/%s.yaml" % (sound_card_init_path, design_name),
                )
            )

    result = {
        "main": {
            "cras-config-dir": design_name,
            "files": files,
        }
    }

    if ucm_suffix:
        result["main"]["ucm-suffix"] = ucm_suffix
    if sound_card_init_conf:
        result["main"]["sound-card-init-conf"] = sound_card_init_conf
        result["main"]["speaker-amp"] = audio_pb.Amplifier.Name(
            hw_feature.audio.speaker_amp
        )

    return result


def _build_battery(hw_topology):
    hw_features = hw_topology.hw_design_config.hardware_features
    hw_feat_battery = hw_features.battery

    result = {}
    if hw_feat_battery.no_battery_boot_supported:
        result[
            "no-battery-boot-supported"
        ] = hw_feat_battery.no_battery_boot_supported
    return result


def _build_camera(hw_topology):
    camera_pb = topology_pb2.HardwareFeatures.Camera
    camera = hw_topology.camera.hardware_feature.camera
    result = {"count": len(camera.devices)}
    if camera.devices:
        result["devices"] = []
        for device in camera.devices:
            interface = {
                camera_pb.INTERFACE_USB: "usb",
                camera_pb.INTERFACE_MIPI: "mipi",
            }[device.interface]
            facing = {
                camera_pb.FACING_FRONT: "front",
                camera_pb.FACING_BACK: "back",
            }[device.facing]
            orientation = {
                camera_pb.ORIENTATION_0: 0,
                camera_pb.ORIENTATION_90: 90,
                camera_pb.ORIENTATION_180: 180,
                camera_pb.ORIENTATION_270: 270,
            }[device.orientation]
            flags = {
                "support-1080p": bool(
                    device.flags & camera_pb.FLAGS_SUPPORT_1080P
                ),
                "support-autofocus": bool(
                    device.flags & camera_pb.FLAGS_SUPPORT_AUTOFOCUS
                ),
            }
            dev = {
                "interface": interface,
                "facing": facing,
                "orientation": orientation,
                "flags": flags,
                "ids": list(device.ids),
            }
            if (
                device.privacy_switch
                != topology_pb2.HardwareFeatures.PRESENT_UNKNOWN
            ):
                dev["has-privacy-switch"] = (
                    device.privacy_switch
                    == topology_pb2.HardwareFeatures.PRESENT
                )
            if device.detachable:
                dev["detachable"] = True
            result["devices"].append(dev)
    return result


def _build_identity(config):
    hw_scan_config = config.sw_config.id_scan_config
    program = config.program
    brand_scan_config = config.brand_config.scan_config
    identity = {}
    ap_fw_suffix = _calculate_image_name_suffix(config.hw_design_config).title()
    _upsert(hw_scan_config.frid, identity, "frid", suffix=ap_fw_suffix)
    _upsert(hw_scan_config.firmware_sku, identity, "sku-id")
    # 'platform-name' is needed to support 'mosys platform name'.
    # Clients should no longer require platform name, but set it here for
    # backwards compatibility.
    if program.mosys_platform_name:
        _upsert(program.mosys_platform_name, identity, "platform-name")
    else:
        _upsert(program.name, identity, "platform-name")
    if brand_scan_config:
        _upsert(brand_scan_config.whitelabel_tag, identity, "whitelabel-tag")

    return identity


def _lookup(id_value, id_map):
    if not id_value.value:
        return None

    key = id_value.value
    if key in id_map:
        return id_map[id_value.value]
    error = "Failed to lookup %s with value: %s" % (
        id_value.__class__.__name__.replace("Id", ""),
        key,
    )
    print(error)
    print("Check the config contents provided:")
    printer = pprint.PrettyPrinter(indent=4)
    printer.pprint(id_map)
    raise Exception(error)


def _build_touch_file_config(config, project_name):
    partners = {x.id.value: x for x in config.partner_list}
    files = []
    for comp in config.components:
        touch = comp.touchscreen
        # Everything is the same for Touch screen/pad, except different fields
        if comp.HasField("touchpad"):
            touch = comp.touchpad
        if touch.product_id:
            vendor = _lookup(comp.manufacturer_id, partners)
            if not vendor:
                raise Exception(
                    "Manufacturer must be set for touch device %s"
                    % comp.id.value
                )

            product_id = touch.product_id
            fw_version = touch.fw_version

            file_name = "%s_%s.bin" % (product_id, fw_version)
            fw_file_path = os.path.join(TOUCH_PATH, vendor.name, file_name)

            if not os.path.exists(fw_file_path):
                raise Exception(
                    "Touchscreen fw bin file doesn't exist at: %s"
                    % fw_file_path
                )

            touch_vendor = vendor.touch_vendor
            sym_link = touch_vendor.symlink_file_format.format(
                vendor_name=vendor.name,
                vendor_id=touch_vendor.vendor_id,
                product_id=product_id,
                fw_version=fw_version,
                product_series=touch.product_series,
            )

            dest = "%s_%s" % (vendor.name, file_name)
            if touch_vendor.destination_file_format:
                dest = touch_vendor.destination_file_format.format(
                    vendor_name=vendor.name,
                    vendor_id=touch_vendor.vendor_id,
                    product_id=product_id,
                    fw_version=fw_version,
                    product_series=touch.product_series,
                )

            files.append(
                {
                    "destination": os.path.join(
                        "/opt/google/touch/firmware", dest
                    ),
                    "source": os.path.join(project_name, fw_file_path),
                    "symlink": os.path.join("/lib/firmware", sym_link),
                }
            )

    result = {}
    _upsert(files, result, "files")
    return result


def _build_modem(config):
    """Returns the cellular modem configuration, or None if absent."""
    hw_features = config.hw_design_config.hardware_features
    cellular_support = _any_present([hw_features.cellular.present])
    if not cellular_support:
        return None
    if hw_features.cellular.model:
        firmware_variant = hw_features.cellular.model.lower()
    else:
        firmware_variant = config.hw_design.name.lower()
    result = {"firmware-variant": firmware_variant}
    if hw_features.cellular.attach_apn_required:
        result["attach-apn-required"] = True
    return result


def _build_scheduler_tune(config):
    """Build the scheduler_tune configuration."""
    scheduler_tune = config.program.platform.scheduler_tune
    if not scheduler_tune:
        return None

    result = {}
    if scheduler_tune.boost_urgent != 0:
        _upsert(scheduler_tune.boost_urgent, result, "boost-urgent")
    if scheduler_tune.boost_top_app != 0:
        _upsert(scheduler_tune.boost_top_app, result, "boost-top-app")
    if scheduler_tune.boost_arcvm != 0:
        _upsert(scheduler_tune.boost_arcvm, result, "boost-arcvm")
    _upsert(scheduler_tune.cpuset_nonurgent, result, "cpuset-nonurgent")
    if scheduler_tune.input_boost != 0:
        _upsert(scheduler_tune.input_boost, result, "input-boost")

    return result


def _build_thermal_config(config, dptf_map):
    if not dptf_map:
        return None

    thermal = config.hw_design_config.hardware_features.thermal
    suffix = thermal.config_path_suffix or ""
    design_name = "_".join(
        component
        for component in [_get_name_for_config(config.hw_design.id), suffix]
        if component
    )
    design_config_id_path = os.path.join(
        design_name, config.hw_design_config.id.value.rpartition(":")[2]
    )
    # Prefer design_config level (sku)
    # Then design level
    # If neither, fall back to project wide config (mapped to `suffix`)
    return dptf_map.get(
        design_config_id_path,
        dptf_map.get(design_name, dptf_map.get(suffix, None)),
    )


def _sw_config(sw_configs, design_config_id):
    """Returns the correct software config for `design_config_id`.

    Returns the correct software config match for `design_config_id`. If no such
    config or multiple such configs are found an exception is raised.
    """
    sw_config_matches = [
        x for x in sw_configs if x.design_config_id.value == design_config_id
    ]
    if len(sw_config_matches) == 1:
        return sw_config_matches[0]
    if len(sw_config_matches) > 1:
        raise ValueError(
            "Multiple software configs found for: %s" % design_config_id
        )
    raise ValueError("Software config is required for: %s" % design_config_id)


def _is_whitelabel(brand_configs, device_brands):
    for device_brand in device_brands:
        if device_brand.id.value in brand_configs:
            brand_scan_config = brand_configs[device_brand.id.value].scan_config
            if brand_scan_config and brand_scan_config.whitelabel_tag:
                return True
    return False


def _transform_build_configs(
    config, config_files=ConfigFiles({}, {}, {}, {}, {}, {}, {})
):
    # pylint: disable=too-many-locals,too-many-branches
    partners = {x.id.value: x for x in config.partner_list}
    programs = {x.id.value: x for x in config.program_list}
    sw_configs = list(config.software_configs)
    brand_configs = {x.brand_id.value: x for x in config.brand_configs}

    results = {}
    for hw_design in config.design_list:
        if config.device_brand_list:
            device_brands = [
                x
                for x in config.device_brand_list
                if x.design_id.value == hw_design.id.value
            ]
        else:
            device_brands = [device_brand_pb2.DeviceBrand()]

        whitelabel = _is_whitelabel(brand_configs, device_brands)

        for device_brand in device_brands:
            # Brand config can be empty since platform JSON config allows it
            brand_config = brand_config_pb2.BrandConfig()
            if device_brand.id.value in brand_configs:
                brand_config = brand_configs[device_brand.id.value]

            for hw_design_config in hw_design.configs:
                sw_config = _sw_config(sw_configs, hw_design_config.id.value)
                program = _lookup(hw_design.program_id, programs)
                signer_configs_by_design = {}
                signer_configs_by_brand = {}
                for signer_config in program.device_signer_configs:
                    design_id = signer_config.design_id.value
                    brand_id = signer_config.brand_id.value
                    if design_id:
                        signer_configs_by_design[design_id] = signer_config
                    elif brand_id:
                        signer_configs_by_brand[brand_id] = signer_config
                    else:
                        raise Exception(
                            "No ID found for signer config: %s" % signer_config
                        )

                device_signer_config = None
                if signer_configs_by_design or signer_configs_by_brand:
                    design_id = hw_design.id.value
                    brand_id = device_brand.id.value
                    if design_id in signer_configs_by_design:
                        device_signer_config = signer_configs_by_design[
                            design_id
                        ]
                    elif brand_id in signer_configs_by_brand:
                        device_signer_config = signer_configs_by_brand[brand_id]
                    else:
                        # Assume that if signer configs are set, every config
                        # is setup
                        raise Exception(
                            "Signer config missing for design: %s, brand: %s"
                            % (design_id, brand_id)
                        )

                transformed_config = _transform_build_config(
                    Config(
                        program=program,
                        hw_design=hw_design,
                        odm=_lookup(hw_design.odm_id, partners),
                        hw_design_config=hw_design_config,
                        device_brand=device_brand,
                        device_signer_config=device_signer_config,
                        oem=_lookup(device_brand.oem_id, partners),
                        sw_config=sw_config,
                        brand_config=brand_config,
                    ),
                    config_files,
                    whitelabel,
                )

                config_json = json.dumps(
                    transformed_config,
                    sort_keys=True,
                    indent=2,
                    separators=(",", ": "),
                )

                if config_json not in results:
                    results[config_json] = transformed_config

    return list(results.values())


def _transform_build_config(config, config_files, whitelabel):
    """Transforms Config instance into target platform JSON schema.

    Args:
        config: Config namedtuple
        config_files: Map to look up the generated config files.
        whitelabel: Whether the config is for a whitelabel design

    Returns:
        Unique config payload based on the platform JSON schema.
    """
    result = {
        "identity": _build_identity(config),
        "name": _get_model_name(config.hw_design.id),
    }

    _upsert(_build_arc(config, config_files), result, "arc")
    _upsert(_build_audio(config), result, "audio")
    _upsert(_build_battery(config), result, "battery")
    _upsert(_build_bluetooth(config), result, "bluetooth")
    _upsert(
        _build_displays(config.hw_design_config.hardware_topology),
        result,
        "displays",
    )
    _upsert(_build_wifi(config, config_files), result, "wifi")
    _upsert(_build_health(config), result, "cros-healthd")
    _upsert(_build_rma(config), result, "rmad")
    _upsert(_build_nnpalm(config), result, "nnpalm")
    _upsert(_build_proximity(config, config_files), result, "proximity-sensor")
    _upsert(_build_branding(config), result, "branding")
    _upsert(_build_pvs(config), result, "pvs")
    _upsert(config.brand_config.wallpaper, result, "wallpaper")
    _upsert(config.brand_config.regulatory_label, result, "regulatory-label")
    _upsert(config.device_brand.brand_code, result, "brand-code")
    _upsert(
        _build_camera(config.hw_design_config.hardware_topology),
        result,
        "camera",
    )
    _upsert(_build_firmware(config), result, "firmware")
    _upsert(_build_fw_signing(config, whitelabel), result, "firmware-signing")
    _upsert(
        _build_fingerprint(config.hw_design_config.hardware_topology),
        result,
        "fingerprint",
    )
    _upsert(_build_ui(config), result, "ui")
    _upsert(_build_usb(config), result, "typecd")
    _upsert(_build_power(config), result, "power")
    _upsert(_build_resource(config), result, "resource")
    _upsert(_build_scheduler_tune(config), result, "scheduler-tune")
    _upsert(
        _build_thermal_config(config, config_files.dptf_map), result, "thermal"
    )
    if config_files.camera_map:
        camera_file = config_files.camera_map.get(config.hw_design.name, {})
        _upsert(camera_file, result, "camera")
    _upsert(config_files.touch_fw, result, "touch")
    _upsert(
        _build_hardware_properties(config.hw_design_config.hardware_topology),
        result,
        "hardware-properties",
    )
    _upsert(_build_modem(config), result, "modem")
    _upsert(
        _build_keyboard(config.hw_design_config.hardware_topology),
        result,
        "keyboard",
    )
    _upsert(
        _build_hps(config.hw_design_config.hardware_topology), result, "hps"
    )
    _upsert(
        _build_poe(config.hw_design_config.hardware_topology),
        result,
        "hardware-properties",
    )
    _upsert(
        _build_storage(config.hw_design_config.hardware_topology),
        result,
        "hardware-properties",
    )
    _upsert(
        _build_stylus(config.hw_design_config.hardware_topology),
        result,
        "hardware-properties",
    )
    _upsert(
        _build_dgpu(config.hw_design_config.hardware_topology), result, "dgpu"
    )
    _upsert(
        _build_uwb(config.hw_design_config.hardware_topology), result, "uwb"
    )
    _upsert(
        _build_detachable_base(
            config.hw_design_config.hardware_features.form_factor.form_factor,
            config.hw_design_config.hardware_features.detachable_base,
        ),
        result,
        "detachable-base",
    )

    return result


def write_output(configs, output=None):
    """Writes a list of configs to platform JSON format.

    Args:
        configs: List of config dicts defined in cros_config_schema.yaml
        output: Target file output (if None, prints to stdout)
    """
    json_output = json.dumps(
        {
            "chromeos": {
                "configs": configs,
            }
        },
        sort_keys=True,
        indent=2,
        separators=(",", ": "),
    )
    if output:
        with open(output, "w", encoding="utf-8") as output_stream:
            # Using print function adds proper trailing newline.
            print(json_output, file=output_stream)
    else:
        print(json_output)


def _feature(name, present):
    attrib = {"name": name}
    if present:
        return etree.Element("feature", attrib=attrib)

    return etree.Element("unavailable-feature", attrib=attrib)


def _any_present(features):
    return topology_pb2.HardwareFeatures.PRESENT in features


def _get_formatted_config_id(design_config):
    return design_config.id.value.lower().replace(":", "_")


def _write_file(output_dir, file_name, file_content):
    os.makedirs(output_dir, exist_ok=True)
    output = os.path.join(output_dir, file_name)
    with open(output, "wb") as f:
        f.write(file_content)


def _get_arc_camera_features(camera, camera_config):
    """Gets camera related features for ARC hardware_features.xml from camera

    topology. Check
    https://developer.android.com/reference/android/content/pm/
    PackageManager#FEATURE_CAMERA
    and CTS android.app.cts.SystemFeaturesTest#testCameraFeatures for the
    correct settings.

    Args:
        camera: A HardwareFeatures.Camera proto message.
        camera_config: SoftwareFeatures.camera_conifg.

    Returns:
        list of camera related ARC features as XML elements.
    """
    camera_pb = topology_pb2.HardwareFeatures.Camera

    # Camera stack treats detachable cameras as external.
    count = len(camera.devices)
    has_front_camera = any(
        (
            not d.detachable and d.facing == camera_pb.FACING_FRONT
            for d in camera.devices
        )
    )
    has_back_camera = any(
        (
            not d.detachable and d.facing == camera_pb.FACING_BACK
            for d in camera.devices
        )
    )
    has_autofocus_back_camera = any(
        (
            not d.detachable
            and d.facing == camera_pb.FACING_BACK
            and d.flags & camera_pb.FLAGS_SUPPORT_AUTOFOCUS
            for d in camera.devices
        )
    )
    # Assumes MIPI cameras support FULL-level.
    # TODO(kamesan): Setting this in project configs when there's an exception.
    has_level_full_camera = any(
        (d.interface == camera_pb.INTERFACE_MIPI for d in camera.devices)
    )
    has_detachable_camera = any(d.detachable for d in camera.devices)

    features = [
        _feature("android.hardware.camera", has_back_camera),
        _feature(
            "android.hardware.camera.any",
            count > 0 or camera_config.has_external_camera,
        ),
        _feature(
            "android.hardware.camera.autofocus", has_autofocus_back_camera
        ),
        _feature(
            "android.hardware.camera.capability.manual_post_processing",
            has_level_full_camera,
        ),
        _feature(
            "android.hardware.camera.capability.manual_sensor",
            has_level_full_camera,
        ),
        _feature("android.hardware.camera.front", has_front_camera),
        _feature("android.hardware.camera.level.full", has_level_full_camera),
    ]
    if has_detachable_camera or camera_config.has_external_camera:
        features.append(_feature("android.hardware.camera.external", True))

    return features


def _generate_arc_hardware_features(hw_features, sw_config, _program):
    """Generates ARC hardware_features.xml file content.

    Args:
        hw_features: HardwareFeatures proto message.
        sw_config: SoftwareConfig proto message.
        _program: Unused.

    Returns:
        bytes of the hardware_features.xml content.
    """
    touchscreen = _any_present([hw_features.screen.touch_support])
    acc = hw_features.accelerometer
    gyro = hw_features.gyroscope
    compass = hw_features.magnetometer
    light_sensor = hw_features.light_sensor
    root = etree.Element("permissions")
    root.extend(
        _get_arc_camera_features(hw_features.camera, sw_config.camera_config)
        + [
            _feature(
                "android.hardware.sensor.accelerometer",
                _any_present([acc.lid_accelerometer, acc.base_accelerometer]),
            ),
            _feature(
                "android.hardware.sensor.gyroscope",
                _any_present([gyro.lid_gyroscope, gyro.base_gyroscope]),
            ),
            _feature(
                "android.hardware.sensor.compass",
                _any_present(
                    [compass.lid_magnetometer, compass.base_magnetometer]
                ),
            ),
            _feature(
                "android.hardware.sensor.light",
                _any_present(
                    [
                        light_sensor.lid_lightsensor,
                        light_sensor.base_lightsensor,
                    ]
                ),
            ),
            _feature("android.hardware.touchscreen", touchscreen),
            _feature("android.hardware.touchscreen.multitouch", touchscreen),
            _feature(
                "android.hardware.touchscreen.multitouch.distinct", touchscreen
            ),
            _feature(
                "android.hardware.touchscreen.multitouch.jazzhand", touchscreen
            ),
        ]
    )
    return XML_DECLARATION + etree.tostring(root, pretty_print=True)


def _generate_arc_media_profiles(hw_features, sw_config, program, dtd_path):
    """Generates ARC media_profiles.xml file content.

    Args:
        hw_features: HardwareFeatures proto message.
        sw_config: SoftwareConfig proto message.
        program: Corresponding program in ConfigBundle.program_list.
        dtd_path: Full path to dtd media profiles file.

    Returns:
        bytes of the media_profiles.xml content, or None if |sw_config|
        disables the generation or there's no camera.
    """

    # pylint: disable=too-many-locals

    def _gen_camcorder_profiles(camera_id, resolutions):
        elem = etree.Element(
            "CamcorderProfiles", attrib={"cameraId": str(camera_id)}
        )
        for width, height in resolutions:
            elem.extend(
                [
                    _gen_encoder_profile(width, height, False),
                    _gen_encoder_profile(width, height, True),
                ]
            )
        elem.extend(
            [
                etree.Element("ImageEncoding", attrib={"quality": "90"}),
                etree.Element("ImageEncoding", attrib={"quality": "80"}),
                etree.Element("ImageEncoding", attrib={"quality": "70"}),
                etree.Element("ImageDecoding", attrib={"memCap": "20000000"}),
            ]
        )
        return elem

    def _gen_encoder_profile(width, height, timelapse):
        elem = etree.Element(
            "EncoderProfile",
            attrib={
                "quality": ("timelapse" if timelapse else "")
                + str(height)
                + "p",
                "fileFormat": "mp4",
                "duration": "60",
            },
        )
        elem.append(
            etree.Element(
                "Video",
                attrib={
                    "codec": "h264",
                    "bitRate": "8000000",
                    "width": str(width),
                    "height": str(height),
                    "frameRate": "30",
                },
            )
        )
        elem.append(
            etree.Element(
                "Audio",
                attrib={
                    "codec": "aac",
                    "bitRate": "96000",
                    "sampleRate": "44100",
                    "channels": "1",
                },
            )
        )
        return elem

    def _gen_video_encoder_cap(name, min_bit_rate, max_bit_rate):
        return etree.Element(
            "VideoEncoderCap",
            attrib={
                "name": name,
                "enabled": "true",
                "minBitRate": str(min_bit_rate),
                "maxBitRate": str(max_bit_rate),
                "minFrameWidth": "320",
                "maxFrameWidth": "1920",
                "minFrameHeight": "240",
                "maxFrameHeight": "1080",
                "minFrameRate": "15",
                "maxFrameRate": "30",
            },
        )

    def _gen_audio_encoder_cap(
        name, min_bit_rate, max_bit_rate, min_sample_rate, max_sample_rate
    ):
        return etree.Element(
            "AudioEncoderCap",
            attrib={
                "name": name,
                "enabled": "true",
                "minBitRate": str(min_bit_rate),
                "maxBitRate": str(max_bit_rate),
                "minSampleRate": str(min_sample_rate),
                "maxSampleRate": str(max_sample_rate),
                "minChannels": "1",
                "maxChannels": "1",
            },
        )

    camera_config = sw_config.camera_config
    if (
        not camera_config.generate_media_profiles
        and not program.generate_camera_media_profiles
    ):
        return None

    camera_pb = topology_pb2.HardwareFeatures.Camera
    root = etree.Element("MediaSettings")
    camera_id = 0
    for facing in [camera_pb.FACING_BACK, camera_pb.FACING_FRONT]:
        camera_device = next(
            (
                d
                for d in hw_features.camera.devices
                if not d.detachable and d.facing == facing
            ),
            None,
        )
        if camera_device is None:
            continue
        if camera_config.camcorder_resolutions:
            resolutions = [
                (r.width, r.height) for r in camera_config.camcorder_resolutions
            ]
        else:
            resolutions = [(1280, 720)]
            if camera_device.flags & camera_pb.FLAGS_SUPPORT_1080P:
                resolutions.append((1920, 1080))
        root.append(_gen_camcorder_profiles(camera_id, resolutions))
        camera_id += 1
    # media_profiles.xml should have at least one CamcorderProfiles.
    if camera_id == 0:
        return None

    root.extend(
        [
            etree.Element("EncoderOutputFileFormat", attrib={"name": "3gp"}),
            etree.Element("EncoderOutputFileFormat", attrib={"name": "mp4"}),
            _gen_video_encoder_cap("h264", 64000, 17000000),
            _gen_video_encoder_cap("h263", 64000, 1000000),
            _gen_video_encoder_cap("m4v", 64000, 2000000),
            _gen_audio_encoder_cap("aac", 758, 288000, 8000, 48000),
            _gen_audio_encoder_cap("heaac", 8000, 64000, 16000, 48000),
            _gen_audio_encoder_cap("aaceld", 16000, 192000, 16000, 48000),
            _gen_audio_encoder_cap("amrwb", 6600, 23050, 16000, 16000),
            _gen_audio_encoder_cap("amrnb", 5525, 12200, 8000, 8000),
            etree.Element(
                "VideoDecoderCap", attrib={"name": "wmv", "enabled": "false"}
            ),
            etree.Element(
                "AudioDecoderCap", attrib={"name": "wma", "enabled": "false"}
            ),
        ]
    )

    if not dtd_path.exists():
        raise Exception(
            "%s file does not exist. Please specify correct path." % dtd_path
        )
    dtd = etree.DTD(str(dtd_path))
    if not dtd.validate(root):
        raise etree.DTDValidateError(
            f"Invalid media_profiles.xml generated:\n{dtd.error_log}"
        )

    return XML_DECLARATION + etree.tostring(root, pretty_print=True)


def _write_files_by_design_config(
    configs,
    output_dir,
    build_dir,
    system_dir,
    file_name_template,
    generate_file_content,
):
    """Writes generated files for each design config.

    Args:
        configs: Source ConfigBundle to process.
        output_dir: Path to the generated output.
        build_dir: Path to the config file from portage's perspective.
        system_dir: Path to the config file in the target device.
        file_name_template: Template string of the config file name including
                            one
        format()-style replacement field for the config id,
                            e.g. 'config_{}.xml'.
        generate_file_content: Function to generate config file content from
        HardwareFeatures and SoftwareConfig proto.

    Returns:
        dict that maps the formatted config id to the correct file.
    """
    # pylint: disable=too-many-arguments,too-many-locals
    result = {}
    configs_by_design = {}
    programs = {x.id.value: x for x in configs.program_list}
    for hw_design in configs.design_list:
        program = _lookup(hw_design.program_id, programs)
        for design_config in hw_design.configs:
            sw_config = _sw_config(
                configs.software_configs, design_config.id.value
            )
            config_content = generate_file_content(
                design_config.hardware_features, sw_config, program
            )
            if not config_content:
                continue
            design_name = hw_design.name.lower()

            # Constructs the following map:
            # design_name -> config -> design_configs
            # This allows any of the following file naming schemes:
            # - All configs within a design share config
            #   (design_name prefix only)
            # - Nobody shares (full design_name and config id prefix needed)
            #
            # Having shared configs when possible makes code reviews easier
            # around # the configs and makes debugging easier on the platform
            # side.
            arc_configs = configs_by_design.get(design_name, {})
            design_configs = arc_configs.get(config_content, [])
            design_configs.append(design_config)
            arc_configs[config_content] = design_configs
            configs_by_design[design_name] = arc_configs

    for design_name, unique_configs in configs_by_design.items():
        for file_content, design_configs in unique_configs.items():
            file_name = file_name_template.format(design_name)
            if len(unique_configs) == 1:
                _write_file(output_dir, file_name, file_content)

            for design_config in design_configs:
                config_id = _get_formatted_config_id(design_config)
                if len(unique_configs) > 1:
                    file_name = file_name_template.format(config_id)
                    _write_file(output_dir, file_name, file_content)
                result[config_id] = _file_v2(
                    os.path.join(build_dir, file_name),
                    os.path.join(system_dir, file_name),
                )
    return result


def _write_arc_hardware_feature_files(configs, output_root_dir, build_root_dir):
    return _write_files_by_design_config(
        configs,
        os.path.join(output_root_dir, "arc"),
        os.path.join(build_root_dir, "arc"),
        "/etc",
        "hardware_features_{}.xml",
        _generate_arc_hardware_features,
    )


def _write_arc_media_profile_files(
    configs, output_root_dir, build_root_dir, dtd_path
):
    return _write_files_by_design_config(
        configs,
        os.path.join(output_root_dir, "arc"),
        os.path.join(build_root_dir, "arc"),
        "/etc",
        "media_profiles_{}.xml",
        functools.partial(_generate_arc_media_profiles, dtd_path=dtd_path),
    )


def _read_config(path):
    """Reads a ConfigBundle proto from a json pb file.

    Args:
        path: Path to the file encoding the json pb proto.
    """
    config = config_bundle_pb2.ConfigBundle()
    with open(path, "r", encoding="utf-8") as f:
        return json_format.Parse(f.read(), config)


def _merge_configs(configs):
    result = config_bundle_pb2.ConfigBundle()
    for config in configs:
        result.MergeFrom(config)

    return result


def _camera_map(configs, project_name):
    """Produces a camera config map for the given configs.

    Produces a map that maps from the design name to the camera config for that
    design.

    Args:
        configs: Source ConfigBundle to process.
        project_name: Name of project processing for.

    Returns:
        map from design name to camera config.
    """
    result = {}
    for design in configs.design_list:
        design_name = design.name
        config_path = CAMERA_CONFIG_SOURCE_PATH_TEMPLATE.format(
            design_name.lower()
        )
        if os.path.exists(config_path):
            destination = CAMERA_CONFIG_DEST_PATH_TEMPLATE.format(
                design_name.lower()
            )
            result[design_name] = {
                "config-file": _file_v2(
                    os.path.join(project_name, config_path), destination
                ),
            }
    return result


def _dptf_map(project_name):
    """Produces a dptf map for the given configs.

    Produces a map that maps from design name to the dptf file config for that
    design. It looks for the dptf files at:
        DPTF_PATH + '/' + DPTF_FILE
    for a project wide config, that it maps under the empty string, and at:
        DPTF_PATH + '/' + design_name + '/' + DPTF_FILE
    for design specific configs that it maps under the design name.
    and at:
        DPTF_PATH + '/' + design_name + '/' + design_config_id '/' + DPTF_FILE
    for design config (firmware sku level) specific configs.

    Args:
        project_name: Name of project processing for.

    Returns:
        map from design name or empty string (project wide), to dptf config.
    """
    result = {}
    for file in glob.iglob(
        os.path.join(DPTF_PATH, "**", DPTF_FILE), recursive=True
    ):
        relative_path = os.path.dirname(file).partition(DPTF_PATH)[2].strip("/")
        if relative_path:
            project_dptf_path = os.path.join(
                project_name, relative_path, DPTF_FILE
            )
        else:
            project_dptf_path = os.path.join(project_name, DPTF_FILE)
        dptf_file = {
            "dptf-dv": project_dptf_path,
            "files": [
                _file(
                    os.path.join(
                        project_name, DPTF_PATH, relative_path, DPTF_FILE
                    ),
                    os.path.join("/etc/dptf", project_dptf_path),
                )
            ],
        }
        result[relative_path] = dptf_file
    return result


def _proximity_map(configs, project_name, output_dir, build_root_dir):
    """Constructs a map from design name to proximity config for that design.

    For Semtech sensors, produce a JSON file that will be used to setup the
    sensor.

    Args:
        configs: Source ConfigBundle to process.
        project_name: Name of project processing for.
        output_dir: Path to the generated output.
        build_root_dir: Path to the config file from portage's perspective.

    Returns:
        dict that maps the design name onto the wifi config for that design.
    """
    # pylint: disable=too-many-locals,too-many-nested-blocks
    result = {}
    prox_config = proximity_config_pb2.ProximityConfig
    for hw_design in configs.design_list:
        design_name = _get_name_for_config(hw_design.id)
        for hw_design_config in hw_design.configs:
            design_config_id = hw_design_config.id.value.lower()
            for (
                proximity_config
            ) in hw_design_config.hardware_features.proximity.configs:
                if proximity_config.HasField("semtech_config"):
                    # aggregate the locations into a single string:
                    locations_list = []
                    for location in proximity_config.location:
                        loc = prox_config.Location.RadioType.Name(
                            location.radio_type
                        )
                        if location.modifier:
                            loc += f"-{location.modifier}"
                        locations_list.append(loc)
                    loc_name = "_".join(locations_list)

                    semtech_file_content = json_format.MessageToJson(
                        proximity_config.semtech_config,
                        sort_keys=True,
                        use_integers_for_enums=True,
                    )
                    output_path = os.path.join(
                        output_dir, "proximity-sensor", design_name
                    )
                    os.makedirs(output_path, exist_ok=True)
                    filename = PROXIMITY_SEMTECH_CONFIG_TEMPLATE.format(
                        loc_name.lower()
                    )
                    output_path = os.path.join(output_path, filename)
                    build_path = os.path.join(
                        build_root_dir,
                        "proximity-sensor",
                        design_name,
                        filename,
                    )
                    if os.path.exists(output_path):
                        with open(output_path, encoding="utf-8") as f:
                            if f.read().rstrip("\n") != semtech_file_content:
                                raise Exception(
                                    f"Project {project_name} has conflicting"
                                    f"proximity file content under {filename}"
                                )
                    else:
                        with open(output_path, "w", encoding="utf-8") as f:
                            # Using print function adds proper trailing newline.
                            print(semtech_file_content, file=f)
                    system_path = (
                        "/usr/share/chromeos-assets"
                        "/proximity-sensor"
                        f"/{design_name}/{filename}"
                    )
                    config = {}
                    config["location"] = loc_name.lower()
                    config["file"] = _file_v2(build_path, system_path)
                    result.setdefault(
                        (design_name, design_config_id), {}
                    ).setdefault("semtech-config", []).append(config)
    return result


def _wifi_sar_map(configs, output_dir, build_root_dir):
    """Constructs a map from (design name, sar ID) to wifi sar config.

    In the process a wifi sar hex file is generated that the config points at.
    This mapping is only made for the intel wifi where the generated file is
    provided when building coreboot.

    Args:
        configs: Source ConfigBundle to process.
        output_dir: Path to the generated output.
        build_root_dir: Path to the config file from portage's perspective.

    Returns:
        dict that maps the design name onto the wifi config for that design.
    """
    # pylint: disable=too-many-locals
    result = {}
    sw_configs = list(configs.software_configs)
    for hw_design in configs.design_list:
        for hw_design_config in hw_design.configs:
            wifi = hw_design_config.hardware_features.wifi
            sw_config = _sw_config(sw_configs, hw_design_config.id.value)
            if hw_design_config.hardware_features.wifi.HasField("wifi_config"):
                wifi_config = wifi.wifi_config
            else:
                wifi_config = sw_config.wifi_config

            if wifi_config.HasField("intel_config"):
                sar_file_content = _create_intel_sar_file_content(
                    wifi_config.intel_config
                )
                coreboot_target = (
                    sw_config.firmware_build_config.build_targets.coreboot
                    + _calculate_image_name_suffix(hw_design_config)
                )
                if not coreboot_target:
                    continue

                wifi_sar_id = _extract_fw_config_value(
                    hw_design_config, hw_design_config.hardware_topology.wifi
                )
                output_path = os.path.join(output_dir, "wifi", coreboot_target)
                os.makedirs(output_path, exist_ok=True)
                filename = f"wifi_sar_{wifi_sar_id}.hex"
                output_path = os.path.join(output_path, filename)
                build_path = os.path.join(
                    build_root_dir, "wifi", coreboot_target, filename
                )
                if os.path.exists(output_path):
                    with open(output_path, "rb") as f:
                        if f.read() != sar_file_content:
                            raise Exception(
                                f"Firmware {coreboot_target} has conflicting "
                                "wifi sar file content under wifi sar id "
                                f"{wifi_sar_id}."
                            )
                else:
                    with open(output_path, "wb") as f:
                        f.write(sar_file_content)
                system_path = os.path.join(
                    "/firmware/cbfs-rw-raw", coreboot_target, filename
                )
                result[(coreboot_target, wifi_sar_id)] = {
                    "sar-file": _file_v2(build_path, system_path)
                }
    return result


def _extract_fw_config_value(hw_design_config, topology):
    """Extracts the firwmare config value for the given topology.

    Args:
        hw_design_config: Design extracting value from.
        topology: Topology proto to extract the firmware config value for.

    Returns:
        the extracted value or raises a ValueError if no firmware
        configuration segment with `name` is found.
    """
    mask = topology.hardware_feature.fw_config.mask
    if not mask:
        raise ValueError(
            f"No firmware configuration mask found in topology {topology}"
        )

    fw_config = hw_design_config.hardware_features.fw_config.value
    value = fw_config & mask
    lsb_bit_set = (~mask + 1) & mask
    return value // lsb_bit_set


def hex_8bit(value):
    """Converts 8bit value into bytearray.

    args:
      8bit value

    returns:
      bytearray of size 1
    """

    if value > 0xFF or value < 0:
        raise Exception(f"Sar file 8bit value {value} out of range")
    return value.to_bytes(1, "little")


def hex_16bit(value):
    """Converts 16bit value into bytearray.

    args:
      16bit value

    returns:
      bytearray of size 2
    """

    if value > 0xFFFF or value < 0:
        raise Exception(f"Sar file 16bit value {value} out of range")
    return value.to_bytes(2, "little")


def hex_32bit(value):
    """Converts 32bit value into bytearray.

    args:
      32bit value

    returns:
      bytearray of size 4
    """

    if value > 0xFFFFFFFF or value < 0:
        raise Exception(f"Sar file 32bit value {value} out of range")
    return value.to_bytes(4, "little")


def wrds_ewrd_encode(sar_table_config):
    """Creates and returns encoded power tables.

    args:
        sar_table_config: contains power table values configured in config.star

    returns:
        Encoded power tables as bytearray
    """

    def power_table(tpc, revision):
        data = bytearray(0)
        if revision == 0:
            data = (
                hex_8bit(tpc.limit_2g)
                + hex_8bit(tpc.limit_5g_1)
                + hex_8bit(tpc.limit_5g_2)
                + hex_8bit(tpc.limit_5g_3)
                + hex_8bit(tpc.limit_5g_4)
            )
        elif revision in (1, 2):
            data = (
                hex_8bit(tpc.limit_2g)
                + hex_8bit(tpc.limit_5g_1)
                + hex_8bit(tpc.limit_5g_2)
                + hex_8bit(tpc.limit_5g_3)
                + hex_8bit(tpc.limit_5g_4)
                + hex_8bit(tpc.limit_5g_5)
                + hex_8bit(tpc.limit_6g_1)
                + hex_8bit(tpc.limit_6g_2)
                + hex_8bit(tpc.limit_6g_3)
                + hex_8bit(tpc.limit_6g_4)
                + hex_8bit(tpc.limit_6g_5)
            )
        else:
            raise Exception(f"ERROR: Invalid power table revision {revision}")
        return data

    def is_zero_filled(databuffer):
        for byte in databuffer:
            if byte != 0:
                return False
        return True

    sar_table = bytearray(0)
    dsar_table = bytearray(0)
    chain_count = 2
    subbands_count = 0
    dsar_set_count = 1

    if sar_table_config.sar_table_version == 0:
        subbands_count = 5
        sar_table = power_table(
            sar_table_config.tablet_mode_power_table_a, 0
        ) + power_table(sar_table_config.tablet_mode_power_table_b, 0)
        dsar_table = power_table(
            sar_table_config.non_tablet_mode_power_table_a, 0
        ) + power_table(sar_table_config.non_tablet_mode_power_table_b, 0)
    elif sar_table_config.sar_table_version == 1:
        subbands_count = 11
        sar_table = power_table(
            sar_table_config.tablet_mode_power_table_a, 1
        ) + power_table(sar_table_config.tablet_mode_power_table_b, 1)
        dsar_table = power_table(
            sar_table_config.non_tablet_mode_power_table_a, 1
        ) + power_table(sar_table_config.non_tablet_mode_power_table_b, 1)
    elif sar_table_config.sar_table_version == 2:
        subbands_count = 22
        sar_table = (
            power_table(sar_table_config.tablet_mode_power_table_a, 2)
            + power_table(sar_table_config.tablet_mode_power_table_b, 2)
            + power_table(sar_table_config.cdb_tablet_mode_power_table_a, 2)
            + power_table(sar_table_config.cdb_tablet_mode_power_table_b, 2)
        )
        dsar_table = (
            power_table(sar_table_config.non_tablet_mode_power_table_a, 2)
            + power_table(sar_table_config.non_tablet_mode_power_table_b, 2)
            + power_table(sar_table_config.cdb_non_tablet_mode_power_table_a, 2)
            + power_table(sar_table_config.cdb_non_tablet_mode_power_table_b, 2)
        )
    elif sar_table_config.sar_table_version == 0xFF:
        return bytearray(0)
    else:
        raise Exception(
            f"ERROR: Invalid power table revision {sar_table_config.sar_table_version}"
        )

    if is_zero_filled(sar_table):
        raise Exception("ERROR: SAR entries are not initialized.")

    if is_zero_filled(dsar_table):
        dsar_set_count = 0
        dsar_table = bytearray(0)

    return (
        hex_8bit(sar_table_config.sar_table_version)
        + hex_8bit(dsar_set_count)
        + hex_8bit(chain_count)
        + hex_8bit(subbands_count)
        + sar_table
        + dsar_table
    )


def wgds_encode(wgds_config):
    """Creates and returns encoded geo offset tables.

    args:
        wgds_config: contains offset table values configured in config.star

    returns:
      Encoded geo offset tables as bytearray
    """

    def wgds_offset_table(offsets, revision):
        if revision == 0:
            return (
                hex_8bit(offsets.max_2g)
                + hex_8bit(offsets.offset_2g_a)
                + hex_8bit(offsets.offset_2g_b)
                + hex_8bit(offsets.max_5g)
                + hex_8bit(offsets.offset_5g_a)
                + hex_8bit(offsets.offset_5g_b)
            )
        if revision in (1, 2):
            return (
                hex_8bit(offsets.max_2g)
                + hex_8bit(offsets.offset_2g_a)
                + hex_8bit(offsets.offset_2g_b)
                + hex_8bit(offsets.max_5g)
                + hex_8bit(offsets.offset_5g_a)
                + hex_8bit(offsets.offset_5g_b)
                + hex_8bit(offsets.max_6g)
                + hex_8bit(offsets.offset_6g_a)
                + hex_8bit(offsets.offset_6g_b)
            )
        raise Exception(f"ERROR: Invalid geo offset table revision {revision}")

    subbands_count = 0
    offsets_count = 3
    if wgds_config.wgds_version in (0, 1):
        subbands_count = 6
    elif wgds_config.wgds_version in (2, 3):
        subbands_count = 9
    elif wgds_config.wgds_version == 0xFF:
        return bytearray(0)
    else:
        raise Exception(
            f"ERROR: Invalid geo offset table revision {wgds_config.wgds_version}"
        )

    return (
        hex_8bit(wgds_config.wgds_version)
        + hex_8bit(offsets_count)
        + hex_8bit(subbands_count)
        + wgds_offset_table(wgds_config.offset_fcc, wgds_config.wgds_version)
        + wgds_offset_table(wgds_config.offset_eu, wgds_config.wgds_version)
        + wgds_offset_table(wgds_config.offset_other, wgds_config.wgds_version)
    )


def antgain_encode(ant_gain_config):
    """Creates and returns encoded antenna gain tables.

    args:
        ant_gain_config: contains antenna gain values configured in config.star

    returns:
        Encoded antenna gain tables as bytearray
    """

    def antgain_table(gains, revision):
        if revision == 0:
            return (
                hex_8bit(gains.ant_gain_2g)
                + hex_8bit(gains.ant_gain_5g_1)
                + hex_8bit(gains.ant_gain_5g_2)
                + hex_8bit(gains.ant_gain_5g_3)
                + hex_8bit(gains.ant_gain_5g_4)
            )
        if revision in (1, 2):
            return (
                hex_8bit(gains.ant_gain_2g)
                + hex_8bit(gains.ant_gain_5g_1)
                + hex_8bit(gains.ant_gain_5g_2)
                + hex_8bit(gains.ant_gain_5g_3)
                + hex_8bit(gains.ant_gain_5g_4)
                + hex_8bit(gains.ant_gain_5g_5)
                + hex_8bit(gains.ant_gain_6g_1)
                + hex_8bit(gains.ant_gain_6g_2)
                + hex_8bit(gains.ant_gain_6g_3)
                + hex_8bit(gains.ant_gain_6g_4)
                + hex_8bit(gains.ant_gain_6g_5)
            )
        raise Exception(
            f"ERROR: Invalid antenna gain table revision {revision}"
        )

    chain_count = 2
    bands_count = 0
    if ant_gain_config.ant_table_version == 0:
        bands_count = 5
    elif ant_gain_config.ant_table_version in (1, 2):
        bands_count = 11
    else:
        return bytearray(0)
    return (
        hex_8bit(ant_gain_config.ant_table_version)
        + hex_8bit(ant_gain_config.ant_mode_ppag)
        + hex_8bit(chain_count)
        + hex_8bit(bands_count)
        + antgain_table(
            ant_gain_config.ant_gain_table_a, ant_gain_config.ant_table_version
        )
        + antgain_table(
            ant_gain_config.ant_gain_table_b, ant_gain_config.ant_table_version
        )
    )


def wtas_encode(wtas_config):
    """Creates and returns encoded time average sar tables.

    args:
        wtas_encode: contains time average sar values configured in config.star

    returns:
      Encoded time average sar tables as bytearray
    """

    if wtas_config.tas_list_size > 16:
        raise Exception(f"Invalid deny list size {wtas_config.tas_list_size}")

    if wtas_config.sar_avg_version == 0xFFFF:
        return bytearray(0)

    if wtas_config.sar_avg_version in (0, 1):
        return (
            hex_8bit(wtas_config.sar_avg_version)
            + hex_8bit(wtas_config.tas_selection)
            + hex_8bit(wtas_config.tas_list_size)
            + hex_16bit(wtas_config.deny_list_entry_1)
            + hex_16bit(wtas_config.deny_list_entry_2)
            + hex_16bit(wtas_config.deny_list_entry_3)
            + hex_16bit(wtas_config.deny_list_entry_4)
            + hex_16bit(wtas_config.deny_list_entry_5)
            + hex_16bit(wtas_config.deny_list_entry_6)
            + hex_16bit(wtas_config.deny_list_entry_7)
            + hex_16bit(wtas_config.deny_list_entry_8)
            + hex_16bit(wtas_config.deny_list_entry_9)
            + hex_16bit(wtas_config.deny_list_entry_10)
            + hex_16bit(wtas_config.deny_list_entry_11)
            + hex_16bit(wtas_config.deny_list_entry_12)
            + hex_16bit(wtas_config.deny_list_entry_13)
            + hex_16bit(wtas_config.deny_list_entry_14)
            + hex_16bit(wtas_config.deny_list_entry_15)
            + hex_16bit(wtas_config.deny_list_entry_16)
        )

    raise Exception(
        f"Invalid time average table revision {wtas_config.sar_avg_version}"
    )


def dsm_encode(dsm_config):
    """Creates and returns device specific method return values.

    args:
        dsm_config: contains device specific method return values configured in
      config.star

    returns:
      Encoded device specific method return values as bytearray
    """

    def enable_supported_functions(dsm_config):
        supported_functions = 0
        mask = 0x2
        if dsm_config.disable_active_sdr_channels >= 0:
            supported_functions |= mask
        mask = mask << 1
        if dsm_config.support_indonesia_5g_band >= 0:
            supported_functions |= mask
        mask = mask << 1
        if dsm_config.support_ultra_high_band >= 0:
            supported_functions |= mask
        mask = mask << 1
        if dsm_config.regulatory_configurations >= 0:
            supported_functions |= mask
        mask = mask << 1
        if dsm_config.uart_configurations >= 0:
            supported_functions |= mask
        mask = mask << 1
        if dsm_config.enablement_11ax >= 0:
            supported_functions |= mask
        mask = mask << 1
        if dsm_config.unii_4 >= 0:
            supported_functions |= mask
        return supported_functions

    def dsm_value(value):
        if value < 0:
            return hex_32bit(0)
        return value.to_bytes(4, "little")

    supported_functions = enable_supported_functions(dsm_config)
    if supported_functions == 0:
        return bytearray(0)
    return (
        dsm_value(supported_functions)
        + dsm_value(dsm_config.disable_active_sdr_channels)
        + dsm_value(dsm_config.support_indonesia_5g_band)
        + dsm_value(dsm_config.support_ultra_high_band)
        + dsm_value(dsm_config.regulatory_configurations)
        + dsm_value(dsm_config.uart_configurations)
        + dsm_value(dsm_config.enablement_11ax)
        + dsm_value(dsm_config.unii_4)
    )


def _create_intel_sar_file_content(intel_config):
    """creates and returns the intel sar file content for the given config.

    creates and returns the sar file content that is used with intel drivers
    only.

    args:
        intel_config: intelconfig config.

    returns:
      sar file content for the given config, see:
      https://chromeos.google.com/partner/dlm/docs/connectivity/wifidyntxpower.html
    """

    # Encode the SAR data in following format
    #
    # +------------------------------------------------------------+
    # | Field     | Size     | Description                         |
    # +------------------------------------------------------------+
    # | Marker    | 4 bytes  | "$SAR"                              |
    # +------------------------------------------------------------+
    # | Version   | 1 byte   | Current version = 1                 |
    # +------------------------------------------------------------+
    # | SAR table | 2 bytes  | Offset of SAR table from start of   |
    # | offset    |          | the header                          |
    # +------------------------------------------------------------+
    # | WGDS      | 2 bytes  | Offset of WGDS table from start of  |
    # | offset    |          | the header                          |
    # +------------------------------------------------------------+
    # | Ant table | 2 bytes  | Offset of Antenna table from start  |
    # | offset    |          | of the header                       |
    # +------------------------------------------------------------+
    # | DSM offset| 2 bytes  | Offset of DSM from start of the     |
    # |           |          | header                              |
    # +------------------------------------------------------------+
    # | Data      | n bytes  | Data for the different tables       |
    # +------------------------------------------------------------+

    def encode_data(data, header, payload, offset):
        payload += data
        if len(data) > 0:
            header += hex_16bit(offset)
            offset += len(data)
        else:
            header += hex_16bit(0)
        return header, payload, offset

    sar_configs = 5
    marker = "$SAR".encode()
    header = bytearray(0)
    header += hex_8bit(1)  # hex file version

    payload = bytearray(0)
    offset = len(marker) + len(header) + (sar_configs * 2)

    data = wrds_ewrd_encode(intel_config.sar_table)
    header, payload, offset = encode_data(data, header, payload, offset)

    data = wgds_encode(intel_config.wgds_table)
    header, payload, offset = encode_data(data, header, payload, offset)

    data = antgain_encode(intel_config.ant_table)
    header, payload, offset = encode_data(data, header, payload, offset)

    data = wtas_encode(intel_config.wtas_table)
    header, payload, offset = encode_data(data, header, payload, offset)

    data = dsm_encode(intel_config.dsm)
    header, payload, offset = encode_data(data, header, payload, offset)

    return marker + header + payload


def Main(
    project_configs, program_config, output, dtd_path
):  # pylint: disable=invalid-name
    """Transforms source proto config into platform JSON.

    Args:
        project_configs: List of source project configs to transform.
        program_config: Program config for the given set of projects.
        output: Output file that will be generated by the transform.
        dtd_path: Full path to dtd media profiles file.
    """
    # pylint: disable=too-many-locals
    configs = _merge_configs(
        [_read_config(program_config)]
        + [_read_config(config) for config in project_configs]
    )
    touch_fw = {}
    camera_map = {}
    dptf_map = {}
    wifi_sar_map = {}
    proximity_map = {}
    output_dir = os.path.dirname(output)
    build_root_dir = output_dir
    if "sw_build_config" in output_dir:
        full_path = os.path.realpath(output)
        project_name = re.match(
            r".*/([\w-]*)/(public_)?sw_build_config/.*", full_path
        ).groups(1)[0]
        # Projects don't know about each other until they are integrated into
        # the build system.  When this happens, the files need to be able to
        # co-exist without any collisions.  This prefixes the project name
        # (which is how portage maps in the project), so project files co-exist
        # and can be installed together.
        # This is necessary to allow projects to share files at the program
        # level without having portage file installation collisions.
        build_root_dir = os.path.join(project_name, output_dir)

        camera_map = _camera_map(configs, project_name)
        dptf_map = _dptf_map(project_name)
        proximity_map = _proximity_map(
            configs, project_name, output_dir, build_root_dir
        )

    wifi_sar_map = _wifi_sar_map(configs, output_dir, build_root_dir)
    if os.path.exists(TOUCH_PATH):
        touch_fw = _build_touch_file_config(configs, project_name)
    arc_hw_feature_files = _write_arc_hardware_feature_files(
        configs, output_dir, build_root_dir
    )
    arc_media_profile_files = _write_arc_media_profile_files(
        configs=configs,
        output_root_dir=output_dir,
        build_root_dir=build_root_dir,
        dtd_path=dtd_path,
    )
    config_files = ConfigFiles(
        arc_hw_features=arc_hw_feature_files,
        arc_media_profiles=arc_media_profile_files,
        touch_fw=touch_fw,
        dptf_map=dptf_map,
        camera_map=camera_map,
        wifi_sar_map=wifi_sar_map,
        proximity_map=proximity_map,
    )
    write_output(_transform_build_configs(configs, config_files), output)


def main(argv=None):
    """Main program which parses args and runs

    Args:
        argv: List of command line arguments, if None uses sys.argv.
    """
    if argv is None:
        argv = sys.argv[1:]
    opts = parse_args(argv)
    if opts.regen:
        opts.project_configs = [fake_config_mod.FAKE_PROJECT_CONFIG]
        opts.program_config = fake_config_mod.FAKE_PROGRAM_CONFIG
        opts.output = pathlib.Path(
            "test_data/proto_converter/sw_build_config/fake_project.json"
        )
        opts.dtd_path = pathlib.Path(__file__).parent / "media_profiles.dtd"
    Main(opts.project_configs, opts.program_config, opts.output, opts.dtd_path)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
