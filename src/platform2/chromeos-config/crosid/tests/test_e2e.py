# Copyright 2021 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Test the crosid tool end-to-end."""

import shlex
import struct
import subprocess

import cros_config_host.identity_table  # pylint: disable=import-error
import pytest  # pylint: disable=wrong-import-order


def getvars(output):
    """Get a dictionary from the output of crosid."""
    result = {}
    for word in shlex.split(output):
        key, _, value = word.partition("=")
        result[key] = value
    return result


def make_config(
    model_name,
    frid_match=None,
    sku_id=None,
    customization_id=None,
    custom_label_tag=None,
):
    identity = {}
    if frid_match is not None:
        identity["frid"] = frid_match
    if sku_id is not None:
        identity["sku-id"] = sku_id
    if customization_id is not None:
        identity["customization-id"] = customization_id
    if custom_label_tag is not None:
        identity["custom-label-tag"] = custom_label_tag
    return {
        "name": model_name,
        "identity": identity,
    }


def make_fake_sysroot(
    path,
    smbios_sku=None,
    fdt_sku=None,
    acpi_frid=None,
    fdt_frid=None,
    vpd_values=None,
    configs=(),
):
    smbios_sysfs_path = path / "sys" / "class" / "dmi" / "id"
    if smbios_sku is not None:
        smbios_sysfs_path.mkdir(exist_ok=True, parents=True)
        (smbios_sysfs_path / "product_sku").write_text(f"sku{smbios_sku}\n")

    proc_fdt_path = path / "proc" / "device-tree"
    proc_fdt_coreboot_path = proc_fdt_path / "firmware" / "coreboot"
    if fdt_sku is not None:
        proc_fdt_coreboot_path.mkdir(exist_ok=True, parents=True)
        contents = fdt_sku.to_bytes(4, byteorder="big")
        (proc_fdt_coreboot_path / "sku-id").write_bytes(contents)

    proc_fdt_chromeos_path = proc_fdt_path / "firmware" / "chromeos"
    if fdt_frid is not None:
        proc_fdt_chromeos_path.mkdir(exist_ok=True, parents=True)
        (proc_fdt_chromeos_path / "readonly-firmware-version").write_text(
            fdt_frid
        )

    chromeos_acpi_path = path / "sys" / "devices" / "platform" / "chromeos_acpi"
    if acpi_frid is not None:
        chromeos_acpi_path.mkdir(exist_ok=True, parents=True)
        (chromeos_acpi_path / "FRID").write_text(acpi_frid)

    if vpd_values:
        vpd_sysfs_path = path / "sys" / "firmware" / "vpd" / "ro"
        vpd_sysfs_path.mkdir(exist_ok=True, parents=True)
        for name, value in vpd_values.items():
            (vpd_sysfs_path / name).write_text(value)

    configs_full = {"chromeos": {"configs": configs}}
    config_path = path / "usr" / "share" / "chromeos-config"
    config_path.mkdir(exist_ok=True, parents=True)
    with open(config_path / "identity.bin", "wb") as output_file:
        cros_config_host.identity_table.WriteIdentityStruct(
            configs_full, output_file
        )


REEF_CONFIGS = [
    make_config(
        "electro",
        frid_match="Google_Reef",
        sku_id=8,
        customization_id="PARMA-ELECTRO",
    ),
    make_config(
        "basking",
        frid_match="Google_Reef",
        sku_id=0,
        customization_id="OEM2-BASKING",
    ),
    make_config(
        "pyro",
        frid_match="Google_Pyro",
        customization_id="NEWTON2-PYRO",
    ),
    make_config(
        "sand",
        frid_match="Google_Sand",
        customization_id="ACER-SAND",
    ),
    make_config(
        "alan",
        frid_match="Google_Snappy",
        sku_id=7,
        customization_id="DOLPHIN-ALAN",
    ),
    make_config(
        "bigdaddy",
        frid_match="Google_Snappy",
        sku_id=2,
        customization_id="BENTLEY-BIGDADDY",
    ),
    make_config(
        "bigdaddy",
        frid_match="Google_Snappy",
        sku_id=5,
        customization_id="BENTLEY-BIGDADDY",
    ),
    make_config(
        "snappy",
        frid_match="Google_Snappy",
        sku_id=8,
        customization_id="MORGAN-SNAPPY",
    ),
    make_config(
        "snappy",
        frid_match="Google_Snappy",
    ),
]


@pytest.mark.parametrize("config_idx", list(range(len(REEF_CONFIGS))))
def test_reef(tmp_path, executable_path, config_idx):
    cfg = REEF_CONFIGS[config_idx]
    identity = cfg["identity"]
    vpd = {}

    customization_id = identity.get("customization-id")
    if customization_id:
        vpd["customization_id"] = customization_id

    make_fake_sysroot(
        tmp_path,
        acpi_frid=f"{identity['frid']}.1234_5678_910.1234.B",
        smbios_sku=identity.get("sku-id"),
        vpd_values=vpd,
        configs=REEF_CONFIGS,
    )

    result = subprocess.run(
        [executable_path, "--sysroot", tmp_path, "-v"],
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        encoding="utf-8",
    )

    assert getvars(result.stdout) == {
        "SKU": str(identity.get("sku-id", "none")),
        "CONFIG_INDEX": str(config_idx),
        "FIRMWARE_MANIFEST_KEY": cfg["name"],
    }


def test_no_match(tmp_path, executable_path):
    # Test the case that no configs match (e.g., running wrong image
    # on device)
    make_fake_sysroot(
        tmp_path,
        acpi_frid="Google_Samus.1234_567_890.ohea",
        configs=REEF_CONFIGS,
    )

    # pylint: disable=subprocess-run-check
    result = subprocess.run(
        [executable_path, "--sysroot", tmp_path, "-v"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        encoding="utf-8",
    )

    assert result.returncode != 0
    assert getvars(result.stdout) == {
        "SKU": "none",
        "CONFIG_INDEX": "unknown",
        "FIRMWARE_MANIFEST_KEY": "",
    }


def test_both_customization_id_and_whitelabel(tmp_path, executable_path):
    # Having both a customization_id and custom_label_tag indicates the
    # RO VPD was tampered/corrupted, and should result in errors.
    make_fake_sysroot(
        tmp_path,
        acpi_frid="Google_Sand.1234_5678_90.AAAA.B",
        vpd_values={
            "customization_id": "ACER-SAND",
            "whitelabel_tag": "some_wl",
        },
        configs=REEF_CONFIGS,
    )

    # pylint: disable=subprocess-run-check
    result = subprocess.run(
        [executable_path, "--sysroot", tmp_path, "-v"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        encoding="utf-8",
    )

    assert result.returncode != 0
    assert result.stdout == ""


VILBOZ14_CONFIGS = [
    make_config("vilboz14", sku_id=0, frid_match="Google_Vilboz"),
    make_config("vilboz14", sku_id=1, frid_match="Google_Vilboz"),
    make_config(
        "vilboz14",
        sku_id=1,
        frid_match="Google_Vilboz",
        custom_label_tag="vilboz14len",
    ),
]


def test_vilboz14(tmp_path, executable_path):
    make_fake_sysroot(
        tmp_path,
        acpi_frid="Google_Vilboz.123",
        smbios_sku=1,
        vpd_values={"custom_label_tag": "vilboz14len"},
        configs=VILBOZ14_CONFIGS,
    )

    # pylint: disable=subprocess-run-check
    result = subprocess.run(
        [executable_path, "--sysroot", tmp_path, "-v"],
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        encoding="utf-8",
    )

    assert getvars(result.stdout) == {
        "SKU": "1",
        "CONFIG_INDEX": "2",
        "FIRMWARE_MANIFEST_KEY": "vilboz14",
    }


TROGDOR_CONFIGS = [
    make_config("trogdor", frid_match="Google_Trogdor"),
    make_config("lazor", frid_match="Google_Lazor", sku_id=0),
    make_config("lazor", frid_match="Google_Lazor", sku_id=1),
    make_config("lazor", frid_match="Google_Lazor", sku_id=2),
    make_config("lazor", frid_match="Google_Lazor", sku_id=3),
    make_config(
        "limozeen", frid_match="Google_Lazor", sku_id=5, custom_label_tag=""
    ),
    make_config(
        "limozeen",
        frid_match="Google_Lazor",
        sku_id=6,
        custom_label_tag="lazorwl",
    ),
    make_config(
        "limozeen", frid_match="Google_Lazor", sku_id=6, custom_label_tag=""
    ),
    make_config("lazor", frid_match="Google_Lazor"),
]


@pytest.mark.parametrize("config_idx", list(range(len(TROGDOR_CONFIGS))))
def test_trogdor(tmp_path, executable_path, config_idx):
    cfg = TROGDOR_CONFIGS[config_idx]
    identity = cfg["identity"]

    vpd = {}
    custom_label_tag = identity.get("custom-label-tag")
    if custom_label_tag:
        vpd["whitelabel_tag"] = custom_label_tag

    make_fake_sysroot(
        tmp_path,
        fdt_frid=f"{identity['frid']}.123_456",
        fdt_sku=identity.get("sku-id"),
        vpd_values=vpd,
        configs=TROGDOR_CONFIGS,
    )

    result = subprocess.run(
        [executable_path, "--sysroot", tmp_path, "-v"],
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        encoding="utf-8",
    )

    assert getvars(result.stdout) == {
        "SKU": str(identity.get("sku-id", "none")),
        "CONFIG_INDEX": str(config_idx),
        "FIRMWARE_MANIFEST_KEY": cfg["name"],
    }


def test_frid_missing(tmp_path, executable_path):
    # When FRID is not available via ACPI or FDT, but required by all
    # configs, this should be an error.
    make_fake_sysroot(
        tmp_path,
        configs=TROGDOR_CONFIGS,
    )

    # pylint: disable=subprocess-run-check
    result = subprocess.run(
        [executable_path, "--sysroot", tmp_path, "-v"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        encoding="utf-8",
    )

    assert result.returncode != 0
    assert getvars(result.stdout) == {
        "SKU": "none",
        "CONFIG_INDEX": "unknown",
        "FIRMWARE_MANIFEST_KEY": "",
    }


def test_missing_identity_table(tmp_path, executable_path):
    # When identity.bin is missing, crosid should exit with an error.

    # pylint: disable=subprocess-run-check
    result = subprocess.run(
        [executable_path, "--sysroot", tmp_path],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        encoding="utf-8",
    )

    assert result.returncode != 0
    assert getvars(result.stdout) == {
        "SKU": "none",
        "CONFIG_INDEX": "unknown",
        "FIRMWARE_MANIFEST_KEY": "",
    }


@pytest.mark.parametrize(
    "contents",
    [
        b"",  # too small for header
        struct.pack("<LLL4x", 42, 0, 0),  # bad version
        struct.pack("<LLL4x", 0, 0, 1),  # too small for entries
    ],
)
def test_corrupted_identity_table(tmp_path, executable_path, contents):
    # When identity.bin is corrupted, crosid should exit with an error.
    identity_file = (
        tmp_path / "usr" / "share" / "chromeos-config" / "identity.bin"
    )
    identity_file.parent.mkdir(exist_ok=True, parents=True)
    identity_file.write_bytes(contents)

    # pylint: disable=subprocess-run-check
    result = subprocess.run(
        [executable_path, "--sysroot", tmp_path],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        encoding="utf-8",
    )

    assert result.returncode != 0
    assert getvars(result.stdout) == {
        "SKU": "none",
        "CONFIG_INDEX": "unknown",
        "FIRMWARE_MANIFEST_KEY": "",
    }


@pytest.mark.parametrize(
    "contents",
    [
        "",
        "\n",
        "sku\n",
        "sku-\n",
        "sku8z\n",
        "8\n",
        "SKU8\n",
    ],
)
def test_corrupted_sku_x86(tmp_path, executable_path, contents):
    # Test with a corrupted SKU file that we won't match a specific
    # SKU.
    make_fake_sysroot(
        tmp_path,
        acpi_frid="Google_Snappy.123",
        smbios_sku=0,
        vpd_values={
            "customization_id": "MORGAN-SNAPPY",
        },
        configs=REEF_CONFIGS,
    )

    sku_file = tmp_path / "sys" / "class" / "dmi" / "id" / "product_sku"
    sku_file.write_text(contents)

    result = subprocess.run(
        [executable_path, "--sysroot", tmp_path],
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        encoding="utf-8",
    )

    assert getvars(result.stdout) == {
        "SKU": "none",
        "CONFIG_INDEX": "8",
        "FIRMWARE_MANIFEST_KEY": "snappy",
    }


@pytest.mark.parametrize(
    "contents",
    [
        b"",
        b"\x00",
        b"\x00\x00\x00\x00\x00",
    ],
)
def test_corrupted_sku_arm(tmp_path, executable_path, contents):
    # Test with a corrupted SKU file that we won't match a specific
    # SKU.
    make_fake_sysroot(
        tmp_path,
        fdt_frid="Google_Lazor.123",
        fdt_sku=0,
        configs=TROGDOR_CONFIGS,
    )

    sku_file = (
        tmp_path / "proc" / "device-tree" / "firmware" / "coreboot" / "sku-id"
    )
    sku_file.write_bytes(contents)

    result = subprocess.run(
        [executable_path, "--sysroot", tmp_path],
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        encoding="utf-8",
    )

    assert getvars(result.stdout) == {
        "SKU": "none",
        "CONFIG_INDEX": "8",
        "FIRMWARE_MANIFEST_KEY": "lazor",
    }


@pytest.mark.parametrize(
    ["key", "expected_result"],
    [
        ("CONFIG_INDEX", "4"),
        ("SKU", "7"),
        ("FIRMWARE_MANIFEST_KEY", "alan"),
    ],
)
def test_filter_output(tmp_path, executable_path, key, expected_result):
    make_fake_sysroot(
        tmp_path,
        acpi_frid="Google_Snappy.123",
        smbios_sku=7,
        vpd_values={"customization_id": "DOLPHIN-ALAN"},
        configs=REEF_CONFIGS,
    )

    result = subprocess.run(
        [executable_path, "--sysroot", tmp_path, "-f", key],
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        encoding="utf-8",
    )

    assert result.stdout == expected_result


def test_factory_override(tmp_path, executable_path):
    """Test that the --sku-id and --custom-label-tag flags work."""
    make_fake_sysroot(
        tmp_path,
        fdt_frid="Google_Lazor.123_456",
        fdt_sku=3,
        configs=TROGDOR_CONFIGS,
    )

    result = subprocess.run(
        [
            executable_path,
            "--sysroot",
            tmp_path,
            "-v",
            "--sku-id",
            "6",
            "--custom-label-tag",
            "lazorwl",
        ],
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        encoding="utf-8",
    )

    assert getvars(result.stdout) == {
        "SKU": "6",
        "CONFIG_INDEX": "6",
        "FIRMWARE_MANIFEST_KEY": "limozeen",
    }
