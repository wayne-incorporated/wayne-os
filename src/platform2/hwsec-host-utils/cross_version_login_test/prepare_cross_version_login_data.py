#!/usr/bin/env python3

# Copyright 2022 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""This script is used for creating the cross-version login testing data.

Given the target CrOS version, the script will download the image from google
storage and create user account in the image. Then, copy and upload the data to
google storage so that we could use it in cross-version login testing.
"""

import argparse
import hashlib
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from typing import List, NamedTuple, Optional


VM_HOST = "127.0.0.1"
VM_PORT = "9222"
SSH_COMMON_ARGS = (
    "-o",
    "StrictHostKeyChecking=no",
    "-o",
    "GlobalKnownHostsFile=/dev/null",
    "-o",
    "UserKnownHostsFile=/dev/null",
    "-o",
    "LogLevel=quiet",
)


class Version(NamedTuple):
    """Represents a parsed ChromiumOS version."""

    milestone: int
    major: int
    minor: int
    patch: int
    # An optional suffix in the "-custombuildYYYYMMDD" format.
    custombuild: str

    def __str__(self) -> str:
        return (
            f"R{self.milestone}-{self.major}.{self.minor}.{self.patch}"
            f"{self.custombuild}"
        )


def main(argv: Optional[List[str]] = None) -> Optional[int]:
    parser = argparse.ArgumentParser(
        description="Generate cross-version test login data"
    )
    parser.add_argument(
        "--board", help="ChromiumOS board, e.g., betty", required=True
    )
    parser.add_argument(
        "--version",
        help="ChromiumOS version, e.g., R100-14526.89.0 or "
        "R100-14526.89.0-custombuild20220130",
        required=True,
    )
    parser.add_argument(
        "--output-dir",
        help="path to the directory to place output files in",
        required=True,
        type=Path,
    )
    parser.add_argument(
        "--ssh-identity-file",
        help="path to the SSH private key file",
        type=Path,
    )
    opts = parser.parse_args(argv)
    run(opts.board, opts.version, opts.output_dir, opts.ssh_identity_file)


def run(
    board: str,
    version_str: str,
    output_dir: Path,
    ssh_identity_file: Optional[Path],
) -> None:
    version = parse_version(version_str)
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        ssh_identity = setup_ssh_identity(ssh_identity_file, temp_path)
        image_path = download_vm_image(board, version, temp_path)
        start_vm(image_path, board)
        try:
            init_vm(version, ssh_identity)
            generate_data()
            upload_data(board, version, output_dir, temp_path, ssh_identity)
        finally:
            stop_vm()


def parse_version(version: str) -> Version:
    """Parses a ChromeOS version string, like "R100-14526.89.0".

    Also allows the "R100-14526.89.0-custombuild20220130" format.
    """
    match = re.fullmatch(
        r"R(\d+)-(\d+)\.(\d+)\.(\d+)(-custombuild\d{8}|)", version
    )
    if not match:
        raise RuntimeError(f"Failed to parse version {version}")
    return Version(
        int(match.group(1)),
        int(match.group(2)),
        int(match.group(3)),
        int(match.group(4)),
        match.group(5),
    )


def setup_ssh_identity(
    ssh_identity_file: Optional[Path], temp_path: Path
) -> Path:
    """Copies the SSH identity file and fixes the permissions."""
    source_path = (
        ssh_identity_file if ssh_identity_file else default_ssh_identity_file()
    )
    target_path = Path(f"{temp_path}/ssh_key")
    shutil.copy(source_path, target_path)
    # Permissions need to be adjusted to prevent ssh complaints.
    target_path.chmod(stat.S_IREAD)
    return target_path


def default_ssh_identity_file() -> Path:
    home = Path.home()
    return Path(f"{home}/chromiumos/chromite/ssh_keys/testing_rsa")


def download_vm_image(board: str, version: Version, temp_path: Path) -> Path:
    """Fetches the ChromiumOS image from Google Cloud Storage."""
    if version.custombuild:
        # Download the custom-built VM image from a special GS folder (which is
        # populated manually by developers).
        image_url = (
            f"gs://chromeos-test-assets-private/tast/cros/hwsec/"
            f"cross_version_login/custombuilds/{version}_{board}.tar.xz"
        )
    else:
        # No "custombuild" in the specified version, hence use the standard GS
        # folder (it's populated by build bots).
        image_url = (
            f"gs://chromeos-image-archive/{board}-release/{version}/"
            f"chromiumos_test_image.tar.xz"
        )
    archive_path = Path(f"{temp_path}/chromiumos_test_image.tar.xz")
    check_run("gsutil", "cp", image_url, archive_path)
    # Unpack the .tar.xz archive.
    check_run("tar", "Jxf", archive_path, "-C", temp_path)
    target_path = Path(f"{temp_path}/chromiumos_test_image.bin")
    if not target_path.exists():
        raise RuntimeError(f"No {target_path} in VM archive")
    return target_path


def start_vm(image_path: Path, board: str) -> None:
    """Runs the VM emulator."""
    check_run(
        "cros_vm",
        "--log-level=warning",
        "--start",
        "--image-path",
        image_path,
        "--board",
        board,
    )


def stop_vm() -> None:
    """Stops the VM emulator."""
    check_run("cros_vm", "--stop")


def init_vm(version: Version, ssh_identity: Path) -> None:
    """Makes sure the VM is in the right state for collecting the state."""
    if version.milestone < 96:
        # Normally the Tast framework takes care of the TPM ownership, however
        # it doesn't support pre-M96 images (as Tast ToT uses the
        # "get_supported_features" tpm_manager command that was added later).
        execute_on_dut("tpm_manager_client take_ownership", ssh_identity)


def generate_data() -> None:
    """Generates a data snapshot by running the Tast test."""
    # "tpm2_simulator" is added by crrev.com/c/3312977, so this test cannot run
    # on older version. Therefore, adds -extrauseflags "tpm2_simulator" here.
    check_run(
        "tast",
        "run",
        "-failfortests",
        "-extrauseflags",
        "tpm2_simulator",
        f"{VM_HOST}:{VM_PORT}",
        "hwsec.PrepareCrossVersionLoginData",
    )


def upload_data(
    board: str,
    version: Version,
    output_dir: Path,
    temp_path: Path,
    ssh_identity: Path,
) -> None:
    """Creates resulting artifacts and uploads to the GS."""
    DUT_ARTIFACTS_DIR = "/tmp/cross_version_login"
    date = time.strftime("%Y%m%d")
    prefix = f"{version}_{board}_{date}"
    # Grab the data file from the DUT.
    data_file = f"{prefix}_data.tar.gz"
    dut_data_path = Path(f"{DUT_ARTIFACTS_DIR}/data.tar.gz")
    data_path = Path(f"{temp_path}/{data_file}")
    copy_from_dut(dut_data_path, data_path, ssh_identity)
    # Grab the config file from the DUT.
    dut_config_path = Path(f"{DUT_ARTIFACTS_DIR}/config.json")
    config_path = Path(f"{output_dir}/{prefix}_config.json")
    copy_from_dut(dut_config_path, config_path, ssh_identity)
    print(f'Config file is created at "{config_path}".', file=sys.stderr)
    # Generate the external data file that points to the file in GS.
    gs_url = (
        f"gs://chromiumos-test-assets-public/tast/cros/hwsec/"
        f"cross_version_login/{data_file}"
    )
    external_data = generate_external_data(gs_url, data_path)
    external_data_path = Path(f"{output_dir}/{data_file}.external")
    with open(external_data_path, "w") as f:
        f.write(external_data)
    print(
        f'External data file is created at "{external_data_path}".',
        file=sys.stderr,
    )
    # Upload the data file to Google Cloud Storage.
    check_run("gsutil", "cp", data_path, gs_url)
    print(f"Testing data is uploaded to {gs_url}", file=sys.stderr)


def copy_from_dut(
    remote_path: Path, local_path: Path, ssh_identity: Path
) -> None:
    """Fetches a file from the DUT."""
    check_run(
        "scp",
        *SSH_COMMON_ARGS,
        "-i",
        ssh_identity,
        "-P",
        VM_PORT,
        f"root@{VM_HOST}:{remote_path}",
        local_path,
    )


def execute_on_dut(command: str, ssh_identity: Path) -> None:
    """Runs the command on the DUT remotely."""
    check_run(
        "ssh",
        *SSH_COMMON_ARGS,
        "-i",
        ssh_identity,
        "-p",
        VM_PORT,
        f"root@{VM_HOST}",
        command,
    )


def generate_external_data(gs_url: str, data_path: Path) -> str:
    """Generates external data in the Tast format (JSON)."""
    st = data_path.stat()
    sha256 = calculate_file_sha256(data_path)
    return f"""{{
  "url": "{gs_url}",
  "size": {st.st_size},
  "sha256sum": "{sha256}"
}}
"""


def check_run(*args: str) -> None:
    """Runs the given command; throws on failure."""
    try:
        subprocess.run(
            args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=True
        )
    except subprocess.CalledProcessError as exc:
        # Print the output to aid debugging (the exception message doesn't
        # include the output).
        print(
            "Command",
            args,
            "printed:\n",
            exc.output.decode("utf-8"),
            file=sys.stderr,
        )
        raise


def calculate_file_sha256(path: Path) -> str:
    READ_SIZE = 4096
    sha256 = hashlib.sha256()
    with open(path, "rb") as infile:
        while True:
            block = infile.read(READ_SIZE)
            if not block:
                break
            sha256.update(block)
    return sha256.hexdigest()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
