#!/usr/bin/env python3
# # -*- coding: utf-8 -*-
# Copyright 2021 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Create tarballs with modem FW, and upload them to OS Archive Mirrors."""

import argparse
from distutils.dir_util import copy_tree
from enum import Enum
import logging
import os
import shutil
import subprocess
import sys
import tempfile


class PackageType(Enum):
    """Packaging options for different firmwares or cust packs."""

    L850_MAIN_FW = "l850-main-fw"
    L850_OEM_FW = "l850-oem-fw"
    L850_OEM_DIR_ONLY = "l850-oem-dir"
    NL668_MAIN_FW = "nl668-main-fw"
    FM101_MAIN_FW = "fm101-main-fw"

    # FM350 firmware payloads
    FM350_MAIN_FW = "fm350-main-fw"  # 81600... directory
    FM350_AP_FW = "fm350-ap-fw"  # FM350... directory
    FM350_DEV_FW = "fm350-dev-fw"  # DEV_OTA file
    FM350_OEM_FW = "fm350-oem-fw"  # OEM_OTA file
    FM350_CARRIER_FW = "fm350-carrier-fw"  # OP_OTA file

    def __str__(self):
        return str(self.value)


MIRROR_PATH = "gs://chromeos-localmirror/distfiles/"
FIBOCOM_TARBALL_PREFIX = "cellular-firmware-fibocom-"
L850_TARBALL_PREFIX = FIBOCOM_TARBALL_PREFIX + "l850-"
NL668_TARBALL_PREFIX = FIBOCOM_TARBALL_PREFIX + "nl668-"
FM101_TARBALL_PREFIX = FIBOCOM_TARBALL_PREFIX + "fm101-"
FM350_TARBALL_PREFIX = FIBOCOM_TARBALL_PREFIX + "fm350-"

FM350_MISC_PREFIXES = ["OEM_OTA_", "DEV_OTA_", "OP_OTA_"]

OEM_FW_PREFIX = "OEM_cust."
OEM_FW_POSTFIX = "_signed.fls3.xz"


class TempDir(object):
    """Context manager to make sure temporary directories are cleaned up."""

    def __init__(self, keep_tmp_files):
        self._keep_tmp_files = keep_tmp_files
        self._tempdir = None

    def __enter__(self):
        self._tempdir = tempfile.mkdtemp()
        return self._tempdir

    def __exit__(self, exc_type, exc_val, exc_tb):
        if not self._keep_tmp_files:
            logging.info("Removing temporary files")
            shutil.rmtree(self._tempdir)
        return False


class FwUploader(object):
    """Class to verify the files and upload the tarball to a gs bucket."""

    def __init__(self, path, upload, tarball_dir_name):
        self.path = os.path.abspath(path)
        self.upload = upload
        self.basename = os.path.basename(self.path)
        self.tarball_dir_name = tarball_dir_name

    def process_fw_and_upload(self, keep_tmp_files):
        if not self.validate():
            return os.EX_USAGE

        with TempDir(keep_tmp_files) as tempdir:
            path_to_package = os.path.join(tempdir, self.tarball_dir_name)
            os.mkdir(path_to_package)

            if not self.prepare_files(self.path, path_to_package):
                logging.error("Failed to prepare files for packaging")
                return os.EX_OSFILE

            os.chdir(tempdir)
            tarball_name = f"{self.tarball_dir_name}.tar.xz"
            subprocess.run(
                [
                    "tar",
                    "-Ipixz",
                    "-cf",
                    f"{tarball_name}",
                    f"{self.tarball_dir_name}/",
                ],
                stderr=subprocess.DEVNULL,
                check=True,
            )
            tarball_path = os.path.join(tempdir, tarball_name)
            logging.info("Tarball created: %s", tarball_path)

            gs_bucket_path = os.path.join(MIRROR_PATH, tarball_name)
            if self.upload:
                logging.info(
                    "Uploading file %s to %s", tarball_path, gs_bucket_path
                )
                subprocess.run(
                    [
                        "gsutil",
                        "cp",
                        "-n",
                        "-a",
                        "public-read",
                        f"{tarball_path}",
                        f"{gs_bucket_path}",
                    ],
                    stderr=subprocess.DEVNULL,
                    check=True,
                )
                logging.info("Setting ACLs on %s", gs_bucket_path)
                subprocess.run(
                    [
                        "gsutil",
                        "acl",
                        "ch",
                        "-g",
                        "mdb.croscellular@google.com:O",
                        f"{gs_bucket_path}",
                    ],
                    stderr=subprocess.DEVNULL,
                    check=True,
                )
            else:
                logging.info(
                    "Use --upload flag to upload file %s to %s",
                    tarball_path,
                    gs_bucket_path,
                )

        return os.EX_OK


class L850MainFw(FwUploader):
    """Uploader class for L850GL main FW."""

    def __init__(self, path, upload):
        super().__init__(path, upload, None)
        self.tarball_dir_name = L850_TARBALL_PREFIX + self.basename.replace(
            ".fls3.xz", ""
        )

    def validate(self):
        main_fw_postfix = "Secureboot.fls3.xz"
        if not self.path.endswith(main_fw_postfix):
            logging.error(
                "The main FW file `%s` name does not match `*%s`",
                self.path,
                main_fw_postfix,
            )
            return False
        return True

    @staticmethod
    def prepare_files(fw_path, target_path):
        logging.info("Copying %s into %s", fw_path, target_path)
        shutil.copy(fw_path, target_path)
        return True


class L850OemFw(FwUploader):
    """Uploader class for L850GL OEM FW."""

    def __init__(self, path, upload):
        super().__init__(path, upload, None)
        self.tarball_dir_name = (
            f"{L850_TARBALL_PREFIX}"
            + f'[{self.basename.replace(OEM_FW_POSTFIX, "")}]'
        )

    def validate(self):
        if not (
            self.basename.startswith(OEM_FW_PREFIX)
            and self.basename.endswith(OEM_FW_POSTFIX)
        ):
            logging.error(
                "The OEM FW file `%s` name does not match `%s*%s`",
                self.basename,
                OEM_FW_PREFIX,
                OEM_FW_POSTFIX,
            )
            return False
        return True

    @staticmethod
    def prepare_files(fw_path, target_path):
        logging.info("Copying %s into %s", fw_path, target_path)
        shutil.copy(fw_path, target_path)
        return True


class L850OemDir(FwUploader):
    """Uploader class for L850GL cust packs directory."""

    def __init__(self, path, upload, revision, board):
        super().__init__(path, upload, None)
        self.tarball_dir_name = (
            f"{L850_TARBALL_PREFIX}{board}"
            + f"-carriers_OEM_{self.basename}-{revision}"
        )
        self.revision = revision

    def validate(self):
        if not self.revision.startswith("r") or not self.revision[1:].isdigit():
            logging.error("The revision should be in the form of r##")
            return False
        if len(self.basename) != 4 or not self.basename.isdigit():
            logging.error(
                "The OEM carrier directory name is expected to "
                "consist of 4 digits"
            )
            return False
        return True

    def prepare_files(self, dir_path, target_path):
        logging.info("Copying %s into %s", dir_path, target_path)
        os.mkdir(os.path.join(target_path, self.basename))
        copy_tree(dir_path, os.path.join(target_path, self.basename))

        return True


class NL668MainFw(FwUploader):
    """Uploader class for NL668 main FW."""

    def __init__(self, path, upload):
        super().__init__(path, upload, None)
        self.tarball_dir_name = NL668_TARBALL_PREFIX + self.basename

    def validate(self):
        if not os.path.isdir(self.path):
            logging.error("The NL668 FW should be a directory")
            return False
        return True

    def prepare_files(self, dir_path, target_path):
        logging.info("Copying %s into %s", dir_path, target_path)
        os.mkdir(os.path.join(target_path, self.basename))
        copy_tree(dir_path, os.path.join(target_path, self.basename))
        return True


class FM101MainFw(FwUploader):
    """Uploader class for FM101 main FW."""

    def __init__(self, path, upload):
        super().__init__(path, upload, None)
        self.tarball_dir_name = FM101_TARBALL_PREFIX + self.basename

    def validate(self):
        if not os.path.isdir(self.path):
            logging.error("The FM101 FW should be a directory")
            return False
        return True

    def prepare_files(self, dir_path, target_path):
        logging.info("Copying %s into %s", dir_path, target_path)
        os.mkdir(os.path.join(target_path, self.basename))
        copy_tree(dir_path, os.path.join(target_path, self.basename))
        return True


class FM350MainFw(FwUploader):
    """Uploader class for FM350 main FW.

    This should be used for both main and AP firmware payloads.
    """

    def __init__(self, path, upload):
        super().__init__(path, upload, None)
        self.tarball_dir_name = FM350_TARBALL_PREFIX + self.basename

    def validate(self):
        if not os.path.isdir(self.path):
            logging.error("The FM350 FW should be a directory")
            return False
        return True

    def prepare_files(self, dir_path, target_path):
        logging.info("Copying %s into %s", dir_path, target_path)
        os.mkdir(os.path.join(target_path, self.basename))
        copy_tree(dir_path, os.path.join(target_path, self.basename))
        return True


class FM350MiscFw(FwUploader):
    """Uploader class for FM350 non-main payloads.

    This should be used for OEM_OTA, DEV_OTA, and OP_OTA payloads.
    """

    def __init__(self, path, upload):
        super().__init__(path, upload, None)
        self.tarball_dir_name = FM350_TARBALL_PREFIX + self.basename

    def validate(self):
        if os.path.isdir(self.path):
            logging.error("Misc FM350 FW should not be a directory")
            return False
        if not any(
            self.basename.startswith(prefix) for prefix in FM350_MISC_PREFIXES
        ):
            logging.error(
                "Expected non-main payload to begin with one of %s",
                FM350_MISC_PREFIXES,
            )
            return False

        return True

    @staticmethod
    def prepare_files(fw_path, target_path):
        logging.info("Copying %s into %s", fw_path, target_path)
        shutil.copy(fw_path, target_path)
        return True


def parse_arguments(argv):
    """Parses command line arguments.

    Args:
        argv: List of commandline arguments.

    Returns:
        Namespace object containing parsed arguments.
    """

    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawTextHelpFormatter
    )

    parser.add_argument(
        "type",
        type=PackageType,
        choices=list(PackageType),
        help="The type of package to create",
    )

    parser.add_argument(
        "path", help="The path to the FW file or directory to be packaged."
    )

    parser.add_argument(
        "--board",
        help="The ChromeOS board in which this cust pack will be used.",
    )

    parser.add_argument(
        "--revision",
        help="The next ebuild number for that board. If the current ebuild "
        "revision is r12, enter r13.",
    )

    parser.add_argument(
        "--upload",
        default=False,
        action="store_true",
        help="upload file to GS bucket.",
    )

    parser.add_argument(
        "--keep-files",
        default=False,
        action="store_true",
        help="Don't delete the tarball files in /tmp. Useful "
        "for Partners. Googlers should not upload files "
        "manually.",
    )

    return parser.parse_args(argv[1:])


def main(argv):
    """Main function."""

    logging.basicConfig(level=logging.DEBUG)
    opts = parse_arguments(argv)
    if opts.type == PackageType.L850_MAIN_FW:
        fw_uploader = L850MainFw(opts.path, opts.upload)
    elif opts.type == PackageType.L850_OEM_FW:
        fw_uploader = L850OemFw(opts.path, opts.upload)
    elif opts.type == PackageType.L850_OEM_DIR_ONLY:
        if not opts.revision:
            logging.error(
                "The ebuild revision is needed to pack it, since "
                "the tarballs need to be unique."
            )
            return os.EX_USAGE
        if not opts.board:
            logging.error("Please enter the board name.")
            return os.EX_USAGE
        fw_uploader = L850OemDir(
            opts.path, opts.upload, opts.revision, opts.board
        )
    elif opts.type == PackageType.NL668_MAIN_FW:
        fw_uploader = NL668MainFw(opts.path, opts.upload)
    elif opts.type == PackageType.FM101_MAIN_FW:
        fw_uploader = FM101MainFw(opts.path, opts.upload)
    elif opts.type in [PackageType.FM350_MAIN_FW, PackageType.FM350_AP_FW]:
        fw_uploader = FM350MainFw(opts.path, opts.upload)
    elif opts.type in [
        PackageType.FM350_DEV_FW,
        PackageType.FM350_OEM_FW,
        PackageType.FM350_CARRIER_FW,
    ]:
        fw_uploader = FM350MiscFw(opts.path, opts.upload)

    return fw_uploader.process_fw_and_upload(opts.keep_files)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
