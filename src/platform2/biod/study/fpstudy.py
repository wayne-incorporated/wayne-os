#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright 2021 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
#
# Chromium OS Dependencies:
# shred       --> sys-apps/coreutils
# mogrify     --> media-gfx/imagemagick
# python gpg  --> dev-python/python-gnupg --> app-crypt/gnupg

"""A tool to manage the fingerprint study."""

from __future__ import print_function

import argparse
import glob
import logging
import os
import shutil
import stat
import subprocess
import sys
import tempfile

# The following imports will be available on the test image, but will usually
# be missing in the SDK.
# pylint: disable=import-error
import gnupg


class Sensor:
    """Hold the parameters for a given fingerprint sensor."""

    def __init__(
        self,
        name: str,
        width: int,
        height: int,
        bits: int,
        frame_size: int,
        frame_offset_image: int,
    ):
        self.name = name
        self.width = width
        self.height = height
        self.bits = bits
        # This is the full vendor frame size that encapsulates the captured
        # image.
        self.frame_size = frame_size
        # The odd little offset into the raw vendor frame buffer where the
        # capture image begins.
        self.frame_offset_image = frame_offset_image


SENSORS = {
    "FPC1145": Sensor(
        "FPC1145", 192, 56, 8, frame_size=35460, frame_offset_image=2340
    ),
    "FPC1025": Sensor(
        "FPC1025", 160, 160, 8, frame_size=26260, frame_offset_image=400
    ),
}

OUTPUT_IMAGE_FILE_EXTS = [
    # The intermediate ASCII Image format.
    "pgm",
    # The fomllowing are created using a tool.
    "pnm",
    "png",
    "jpg",
]

CAPTURE_FILE_EXTS = [
    "gpg",
    "raw",
    # A special FPC image.
    "fmi",
]


def find_files(path: str, ext: str) -> list:
    """Find all files that have the specified file extension.

    Args:
        path: A directory or single file path, where we will search for file(s)
            of the given |ext|.
        ext: The file extension.

    Returns:
        A list of file paths that matching |path| and |ext|.
    """

    files = []
    if os.path.isdir(path):
        files = glob.glob(path + "/**/*" + ext, recursive=True)
    elif os.path.isfile(path):
        _, path_ext = os.path.splitext(path)
        if path_ext != ext:
            raise Exception(f'The given path "{path}" is not a "{ext}" file')
        files = [path]
    else:
        raise Exception(f'The given path "{path}" is not a directory or file')

    return files


def decrypt(private_key: str, private_key_pass: str, files: list):
    """Decrypt the given file."""

    # Enable basic stdout logging for gnupg.
    h = logging.StreamHandler()
    l = logging.getLogger("gnupg")
    # Change this to logging.DEBUG to debug gnupg issues.
    l.setLevel(logging.INFO)
    l.addHandler(h)

    with tempfile.TemporaryDirectory() as gnupghome:
        os.chmod(gnupghome, stat.S_IRWXU)
        # Creating this directory makes old gnupg versions happy.
        os.makedirs(f"{gnupghome}/private-keys-v1.d", mode=stat.S_IRWXU)

        try:
            gpg = gnupg.GPG(
                gnupghome=gnupghome,
                verbose=False,
                options=[
                    "--no-options",
                    "--no-default-recipient",
                    "--trust-model",
                    "always",
                ],
            )

            with open(private_key, mode="rb") as key_file:
                key_data = key_file.read()
                if gpg.import_keys(key_data).count != 1:
                    raise Exception(f"Failed to import key {private_key}.")

            for file in files:
                file_parts = os.path.splitext(file)
                assert file_parts[1] == ".gpg"
                file_output = file_parts[0]
                print(f"Decrypting file {file} to {file_output}.")
                with open(file, mode="rb") as file_input_stream:
                    ret = gpg.decrypt_file(
                        file_input_stream,
                        always_trust=True,
                        passphrase=private_key_pass,
                        output=file_output,
                    )
                    if not ret.ok:
                        raise Exception(f"Failed to decrypt file {file}")

                    if not os.path.exists(file_output):
                        raise Exception(
                            f"Output file {file_output} was not created"
                        )
        finally:
            # Shred all remnants GPG keys in the temp directory.
            os.system(f"find {gnupghome} -type f | xargs shred -v")


def cmd_decrypt(args: argparse.Namespace) -> int:
    """Decrypt all gpg encrypted fingerprint captures."""

    if not os.path.isfile(args.key):
        print(f"Error - The given key file {args.key} does not exist.")
        return 1

    try:
        files = find_files(args.path, ".gpg")
    except Exception as e:
        print(f"Error - {e}")
        return 1
    if not files:
        print("Error - The given path does not contain gpg files.")
        return 1

    if not files:
        print("Error - The given dir path does not contain encrypted files.")
        return 1

    if not shutil.which("shred"):
        print("Error - The shred utility does not exist.")
        return 1

    try:
        decrypt(args.key, args.password, files)
    except Exception as e:
        print(f"Error - {e}.")
        print(
            "Ensure that you provided or were prompted for the private "
            "key password."
        )
        return 1


def cmd_convert(args: argparse.Namespace) -> int:
    """Convert all raw samples to the specified output format."""

    try:
        files = find_files(args.path, ".raw")
    except Exception as e:
        print(f"Error - {e}.")
        return 1
    if not files:
        print("Error - The given path does not contain raw files.")
        return 1

    if args.outtype != "pgm" and not shutil.which("mogrify"):
        print("Error - The mogrify utility does not exist.")
        print("Please install imagemagick.")
        return 1

    sensor = SENSORS[args.sensor]
    print(
        f"Sensor {args.sensor} is {sensor.height} x {sensor.width} with "
        f"{sensor.bits} bits of resolution."
    )

    for infile in files:
        print(f"Converting {infile} to {args.outtype}.")

        outfile, _ = os.path.splitext(infile)
        outfile += "." + args.outtype

        # We always build the ASCII PGM representation of the image.
        # If the user wants a PGM image, we just save it to a file.
        # If the user wants a more complex type, we feed the PGM representation
        # into mogrify and save the output image binary.

        # More information about PGM can be found at
        # https://en.wikipedia.org/wiki/Netpbm#File_formats
        #
        # This raw to PGM conversion can also be seen in the upload_pgm_image
        # function of ec/common/fpsensor/fpsensor.c and the cmd_fp_frame
        # function of ec/util/ectool.c. Check commit description for more info.
        pgm_buffer = ""
        with open(infile, "rb") as fin:
            b = fin.read()
            if len(b) != sensor.frame_size:
                print(
                    f"Error - Raw frame is size {len(b)}, but we expected "
                    f"size {sensor.frame_size}"
                )
                return 1
            # Use magic vendor frame offset.
            b = b[sensor.frame_offset_image :]

            # Write 8-bpp PGM ASCII header.
            pgm_buffer += "P2\n"
            pgm_buffer += f"{sensor.width} {sensor.height}\n"
            pgm_buffer += f"{2**sensor.bits - 1}\n"
            # Write table of pixel values.
            for h in range(sensor.height):
                for w in range(sensor.width):
                    pgm_buffer += f"{int(b[sensor.width*h + w])} "
                pgm_buffer += "\n"
            # Write non-essential footer.
            pgm_buffer += "# END OF FILE\n"

        with open(outfile, "wb") as fout:
            if args.outtype == "pgm":
                fout.write(bytes(pgm_buffer, "utf-8"))
            else:
                # Install imagemagick
                # mogrify -format png *.pgm
                p = subprocess.run(
                    ["mogrify", "-format", args.outtype, "-"],
                    capture_output=True,
                    input=bytes(pgm_buffer, "utf-8"),
                    check=False,
                )
                if p.returncode != 0:
                    print("mogrify:", str(p.stderr, "utf-8"))
                    print(f"Error - mogrify returned {p.returncode}.")
                    return 1
                fout.write(p.stdout)

    return 0


def cmd_rm(args: argparse.Namespace) -> int:
    """Recursively shred and remove files of a certain extension."""

    try:
        files = find_files(args.path, args.ext)
    except Exception as e:
        print(f"Error - {e}.")
        return 1
    if not files:
        print(f"Error - The given path does not contain {args.ext} files.")
        return 1

    if args.ext in CAPTURE_FILE_EXTS:
        print(
            f"WARNING: You are about to destroy {len(files)} original "
            f'".{args.ext}" fingerprint capture files from path '
            f'"{args.path}".'
        )
        resp = input("Confirm y/n: ")
        if not resp in ["y", "Y"]:
            print("Aborting.")
            return 0

    if not shutil.which("shred"):
        print("Error - The shred utility does not exist.")
        return 1

    files_list = "\n".join(files) + "\n"
    print(f"Shredding {len(files)} files.")
    p = subprocess.run(
        ["xargs", "shred", "-v"],
        capture_output=True,
        input=bytes(files_list, "utf-8"),
        check=False,
    )
    if p.returncode != 0:
        print("shred stdout:\n", str(p.stdout, "utf-8"))
        print("shred stderr:\n", str(p.stderr, "utf-8"))
        print(f"Error - shred returned {p.returncode}.")
        return 1

    for file in files:
        print(f"Removing {file}.")
        os.remove(file)


def main(argv: list) -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(
        dest="subcommand", required=True, title="subcommands"
    )

    # Parser for "decrypt" subcommand.
    parser_decrypt = subparsers.add_parser("decrypt", help=cmd_decrypt.__doc__)
    parser_decrypt.add_argument("key", help="Path to the GPG private key")
    parser_decrypt.add_argument(
        "path",
        help="Path to directory of encrypted captures "
        "or single encrypted file",
    )
    parser_decrypt.add_argument(
        "--password", default=None, help="Password for private key"
    )
    parser_decrypt.set_defaults(func=cmd_decrypt)

    # Parser for "convert" subcommand.
    parser_convert = subparsers.add_parser("convert", help=cmd_convert.__doc__)
    parser_convert.add_argument(
        "sensor",
        choices=SENSORS,
        help="The sensor that generated the raw samples",
    )
    parser_convert.add_argument(
        "outtype",
        type=str,
        choices=OUTPUT_IMAGE_FILE_EXTS,
        help="The output image type to convert to",
    )
    parser_convert.add_argument(
        "path", help="Path to directory of raw captures or single raw file"
    )
    parser_convert.set_defaults(func=cmd_convert)

    # Parser for "rm" subcommand.
    parser_rm = subparsers.add_parser("rm", help=cmd_rm.__doc__)
    parser_rm.add_argument(
        "ext",
        type=str,
        choices=OUTPUT_IMAGE_FILE_EXTS + CAPTURE_FILE_EXTS,
        help="The file extension to remove",
    )
    parser_rm.add_argument(
        "path", help="Path to directory of raw captures or single raw file"
    )
    parser_rm.set_defaults(func=cmd_rm)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
