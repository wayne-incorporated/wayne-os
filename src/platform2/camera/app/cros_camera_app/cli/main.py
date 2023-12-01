#!/usr/bin/env python3
# Copyright 2023 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""The main command-line interface module for CCA.

Run `cca help` for more information about the supported subcommands.
"""

import argparse
import codecs
import json
import logging
import pathlib
import shutil
import sys
from typing import List, Optional, Tuple

from cros_camera_app import app
from cros_camera_app import device
from cros_camera_app import fake_hal
from cros_camera_app.cli import util


cli = util.CLIRunner(
    argparse.ArgumentParser(
        description="ChromeOS Camera App (CCA) CLI.",
    )
)


@cli.command("main", parent=None)
@cli.option(
    "--debug",
    action="store_true",
    help="enable debug logging",
)
def cmd_main(debug: bool):
    # ChromeOS shell might use C locale instead of UTF-8, which may trigger
    # encoding error when printing non-ASCII characters. Here we enforce stdout
    # and stderr to use UTF-8 encoding.
    if codecs.lookup(sys.stdout.encoding).name != "utf-8":
        # pylint: disable=consider-using-with
        sys.stdout = open(
            sys.stdout.fileno(), mode="w", encoding="utf-8", buffering=1
        )

    if codecs.lookup(sys.stderr.encoding).name != "utf-8":
        # pylint: disable=consider-using-with
        sys.stderr = open(
            sys.stderr.fileno(), mode="w", encoding="utf-8", buffering=1
        )

    log_level = logging.DEBUG if debug else logging.INFO
    log_format = "%(asctime)s - %(levelname)s - %(funcName)s: %(message)s"
    logging.basicConfig(level=log_level, format=log_format)


@cli.command(
    "setup",
    parent=cmd_main,
    help="Setup the DUT",
    description="Setup the DUT to make it ready to be controlled remotely.",
)
def cmd_setup():
    device.setup()


@cli.command(
    "open",
    parent=cmd_main,
    help="Open CCA",
    description="Open CCA.",
)
@cli.option(
    "--facing",
    help="facing of the camera to be opened",
    action=util.EnumAction,
    enum_type=app.Facing,
)
@cli.option(
    "--mode",
    help="target capture mode in app",
    action=util.EnumAction,
    enum_type=app.Mode,
)
def cmd_open(facing: app.Facing, mode: app.Mode):
    # TODO(shik): Wake up the display if it's sleeping.
    cca = app.CameraApp()
    cca.open(facing=facing, mode=mode)


@cli.command(
    "close",
    parent=cmd_main,
    help="Close CCA",
    description="Close CCA if it's open.",
)
def cmd_close():
    cca = app.CameraApp()
    cca.close()


@cli.command(
    "take-photo",
    parent=cmd_main,
    help="Take a photo",
    description="Take a photo using CCA.",
)
@cli.option(
    "--facing",
    help="facing of the camera to be captured",
    action=util.EnumAction,
    enum_type=app.Facing,
)
@cli.option(
    "--output",
    help="output path to save the photo",
    type=pathlib.Path,
)
def cmd_take_photo(facing: app.Facing, output: pathlib.Path):
    # TODO(shik): Provide an option to reuse the existing CCA session and not to
    # close the app afterward.
    cca = app.CameraApp()
    path = cca.take_photo(facing=facing)
    if output:
        shutil.copy2(path, output)
        logging.info("Copied photo from %s to %s", path, output)
    else:
        logging.info("Saved photo at %s", path)


@cli.command(
    "record-video",
    parent=cmd_main,
    help="Record a video",
    description="Record a video using CCA.",
)
@cli.option(
    "--facing",
    help="facing of the camera to be recorded",
    action=util.EnumAction,
    enum_type=app.Facing,
)
@cli.option(
    "--duration",
    help="duration in seconds to be recorded",
    type=float,
    default=3,
)
@cli.option(
    "--output",
    help="output path to save the video",
    type=pathlib.Path,
)
def cmd_record_video(facing: app.Facing, duration: float, output: pathlib.Path):
    cca = app.CameraApp()
    path = cca.record_video(facing=facing, duration=duration)
    if output:
        shutil.copy2(path, output)
        logging.info("Copied video from %s to %s", path, output)
    else:
        logging.info("Saved video at %s", path)


@cli.command(
    "screenshot",
    parent=cmd_main,
    help="Take a screenshot",
    description="Take a screenshot of CCA window.",
)
@cli.option(
    "--output",
    help="output path to save the image data",
    default="screenshot.png",
    type=pathlib.Path,
)
def cmd_screenshot(output: pathlib.Path):
    cca = app.CameraApp()
    image_data = cca.screenshot()
    with open(output, "wb") as f:
        f.write(image_data)
        logging.info("Saved screenshot at %s", output)


@cli.command(
    "eval",
    parent=cmd_main,
    help="Evaluate an expression",
    description="Evaluate a JavaScript expression in CCA context.",
)
@cli.option(
    "expr",
    help="JavaScript experssion to be evaluated",
)
def cmd_eval(expr: str):
    cca = app.CameraApp()
    val = cca.eval(expr)
    output = json.dumps(val, sort_keys=True, indent=2)
    print(output)


@cli.command(
    "fake-hal",
    parent=cmd_main,
    help="Setup Fake HAL",
    description="Setup Fake HAL JSON config file.",
)
def cmd_fake_hal():
    pass


@cli.command(
    "persist",
    parent=cmd_fake_hal,
    help="Persist the config",
    description="Persist the config by copying to /etc/camera.",
)
def cmd_fake_hal_persist():
    fake_hal.persist()


@cli.command(
    "add",
    parent=cmd_fake_hal,
    help="Add a camera",
    description=(
        "Add and connect a camera to Fake HAL."
        " The supported formats are populated from a predefined list,"
        " and can be filtered by --max-* options."
    ),
)
@cli.option(
    "--max-width",
    help="the maximum width to filter supported formats",
    type=int,
)
@cli.option(
    "--max-height",
    help="the maximum height to filter supported formats",
    type=int,
)
@cli.option(
    "--max-fps",
    help="the maximum fps to filter supported formats",
    type=int,
)
@cli.option(
    "--frame",
    help=(
        "the source of camera frame in jpg, mjpg, or y4m format."
        " If not specified, a test pattern would be used."
    ),
    type=pathlib.Path,
)
def cmd_fake_hal_add(
    max_width: Optional[int] = None,
    max_height: Optional[int] = None,
    max_fps: Optional[int] = None,
    frame: Optional[pathlib.Path] = None,
):
    def should_keep(
        width: int, height: int, fps_range: Tuple[int, int]
    ) -> bool:
        return (
            (max_width is None or width <= max_width)
            and (max_height is None or height <= max_height)
            and (max_fps is None or fps_range[1] <= max_fps)
        )

    fake_hal.add_camera(
        should_keep=should_keep,
        frame_path=frame,
    )


@cli.command(
    "remove",
    parent=cmd_fake_hal,
    help="Remove camera(s)",
    description=(
        "Remove and disconnect camera(s) from Fake HAL."
        " If --id is not specified, all cameras would be removed."
    ),
)
@cli.option(
    "--id",
    dest="camera_id",
    help="camera id to remove. This option can be specified multiple times.",
    type=int,
    action="append",
)
def cmd_fake_hal_remove(camera_id: Optional[List[int]]):
    fake_hal.remove_cameras(lambda x: camera_id is None or x in camera_id)


@cli.command(
    "edit",
    parent=cmd_fake_hal,
    help="Edit config in editor",
    description=(
        "Edit Fake HAL config interactively. If --editor is not specified,"
        " vim with a minimal sensible config would be used."
    ),
)
@cli.option(
    "--editor",
    help="the editor to edit the config",
)
def cmd_fake_hal_edit(editor: Optional[str]):
    fake_hal.edit_config_with_editor(editor)


@cli.command(
    "connect",
    parent=cmd_fake_hal,
    help="Connect camera(s)",
    description=(
        "Connect existing camera(s) in Fake HAL config."
        " If --id is not specified, all cameras would be connected."
    ),
)
@cli.option(
    "--id",
    dest="camera_id",
    help="camera id to connect. This option can be specified multiple times.",
    type=int,
    action="append",
)
def cmd_fake_hal_connect(camera_id: Optional[List[int]]):
    fake_hal.connect_cameras(lambda x: camera_id is None or x in camera_id)


@cli.command(
    "disconnect",
    parent=cmd_fake_hal,
    help="Disconnect camera(s)",
    description=(
        "Disconnect existing camera(s) in Fake HAL config."
        " If --id is not specified, all cameras would be disconnected."
    ),
)
@cli.option(
    "--id",
    dest="camera_id",
    help=(
        "camera id to disconnect."
        " This option can be specified multiple times."
    ),
    type=int,
    action="append",
)
def cmd_fake_hal_disconnect(camera_id: Optional[List[int]]):
    fake_hal.disconnect_cameras(lambda x: camera_id is None or x in camera_id)


@cli.command(
    "info",
    parent=cmd_fake_hal,
    help="Show config information",
    description="Show the current Fake HAL config information.",
)
def cmd_fake_hal_info():
    fake_hal.dump_config_info(sys.stdout)


def main(argv: Optional[List[str]] = None) -> Optional[int]:
    return cli.run(argv)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
