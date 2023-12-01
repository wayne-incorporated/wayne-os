# Downloadable Content (DLC) Service Daemon Utility

## dlcservice-util

This is a wrapper utility for `dlcservice`. It can be used to install and
uninstall DLC modules, as well as print a list of installed modules.

## Usage

To install a DLC module, set the `--install` flag and set `--id` to a DLC ID.

`dlcservice_util --install --id="foo"`

To uninstall a DLC module, set the `--uninstall` flag and set `--id` to a
DLC ID.

`dlcservice_util --uninstall --id="foo"`

To list installed modules, set the `--list` flag.

`dlcservice_util --list`
