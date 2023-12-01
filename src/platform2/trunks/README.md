# Trunks

Trunks is a daemon and library for interfacing with a Trusted Platform Module
(TPM).

Be aware that trunks does not comply with the Trusted Computing Group (TCG)
Software Stack (TSS) specification.

## Components

### trunksd

A daemon that centralizes access by other system daemons to a single shared TPM.
Other daemons send D-Bus requests to trunksd with TPM commands, trunksd sends
them through /dev/tpm0 (which can only be opened by a single process) and
responds over D-Bus with the TPM response.

Trunksd also performs resource management for the TPM, loading and unloading
objects transparently for the calling daemons.

### libtrunks

The calling-daemon side shared library that provides a C++ API for serializing
and deserializing various TPM commands and performing higher-level operations.

It is possible to use libtrunks independent of trunksd by providing a custom
CommandTransceiver to perform communication directly with a TPM, but the default
scenario is when libtrunks and trunksd are used together and communicate over a
D-Bus based transceiver.

## TPM Specification

See http://www.trustedcomputinggroup.org.  This version of trunks is based on
TPM 2.0 rev 00.99.

### Structures

`generator/raw_structures.txt`

`generator/raw_structures_fixed.txt`

This file is a direct PDF scrape (*) of 'Part 2 - Structures'.  The `_fixed`
version includes some manual fixes to make processing easier.

### Commands

`generator/raw_commands.txt`

`generator/raw_commands_fixed.txt`

This file is a direct PDF scrape (*) of 'Part 3 - Commands'.  The `_fixed`
version includes some manual fixes to make processing easier.

(*) Scraping for this version of trunks used Poppler's `pdftotext` utility
    v0.18.4.

## Code Generation

### `generator/extract_structures.sh`

Extracts structured information about types, constants, structures, and unions
from `generator/raw_structures_fixed.txt`.  The output of this script is
intended to be parsed by `generator.py`.

### `generator/extract_commands.sh`

Extracts structured information about commands from
`generator/raw_commands_fixed.txt`.  The output of this script is intended to be
parsed by `generator.py`.

### `generator/generator.py`

Generates C++ serialization and parsing code for TPM commands.  Inputs must be
formatted as by the `extract_*` scripts.
