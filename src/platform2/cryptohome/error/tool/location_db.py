#!/usr/bin/env python3
# Copyright 2022 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""This tool maintains locations.h.

This tool generates and maintains the data in error/locations.h and also
verifies that the usage of error location is correct.
"""

import argparse
import bisect
import logging
import operator
import os
import os.path
import pathlib
import re
import subprocess
import sys
from typing import Dict, List, Optional, Set, Tuple
from xml.dom import pulldom


class TPMConsts:
    """A class for holding TPM constants."""

    # TPM related constants

    TPM2_RC_VER1 = 0x100
    TPM2_RC_FMT1 = 0x080
    TPM2_RC_WARN = 0x900
    TPM2_RC_S = 0x800
    TPM2_RC_P = 0x040
    TPM2_TRUNKS_ERROR_BASE = 7 << 12
    TPM2_TCTI_ERROR_BASE = 8 << 12
    TPM2_SAPI_ERROR_BASE = 9 << 12
    TPM2_RESOURCE_MANAGER_TPM_BASE = 11 << 12

    # For TPM Unified Errors, see platform2/libhwsec/error/tpm_error.h
    TPM_UNIFIED_TPM_MANAGER_BASE = TPM2_TRUNKS_ERROR_BASE + 0x800
    TPM_UNIFIED_TPM_MANAGER_MAX = TPM2_TRUNKS_ERROR_BASE + 0x87F

    TPM_UNIFIED_NVRAM_BASE = TPM2_TRUNKS_ERROR_BASE + 0x880
    TPM_UNIFIED_NVRAM_MAX = TPM2_TRUNKS_ERROR_BASE + 0x8FF

    TPM_UNIFIED_EC_BASE = TPM2_TRUNKS_ERROR_BASE + 0x900
    TPM_UNIFIED_EC_MAX = TPM2_TRUNKS_ERROR_BASE + 0x97F

    TPM_UNIFIED_HASHED_BASE = TPM2_TRUNKS_ERROR_BASE + 0xC00
    TPM_UNIFIED_HASHED_MAX = TPM2_TRUNKS_ERROR_BASE + 0xFFF

    TPM2_LAYER_MASK = 0xFFFFF000
    # Masks out the P and N bits (see TPM 2.0 Part 2 Table 14).
    TPM2_FORMAT_ONE_ERROR_MASK = 0x0BF
    # Selects just the N bits that identify the subject index.
    TPM2_SUBJECT_MASK = 0x700

    # For the bits below on format zero, see Table 13 — Format-Zero Response
    # Codes of TPM 2.0 Spec Part 2: Structures.
    # Indicates the error is vendor-specific if set.
    TPM_T_BIT = 0x400
    # Indicates the error is TPM 2.0.
    TPM_V_BIT = 0x100

    TPM1_TPM_E_BASE = 0x0
    TPM1_TSS_E_BASE = 0x0

    TPM1_TPM_E_NON_FATAL = 0x800

    TPM1_TSS_LAYER_TPM = 0x0
    TPM1_TSS_LAYER_TDDL = 0x1000
    TPM1_TSS_LAYER_TCS = 0x2000
    TPM1_TSS_LAYER_TSP = 0x3000

    TPM1_TPM_LAYER_START = TPM1_TSS_LAYER_TPM + TPM1_TPM_E_BASE
    TPM1_TDDL_LAYER_START = TPM1_TSS_LAYER_TDDL + TPM1_TSS_E_BASE
    TPM1_TCS_LAYER_START = TPM1_TSS_LAYER_TCS + TPM1_TSS_E_BASE
    TPM1_TSP_LAYER_START = TPM1_TSS_LAYER_TSP + TPM1_TSS_E_BASE


class TPMErrorDecoder:
    """A utility for decoding TPM 1.2 and 2.0 errors."""

    # A dictionary that maps between TPM 1.2 error and their representation.
    TPM1_ERRORS = {
        0: "TSS_SUCCESS",
        # Layer 0 (TPM)
        TPMConsts.TPM1_TPM_LAYER_START + 0x000: "TPM_E_SUCCESS",
        TPMConsts.TPM1_TPM_LAYER_START + 0x001: "TPM_E_AUTHFAIL",
        TPMConsts.TPM1_TPM_LAYER_START + 0x003: "TPM_E_BAD_PARAMETER",
        TPMConsts.TPM1_TPM_LAYER_START + 0x002: "TPM_E_BADINDEX",
        TPMConsts.TPM1_TPM_LAYER_START + 0x004: "TPM_E_AUDITFAILURE",
        TPMConsts.TPM1_TPM_LAYER_START + 0x005: "TPM_E_CLEAR_DISABLED",
        TPMConsts.TPM1_TPM_LAYER_START + 0x006: "TPM_E_DEACTIVATED",
        TPMConsts.TPM1_TPM_LAYER_START + 0x007: "TPM_E_DISABLED",
        TPMConsts.TPM1_TPM_LAYER_START + 0x008: "TPM_E_DISABLED_CMD",
        TPMConsts.TPM1_TPM_LAYER_START + 0x009: "TPM_E_FAIL",
        TPMConsts.TPM1_TPM_LAYER_START + 0x01C: "TPM_E_FAILEDSELFTEST",
        TPMConsts.TPM1_TPM_LAYER_START + 0x00A: "TPM_E_BAD_ORDINAL",
        TPMConsts.TPM1_TPM_LAYER_START + 0x00B: "TPM_E_INSTALL_DISABLED",
        TPMConsts.TPM1_TPM_LAYER_START + 0x00C: "TPM_E_INVALID_KEYHANDLE",
        TPMConsts.TPM1_TPM_LAYER_START + 0x00D: "TPM_E_KEYNOTFOUND",
        TPMConsts.TPM1_TPM_LAYER_START + 0x00E: "TPM_E_INAPPROPRIATE_ENC",
        TPMConsts.TPM1_TPM_LAYER_START + 0x00F: "TPM_E_MIGRATEFAIL",
        TPMConsts.TPM1_TPM_LAYER_START + 0x010: "TPM_E_INVALID_PCR_INFO",
        TPMConsts.TPM1_TPM_LAYER_START + 0x011: "TPM_E_NOSPACE",
        TPMConsts.TPM1_TPM_LAYER_START + 0x012: "TPM_E_NOSRK",
        TPMConsts.TPM1_TPM_LAYER_START + 0x013: "TPM_E_NOTSEALED_BLOB",
        TPMConsts.TPM1_TPM_LAYER_START + 0x014: "TPM_E_OWNER_SET",
        TPMConsts.TPM1_TPM_LAYER_START + 0x015: "TPM_E_RESOURCES",
        TPMConsts.TPM1_TPM_LAYER_START + 0x016: "TPM_E_SHORTRANDOM",
        TPMConsts.TPM1_TPM_LAYER_START + 0x017: "TPM_E_SIZE",
        TPMConsts.TPM1_TPM_LAYER_START + 0x018: "TPM_E_WRONGPCRVAL",
        TPMConsts.TPM1_TPM_LAYER_START + 0x019: "TPM_E_BAD_PARAM_SIZE",
        TPMConsts.TPM1_TPM_LAYER_START + 0x01A: "TPM_E_SHA_THREAD",
        TPMConsts.TPM1_TPM_LAYER_START + 0x01B: "TPM_E_SHA_ERROR",
        TPMConsts.TPM1_TPM_LAYER_START + 0x01C: "TPM_E_FAILEDSELFTEST",
        TPMConsts.TPM1_TPM_LAYER_START + 0x01D: "TPM_E_AUTH2FAIL",
        TPMConsts.TPM1_TPM_LAYER_START + 0x01E: "TPM_E_BADTAG",
        TPMConsts.TPM1_TPM_LAYER_START + 0x01F: "TPM_E_IOERROR",
        TPMConsts.TPM1_TPM_LAYER_START + 0x020: "TPM_E_ENCRYPT_ERROR",
        TPMConsts.TPM1_TPM_LAYER_START + 0x021: "TPM_E_DECRYPT_ERROR",
        TPMConsts.TPM1_TPM_LAYER_START + 0x022: "TPM_E_INVALID_AUTHHANDLE",
        TPMConsts.TPM1_TPM_LAYER_START + 0x023: "TPM_E_NO_ENDORSEMENT",
        TPMConsts.TPM1_TPM_LAYER_START + 0x024: "TPM_E_INVALID_KEYUSAGE",
        TPMConsts.TPM1_TPM_LAYER_START + 0x025: "TPM_E_WRONG_ENTITYTYPE",
        TPMConsts.TPM1_TPM_LAYER_START + 0x026: "TPM_E_INVALID_POSTINIT",
        TPMConsts.TPM1_TPM_LAYER_START + 0x027: "TPM_E_INAPPROPRIATE_SIG",
        TPMConsts.TPM1_TPM_LAYER_START + 0x028: "TPM_E_BAD_KEY_PROPERTY",
        TPMConsts.TPM1_TPM_LAYER_START + 0x029: "TPM_E_BAD_MIGRATION",
        TPMConsts.TPM1_TPM_LAYER_START + 0x02A: "TPM_E_BAD_SCHEME",
        TPMConsts.TPM1_TPM_LAYER_START + 0x02B: "TPM_E_BAD_DATASIZE",
        TPMConsts.TPM1_TPM_LAYER_START + 0x02C: "TPM_E_BAD_MODE",
        TPMConsts.TPM1_TPM_LAYER_START + 0x02D: "TPM_E_BAD_PRESENCE",
        TPMConsts.TPM1_TPM_LAYER_START + 0x02E: "TPM_E_BAD_VERSION",
        TPMConsts.TPM1_TPM_LAYER_START + 0x02F: "TPM_E_NO_WRAP_TRANSPORT",
        TPMConsts.TPM1_TPM_LAYER_START + 0x030: "TPM_E_AUDITFAIL_UNSUCCESSFUL",
        TPMConsts.TPM1_TPM_LAYER_START + 0x031: "TPM_E_AUDITFAIL_SUCCESSFUL",
        TPMConsts.TPM1_TPM_LAYER_START + 0x032: "TPM_E_NOTRESETABLE",
        TPMConsts.TPM1_TPM_LAYER_START + 0x033: "TPM_E_NOTLOCAL",
        TPMConsts.TPM1_TPM_LAYER_START + 0x034: "TPM_E_BAD_TYPE",
        TPMConsts.TPM1_TPM_LAYER_START + 0x035: "TPM_E_INVALID_RESOURCE",
        TPMConsts.TPM1_TPM_LAYER_START + 0x036: "TPM_E_NOTFIPS",
        TPMConsts.TPM1_TPM_LAYER_START + 0x037: "TPM_E_INVALID_FAMILY",
        TPMConsts.TPM1_TPM_LAYER_START + 0x038: "TPM_E_NO_NV_PERMISSION",
        TPMConsts.TPM1_TPM_LAYER_START + 0x039: "TPM_E_REQUIRES_SIGN",
        TPMConsts.TPM1_TPM_LAYER_START + 0x03A: "TPM_E_KEY_NOTSUPPORTED",
        TPMConsts.TPM1_TPM_LAYER_START + 0x03B: "TPM_E_AUTH_CONFLICT",
        TPMConsts.TPM1_TPM_LAYER_START + 0x03C: "TPM_E_AREA_LOCKED",
        TPMConsts.TPM1_TPM_LAYER_START + 0x03D: "TPM_E_BAD_LOCALITY",
        TPMConsts.TPM1_TPM_LAYER_START + 0x03E: "TPM_E_READ_ONLY",
        TPMConsts.TPM1_TPM_LAYER_START + 0x03F: "TPM_E_PER_NOWRITE",
        TPMConsts.TPM1_TPM_LAYER_START + 0x040: "TPM_E_FAMILYCOUNT",
        TPMConsts.TPM1_TPM_LAYER_START + 0x041: "TPM_E_WRITE_LOCKED",
        TPMConsts.TPM1_TPM_LAYER_START + 0x042: "TPM_E_BAD_ATTRIBUTES",
        TPMConsts.TPM1_TPM_LAYER_START + 0x043: "TPM_E_INVALID_STRUCTURE",
        TPMConsts.TPM1_TPM_LAYER_START + 0x044: "TPM_E_KEY_OWNER_CONTROL",
        TPMConsts.TPM1_TPM_LAYER_START + 0x045: "TPM_E_BAD_COUNTER",
        TPMConsts.TPM1_TPM_LAYER_START + 0x046: "TPM_E_NOT_FULLWRITE",
        TPMConsts.TPM1_TPM_LAYER_START + 0x047: "TPM_E_CONTEXT_GAP",
        TPMConsts.TPM1_TPM_LAYER_START + 0x048: "TPM_E_MAXNVWRITES",
        TPMConsts.TPM1_TPM_LAYER_START + 0x049: "TPM_E_NOOPERATOR",
        TPMConsts.TPM1_TPM_LAYER_START + 0x04A: "TPM_E_RESOURCEMISSING",
        TPMConsts.TPM1_TPM_LAYER_START + 0x04B: "TPM_E_DELEGATE_LOCK",
        TPMConsts.TPM1_TPM_LAYER_START + 0x04C: "TPM_E_DELEGATE_FAMILY",
        TPMConsts.TPM1_TPM_LAYER_START + 0x04D: "TPM_E_DELEGATE_ADMIN",
        TPMConsts.TPM1_TPM_LAYER_START + 0x04E: "TPM_E_TRANSPORT_NOTEXCLUSIVE",
        TPMConsts.TPM1_TPM_LAYER_START + 0x04F: "TPM_E_OWNER_CONTROL",
        TPMConsts.TPM1_TPM_LAYER_START + 0x050: "TPM_E_DAA_RESOURCES",
        TPMConsts.TPM1_TPM_LAYER_START + 0x051: "TPM_E_DAA_INPUT_DATA0",
        TPMConsts.TPM1_TPM_LAYER_START + 0x052: "TPM_E_DAA_INPUT_DATA1",
        TPMConsts.TPM1_TPM_LAYER_START + 0x053: "TPM_E_DAA_ISSUER_SETTINGS",
        TPMConsts.TPM1_TPM_LAYER_START + 0x054: "TPM_E_DAA_TPM_SETTINGS",
        TPMConsts.TPM1_TPM_LAYER_START + 0x055: "TPM_E_DAA_STAGE",
        TPMConsts.TPM1_TPM_LAYER_START + 0x056: "TPM_E_DAA_ISSUER_VALIDITY",
        TPMConsts.TPM1_TPM_LAYER_START + 0x057: "TPM_E_DAA_WRONG_W",
        TPMConsts.TPM1_TPM_LAYER_START + 0x058: "TPM_E_BAD_HANDLE",
        TPMConsts.TPM1_TPM_LAYER_START + 0x059: "TPM_E_BAD_DELEGATE",
        TPMConsts.TPM1_TPM_LAYER_START + 0x05A: "TPM_E_BADCONTEXT",
        TPMConsts.TPM1_TPM_LAYER_START + 0x05B: "TPM_E_TOOMANYCONTEXTS",
        TPMConsts.TPM1_TPM_LAYER_START + 0x05C: "TPM_E_MA_TICKET_SIGNATURE",
        TPMConsts.TPM1_TPM_LAYER_START + 0x05D: "TPM_E_MA_DESTINATION",
        TPMConsts.TPM1_TPM_LAYER_START + 0x05E: "TPM_E_MA_SOURCE",
        TPMConsts.TPM1_TPM_LAYER_START + 0x05F: "TPM_E_MA_AUTHORITY",
        TPMConsts.TPM1_TPM_LAYER_START + 0x061: "TPM_E_PERMANENTEK",
        TPMConsts.TPM1_TPM_LAYER_START + 0x062: "TPM_E_BAD_SIGNATURE",
        TPMConsts.TPM1_TPM_LAYER_START + 0x063: "TPM_E_NOCONTEXTSPACE",
        TPMConsts.TPM1_TPM_LAYER_START
        + TPMConsts.TPM1_TPM_E_NON_FATAL: "TPM_E_RETRY",
        TPMConsts.TPM1_TPM_LAYER_START
        + TPMConsts.TPM1_TPM_E_NON_FATAL
        + 1: "TPM_E_NEEDS_SELFTEST",
        TPMConsts.TPM1_TPM_LAYER_START
        + TPMConsts.TPM1_TPM_E_NON_FATAL
        + 2: "TPM_E_DOING_SELFTEST",
        TPMConsts.TPM1_TPM_LAYER_START
        + TPMConsts.TPM1_TPM_E_NON_FATAL
        + 3: "TPM_E_DEFEND_LOCK_RUNNING",
        TPMConsts.TPM1_TPM_LAYER_START + 0x008: "TPM_E_DISABLED_CMD",
        # Layer 1 (TDDL)
        TPMConsts.TPM1_TDDL_LAYER_START + 0x002: "TDDL: TSS_E_FAIL",
        TPMConsts.TPM1_TDDL_LAYER_START + 0x003: "TDDL: TSS_E_BAD_PARAMETER",
        TPMConsts.TPM1_TDDL_LAYER_START + 0x004: "TDDL: TSS_E_INTERNAL_ERROR",
        TPMConsts.TPM1_TDDL_LAYER_START + 0x006: "TDDL: TSS_E_NOTIMPL",
        TPMConsts.TPM1_TDDL_LAYER_START + 0x020: "TDDL: TSS_E_PS_KEY_NOTFOUND",
        TPMConsts.TPM1_TDDL_LAYER_START
        + 0x008: "TDDL: TSS_E_KEY_ALREADY_REGISTERED",
        TPMConsts.TPM1_TDDL_LAYER_START + 0x016: "TDDL: TSS_E_CANCELED",
        TPMConsts.TPM1_TDDL_LAYER_START + 0x012: "TDDL: TSS_E_TIMEOUT",
        TPMConsts.TPM1_TDDL_LAYER_START + 0x005: "TDDL: TSS_E_OUTOFMEMORY",
        TPMConsts.TPM1_TDDL_LAYER_START + 0x010: "TDDL: TSS_E_TPM_UNEXPECTED",
        TPMConsts.TPM1_TDDL_LAYER_START + 0x011: "TDDL: TSS_E_COMM_FAILURE",
        TPMConsts.TPM1_TDDL_LAYER_START
        + 0x014: "TDDL: TSS_E_TPM_UNSUPPORTED_FEATURE",
        TPMConsts.TPM1_TDDL_LAYER_START
        + 0x089: "TDDL: TDDL_E_COMPONENT_NOT_FOUND",
        TPMConsts.TPM1_TDDL_LAYER_START + 0x081: "TDDL: TDDL_E_ALREADY_OPENED",
        TPMConsts.TPM1_TDDL_LAYER_START + 0x088: "TDDL: TDDL_E_BADTAG",
        TPMConsts.TPM1_TDDL_LAYER_START
        + 0x083: "TDDL: TDDL_E_INSUFFICIENT_BUFFER",
        TPMConsts.TPM1_TDDL_LAYER_START
        + 0x084: "TDDL: TDDL_E_COMMAND_COMPLETED",
        TPMConsts.TPM1_TDDL_LAYER_START + 0x085: "TDDL: TDDL_E_COMMAND_ABORTED",
        TPMConsts.TPM1_TDDL_LAYER_START + 0x082: "TDDL: TDDL_E_ALREADY_CLOSED",
        TPMConsts.TPM1_TDDL_LAYER_START + 0x087: "TDDL: TDDL_E_IOERROR",
        # Layer 2 (TCS)
        TPMConsts.TPM1_TCS_LAYER_START + 0x002: "TCS: TSS_E_FAIL",
        TPMConsts.TPM1_TCS_LAYER_START + 0x003: "TCS: TSS_E_BAD_PARAMETER",
        TPMConsts.TPM1_TCS_LAYER_START + 0x004: "TCS: TSS_E_INTERNAL_ERROR",
        TPMConsts.TPM1_TCS_LAYER_START + 0x006: "TCS: TSS_E_NOTIMPL",
        TPMConsts.TPM1_TCS_LAYER_START + 0x020: "TCS: TSS_E_PS_KEY_NOTFOUND",
        TPMConsts.TPM1_TCS_LAYER_START
        + 0x008: "TCS: TSS_E_KEY_ALREADY_REGISTERED",
        TPMConsts.TPM1_TCS_LAYER_START + 0x016: "TCS: TSS_E_CANCELED",
        TPMConsts.TPM1_TCS_LAYER_START + 0x012: "TCS: TSS_E_TIMEOUT",
        TPMConsts.TPM1_TCS_LAYER_START + 0x005: "TCS: TSS_E_OUTOFMEMORY",
        TPMConsts.TPM1_TCS_LAYER_START + 0x010: "TCS: TSS_E_TPM_UNEXPECTED",
        TPMConsts.TPM1_TCS_LAYER_START + 0x011: "TCS: TSS_E_COMM_FAILURE",
        TPMConsts.TPM1_TCS_LAYER_START
        + 0x014: "TCS: TSS_E_TPM_UNSUPPORTED_FEATURE",
        TPMConsts.TPM1_TCS_LAYER_START + 0x0C8: "TCS: TCS_E_KEY_MISMATCH",
        TPMConsts.TPM1_TCS_LAYER_START + 0x0CA: "TCS: TCS_E_KM_LOADFAILED",
        TPMConsts.TPM1_TCS_LAYER_START + 0x0CC: "TCS: TCS_E_KEY_CONTEXT_RELOAD",
        TPMConsts.TPM1_TCS_LAYER_START + 0x0CD: "TCS: TCS_E_BAD_INDEX",
        TPMConsts.TPM1_TCS_LAYER_START
        + 0x0C1: "TCS: TCS_E_INVALID_CONTEXTHANDLE",
        TPMConsts.TPM1_TCS_LAYER_START + 0x0C2: "TCS: TCS_E_INVALID_KEYHANDLE",
        TPMConsts.TPM1_TCS_LAYER_START + 0x0C3: "TCS: TCS_E_INVALID_AUTHHANDLE",
        TPMConsts.TPM1_TCS_LAYER_START
        + 0x0C4: "TCS: TCS_E_INVALID_AUTHSESSION",
        TPMConsts.TPM1_TCS_LAYER_START + 0x0C2: "TCS: TCS_E_INVALID_KEYHANDLE",
        TPMConsts.TPM1_TCS_LAYER_START + 0x0C5: "TCS: TCS_E_INVALID_KEY",
        # Layer 3 (TSP)
        TPMConsts.TPM1_TSP_LAYER_START + 0x002: "TSP: TSS_E_FAIL",
        TPMConsts.TPM1_TSP_LAYER_START + 0x003: "TSP: TSS_E_BAD_PARAMETER",
        TPMConsts.TPM1_TSP_LAYER_START + 0x004: "TSP: TSS_E_INTERNAL_ERROR",
        TPMConsts.TPM1_TSP_LAYER_START + 0x006: "TSP: TSS_E_NOTIMPL",
        TPMConsts.TPM1_TSP_LAYER_START + 0x020: "TSP: TSS_E_PS_KEY_NOTFOUND",
        TPMConsts.TPM1_TSP_LAYER_START
        + 0x008: "TSP: TSS_E_KEY_ALREADY_REGISTERED",
        TPMConsts.TPM1_TSP_LAYER_START + 0x016: "TSP: TSS_E_CANCELED",
        TPMConsts.TPM1_TSP_LAYER_START + 0x012: "TSP: TSS_E_TIMEOUT",
        TPMConsts.TPM1_TSP_LAYER_START + 0x005: "TSP: TSS_E_OUTOFMEMORY",
        TPMConsts.TPM1_TSP_LAYER_START + 0x010: "TSP: TSS_E_TPM_UNEXPECTED",
        TPMConsts.TPM1_TSP_LAYER_START + 0x011: "TSP: TSS_E_COMM_FAILURE",
        TPMConsts.TPM1_TSP_LAYER_START
        + 0x014: "TSP: TSS_E_TPM_UNSUPPORTED_FEATURE",
        TPMConsts.TPM1_TSP_LAYER_START
        + 0x101: "TSP: TSS_E_INVALID_OBJECT_TYPE",
        TPMConsts.TPM1_TSP_LAYER_START
        + 0x10C: "TSP: TSS_E_INVALID_OBJECT_INITFLAG",
        TPMConsts.TPM1_TSP_LAYER_START + 0x126: "TSP: TSS_E_INVALID_HANDLE",
        TPMConsts.TPM1_TSP_LAYER_START + 0x102: "TSP: TSS_E_NO_CONNECTION",
        TPMConsts.TPM1_TSP_LAYER_START + 0x103: "TSP: TSS_E_CONNECTION_FAILED",
        TPMConsts.TPM1_TSP_LAYER_START + 0x104: "TSP: TSS_E_CONNECTION_BROKEN",
        TPMConsts.TPM1_TSP_LAYER_START + 0x105: "TSP: TSS_E_HASH_INVALID_ALG",
        TPMConsts.TPM1_TSP_LAYER_START
        + 0x106: "TSP: TSS_E_HASH_INVALID_LENGTH",
        TPMConsts.TPM1_TSP_LAYER_START + 0x107: "TSP: TSS_E_HASH_NO_DATA",
        TPMConsts.TPM1_TSP_LAYER_START + 0x127: "TSP: TSS_E_SILENT_CONTEXT",
        TPMConsts.TPM1_TSP_LAYER_START
        + 0x109: "TSP: TSS_E_INVALID_ATTRIB_FLAG",
        TPMConsts.TPM1_TSP_LAYER_START
        + 0x10A: "TSP: TSS_E_INVALID_ATTRIB_SUBFLAG",
        TPMConsts.TPM1_TSP_LAYER_START
        + 0x10B: "TSP: TSS_E_INVALID_ATTRIB_DATA",
        TPMConsts.TPM1_TSP_LAYER_START + 0x10D: "TSP: TSS_E_NO_PCRS_SET",
        TPMConsts.TPM1_TSP_LAYER_START + 0x10E: "TSP: TSS_E_KEY_NOT_LOADED",
        TPMConsts.TPM1_TSP_LAYER_START + 0x10F: "TSP: TSS_E_KEY_NOT_SET",
        TPMConsts.TPM1_TSP_LAYER_START + 0x110: "TSP: TSS_E_VALIDATION_FAILED",
        TPMConsts.TPM1_TSP_LAYER_START + 0x111: "TSP: TSS_E_TSP_AUTHREQUIRED",
        TPMConsts.TPM1_TSP_LAYER_START + 0x112: "TSP: TSS_E_TSP_AUTH2REQUIRED",
        TPMConsts.TPM1_TSP_LAYER_START + 0x113: "TSP: TSS_E_TSP_AUTHFAIL",
        TPMConsts.TPM1_TSP_LAYER_START + 0x114: "TSP: TSS_E_TSP_AUTH2FAIL",
        TPMConsts.TPM1_TSP_LAYER_START
        + 0x115: "TSP: TSS_E_KEY_NO_MIGRATION_POLICY",
        TPMConsts.TPM1_TSP_LAYER_START + 0x116: "TSP: TSS_E_POLICY_NO_SECRET",
        TPMConsts.TPM1_TSP_LAYER_START + 0x117: "TSP: TSS_E_INVALID_OBJ_ACCESS",
        TPMConsts.TPM1_TSP_LAYER_START + 0x118: "TSP: TSS_E_INVALID_ENCSCHEME",
        TPMConsts.TPM1_TSP_LAYER_START + 0x119: "TSP: TSS_E_INVALID_SIGSCHEME",
        TPMConsts.TPM1_TSP_LAYER_START + 0x120: "TSP: TSS_E_ENC_INVALID_LENGTH",
        TPMConsts.TPM1_TSP_LAYER_START + 0x121: "TSP: TSS_E_ENC_NO_DATA",
        TPMConsts.TPM1_TSP_LAYER_START + 0x122: "TSP: TSS_E_ENC_INVALID_TYPE",
        TPMConsts.TPM1_TSP_LAYER_START + 0x123: "TSP: TSS_E_INVALID_KEYUSAGE",
        TPMConsts.TPM1_TSP_LAYER_START
        + 0x124: "TSP: TSS_E_VERIFICATION_FAILED",
        TPMConsts.TPM1_TSP_LAYER_START + 0x125: "TSP: TSS_E_HASH_NO_IDENTIFIER",
        TPMConsts.TPM1_TSP_LAYER_START + 0x13B: "TSP: TSS_E_NV_AREA_EXIST",
        TPMConsts.TPM1_TSP_LAYER_START + 0x13C: "TSP: TSS_E_NV_AREA_NOT_EXIST",
    }

    # A dictionary that maps between TPM 2.0 error and their representation.
    TPM2_ERRORS = {
        0: "TPM_RC_SUCCESS",
        # Format 0 error code.
        TPMConsts.TPM2_RC_VER1 + 0x000: "TPM_RC_INITIALIZE",
        TPMConsts.TPM2_RC_VER1 + 0x001: "TPM_RC_FAILURE",
        TPMConsts.TPM2_RC_VER1 + 0x003: "TPM_RC_SEQUENCE",
        TPMConsts.TPM2_RC_VER1 + 0x00B: "TPM_RC_PRIVATE",
        TPMConsts.TPM2_RC_VER1 + 0x019: "TPM_RC_HMAC",
        TPMConsts.TPM2_RC_VER1 + 0x020: "TPM_RC_DISABLED",
        TPMConsts.TPM2_RC_VER1 + 0x021: "TPM_RC_EXCLUSIVE",
        TPMConsts.TPM2_RC_VER1 + 0x024: "TPM_RC_AUTH_TYPE",
        TPMConsts.TPM2_RC_VER1 + 0x025: "TPM_RC_AUTH_MISSING",
        TPMConsts.TPM2_RC_VER1 + 0x026: "TPM_RC_POLICY",
        TPMConsts.TPM2_RC_VER1 + 0x027: "TPM_RC_PCR",
        TPMConsts.TPM2_RC_VER1 + 0x028: "TPM_RC_PCR_CHANGED",
        TPMConsts.TPM2_RC_VER1 + 0x02D: "TPM_RC_UPGRADE",
        TPMConsts.TPM2_RC_VER1 + 0x02E: "TPM_RC_TOO_MANY_CONTEXTS",
        TPMConsts.TPM2_RC_VER1 + 0x02F: "TPM_RC_AUTH_UNAVAILABLE",
        TPMConsts.TPM2_RC_VER1 + 0x030: "TPM_RC_REBOOT",
        TPMConsts.TPM2_RC_VER1 + 0x031: "TPM_RC_UNBALANCED",
        TPMConsts.TPM2_RC_VER1 + 0x042: "TPM_RC_COMMAND_SIZE",
        TPMConsts.TPM2_RC_VER1 + 0x043: "TPM_RC_COMMAND_CODE",
        TPMConsts.TPM2_RC_VER1 + 0x044: "TPM_RC_AUTHSIZE",
        TPMConsts.TPM2_RC_VER1 + 0x045: "TPM_RC_AUTH_CONTEXT",
        TPMConsts.TPM2_RC_VER1 + 0x046: "TPM_RC_NV_RANGE",
        TPMConsts.TPM2_RC_VER1 + 0x047: "TPM_RC_NV_SIZE",
        TPMConsts.TPM2_RC_VER1 + 0x048: "TPM_RC_NV_LOCKED",
        TPMConsts.TPM2_RC_VER1 + 0x049: "TPM_RC_NV_AUTHORIZATION",
        TPMConsts.TPM2_RC_VER1 + 0x04A: "TPM_RC_NV_UNINITIALIZED",
        TPMConsts.TPM2_RC_VER1 + 0x04B: "TPM_RC_NV_SPACE",
        TPMConsts.TPM2_RC_VER1 + 0x04C: "TPM_RC_NV_DEFINED",
        TPMConsts.TPM2_RC_VER1 + 0x050: "TPM_RC_BAD_CONTEXT",
        TPMConsts.TPM2_RC_VER1 + 0x051: "TPM_RC_CPHASH",
        TPMConsts.TPM2_RC_VER1 + 0x052: "TPM_RC_PARENT",
        TPMConsts.TPM2_RC_VER1 + 0x053: "TPM_RC_NEEDS_TEST",
        TPMConsts.TPM2_RC_VER1 + 0x054: "TPM_RC_NO_RESULT",
        TPMConsts.TPM2_RC_VER1 + 0x055: "TPM_RC_SENSITIVE",
        # Format 1 error code.
        TPMConsts.TPM2_RC_FMT1 + 0x001: "TPM_RC_ASYMMETRIC",
        TPMConsts.TPM2_RC_FMT1 + 0x002: "TPM_RC_ATTRIBUTES",
        TPMConsts.TPM2_RC_FMT1 + 0x003: "TPM_RC_HASH",
        TPMConsts.TPM2_RC_FMT1 + 0x004: "TPM_RC_VALUE",
        TPMConsts.TPM2_RC_FMT1 + 0x005: "TPM_RC_HIERARCHY",
        TPMConsts.TPM2_RC_FMT1 + 0x007: "TPM_RC_KEY_SIZE",
        TPMConsts.TPM2_RC_FMT1 + 0x008: "TPM_RC_MGF",
        TPMConsts.TPM2_RC_FMT1 + 0x009: "TPM_RC_MODE",
        TPMConsts.TPM2_RC_FMT1 + 0x00A: "TPM_RC_TYPE",
        TPMConsts.TPM2_RC_FMT1 + 0x00B: "TPM_RC_HANDLE",
        TPMConsts.TPM2_RC_FMT1 + 0x00C: "TPM_RC_KDF",
        TPMConsts.TPM2_RC_FMT1 + 0x00D: "TPM_RC_RANGE",
        TPMConsts.TPM2_RC_FMT1 + 0x00E: "TPM_RC_AUTH_FAIL",
        TPMConsts.TPM2_RC_FMT1 + 0x00F: "TPM_RC_NONCE",
        TPMConsts.TPM2_RC_FMT1 + 0x010: "TPM_RC_PP",
        TPMConsts.TPM2_RC_FMT1 + 0x012: "TPM_RC_SCHEME",
        TPMConsts.TPM2_RC_FMT1 + 0x015: "TPM_RC_SIZE",
        TPMConsts.TPM2_RC_FMT1 + 0x016: "TPM_RC_SYMMETRIC",
        TPMConsts.TPM2_RC_FMT1 + 0x017: "TPM_RC_TAG",
        TPMConsts.TPM2_RC_FMT1 + 0x018: "TPM_RC_SELECTOR",
        TPMConsts.TPM2_RC_FMT1 + 0x01A: "TPM_RC_INSUFFICIENT",
        TPMConsts.TPM2_RC_FMT1 + 0x01B: "TPM_RC_SIGNATURE",
        TPMConsts.TPM2_RC_FMT1 + 0x01C: "TPM_RC_KEY",
        TPMConsts.TPM2_RC_FMT1 + 0x01D: "TPM_RC_POLICY_FAIL",
        TPMConsts.TPM2_RC_FMT1 + 0x01F: "TPM_RC_INTEGRITY",
        TPMConsts.TPM2_RC_FMT1 + 0x020: "TPM_RC_TICKET",
        TPMConsts.TPM2_RC_FMT1 + 0x021: "TPM_RC_RESERVED_BITS",
        TPMConsts.TPM2_RC_FMT1 + 0x022: "TPM_RC_BAD_AUTH",
        TPMConsts.TPM2_RC_FMT1 + 0x023: "TPM_RC_EXPIRED",
        TPMConsts.TPM2_RC_FMT1 + 0x024: "TPM_RC_POLICY_CC",
        TPMConsts.TPM2_RC_FMT1 + 0x025: "TPM_RC_BINDING",
        TPMConsts.TPM2_RC_FMT1 + 0x026: "TPM_RC_CURVE",
        TPMConsts.TPM2_RC_FMT1 + 0x027: "TPM_RC_ECC_POINT",
        # Format 0 error code.
        TPMConsts.TPM2_RC_WARN + 0x001: "TPM_RC_CONTEXT_GAP",
        TPMConsts.TPM2_RC_WARN + 0x002: "TPM_RC_OBJECT_MEMORY",
        TPMConsts.TPM2_RC_WARN + 0x003: "TPM_RC_SESSION_MEMORY",
        TPMConsts.TPM2_RC_WARN + 0x004: "TPM_RC_MEMORY",
        TPMConsts.TPM2_RC_WARN + 0x005: "TPM_RC_SESSION_HANDLES",
        TPMConsts.TPM2_RC_WARN + 0x006: "TPM_RC_OBJECT_HANDLES",
        TPMConsts.TPM2_RC_WARN + 0x007: "TPM_RC_LOCALITY",
        TPMConsts.TPM2_RC_WARN + 0x008: "TPM_RC_YIELDED",
        TPMConsts.TPM2_RC_WARN + 0x009: "TPM_RC_CANCELED",
        TPMConsts.TPM2_RC_WARN + 0x00A: "TPM_RC_TESTING",
        TPMConsts.TPM2_RC_WARN + 0x010: "TPM_RC_REFERENCE_H0",
        TPMConsts.TPM2_RC_WARN + 0x011: "TPM_RC_REFERENCE_H1",
        TPMConsts.TPM2_RC_WARN + 0x012: "TPM_RC_REFERENCE_H2",
        TPMConsts.TPM2_RC_WARN + 0x013: "TPM_RC_REFERENCE_H3",
        TPMConsts.TPM2_RC_WARN + 0x014: "TPM_RC_REFERENCE_H4",
        TPMConsts.TPM2_RC_WARN + 0x015: "TPM_RC_REFERENCE_H5",
        TPMConsts.TPM2_RC_WARN + 0x016: "TPM_RC_REFERENCE_H6",
        TPMConsts.TPM2_RC_WARN + 0x018: "TPM_RC_REFERENCE_S0",
        TPMConsts.TPM2_RC_WARN + 0x019: "TPM_RC_REFERENCE_S1",
        TPMConsts.TPM2_RC_WARN + 0x01A: "TPM_RC_REFERENCE_S2",
        TPMConsts.TPM2_RC_WARN + 0x01B: "TPM_RC_REFERENCE_S3",
        TPMConsts.TPM2_RC_WARN + 0x01C: "TPM_RC_REFERENCE_S4",
        TPMConsts.TPM2_RC_WARN + 0x01D: "TPM_RC_REFERENCE_S5",
        TPMConsts.TPM2_RC_WARN + 0x01E: "TPM_RC_REFERENCE_S6",
        TPMConsts.TPM2_RC_WARN + 0x020: "TPM_RC_NV_RATE",
        TPMConsts.TPM2_RC_WARN + 0x021: "TPM_RC_LOCKOUT",
        TPMConsts.TPM2_RC_WARN + 0x022: "TPM_RC_RETRY",
        TPMConsts.TPM2_RC_WARN + 0x023: "TPM_RC_NV_UNAVAILABLE",
        TPMConsts.TPM2_RC_WARN + 0x7F: "TPM_RC_NOT_USED",
        # Trunks and related errors.
        TPMConsts.TPM2_TRUNKS_ERROR_BASE + 1: "TRUNKS_RC_AUTHORIZATION_FAILED",
        TPMConsts.TPM2_TRUNKS_ERROR_BASE + 2: "TRUNKS_RC_ENCRYPTION_FAILED",
        TPMConsts.TPM2_TRUNKS_ERROR_BASE + 3: "TRUNKS_RC_READ_ERROR",
        TPMConsts.TPM2_TRUNKS_ERROR_BASE + 4: "TRUNKS_RC_WRITE_ERROR",
        TPMConsts.TPM2_TRUNKS_ERROR_BASE + 5: "TRUNKS_RC_IPC_ERROR",
        TPMConsts.TPM2_TRUNKS_ERROR_BASE + 6: "TRUNKS_RC_SESSION_SETUP_ERROR",
        TPMConsts.TPM2_TRUNKS_ERROR_BASE
        + 7: "TRUNKS_RC_INVALID_TPM_CONFIGURATION",
        TPMConsts.TPM2_TCTI_ERROR_BASE + 1: "TCTI_RC_TRY_AGAIN",
        TPMConsts.TPM2_TCTI_ERROR_BASE + 2: "TCTI_RC_GENERAL_FAILURE",
        TPMConsts.TPM2_TCTI_ERROR_BASE + 3: "TCTI_RC_BAD_CONTEXT",
        TPMConsts.TPM2_TCTI_ERROR_BASE + 4: "TCTI_RC_WRONG_ABI_VERSION",
        TPMConsts.TPM2_TCTI_ERROR_BASE + 5: "TCTI_RC_NOT_IMPLEMENTED",
        TPMConsts.TPM2_TCTI_ERROR_BASE + 6: "TCTI_RC_BAD_PARAMETER",
        TPMConsts.TPM2_TCTI_ERROR_BASE + 7: "TCTI_RC_INSUFFICIENT_BUFFER",
        TPMConsts.TPM2_TCTI_ERROR_BASE + 8: "TCTI_RC_NO_CONNECTION",
        TPMConsts.TPM2_TCTI_ERROR_BASE + 9: "TCTI_RC_DRIVER_NOT_FOUND",
        TPMConsts.TPM2_TCTI_ERROR_BASE + 10: "TCTI_RC_DRIVERINFO_NOT_FOUND",
        TPMConsts.TPM2_TCTI_ERROR_BASE + 11: "TCTI_RC_NO_RESPONSE",
        TPMConsts.TPM2_TCTI_ERROR_BASE + 12: "TCTI_RC_BAD_VALUE",
        TPMConsts.TPM2_SAPI_ERROR_BASE + 1: "SAPI_RC_INVALID_SESSIONS",
        TPMConsts.TPM2_SAPI_ERROR_BASE + 2: "SAPI_RC_ABI_MISMATCH",
        TPMConsts.TPM2_SAPI_ERROR_BASE + 3: "SAPI_RC_INSUFFICIENT_BUFFER",
        TPMConsts.TPM2_SAPI_ERROR_BASE + 4: "SAPI_RC_BAD_PARAMETER",
        TPMConsts.TPM2_SAPI_ERROR_BASE + 5: "SAPI_RC_BAD_SEQUENCE",
        TPMConsts.TPM2_SAPI_ERROR_BASE + 6: "SAPI_RC_NO_DECRYPT_PARAM",
        TPMConsts.TPM2_SAPI_ERROR_BASE + 7: "SAPI_RC_NO_ENCRYPT_PARAM",
        TPMConsts.TPM2_SAPI_ERROR_BASE + 8: "SAPI_RC_NO_RESPONSE_RECEIVED",
        TPMConsts.TPM2_SAPI_ERROR_BASE + 9: "SAPI_RC_BAD_SIZE",
        TPMConsts.TPM2_SAPI_ERROR_BASE + 10: "SAPI_RC_CORRUPTED_DATA",
        TPMConsts.TPM2_SAPI_ERROR_BASE + 11: "SAPI_RC_INSUFFICIENT_CONTEXT",
        TPMConsts.TPM2_SAPI_ERROR_BASE + 12: "SAPI_RC_INSUFFICIENT_RESPONSE",
        TPMConsts.TPM2_SAPI_ERROR_BASE + 13: "SAPI_RC_INCOMPATIBLE_TCTI",
        TPMConsts.TPM2_SAPI_ERROR_BASE + 14: "SAPI_RC_MALFORMED_RESPONSE",
        TPMConsts.TPM2_SAPI_ERROR_BASE + 15: "SAPI_RC_BAD_TCTI_STRUCTURE",
        TPMConsts.TPM2_SAPI_ERROR_BASE + 16: "SAPI_RC_NO_CONNECTION",
    }

    def __init__(self):
        pass

    @staticmethod
    def _map_tpm2_error(err: int) -> str:
        """Find the textual representation of a TPM2 error."""

        if err in TPMErrorDecoder.TPM2_ERRORS:
            return TPMErrorDecoder.TPM2_ERRORS[err]
        return ""

    @staticmethod
    def _map_tpm12_error(err: int) -> str:
        """Find the textual representation of a TPM1.2 error."""

        if err in TPMErrorDecoder.TPM1_ERRORS:
            return TPMErrorDecoder.TPM1_ERRORS[err]
        return ""

    @staticmethod
    def _is_format_one(err: int) -> bool:
        """Check if an error is a TPM Format One Error."""

        # For more information, see TPM2.0 specification.
        return (err & TPMConsts.TPM2_LAYER_MASK) == 0 and (
            err & TPMConsts.TPM2_RC_FMT1
        ) != 0

    @staticmethod
    def _handle_unified(err: int) -> Tuple[bool, str]:
        """Deal with TPM Unified Errors.

        Returns:
            True and the textual representation if it's a TPM Unified Error.
            False otherwise.
        """

        # For the errors below, refer to platform2/libhwsec/error/tpm_error.h
        # for more info.
        if (
            TPMConsts.TPM_UNIFIED_TPM_MANAGER_BASE
            <= err
            <= TPMConsts.TPM_UNIFIED_TPM_MANAGER_MAX
        ):
            return True, "TPM Manager Error 0x%02x" % (
                err - TPMConsts.TPM_UNIFIED_TPM_MANAGER_BASE
            )

        if (
            TPMConsts.TPM_UNIFIED_NVRAM_BASE
            <= err
            <= TPMConsts.TPM_UNIFIED_NVRAM_MAX
        ):
            return True, "TPM Manager NVRAM Error 0x%02x" % (
                err - TPMConsts.TPM_UNIFIED_NVRAM_BASE
            )

        if TPMConsts.TPM_UNIFIED_EC_BASE <= err <= TPMConsts.TPM_UNIFIED_EC_MAX:
            return True, "Elliptic Curve Error 0x%02x" % (
                err - TPMConsts.TPM_UNIFIED_EC_BASE
            )

        if (
            TPMConsts.TPM_UNIFIED_HASHED_BASE
            <= err
            <= TPMConsts.TPM_UNIFIED_HASHED_MAX
        ):
            return True, "Hashed Error 0x%04x" % (
                err - TPMConsts.TPM_UNIFIED_HASHED_BASE
            )

        return False, ""

    @staticmethod
    def decode(err: int) -> str:
        """Convert a given TPM error to textual representation."""

        is_unified, unified_repr = TPMErrorDecoder._handle_unified(err)
        if is_unified:
            return unified_repr

        err_str = TPMErrorDecoder._map_tpm2_error(err)
        if err_str != "":
            return err_str

        prefix = ""
        # Check for resource manager related error code.
        if (
            err & TPMConsts.TPM2_LAYER_MASK
        ) == TPMConsts.TPM2_RESOURCE_MANAGER_TPM_BASE:
            err = err & (~TPMConsts.TPM2_LAYER_MASK)
            err_str = TPMErrorDecoder._map_tpm2_error(err)
            prefix = "Resource Manager: "

        if TPMErrorDecoder._is_format_one(err):
            if err & TPMConsts.TPM2_RC_P != 0:
                prefix += "Parameter "
            elif err & TPMConsts.TPM2_RC_S != 0:
                prefix += "Session "
            else:
                prefix += "Handle "

            prefix += "%d: " % ((err & TPMConsts.TPM2_SUBJECT_MASK) >> 8,)
            err = err & TPMConsts.TPM2_FORMAT_ONE_ERROR_MASK
            err_str = TPMErrorDecoder._map_tpm2_error(err)
        else:
            # Format 0
            if (
                err & TPMConsts.TPM_T_BIT == 0
                and err & TPMConsts.TPM_V_BIT == 0
            ):
                # Legacy error.
                err_str = TPMErrorDecoder._map_tpm12_error(err)
        if err_str == "":
            err_str = "Unknown Error 0x%03x" % (err,)
        return prefix + err_str


class Symbol:
    """Represents a symbol for error location."""

    HEADER_TEMPLATE = "/* %s */\n%s = %d,\n"

    def __init__(self, symbol: str):
        """Constructor for Symbol.

        Args:
            symbol: The representation of the symbol.
        """

        # 'symbol' is the string that represents the symbol.
        # It is the identifier used in the C/C++ source.
        self.symbol = symbol

        # 'allow_dup' is set to true if the configuration file specifically
        # allows this symbol to be used multiple times in the source file.
        self.allow_dup = False

        # 'line_num' is the list of line numbers at which this symbol
        # appeared in the source file. It corresponds 1:1 with
        # self.index_in_file and self.path.
        self.line_num = []

        # 'index_in_file' is the location of the symbol in the source file, in
        # number of characters. It is a list and each element corresponds 1:1
        # with self.line_num and self.path.
        self.index_in_file = []

        # 'path' is the path to the file. It is a list and each element
        # corresponds 1:1 with self.index_in_file and self.line_num.
        self.path = []

        # 'value' is the numeric value of the symbol, if one is assigned.
        # It is the value for the enum in the generated file.
        self.value = None

    def generate_lines(self) -> List[str]:
        """Generates the lines for this symbol in locations.h.

        Returns:
            A list of strings that is the lines to be placed in locations.h.
        """

        assert self.value is not None
        return [
            Symbol.HEADER_TEMPLATE
            % (self._generate_comments(), self.symbol, self.value),
        ]

    def _generate_comments(self) -> str:
        if self.allow_dup:
            return "=Duplicate Allowed="
        if len(self.line_num) == 0 and len(self.path) == 0:
            return "=Obsolete="
        assert len(self.line_num) == 1 and len(self.path) == 1
        return "%s" % (self.path[0],)

    def merge(self, target: "Symbol"):
        """Merges information from another symbol into this object.

        The caller is responsible for destroying target after the call.
        There's no guarantee on the state of target after the call.

        Args:
            target: Another Symbol.
        """

        assert self.symbol == target.symbol
        assert self.allow_dup == target.allow_dup
        assert len(self.line_num) == len(self.index_in_file)
        assert len(self.line_num) == len(self.path)
        assert len(target.line_num) == len(target.index_in_file)
        assert len(target.line_num) == len(target.path)

        self.line_num += target.line_num
        self.path += target.path
        self.index_in_file += target.index_in_file

        if self.value is not None:
            assert target.value is None
        else:
            self.value = target.value

    def __str__(self) -> str:
        locs = ",".join(["%s:%d" % x for x in zip(self.path, self.line_num)])
        result = "%s=%s @ %s" % (self.symbol, self.value, locs)
        if self.allow_dup:
            result += " duplicates allowed"
        return result


class LineNumberFinder:
    """This converts index in file to line number.

    This utility converts position in the file into line number.
    Each instance represents a file.
    """

    def __init__(self, content: str):
        """Constructor for LineNumberFinder.

        Args:
            content: The content of the file.
        """

        # '_content' is the content of the file in string format.
        self._content = content

        # '_line_num_of_index' is the mapping from line number to index.
        # -1 here so that binary search is guaranteed to be bounded and that
        # the line number starts from 1.
        self._line_num_of_index = [-1, 0]

        self._preprocess()

    def _preprocess(self):
        """Populate self._line_num_of_index."""
        self._line_num_of_index.extend(
            i for i, c in enumerate(self._content) if c == "\n"
        )
        self._line_num_of_index.append(len(self._content))

    def find_by_pos(self, idx: int) -> int:
        """Find the line that idx char is on.

        Args:
            idx: The location in number of characters.

        Returns:
            An integer that is the line number, it starts from 1.
        """
        return bisect.bisect_right(self._line_num_of_index, idx) - 1


class SourceScanner:
    """This scans for error location usage in the source"""

    ERROR_LOC_USAGE_RE = r"CRYPTOHOME_ERR_LOC\(\s*([a-zA-Z][a-zA-Z0-9]*)\s*\)"

    @staticmethod
    def scan_single_file(path: str) -> List[Symbol]:
        """Scan a single file for error location usage.

        Args:
            path: The path to the file to scan.

        Returns:
            A list of Symbol, representing the symbols found in the given file.
        """

        logging.debug("Scanning file %s", path)
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
        linenum_util = LineNumberFinder(content)
        results = []

        # Search for the target string in the source file.
        pat = re.compile(SourceScanner.ERROR_LOC_USAGE_RE)
        for m in pat.finditer(content):
            loc_name = m.group(1)
            loc_pos = m.start(1)
            symbol = Symbol(loc_name)
            symbol.path.append(path)
            symbol.index_in_file.append(loc_pos)
            symbol.line_num.append(linenum_util.find_by_pos(loc_pos))
            results.append(symbol)

        return results

    @staticmethod
    def scan_directory(path: str, allowed_ext: Set[str]) -> List[Symbol]:
        """Scan a directory recursively for error location usage.

        Args:
            path: The path to the directory to scan.
            allowed_ext: Allowed extensions.
                Only scan files with extensions in the Set.

        Returns:
            A list of Symbol, representing the symbols found in the directory.
        """

        logging.debug("Scanning directory %s", path)
        result = []
        for f in os.scandir(path):
            if f.is_dir():
                result += SourceScanner.scan_directory(f.path, allowed_ext)
                continue
            if (
                f.is_file()
                and os.path.splitext(f.name.lower())[1] in allowed_ext
            ):
                result += SourceScanner.scan_single_file(f.path)
        return result


class Verifier:
    """Verifies the result from scanning.

    This is used to verify that the result from scanner is the correct usage
    for error location, i.e. there are no duplications outside of the allowed
    ones. It also helps to collate the various symbols together.
    """

    def __init__(self, dup_allowlist: Set[str]):
        """Constructor for Verifier.

        Args:
            dup_allowlist: a set of symbol representation that is in the
            duplication allowlist. If a symbol is in the allowlist, then that
            string can be used multiple times in the source file.
        """

        # '_dup_allowlist' is the duplication allowlist, see comment above.
        self._dup_allowlist = dup_allowlist

    def _update_allow_dup_in_symbols(self, symbols):
        """Update .allow_dup for all symbol in symbols."""

        for sym in symbols:
            if sym.symbol in self._dup_allowlist:
                sym.allow_dup = True

    def collate_and_verify(
        self, input_symbols: List[Symbol]
    ) -> Tuple[Dict[str, Symbol], Dict[str, Symbol]]:
        """Collate the list of symbols and check for duplications.

        This function collate the symbols by merging the same symbol in the
        `input_symbols` list, and check to see if there's any duplicate for
        symbols not in the `self._dup_allowlist`.

        Args:
            input_symbols: A list of symbols from the codebase.

        Returns:
            Tuple of collated_symbols and violating_dup.
            `collated_symbols` is the collated symbols after removing
            duplicates.
            `violating_dup` is the set of symbols that are duplicated and not
            in the allow list.
        """

        self._update_allow_dup_in_symbols(input_symbols)
        collated_symbols = {}
        violating_dup = {}
        for sym in input_symbols:
            dup = collated_symbols.get(sym.symbol)
            if dup:
                if sym.allow_dup:
                    dup.merge(sym)
                else:
                    dup.merge(sym)
                    violating_dup[sym.symbol] = dup
            else:
                # No duplicates.
                collated_symbols[sym.symbol] = sym
        return collated_symbols, violating_dup


class AuthorManager:
    """Manages committers and separator in locations.h to avoid collision.

    This class maintains the list of committers who've been allocated their own
    block of values in locations.h. This will prevent/reduce the amount of
    merge conflict that could happen in locations.h.
    """

    # A list of committers and their respective starting value in locations.h
    # This list should always be sorted by value.
    COMMITTERS = [
        (1500, "zuan@chromium.org"),
        (1700, "yich@google.com"),
        (1900, "anastasiian@google.com"),
        (2100, "jadmanski@google.com"),
        (2300, "thomascedeno@google.com"),
        (2500, "betuls@google.com"),
        (2700, "emaxx@chromium.org"),
        (2900, "dlunev@chromium.org"),
        (3100, "hardikgoyal@google.com"),
        (3300, "hcyang@google.com"),
        (3500, "lziest@google.com"),
    ]

    # Default starting value for committers who are not listed.
    # The enums start at 100 because we want to reserve the first 100 enum
    # in case there's any special use case.
    DEFAULT_START = 100

    def __init__(self):
        """Constructor for AuthorManager"""

        # Verify that COMMITTERS is indeed sorted.
        last = AuthorManager.DEFAULT_START
        for start, _ in AuthorManager.COMMITTERS:
            assert start > last
            last = start

    def _get_git_config_email(self) -> str:
        """Retrieves the email used as git's committing email in cryptohome.

        Returns:
            str: The email to commit the CL.
        """

        # Execute git config user.email to get the user's email.
        result = subprocess.run(
            ["git", "config", "user.email"], stdout=subprocess.PIPE, check=True
        )
        # Note that cwd is not set because we're expected to be at the source
        # directory.
        return result.stdout.decode("utf8").strip()

    def get_start(self, commit_email: Optional[str] = None) -> int:
        """Retrieves the starting value in locations.h for the commit email.

        Args:
            commit_email: Commit email for getting the starting value. Use None
                to get the value from git.

        Returns:
            int: The starting value.
        """

        if commit_email is None:
            commit_email = self._get_git_config_email()
        for start, committer in AuthorManager.COMMITTERS:
            if committer == commit_email:
                return start
        return AuthorManager.DEFAULT_START

    def _generate_single_comment(self, location: int) -> List[str]:
        """Generates the separator comment block at location.

        Args:
            location: The location/value at which this block will be placed in
                locations.h.

        Returns:
            List[str]: The comments, each element of the list is a line.
        """

        result = []
        # This comment block's only purpose is to avoid merge conflict between
        # different blocks of generated enums.
        result.append("  //////////////////////////////////////////////////\n")
        result.append(
            "  //// This is a separator block at value %d\n" % location
        )
        result.append("  //// See location_db.py for more info.\n")
        result.append("  //////////////////////////////////////////////////\n")
        return result

    def get_separator_comment(
        self, previous_value: int, next_value: int
    ) -> List[str]:
        """Generates/retrieves the separator comment in locations.h.

        This function generate/retrieve the separator comment block that is
        supposed to appear between the 2 given value in locations.h

        Args:
            previous_value: The first value before the comment.
            next_value: The value right after the comment.

        Returns:
            List[str]: Each str in the list is a line of comment to be inserted.
        """

        # From a big O perspective the algorithm below is suboptimal, and could
        # be replaced with a binary search tree. However, the amount of
        # committers we've is very low so the optimization is probably not
        # worth it given the complexity and higher constant time.
        result = []
        for start, _ in AuthorManager.COMMITTERS:
            if previous_value < start <= next_value:
                result += self._generate_single_comment(start)
        return result


class LocationDB:
    """Database in locations.h

    This class manages the mapping between error location symbol and their
    values in locations.h.
    """

    GENERATED_START = (
        "// Start of generated content. Do NOT modify after this line."
    )
    GENERATED_END = "// End of generated content."
    EXISTING_RECORDS_RE = (
        r"\/\*\s*([a-zA-Z0-9:/_.= \n]|\s)*\s*\*\/\s*"
        r"\s+([a-zA-Z][a-zA-Z0-9]*)\s*\=\s*([0-9]+)\s*,"
    )

    def __init__(self, path: str, dup_allowlist: Set[str]):
        """Constructor for LocationDB.

        Args:
            path: The path to locations.h.
            dup_allowlist: Duplication allowlist, see
            Verifier.__init__'s documentation.
        """

        # 'path' is the path to locations.h.
        self.path = path

        # '_dup_allowlist' is a set that holds the allowlist of symbols that
        # can be used multiple times in the source tree. See Verifier.__init__
        # for more info.
        self._dup_allowlist = dup_allowlist

        # 'symbols' is a dict that maps the symbol's representation (as a str)
        # to the Symbol object. It is None if we are not loaded yet.
        self.symbols = None

        # 'value_to_symbol' is a dict that maps the symbol's value (the integer
        # value of the enum) to the Symbol object. It is None if we are not
        # loaded yet.
        self.value_to_symbol = None

        # '_lines' holds the content of the locations.h file. It is None if we
        # are not loaded yet.
        self._lines = None

        # '_start_line' is the line number in locations.h at which the enum
        # section starts. It is None if we are not loaded yet.
        # Line number starts from 1.
        self._start_line = None

        # '_end_line' is the line number in locations.h at which the enum
        # section ends. It is None if we are not loaded yet.
        # Line number starts from 1.
        self._end_line = None

        # '_author_manager' is an instance of AuthorManager, for managing the
        # start location and separator comment blocks in locations.h
        self._author_manager = AuthorManager()

    def _find_generated_marker(self):
        """Finds and sets the start and end of generated marker.

        Returns:
            bool: True iff only one pair of generated marker is found.
        """

        self._start_line = None
        self._end_line = None
        for line_num_index, line in enumerate(self._lines):
            line_num = line_num_index + 1
            if line.strip() == LocationDB.GENERATED_START:
                if self._start_line is not None:
                    logging.error(
                        ("Multiple generated starting marker at %d and %d"),
                        self._start_line,
                        line_num,
                    )
                    return False
                self._start_line = line_num
            if line.strip() == LocationDB.GENERATED_END:
                if self._end_line is not None:
                    logging.error(
                        ("Multiple generated ending marker at %d and %d"),
                        self._end_line,
                        line_num,
                    )
                    return False
                self._end_line = line_num
        if self._start_line is None:
            logging.error("No generated starting marker in locations.h")
            return False
        if self._end_line is None:
            logging.error("No generated ending marker in locations.h")
            return False
        return True

    def _scan_for_existing_records(self, content):
        """Parse all existing records in 'content'."""
        pat = re.compile(LocationDB.EXISTING_RECORDS_RE)
        self.symbols = {}
        for m in pat.finditer(content):
            s = Symbol(m.group(2))
            s.value = int(m.group(3))
            self.symbols[s.symbol] = s
        return len(self.symbols)

    def _build_reverse_map(self):
        """Populate self.value_to_symbol."""
        self.value_to_symbol = {}
        for sym in self.symbols:
            value = self.symbols[sym].value
            if value is not None:
                # symbols are guaranteed to be unique in existing locations.h.
                assert value not in self.value_to_symbol
                self.value_to_symbol[value] = sym

    def _get_generated_lines(self):
        assert self._start_line is not None
        assert self._end_line is not None
        return "\n".join(self._lines[self._start_line : self._end_line - 1])

    def load(self) -> bool:
        """Load from locations.h.

        This method will load the content of locations.h from `self.path`.

        Returns:
            bool: True if successful.
        """

        with open(self.path, "r", encoding="utf-8") as f:
            self._lines = f.readlines()
        if not self._find_generated_marker():
            return False
        self._scan_for_existing_records(self._get_generated_lines())
        self._build_reverse_map()
        return True

    def _generate_header_lines(self):
        symbols_list = list(self.symbols.values())
        symbols_list.sort(key=operator.attrgetter("value"))
        result = []
        previous_value = -1
        for sym in symbols_list:
            assert isinstance(sym.value, int)
            result += self._author_manager.get_separator_comment(
                previous_value, sym.value
            )
            result += sym.generate_lines()
            previous_value = sym.value
        # 1<<32 is a large value that we know is larger than all known possible
        # symbol values.
        result += self._author_manager.get_separator_comment(
            previous_value, 1 << 32
        )
        return result

    def store(self) -> None:
        """Save the state in this object back into locations.h.

        This method will convert the state in this object into string content
        to be written back into locations.h, then it'll write the result into
        `self.path`.
        """

        assert self._lines is not None and self.symbols is not None
        result_lines = []
        # Include the portion that is before the generated content.
        result_lines += self._lines[0 : self._start_line]
        # Add the generated portion
        result_lines += self._generate_header_lines()
        # Include the portion that is after the generated content.
        result_lines += self._lines[self._end_line - 1 :]
        with open(self.path, "w", encoding="utf-8") as f:
            f.write("".join(result_lines))
        # Invalidate the variables to ensure stale data isn't left behind.
        self.symbols = None
        self._lines = None
        self._start_line = None
        self._end_line = None
        self.value_to_symbol = None
        # Format the result
        subprocess.call(["clang-format", "-i", self.path])

    def update_from_scan_result(self, result: Dict[str, Symbol]) -> None:
        """Update the state of this object.

        This method will update the internal state within this object from
        the Symbols found in `result`.

        Args:
            result: A dict of symbols found in source tree.
        """

        taken = set()

        # Clear relevant fields in the current symbols.
        for sym in self.symbols.values():
            sym.line_num = []
            sym.path = []
            sym.index_in_file = []
            sym.allow_dup = sym.symbol in self._dup_allowlist
            if sym.value:
                taken.add(sym.value)

        next_value = self._author_manager.get_start()

        def _get_next_value(next_value_param):
            while next_value_param in taken:
                next_value_param += 1
            taken.add(next_value_param)
            return next_value_param

        for sym in result.values():
            if sym.symbol in self.symbols:
                self.symbols[sym.symbol].merge(sym)
            else:
                self.symbols[sym.symbol] = sym
                next_value = _get_next_value(next_value)
                self.symbols[sym.symbol].value = next_value

        self._build_reverse_map()


class EnumsXmlDB:
    """For reading and writing enums.xml

    This class allows us to discover the error locations that are already
    documented in enums.xml. It also allows us to update enums.xml with the
    given new sets of documented error locations.
    """

    ENUM_START_MARKER_TEMPLATE = '<enum name="%s">'
    ENUM_STOP_MARKER = "</enum>"
    GENERATED_COMMENTS = """
  This enum is intended to be populated automatically by
  platform2/cryptohome/error/tool/location_db.py. It populates all values
  found in the cryptohome code base.

  It is allowed to manually add <int> error location to this file, and the
  added error location will continue to be updated when the script runs the
  next time. However, the label, and all changes to the label field may be
  overwritten by the tool. Furthermore, removal of <int> may be added back
  if that bucket is still observed in the field.
"""
    ERROR_LOCATION_COMMENTS = f"""<!--{GENERATED_COMMENTS}
  The labels are the Cryptohome Error Location enum defined in
  platform2/cryptohome/error/locations.h
  -->

"""

    ERROR_LOCATION_WITH_TPM_COMMENTS = f"""<!--{GENERATED_COMMENTS}
  The labels are the composites of Cryptohome Error Location enum defined in
  platform2/cryptohome/error/locations.h
  and respective TPM error code.
  -->

"""
    INT_VALUE_TAG_TEMPLATE = '<int value="%d" label="%s"/>\n'

    def __init__(self, enums_xml_path: str):
        """Constructor for EnumsXmlDB.

        Args:
            enums_xml_path: Absolute full path to enums.xml
        """
        self.enums_xml_path = enums_xml_path
        # Standard location values used by Cryptohome.Error.AllLocations
        self.error_locs = []
        # Composite values used by Cryptohome.Error.LeafErrorWithTPM
        self.leaf_with_tpm_locs = []

    def _capture_int_val_in_dom(
        self, xml_path: str, enum_name: str
    ) -> List[int]:
        """Loads enums.xml and fetch all int values in specified enum."""

        event_stream = pulldom.parse(xml_path)
        found = False
        result = []
        for event, node in event_stream:
            # Collect values for the specified enum.
            if (
                event == "START_ELEMENT"
                and node.tagName == "enum"
                and node.hasAttribute("name")
                and node.getAttribute("name") == enum_name
            ):
                # Found a specified enum node.
                found = True
            if event == "END_ELEMENT" and node.tagName == "enum":
                # Went out of scope of found enum node.
                found = False
            if (
                found
                and event == "START_ELEMENT"
                and node.tagName == "int"
                and node.hasAttribute("value")
            ):
                # Convert the found enum value as int and append to the result.
                result.append(int(node.getAttribute("value")))
        return result

    def load_enums_xml(self) -> None:
        """Loads enums.xml file.

        This method will populate self.error_locs with the list of error
        locations (as int) found in enums.xml, where the file path is
        specified in the constructor.
        """

        self.error_locs = self._capture_int_val_in_dom(
            self.enums_xml_path, "CryptohomeErrorLocation"
        )
        self.leaf_with_tpm_locs = self._capture_int_val_in_dom(
            self.enums_xml_path, "CryptohomeErrorLocationWithTPMError"
        )

    def _update_enum_in_enums_xml(
        self,
        enum_name: str,
        values_to_write: List[Tuple[int, str]],
        comments: str,
    ) -> bool:
        """Update all values for a enum in enums.xml

        Given previously specified enums.xml path, read it and update the
        values belonging to the specified <enum> tag. This will empty all
        <values> in the <enum> tag and replace them with contents specified
        by values_to_write.

        Args:
            enum_name: Specifies the <enum> tag to update.
            values_to_write: Content to place in the <enum> tag. Each
                element of the list is the value to label mapping for a
                <value> tag.
            comments: Comments to add in the <enum> tag.

        Returns:
            successful: True if successful.
        """

        with open(self.enums_xml_path, "r", encoding="utf-8") as f:
            lines = f.readlines()

        start_marker = EnumsXmlDB.ENUM_START_MARKER_TEMPLATE % enum_name
        start_marker_found = False
        start_marker_idx = None
        # Traverse all lines to find the start marker position and make sure
        # the lines have only one start marker.
        for idx, line in enumerate(lines):
            if line.strip() == start_marker:
                if start_marker_found:
                    logging.error(
                        "Expect only one %s <enum> tag in enums.xml", enum_name
                    )
                    return False
                start_marker_found = True
                start_marker_idx = idx
        if not start_marker_found:
            logging.error("No %s enum tag found in enums.xml", enum_name)
            return False

        result = lines[0 : start_marker_idx + 1]
        result.append(comments)
        for value, label in values_to_write:
            result.append(EnumsXmlDB.INT_VALUE_TAG_TEMPLATE % (value, label))

        # Note that we do not have nested <enum> tag for
        # CryptohomeErrorLocation, if that changes, we might need to change
        # this code.
        idx = start_marker_idx
        while idx < len(lines):
            if lines[idx].strip() == EnumsXmlDB.ENUM_STOP_MARKER:
                break
            idx += 1
        if idx == len(lines):
            logging.error(
                "No end of enum tag found for %s in enums.xml", enum_name
            )
            return False

        result += lines[idx:]

        with open(self.enums_xml_path, "w", encoding="utf-8") as f:
            f.write("".join(result))

        # Pretty print for conformance with the style.
        enums_xml_dir = pathlib.Path(self.enums_xml_path)
        subprocess.call(
            ["./pretty_print.py", "--non-interactive", "enums.xml"],
            cwd=enums_xml_dir.parent,
        )
        return True

    def update_enums_xml_with_error_loc(
        self, values_to_write: List[Tuple[int, str]]
    ) -> bool:
        """Updates enums.xml with the given error locations.

        Args:
            values_to_write: A list of error locations
            to write, each is a tuple. The first element of the tuple is the
            value and the second element is the label.

        Returns:
            True for success.
        """

        return self._update_enum_in_enums_xml(
            "CryptohomeErrorLocation",
            values_to_write,
            EnumsXmlDB.ERROR_LOCATION_COMMENTS,
        )

    def update_enums_xml_with_leaf_and_tpm_loc(
        self, values_to_write: List[Tuple[int, str]]
    ) -> bool:
        """Updates enums.xml with the given leaf+tpm composite locations.

        Args:
            values_to_write: A list of leaf+tpm composite locations
            to write, each is a tuple. The first element of the tuple is the
            value and the second element is the label.

        Returns:
            True for success.
        """

        return self._update_enum_in_enums_xml(
            "CryptohomeErrorLocationWithTPMError",
            values_to_write,
            EnumsXmlDB.ERROR_LOCATION_WITH_TPM_COMMENTS,
        )


class DBTool:
    """Bridge for various classes above.

    This class is in charge of calling the various classes above and bridge
    their input/outputs to each other.
    """

    ALLOWED_SRC_EXT = frozenset({".cc", ".h"})
    SCAN_DENYLIST = frozenset({"./error/location_utils.h"})
    LOCATIONS_H_PATH = "./error/locations.h"

    # TPM error range [ERROR_LOC_TPM_START, ERROR_LOC_TPM_END).
    # Lower bound is included; upper bound is excluded.
    ERROR_LOC_TPM_START = 0x10000
    ERROR_LOC_TPM_END = 0x20000

    def __init__(self, allowlist_path: str):
        """Constructor for DBTool.

        Args:
            allowlist_path: The path to the file that stores the content
            of dup_allowlist. Each line is a symbol that is in the allowlist,
            thus each line is a symbol that can appear multiple times in the
            code base.
        """

        # 'db_path' is the path to locations.h.
        self.db_path = DBTool.LOCATIONS_H_PATH

        # 'allowlist_path' is the path to duplication allowlist configuration.
        # See comment in DBTool.__init__() above.
        self.allowlist_path = allowlist_path

        # '_dup_allowlist' is the duplication allowlist, see comment in
        # Verifier.__init__().
        self._dup_allowlist = set({})
        self._load_dup_allowlist()

        # 'verifier' is an instance of Verifier for verifying symbols.
        self.verifier = Verifier(self._dup_allowlist)

        # 'db' is an instance of LocationDB for loading/storing locations.h.
        self.db = LocationDB(self.db_path, self._dup_allowlist)

    def _load_dup_allowlist(self):
        """Load self._dup_allowlist from file."""

        with open(self.allowlist_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
        lines = [line.strip() for line in lines]
        lines = [line for line in lines if len(line) > 0 and line[0] != "#"]
        for line in lines:
            self._dup_allowlist.add(line)

    def check_sources(self) -> Tuple[bool, Dict[str, Symbol]]:
        """Scan the codebase and check for errors.

        Returns:
            Returns (success, symbols), whereby success is a True iff the
            operation is successful and there's no error found, and in that
            case Symbol will be the symbols found in the code base.
        """

        # Scan for all symbols.
        all_symbols = SourceScanner.scan_directory(".", DBTool.ALLOWED_SRC_EXT)
        all_symbols = [
            r for r in all_symbols if r.path[0] not in DBTool.SCAN_DENYLIST
        ]
        collated_symbols, violations = self.verifier.collate_and_verify(
            all_symbols
        )
        # Notify the user on any violations.
        if len(violations) != 0:
            print("Please remove duplicate usage of error location in code:")
            for s in violations:
                print(violations[s])
            return False, None
        return True, collated_symbols

    def update_location_db(self) -> bool:
        """Scan the code base and update locations.h

        Scan the code base for all usage of error symbols, then process them
        to see if there's any error. If there's no error, update locations.h.

        Returns:
            True if successful.
        """

        if not self._load_full_db():
            return False
        self.db.store()

        return True

    def _load_full_db(self):
        success, symbols = self.check_sources()
        if not success:
            return False

        # Load the content of the locations.h
        self.db.load()
        self.db.update_from_scan_result(symbols)
        return True

    def lookup_symbol(self, value: str) -> bool:
        """Print the usage location for an error ID node.

        Given an error ID node, as in, a symbol, locate where it is used and
        print it out.

        Args:
            value: The symbol.
        """

        self._load_full_db()
        if value not in self.db.value_to_symbol:
            print("Value %s not found" % value)
            return False
        symbol = self.db.symbols[self.db.value_to_symbol[value]]
        print(
            "Value %s is %s and can be found at:"
            % (symbol.value, symbol.symbol)
        )
        for path, line in zip(symbol.path, symbol.line_num):
            print("%s:%d" % (path, line))
        return True

    def decode_stack(self, locs: str) -> None:
        """Print the stack for an error ID.

        Given an error ID (dash-separated symbols), decode the symbols and
        print out their location in the code base.

        Args:
            locs: A dash-separated symbols string.
        """

        self._load_full_db()

        stack = [int(x) for x in locs.split("-")]
        for val in stack:
            if val not in self.db.value_to_symbol:
                print("Value %s not found" % val)
            else:
                symbol = self.db.symbols[self.db.value_to_symbol[val]]
                print("%s" % (symbol,))

    def decode_tpm(self, tpm_err: str) -> None:
        """Print the TPM error's textual representation.

        Args:
            tpm_err: The TPM error, in decimal or hex.
        """

        try:
            value = int(tpm_err, 0)
        except ValueError:
            print(
                "Please specify the TPM value in decimal or hexidecimal, "
                "for example: 0x84 or 132"
            )
            return

        err_str = TPMErrorDecoder.decode(value)
        print("TPM Error: %s" % (err_str,))

    def _read_stdin_ints(self) -> List[int]:
        """Reads a list of int line-by-line from stdin."""

        def is_integer(s: str) -> bool:
            """Returns True if the input string is a valid int"""
            try:
                _ = int(s)
                return True
            except Exception:
                return False

        inputs = sys.stdin.readlines()
        inputs = [x.strip() for x in inputs]
        inputs = [int(x) for x in inputs if is_integer(x)]

        return inputs

    def _load_enums_xml(self, chromium_src_path: str) -> EnumsXmlDB:
        """Loads the enums.xml into a EnumsXmlDB object."""

        # Normalize the path first.
        chromium_src_path = pathlib.Path(chromium_src_path)
        chromium_src_path = chromium_src_path.expanduser().resolve()

        # Find path to enums.xml
        enums_xml_path = (
            chromium_src_path / "tools" / "metrics" / "histograms" / "enums.xml"
        )

        # Load enums.xml
        enums_db = EnumsXmlDB(str(enums_xml_path))
        enums_db.load_enums_xml()

        return enums_db

    def update_enums_xml_with_error_loc(self, chromium_src_path: str) -> None:
        """Updates the enums.xml with the error location symbols used.

        This method will read the list of error locations that are actually
        encountered in the field from the stdin and ensure that they're in
        enums.xml.

        Args:
            chromium_src_path: Path to Chromium source code.
        """

        enums_db = self._load_enums_xml(chromium_src_path)

        inputs = self._read_stdin_ints()

        # Load the DB and grab all values.
        self._load_full_db()
        result_error_loc_values = list(
            set(inputs).union(set(enums_db.error_locs))
        )
        result_error_loc_values.sort()
        result_error_locs = [
            (x, self.db.value_to_symbol[x])
            for x in result_error_loc_values
            if x in self.db.value_to_symbol
        ]
        invalid_locs = [
            x
            for x in result_error_loc_values
            if x not in self.db.value_to_symbol
        ]

        for loc in invalid_locs:
            # Check and handle TPM errors.
            if DBTool.ERROR_LOC_TPM_START <= loc < DBTool.ERROR_LOC_TPM_END:
                # TPM error exists between 0x10000 to 0x1FFFF
                tpm_err = loc - DBTool.ERROR_LOC_TPM_START

                tpm_err_str = TPMErrorDecoder.decode(tpm_err)
                result_error_locs.append((loc, tpm_err_str))
            else:
                # Log warnings for invalid inputs.
                logging.warning("Invalid error location value: %d", loc)

        # Write all valid output to enums.xml
        if not enums_db.update_enums_xml_with_error_loc(result_error_locs):
            logging.error(
                "Failed to update enums.xml, call to "
                "update_enums_xml_with_error_loc failed."
            )

    def _decode_leaf_and_tpm_loc(self, val: int) -> str:
        """Decode a leaf+tpm composite value into textual representation"""

        # The first 16 bits of the composite value represents the
        # cryptohome error location. The last 16 bits represents the
        # TPM error. As cryptohome location with value 0 is reserved, it
        # should never appear in ordinary errors, hence we use an all-zero
        # composite value to represent success case (no error).
        # In addition, if location is non-zero but TPM error is zero, it means
        # that the error location doesn't have a TPM error.
        leaf_part = (val >> 16) & 0xFFFF
        tpm_part = val & 0xFFFF

        if leaf_part == 0 and tpm_part == 0:
            return "Success"

        leaf_repr = (
            self.db.value_to_symbol[leaf_part]
            if leaf_part in self.db.value_to_symbol
            else ("Unknown Loc %d" % leaf_part)
        )

        if tpm_part == 0:
            return leaf_repr

        tpm_repr = TPMErrorDecoder.decode(tpm_part)

        return "%s - %s" % (leaf_repr, tpm_repr)

    def update_enums_xml_with_leaf_and_tpm_loc(
        self, chromium_src_path: str
    ) -> None:
        """Updates the enums.xml with the composite location symbols used.

        This method will read the list of leaf+tpm composite locations that
        are actually encountered in the field from the stdin and ensure that
        they're in enums.xml.

        Args:
            chromium_src_path: Path to Chromium source code.
        """

        enums_db = self._load_enums_xml(chromium_src_path)

        inputs = self._read_stdin_ints()

        # Load the DB and grab all values.
        self._load_full_db()
        result_loc_values = sorted(
            set(inputs) | set(enums_db.leaf_with_tpm_locs)
        )
        result_locs = [
            (x, self._decode_leaf_and_tpm_loc(x)) for x in result_loc_values
        ]
        # Write all valid output to enums.xml
        if not enums_db.update_enums_xml_with_leaf_and_tpm_loc(result_locs):
            logging.error(
                "Failed to update enums.xml, call to "
                "update_enums_xml_with_leaf_and_tpm_loc failed."
            )


class DBToolCommandLine:
    """This class handles the command line operations for the tool."""

    def __init__(self):
        """Constructor for DBToolCommandLine."""

        # 'parser' is an ArgumentParser instance for parsing command line
        # arguments.
        self.parser = None

        # 'args' is the arguments parsed by self.parser.
        self.args = None

        # 'db_tool' is an instance of DBTool for carrying out the operations
        # specified in arguments.
        self.db_tool = None

        # 'allowlist_path' is the path to the duplication allowlist
        # configuration.
        self.allowlist_path = None

    def _setup_logging(self):
        logging.basicConfig(level=logging.INFO)

    def _parse_args(self):
        self.parser = argparse.ArgumentParser(
            description="Tool for handling error location in locations.h"
        )
        self.parser.add_argument(
            "--update",
            help="Scan the source directory and update the locations.h db",
            action="store_true",
        )
        self.parser.add_argument(
            "--check",
            help=(
                "Scan the source directory and check that cryptohome error is "
                "used correctly."
            ),
            action="store_true",
        )
        self.parser.add_argument(
            "--lookup", help="Lookup a single error location code", default=None
        )
        self.parser.add_argument(
            "--decode",
            help="Decode a stack of error location, ex.42-7-15",
            default=None,
        )
        self.parser.add_argument(
            "--decode-tpm",
            help="Decode a TPM error, could be decimal or hex.",
            default=None,
        )
        self.parser.add_argument(
            "--update-enums-xml-with-error-loc",
            help=(
                "Update the enums.xml, will need to supply chromium source "
                "directory"
            ),
            action="store_true",
        )

        self.parser.add_argument(
            "--update-enums-xml-with-leaf-and-tpm-loc",
            help=(
                "Update the enums.xml with values from the Cryptohome.Error."
                "LeafErrorWithTPM UMA, will need to supply chromium source "
                "directory"
            ),
            action="store_true",
        )

        self.parser.add_argument(
            "--chromium-src",
            help="Path to Chromium source code",
            default="~/chromium/src",
        )
        self.parser.add_argument(
            "--src", help=("The cryptohome source directory"), default=None
        )
        self.args = self.parser.parse_args()

    def _goto_srcdir(self):
        assert self.args is not None
        srcdir = self.args.src
        if srcdir is None:
            srcdir = os.path.join(os.path.dirname(__file__), "..", "..")
        srcdir = os.path.abspath(srcdir)
        logging.info("Using cryptohome source at: %s", srcdir)
        os.chdir(srcdir)

    def _get_dup_allowlist_path(self):
        path = os.path.join(os.path.dirname(__file__), "dup_allowlist.txt")
        path = os.path.abspath(path)
        return path

    def main(self):
        """The main function for this command line tool.

        Returns:
            int: The exit code.
        """
        self._parse_args()
        self._setup_logging()
        self.allowlist_path = self._get_dup_allowlist_path()
        self._goto_srcdir()
        self.db_tool = DBTool(self.allowlist_path)
        if self.args.update:
            self.db_tool.update_location_db()
        elif self.args.check:
            result, _ = self.db_tool.check_sources()
            if not result:
                return 1
        elif self.args.lookup is not None:
            self.db_tool.lookup_symbol(int(self.args.lookup))
        elif self.args.decode is not None:
            self.db_tool.decode_stack(self.args.decode)
        elif self.args.decode_tpm is not None:
            self.db_tool.decode_tpm(self.args.decode_tpm)
        elif self.args.update_enums_xml_with_error_loc:
            self.db_tool.update_enums_xml_with_error_loc(self.args.chromium_src)
        elif self.args.update_enums_xml_with_leaf_and_tpm_loc:
            self.db_tool.update_enums_xml_with_leaf_and_tpm_loc(
                self.args.chromium_src
            )
        else:
            logging.error("No action specified, please see --help")
            return 1
        return 0


# Invoke the main function for the tool.
if __name__ == "__main__":
    cmdline = DBToolCommandLine()
    return_value = cmdline.main()
    sys.exit(return_value)
