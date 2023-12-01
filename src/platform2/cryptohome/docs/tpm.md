# TPM

[TOC]

## Overview

Cryptohome uses the TPM merely for secure key storage to help protect the user
from data loss should their device be lost or compromised. Keys sealed by the
TPM can only be used on the TPM itself, meaning that offline or brute-force
attacks are difficult.
