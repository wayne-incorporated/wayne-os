// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fmt;
use std::fmt::Display;

use super::cr50_read_rma_sn_bits;
use super::get_board_id_with_gsctool;
use super::run_gsctool_cmd;
use super::u8_slice_to_hex_string;
use super::RmaSnBits;
use super::SnBits;
use crate::context::Context;
use crate::tpm2::BoardID;
use crate::tpm2::ERASED_BOARD_ID;

#[derive(Debug, PartialEq, Eq)]
pub enum Cr50SetSnBitsVerdict {
    Successful,
    GeneralError,
    AlreadySetError,
    AlreadySetDifferentlyError,
    MissingVpdKeyError,
}

impl Display for Cr50SetSnBitsVerdict {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Cr50SetSnBitsVerdict::Successful => write!(f, "Successful"),
            Cr50SetSnBitsVerdict::GeneralError => write!(f, "GeneralError"),
            Cr50SetSnBitsVerdict::AlreadySetError => write!(f, "AlreadySetError"),
            Cr50SetSnBitsVerdict::AlreadySetDifferentlyError => {
                write!(f, "AlreadySetDifferentlyError")
            }
            Cr50SetSnBitsVerdict::MissingVpdKeyError => write!(f, "MissingVpdKeyError"),
        }
    }
}

impl From<Cr50SetSnBitsVerdict> for i32 {
    fn from(verdict: Cr50SetSnBitsVerdict) -> Self {
        match verdict {
            Cr50SetSnBitsVerdict::Successful => 0,
            Cr50SetSnBitsVerdict::GeneralError => 1,
            Cr50SetSnBitsVerdict::AlreadySetError => 2,
            Cr50SetSnBitsVerdict::AlreadySetDifferentlyError => 3,
            Cr50SetSnBitsVerdict::MissingVpdKeyError => 4,
        }
    }
}

pub fn report_device_has_been_rmaed(dry_run: bool) -> Result<(), Cr50SetSnBitsVerdict> {
    if dry_run {
        println!("WARNING: This device has been RMAed, preventing changes to SN Bits.");
        Ok(())
    } else {
        eprintln!("ERROR: This device has been RMAed, SN Bits cannot be set.");
        Err(Cr50SetSnBitsVerdict::GeneralError)
    }
}

pub fn cr50_compute_updater_sn_bits(sn: &str) -> SnBits {
    let mut hasher = hmac_sha256::Hash::new();
    hasher.update(sn);
    let hashed_value = &hasher.finalize();
    hashed_value[..12].try_into().unwrap()
}

pub fn board_id_is_set(ctx: &mut impl Context) -> Result<bool, Cr50SetSnBitsVerdict> {
    let board_id: BoardID = {
        get_board_id_with_gsctool(ctx).map_err(|_| {
            eprintln!("ERROR: Failed to execute gsctool -a -i");
            Cr50SetSnBitsVerdict::GeneralError
        })?
    };
    Ok(board_id.part_1 != ERASED_BOARD_ID.part_1 || board_id.part_2 != ERASED_BOARD_ID.part_2)
}

pub fn is_rmaed(rma_sn_bits: RmaSnBits) -> bool {
    rma_sn_bits.rma_status != 0xff
}

pub fn cr50_check_sn_bits(
    ctx: &mut impl Context,
    sn_bits: SnBits,
    dry_run: bool,
) -> Result<(), Cr50SetSnBitsVerdict> {
    let rma_sn_bits = cr50_read_rma_sn_bits(ctx).map_err(|_| {
        eprintln!("ERROR: Failed to read RMA+SN Bits.");
        Cr50SetSnBitsVerdict::GeneralError
    })?;
    if is_rmaed(rma_sn_bits) {
        report_device_has_been_rmaed(dry_run)
    } else if rma_sn_bits.sn_bits == [0x00_u8; 12] {
        Ok(())
    } else if rma_sn_bits.sn_bits != sn_bits {
        eprintln!(
            "ERROR: SN Bits have been set differently ({} vs {}).",
            u8_slice_to_hex_string(&rma_sn_bits.sn_bits),
            u8_slice_to_hex_string(&sn_bits)
        );
        Err(Cr50SetSnBitsVerdict::AlreadySetDifferentlyError)
    } else if dry_run {
        println!("SN Bits are properly set.");
        Err(Cr50SetSnBitsVerdict::Successful)
    } else {
        eprintln!("ERROR: SN Bits had already been set before.");
        Err(Cr50SetSnBitsVerdict::AlreadySetError)
    }
}

fn set_sn_bits_with_gsctool(
    ctx: &mut impl Context,
    sn_bits: SnBits,
) -> Result<i32, Cr50SetSnBitsVerdict> {
    let gsctool_output = run_gsctool_cmd(
        ctx,
        vec!["--any", "--sn_bits", &u8_slice_to_hex_string(&sn_bits)],
    )
    .map_err(|_| {
        eprintln!("ERROR: Failed to run gsctool.");
        Cr50SetSnBitsVerdict::GeneralError
    })?;
    Ok(gsctool_output.status.code().unwrap())
}

pub fn cr50_set_sn_bits(
    ctx: &mut impl Context,
    sn_bits: SnBits,
) -> Result<(), Cr50SetSnBitsVerdict> {
    let exit_status = set_sn_bits_with_gsctool(ctx, sn_bits)?;
    if exit_status != 0 {
        let warn_str: &str = if exit_status > 2 && board_id_is_set(ctx)? {
            " (Board ID is set)"
        } else {
            ""
        };
        eprintln!(
            "ERROR: Failed to set SN Bits to {}{}.",
            u8_slice_to_hex_string(&sn_bits),
            warn_str
        );
        Err(Cr50SetSnBitsVerdict::GeneralError)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::context::mock::MockContext;
    use crate::context::Context;
    use crate::cr50::cr50_check_sn_bits;
    use crate::cr50::cr50_compute_updater_sn_bits;
    use crate::cr50::Cr50SetSnBitsVerdict;
    use crate::cr50::RmaSnBits;

    #[test]
    fn test_cr50_compute_updater_sn_bits() {
        let meow: &str = "meow";
        let hashed_meow = cr50_compute_updater_sn_bits(meow);
        assert_eq!(
            hashed_meow,
            [0x40, 0x4c, 0xdd, 0x7b, 0xc1, 0x09, 0xc4, 0x32, 0xf8, 0xcc, 0x24, 0x43]
        );
    }

    #[test]
    fn test_board_id_is_set() {
        use crate::context::mock::MockContext;
        use crate::context::Context;
        use crate::cr50::board_id_is_set;
        use crate::tpm2::BoardID;

        let mut mock_ctx = MockContext::new();

        mock_ctx
            .cmd_runner()
            .add_successful_gsctool_read_board_id_interaction(BoardID {
                part_1: 0x12345678,
                part_2: 0x12345678,
                flag: 0x12345678,
            });
        let flag = board_id_is_set(&mut mock_ctx);
        assert_eq!(flag, Ok(true));
    }

    #[test]
    fn test_board_id_is_not_set() {
        use crate::context::mock::MockContext;
        use crate::context::Context;
        use crate::cr50::board_id_is_set;
        use crate::tpm2::ERASED_BOARD_ID;

        let mut mock_ctx = MockContext::new();

        mock_ctx
            .cmd_runner()
            .add_successful_gsctool_read_board_id_interaction(ERASED_BOARD_ID);
        let flag = board_id_is_set(&mut mock_ctx);
        assert_eq!(flag, Ok(false));
    }

    #[test]
    fn test_cr50_check_sn_bits_rmaed_dry_run() {
        let mut mock_ctx = MockContext::new();
        mock_ctx
            .cmd_runner()
            .add_successful_cr50_read_rma_sn_bits_interaction_non_generic_tpm2(RmaSnBits {
                sn_data_version: [0x12, 0x34, 0x56],
                rma_status: 0x94,
                sn_bits: [
                    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
                ],
            });

        let result = cr50_check_sn_bits(
            &mut mock_ctx,
            [
                0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
            ],
            true,
        );
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn test_cr50_check_sn_bits_rmaed_non_dry_run() {
        let mut mock_ctx = MockContext::new();
        mock_ctx
            .cmd_runner()
            .add_successful_cr50_read_rma_sn_bits_interaction_non_generic_tpm2(RmaSnBits {
                sn_data_version: [0x12, 0x34, 0x56],
                rma_status: 0x87,
                sn_bits: [
                    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
                ],
            });

        let result = cr50_check_sn_bits(
            &mut mock_ctx,
            [
                0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
            ],
            false,
        );
        assert_eq!(result, Err(Cr50SetSnBitsVerdict::GeneralError));
    }

    #[test]
    fn test_cr50_check_sn_bits_ok() {
        let mut mock_ctx = MockContext::new();
        mock_ctx
            .cmd_runner()
            .add_successful_cr50_read_rma_sn_bits_interaction_non_generic_tpm2(RmaSnBits {
                sn_data_version: [0x12, 0x34, 0x56],
                rma_status: 0xff,
                sn_bits: [0x00; 12],
            });

        let result = cr50_check_sn_bits(
            &mut mock_ctx,
            [
                0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
            ],
            false,
        );
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn test_cr50_check_sn_bits_different() {
        let mut mock_ctx = MockContext::new();
        mock_ctx
            .cmd_runner()
            .add_successful_cr50_read_rma_sn_bits_interaction_non_generic_tpm2(RmaSnBits {
                sn_data_version: [0x12, 0x34, 0x56],
                rma_status: 0xff,
                sn_bits: [0x11; 12],
            });

        let result = cr50_check_sn_bits(
            &mut mock_ctx,
            [
                0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
            ],
            false,
        );
        assert_eq!(
            result,
            Err(Cr50SetSnBitsVerdict::AlreadySetDifferentlyError)
        );
    }

    #[test]
    fn test_cr50_check_sn_bits_dry_run() {
        let mut mock_ctx = MockContext::new();
        mock_ctx
            .cmd_runner()
            .add_successful_cr50_read_rma_sn_bits_interaction_non_generic_tpm2(RmaSnBits {
                sn_data_version: [0x12, 0x34, 0x56],
                rma_status: 0xff,
                sn_bits: [
                    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
                ],
            });

        let result = cr50_check_sn_bits(
            &mut mock_ctx,
            [
                0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
            ],
            true,
        );
        assert_eq!(result, Err(Cr50SetSnBitsVerdict::Successful));
    }

    #[test]
    fn test_cr50_check_sn_bits_non_dry_run() {
        let mut mock_ctx = MockContext::new();
        mock_ctx
            .cmd_runner()
            .add_successful_cr50_read_rma_sn_bits_interaction_non_generic_tpm2(RmaSnBits {
                sn_data_version: [0x12, 0x34, 0x56],
                rma_status: 0xff,
                sn_bits: [
                    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
                ],
            });

        let result = cr50_check_sn_bits(
            &mut mock_ctx,
            [
                0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
            ],
            false,
        );
        assert_eq!(result, Err(Cr50SetSnBitsVerdict::AlreadySetError));
    }

    #[test]
    fn test_cr50_set_sn_bits_ok() {
        use crate::cr50::cr50_set_sn_bits;

        let mut mock_ctx = MockContext::new();
        mock_ctx.cmd_runner().add_gsctool_interaction(
            vec!["--any", "--sn_bits", "112233445566778899aabbcc"],
            0,
            "",
            "",
        );

        let result = cr50_set_sn_bits(
            &mut mock_ctx,
            [
                0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
            ],
        );
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn test_cr50_set_sn_bits_gt_2_exit_code() {
        use crate::cr50::cr50_set_sn_bits;

        let mut mock_ctx = MockContext::new();
        mock_ctx.cmd_runner().add_gsctool_interaction(
            vec!["--any", "--sn_bits", "112233445566778899aabbcc"],
            7,
            "",
            "",
        );
        mock_ctx
            .cmd_runner()
            .add_successful_gsctool_read_board_id_arbitary_interaction();

        let result = cr50_set_sn_bits(
            &mut mock_ctx,
            [
                0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
            ],
        );
        assert_eq!(result, Err(Cr50SetSnBitsVerdict::GeneralError));
    }

    #[test]
    fn test_cr50_set_sn_bits_lt_3_exit_code() {
        use crate::cr50::cr50_set_sn_bits;

        let mut mock_ctx = MockContext::new();
        mock_ctx.cmd_runner().add_gsctool_interaction(
            vec!["--any", "--sn_bits", "112233445566778899aabbcc"],
            1,
            "",
            "",
        );

        let result = cr50_set_sn_bits(
            &mut mock_ctx,
            [
                0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
            ],
        );
        assert_eq!(result, Err(Cr50SetSnBitsVerdict::GeneralError));
    }
}
