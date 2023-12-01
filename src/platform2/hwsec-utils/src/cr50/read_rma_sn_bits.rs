// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use super::RmaSnBits;
use crate::context::Context;
use crate::error::HwsecError;
use crate::tpm2::nv_read;

pub fn cr50_read_rma_sn_bits(ctx: &mut impl Context) -> Result<RmaSnBits, HwsecError> {
    const READ_SN_BITS_INDEX: u32 = 0x013fff01;
    const READ_SN_BITS_LENGTH: u16 = 16;

    let sn_bits = nv_read(ctx, READ_SN_BITS_INDEX, READ_SN_BITS_LENGTH)?;
    if sn_bits.len() != READ_SN_BITS_LENGTH as usize {
        return Err(HwsecError::InternalError);
    }

    Ok(RmaSnBits {
        sn_data_version: sn_bits[0..3]
            .try_into()
            .map_err(|_| HwsecError::InternalError)?,
        rma_status: sn_bits[3],
        sn_bits: sn_bits[4..]
            .try_into()
            .map_err(|_| HwsecError::InternalError)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::mock::MockContext;
    use crate::tpm2::tests::split_into_hex_strtok;

    #[test]
    fn test_cr50_read_rma_sn_bits_success() {
        use crate::tpm2::tests::split_into_hex_strtok;

        let mut mock_ctx = MockContext::new();

        mock_ctx.cmd_runner().set_trunksd_running(true);
        mock_ctx.cmd_runner().add_tpm_interaction(
            "trunks_send",
            vec!["--raw"],
            split_into_hex_strtok(
                "80 02 00 00 00 23 00 00 \
                01 4e 01 3f ff 01 01 3f \
                ff 01 00 00 00 09 40 00 \
                00 09 00 00 00 00 00 00 \
                10 00 00",
            ),
            0,
            "800200000025000000000000001200100FFFFFFF877F50D208EC89E9C1691F540000010000",
            "",
        );

        let rma_sn_bits = cr50_read_rma_sn_bits(&mut mock_ctx);
        assert_eq!(
            rma_sn_bits,
            Ok(RmaSnBits {
                sn_data_version: [0x0f, 0xff, 0xff],
                rma_status: 0xff,
                sn_bits: [0x87, 0x7f, 0x50, 0xd2, 0x08, 0xec, 0x89, 0xe9, 0xc1, 0x69, 0x1f, 0x54],
            })
        );
    }

    #[test]
    fn test_cr50_read_rma_sn_bits_nv_read_malfunction() {
        let mut mock_ctx = MockContext::new();

        mock_ctx.cmd_runner().set_trunksd_running(true);
        mock_ctx.cmd_runner().add_tpm_interaction(
            "trunks_send",
            vec!["--raw"],
            split_into_hex_strtok(
                "80 02 00 00 00 23 00 00 \
                01 4e 01 3f ff 01 01 3f \
                ff 01 00 00 00 09 40 00 \
                00 09 00 00 00 00 00 00 \
                10 00 00",
            ),
            1,
            "",
            "",
        );

        let rma_sn_bits = cr50_read_rma_sn_bits(&mut mock_ctx);
        assert_eq!(rma_sn_bits, Err(HwsecError::CommandRunnerError));
    }
}
