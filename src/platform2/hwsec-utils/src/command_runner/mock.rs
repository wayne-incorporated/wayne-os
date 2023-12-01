// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::collections::VecDeque;
use std::fmt::Write;

use crate::command_runner::CommandRunner;
use crate::cr50::RmaSnBits;
use crate::cr50::GSCTOOL_CMD_NAME;
use crate::output::HwsecOutput;
use crate::output::HwsecStatus;
use crate::tpm2::tests::split_into_hex_strtok;
use crate::tpm2::BoardID;

// For any member variable x in MockCommandInput:
// x = Some(_) means that we would check the correspondence;
// otherwise, we don't really care about its exact value.
// To know more, take a glance at impl CommandRunner for MockCommandRunner.
pub struct MockCommandInput {
    pub cmd_name: Option<String>,
    pub args: Option<Vec<String>>,
}

impl MockCommandInput {
    pub fn new(cmd_name: &str, args: Vec<&str>) -> Self {
        Self {
            cmd_name: Some(cmd_name.to_owned()),
            args: Some(args.iter().map(|&s| s.into()).collect()),
        }
    }
}

pub struct MockCommandOutput {
    pub result: Result<HwsecOutput, std::io::Error>,
}

impl MockCommandOutput {
    pub fn new(exit_status: i32, out: &str, err: &str) -> Self {
        Self {
            result: Ok(HwsecOutput {
                status: HwsecStatus::from_raw(exit_status),
                stdout: out.to_owned().as_bytes().to_vec(),
                stderr: err.to_owned().as_bytes().to_vec(),
            }),
        }
    }
}

pub struct MockCommandRunner {
    expectations: VecDeque<(MockCommandInput, MockCommandOutput)>,
}

impl Default for MockCommandRunner {
    fn default() -> Self {
        Self::new()
    }
}

fn u8_slice_to_upper_hex_string(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        write!(&mut s, "{:02X}", b).unwrap();
    }
    s
}

impl MockCommandRunner {
    pub fn new() -> Self {
        MockCommandRunner {
            expectations: VecDeque::new(),
        }
    }
    pub fn add_expectation(&mut self, inp: MockCommandInput, out: MockCommandOutput) {
        self.expectations.push_back((inp, out));
    }
    pub fn set_trunksd_running(&mut self, status: bool) {
        self.add_expectation(
            MockCommandInput::new("status", vec!["trunksd"]),
            MockCommandOutput::new(
                0,
                if status {
                    "trunksd start/running, process 17302"
                } else {
                    "trunksd stop/waiting"
                },
                "",
            ),
        );
    }
    pub fn add_tpm_interaction(
        &mut self,
        cmd_name: &str,
        flag: Vec<&str>,
        hex_str_tokens: Vec<&str>,
        exit_status: i32,
        out: &str,
        err: &str,
    ) {
        self.add_expectation(
            MockCommandInput::new(cmd_name, [&flag[..], &hex_str_tokens[..]].concat()),
            MockCommandOutput::new(exit_status, out, err),
        );
    }
    pub fn add_gsctool_interaction(
        &mut self,
        mut flag: Vec<&str>,
        exit_status: i32,
        out: &str,
        err: &str,
    ) {
        if cfg!(feature = "ti50_onboard") {
            flag.push("--dauntless");
        }

        self.add_expectation(
            MockCommandInput::new(GSCTOOL_CMD_NAME, flag),
            MockCommandOutput::new(exit_status, out, err),
        );
    }
    pub fn add_metrics_client_expectation(&mut self, event_id: u64) {
        use crate::cr50::GSC_METRICS_PREFIX;
        self.add_expectation(
            MockCommandInput::new(
                "metrics_client",
                vec![
                    "-s",
                    &format!("{}.FlashLog", GSC_METRICS_PREFIX),
                    &format!("0x{:02x}", event_id),
                ],
            ),
            MockCommandOutput::new(0, "", ""),
        );
    }
    pub fn add_successful_generic_read_board_id_interaction(&mut self, board_id: BoardID) {
        self.add_tpm_interaction(
            "trunks_send",
            vec!["--raw"],
            split_into_hex_strtok(
                "80 02 00 00 00 23 00 00 \
                01 4e 01 3f ff 00 01 3f \
                ff 00 00 00 00 09 40 00 \
                00 09 00 00 00 00 00 00 \
                0c 00 00",
            ),
            0,
            &format!(
                "800200000021000000000000000E000C{:08X}{:08X}{:08X}0000010000",
                board_id.part_1.swap_bytes(),
                board_id.part_2.swap_bytes(),
                board_id.flag.swap_bytes(),
            ),
            "",
        );
    }
    pub fn add_successful_generic_read_board_id_arbitary_interaction(&mut self) {
        // Use this when not in want of specifying board id.
        // Reading board id with mock context
        // after calling this function with would return
        // BoardID {
        //     part_1: 0x4d524646,
        //     part_2: 0xb2adb9b9,
        //     flag: 0x00007f7f
        // }
        self.add_successful_generic_read_board_id_interaction(BoardID {
            part_1: 0x4d524646,
            part_2: 0xb2adb9b9,
            flag: 0x00007f7f,
        });
    }
    pub fn add_successful_gsctool_read_board_id_interaction(&mut self, board_id: BoardID) {
        self.add_gsctool_interaction(
            vec!["--any", "--board_id"],
            0,
            &format!(
                "finding_device 18d1:5014\n\
                Found device.\n\
                found interface 3 endpoint 4, chunk_len 64\n\
                READY\n\
                -------\n\
                Board ID space: {:08x}:{:08x}:{:08x}\n",
                board_id.part_1, board_id.part_2, board_id.flag
            ),
            "",
        );
    }
    pub fn add_successful_gsctool_read_board_id_arbitary_interaction(&mut self) {
        // Use this when not in want of specifying a board id.
        // Reading board id with mock context
        // after calling this function with would return
        // BoardID {
        //     part_1: 0x43425559,
        //     part_2: 0xbcbdaaa6,
        //     flag: 0x00007f80
        // }
        self.add_successful_gsctool_read_board_id_interaction(BoardID {
            part_1: 0x43425559,
            part_2: 0xbcbdaaa6,
            flag: 0x00007f80,
        });
    }
    pub fn add_successful_cr50_get_name_arbitary_interaction(&mut self) {
        self.add_successful_gsctool_read_board_id_arbitary_interaction();
    }
    pub fn add_successful_cr50_read_rma_sn_bits_interaction_non_generic_tpm2(
        &mut self,
        rma_sn_bits: RmaSnBits,
    ) {
        self.set_trunksd_running(true);
        self.add_tpm_interaction(
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
            &format!(
                "80020000002500000000000000120010{}{:02X}{}0000010000",
                u8_slice_to_upper_hex_string(&rma_sn_bits.sn_data_version),
                rma_sn_bits.rma_status,
                u8_slice_to_upper_hex_string(&rma_sn_bits.sn_bits),
            ),
            "",
        );
    }
    pub fn add_successful_cr50_read_rma_sn_bits_arbitary_interaction(&mut self) {
        // Use this when not in want of specifying rma sn bits.
        // Reading rma sn bits with mock context
        // after calling this function with would return
        // RmaSnBits {
        //     sn_data_version: [0x0f, 0xff, 0xff],
        //     rma_status: 0xff,
        //     sn_bits: [0x87, 0x7f, 0x50, 0xd2, 0x08, 0xec, 0x89, 0xe9, 0xc1, 0x69, 0x1f, 0x54],
        // }
        self.add_successful_cr50_read_rma_sn_bits_interaction_non_generic_tpm2(RmaSnBits {
            sn_data_version: [0x0f, 0xff, 0xff],
            rma_status: 0xff,
            sn_bits: [
                0x87, 0x7f, 0x50, 0xd2, 0x08, 0xec, 0x89, 0xe9, 0xc1, 0x69, 0x1f, 0x54,
            ],
        });
    }
    pub fn add_successful_get_gbb_flags_interaction(&mut self, gbb_flag: u32) {
        self.add_expectation(
            MockCommandInput::new("futility", vec!["gbb", "--get", "--flash", "--flags"]),
            MockCommandOutput::new(
                0,
                &format!(
                    include_str!("expected_message/successfully_get_gbb_flags_response.txt"),
                    gbb_flag
                ),
                "",
            ),
        );
    }
    pub fn add_successful_set_gbb_flags_interaction(&mut self, gbb_flag: u32) {
        self.add_expectation(
            MockCommandInput::new(
                "futility",
                vec![
                    "gbb",
                    "--set",
                    "--flash",
                    &format!("--flags=0x{:08x}", gbb_flag),
                ],
            ),
            MockCommandOutput::new(
                0,
                include_str!("expected_message/successfully_set_gbb_flags_response.txt"),
                "",
            ),
        );
    }
}

impl CommandRunner for MockCommandRunner {
    fn run(&mut self, cmd_name: &str, args: Vec<&str>) -> Result<HwsecOutput, std::io::Error> {
        assert!(
            !self.expectations.is_empty(),
            "Failed to pop front from queue -- it's empty!"
        );
        let io_pair = self.expectations.pop_front().unwrap();
        let inp = io_pair.0;
        let out = io_pair.1;
        if let Some(inp_name) = inp.cmd_name {
            assert_eq!(cmd_name, inp_name);
        }
        if let Some(inp_args) = inp.args {
            assert_eq!(args, inp_args);
        }
        out.result
    }
    fn output(&mut self, cmd_name: &str, args: Vec<&str>) -> Result<String, std::io::Error> {
        let run_result = self.run(cmd_name, args)?;
        Ok(String::from_utf8_lossy(&run_result.stdout).to_string())
    }
}

impl Drop for MockCommandRunner {
    fn drop(&mut self) {
        assert!(self.expectations.is_empty());
    }
}
