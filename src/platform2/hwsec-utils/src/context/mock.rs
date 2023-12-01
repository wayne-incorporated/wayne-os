// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::collections::hash_map::DefaultHasher;
use std::fs::File;
use std::hash::Hash;
use std::hash::Hasher;
use std::path::Path;

use libchromeos::error;
use tempfile::TempDir;

use super::Context;
use crate::command_runner::MockCommandRunner;
use crate::error::HwsecError;

pub(crate) struct MockContext {
    cmd_runner: MockCommandRunner,
    temp_dir: TempDir,
}

fn calculate_hash<T: Hash>(t: &T) -> u64 {
    let mut s = DefaultHasher::new();
    t.hash(&mut s);
    s.finish()
}

impl MockContext {
    pub fn new() -> Self {
        Self {
            cmd_runner: MockCommandRunner::new(),
            temp_dir: TempDir::new().unwrap(),
        }
    }
    fn get_mock_path_string(&mut self, path_str: &str) -> String {
        let file_path_hash = calculate_hash(&path_str).to_string();
        format!("{}/{}", self.temp_dir.path().display(), file_path_hash)
    }

    pub fn create_path(&mut self, path_str: &str) -> bool {
        let new_path_string = self.get_mock_path_string(path_str);
        File::create(new_path_string).is_ok()
    }
}

impl Context for MockContext {
    type CommandRunner = MockCommandRunner;
    fn cmd_runner(&mut self) -> &mut Self::CommandRunner {
        &mut self.cmd_runner
    }

    fn path_exists(&mut self, path_str: &str) -> bool {
        let new_path_string = self.get_mock_path_string(path_str);
        Path::new(&new_path_string).exists()
    }

    fn read_file_to_string(&mut self, path_str: &str) -> Result<String, HwsecError> {
        let new_path_string = self.get_mock_path_string(path_str);

        std::fs::read_to_string(new_path_string).map_err(|_| {
            error!("Failed to read {}", path_str);
            HwsecError::FileError
        })
    }

    fn write_contents_to_file(
        &mut self,
        path_str: &str,
        contents: &[u8],
    ) -> Result<(), HwsecError> {
        let new_path_string = self.get_mock_path_string(path_str);

        std::fs::write(new_path_string, contents).map_err(|_| {
            error!("Failed to write {}", path_str);
            HwsecError::FileError
        })
    }

    fn sleep(&mut self, _sec: u64) {
        // Don't sleep when performing unit tests
    }
}

#[cfg(test)]
mod tests {
    use super::MockContext;
    use crate::context::Context;

    #[test]
    fn test_create_path() {
        let mut mock_ctx = MockContext::new();
        assert!(mock_ctx.create_path("/test"));
        assert!(mock_ctx.path_exists("/test"));
    }
}
