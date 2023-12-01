# Cryptohome P0 Checklist Fix

**Author(s)**: kerrnel@chromium.org

 - Always include a unit test that exposes the problem before the fix.
 - Carefully evaluate the merge to release and beta branches.
 - If merging to stable, notify the test team of the fix, and what user paths it could impact.
 - The engineer developing/merging the fix should perform manual testing of the functionality affected by the change on a production build that has the merged fix.
 - Always run `tast run hwsec.* ${TEST_DEVICE_IP}` before submission.
 - File a tracking bug to write an integration test after the immediate fix and
 unit test land.
