This is the CROS\_WORKON\_MANUAL\_UPREV ebuild for virglrenderer.

This ebuild compiles source code that is automatically mirrored on ToT/main
from upstream into the git repo at src/third\_party/virglrenderer

While the source code is set up to sync automatically, this ebuild DOES NOT
automatically uprev to the new sources (hence CROS\_WORKON\_MANUAL\_UPREV).
This is intentional to prevent running unreviewed code in our images.

To help with regular uprevs a pupr job listens regularly on ToT/main only to
new changes in the source repo. Only when such changes are found pupr
automatically generates an uprev CL at
https://chromium-review.googlesource.com/q/virglrenderer+Automatic+uprev
by setting the ebuild commit hash to the latest upstream commit and
incrementing the ebuild revision number suffix.

For all manual changes to the ebuild (especially on branches), it is the CL
author's responsibility to manually increment the ebuild's revision number
suffix. When adding local patches to cros/main and release branch ebuilds, it
MUST be ensured that both the 9999 and versioned ebuilds contain the intended
patches. Failure to do so will result in divergence of virglrenderer's
behavior between developers using workon 9999 ebuilds and testers/users using
the versioned ebuilds in pre-built Chrome OS images.
