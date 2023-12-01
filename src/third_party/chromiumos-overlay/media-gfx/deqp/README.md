* First obtain local copy of dEQP repo, for instance
  git clone https://github.com/KhronosGroup/VK-GL-CTS
* Then checkout desired branch/tag/commit in VK-GL-CTS, for instance
  git checkout origin/vulkan-cts-1.3.4.1
* Finally run this script inside the chroot
  . update.sh VK-GL-CTS

* Test the ebuild using emerge-volteer deqp
* If there is a configure failure check if a new external tarball needs to be
  added to update.sh and the ebuild.
* You may have to update the manifest
  ebuild deqp-... manifest
* Double check that the paths of the main test lists for egl.txt, gles*.txt are
  still correct (renaming from master -> main going on)
  ls VK-GL-CTS/android/cts/main/
