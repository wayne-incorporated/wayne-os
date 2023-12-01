For debugging Android CTS/deqp failures we are on purpose not following the
official releases, as these are outdated. Instead we are building from the
android11-tests-dev branch which includes the newest upstream fixes.

* first obtain local copy of dEQP repo,
  git clone https://android.googlesource.com/platform/external/deqp
* then checkout android11-tests-dev,
  git checkout origin/android11-tests-dev
* finally run this script inside the chroot
  sh update.sh deqp
