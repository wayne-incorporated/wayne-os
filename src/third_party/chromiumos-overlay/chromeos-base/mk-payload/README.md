mk_payload is a binary used by ARCVM to create a composite disk of using apexes.
See [go/arcvm-block-apex](http://go/arcvm-block-apex) for more background.

To update the mk_payload binary used by CrOS builders, do the following

To update to a newer version of mk_payload, you'll need to
* Download push_to_device.zip from an Android builder (e.g
    ab/git_master-arc-dev). Make sure to include the version # nocheck
    used here in your commit.
    * If you want to build this manually, you can run `m mk_payload` from your
      lunch'd Android checkout. However, you should only upload a binary
      from a builder.
* Unzip it
    * unzip -d ptd push_to_device.zip
* run the files/gather.sh script
    * files/gather.sh ptd/bin/mk_payload <NEW_VERSION>
* rename the ebuild, incrementing the version
    * e.g. if incrementing from 0.0.3 -> 0.0.4, you would do
      `git mv mk-payload-0.0.3.ebuild mk-payload-0.0.4.ebuild`
* cros_sdk
* (inside chroot) sudo ebuild <PATH_TO_THIS_EBUILD> manifest

The only place this is used is inside board_specific_setup, so to test locally
you'll have to manually create a new image with it.
