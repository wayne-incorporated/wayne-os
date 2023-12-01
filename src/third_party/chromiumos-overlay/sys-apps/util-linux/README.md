This ebuild is forked from the portage-stable version for the purpose of
including the nosymfollow patch on supported kernels (currently Chrome OS 5.4).
It should be returned to portage-stable when the following conditions are met:

1.  The `MNT_NOSYMFOLLOW` flag is included in an upstream release (expected
    when Linux kernel 5.8 comes out).
2.  All of our supported kernels include the flag, through some combination of:
    1.  Backporting the [main patch](https://lore.kernel.org/linux-fsdevel/20200304173446.122990-1-zwisler@google.com/)
        and the [LSM changes](http://b/152074038) to older kernels.
    2.  Moving devices forward to kernels that support `MNT_NOSYMFOLLOW`.
