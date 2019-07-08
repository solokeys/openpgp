# Tests

Initially obtain from GNUK repository.

[wiki](https://wiki.debian.org/GNUK)

[repository](https://salsa.debian.org/gnuk-team/gnuk/gnuk)

[repository with last commits](http://git.gniibe.org/gitweb/?p=gnuk/gnuk.git)


tests lay [here](https://salsa.debian.org/gnuk-team/gnuk/gnuk/tree/master/tests)


## original readme

Here is a test suite for OpenPGP card.

For now, only TPDU card reader is supported for OpenPGP card.
Gnuk Token is supported as well.


You need to install:

   `$ sudo apt install python3-pytest python3-usb python3-cffi`

Please run test by typing:

    `$ py.test-3 -x`

Or with verbose

    `$ py.test-3 -x -vv`

or
    
    `$ py.test-3 -x v`
