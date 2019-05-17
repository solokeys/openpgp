This repository contains a portable implementation for OpenPGP and will be
able to run on PC for testing and development, and can run on Solo.

# Requirements

This should run fine on Linux, OS X, or Ubuntu on Windows.

# Set up

Clone Gnuk to get their testing suite.  Note, there are symlinks in the repo, so
make sure you clone using a \*nix environment! 

```
git clone https://salsa.debian.org/gnuk-team/gnuk/gnuk
```

Install Python test tools to run Gnuk tests.

```
sudo apt install python3-pytest python3-usb python3-cffi
```

Replace the normal card reader class, with our testing class to connect
the CCID/OpenPGP application over UDP to our local application.

```
cp card_reader.py gnuk/tests/card_reader.py
```

Build our `CCID/OpenPGP` application

```
make
```

# Running

In one terminal, run our `CCID/OpenPGP` application.

```
./main
```

In another terminal, run the Gnuk test suite.

```
cd gnuk/tests && py.test-3 -x
```

# Progress

Currently, no CCID or OpenPGP functionality is implemented.  If the application
is run with tests, you will see the tests fail and the application output this.

```
Hello CCID/OpenPGP
Init CCID
>> 6f 0b 00 00 00 00 00 00 00 00 00 a4 04 00 06 d2 76 00 01 24 01
```

These `6f 0b 00 00 00 00 00 00 00 00 00 a4 04 00 06 d2 76 00 01 24 01` bytes come from `card.cmd_select_openpgp()` in the tests.
