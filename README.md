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
the `CCID/OpenPGP` application locally to the tests via UDP.

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

# Emulate via USBIP

Setup
```
sudo mkdir /usr/share/hwdata
sudo cp /var/lib/usbutils/usb.ids /usr/share/hwdata/usb.ids
```

1st terminal
```
cd pc
make all
./ccid
```

2nd terminal
```
sudo modprobe vhci-hcd  (once after reboot!!!)
usbip attach -r 127.0.0.1 -b 1-1
sudo lsusb -d 03eb:206e -v
```

list devices:
```
usbip list -r 127.0.0.1
or
usbip list -l
```

# TODO

1. Change name from `Applet` to `Application`
2. test via virtual USB in linux
3. Add tests for:
  - access rights to commands and DO
  - refactor some tests and change some "magic" values in them
  - test RSA4096 generation and increase interface timeouts
4. Add tests and functionality for:
  - ECDSA
  - reset card 
  - user DO (0101-0104) and check access rights
  - PSO:ENCIPHER and DECIPHER with AES
  - Secure messaging????
  - ALGO_ED25519 (EdDSA), ALGO_CURVE25519(ECDH)???


