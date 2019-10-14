This repository contains a portable implementation for OpenPGP and will be
able to run on PC for testing and development, and can run on Solo.

# Requirements

This should run fine on Linux, OS X, or Ubuntu on Windows.

# Set up

Clone Gnuk to get their testing suite.  Note, there are symlinks in the repo, so
make sure you clone using a \*nix environment!

```
git clone https://github.com/solokeys/openpgp.git
```

Install Python test tools to run Gnuk tests.

```
sudo apt install python3-pytest python3-usb python3-cffi
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

In another terminal: 

connect it via USBIP

```
sudo usbip attach -r 127.0.0.1 -b 1-1
kill pcscd (somehow)
```

run python test suite.

```
cd pytest 
sudo py.test-3 -s -x
```

# Work with USBIP

Setup
```
sudo mkdir /usr/share/hwdata
sudo cp /var/lib/usbutils/usb.ids /usr/share/hwdata/usb.ids
```

init commands
```
sudo modprobe vhci-hcd  (once after reboot!!!)
sudo usbip attach -r 127.0.0.1 -b 1-1
sudo lsusb -d 072f:90cc -v
```

Check if all is in working state

```
pcsc_scan
gpg2 --card-edit (command line: admin, list, name, lang, generate)
gpg2 --card-edit --expert (admin, key-attr)
```

list devices:
```
usbip list -r 127.0.0.1
or
usbip list -l
```

gpg export keys
```
To get a simple file of your public key, you can just use 
gpg2 --armor --export keyID > pubkey.asc
gpg2 --output pubkey.pgp --armor --export keyID
gpg2 --armor --export-secret-key keyID > privatekey.asc
gpg2 --output backupkeys.pgp --armor --export --export-options export-backup user@email
```

gpg import keys from card
```
gpg2 --import pubkey.asc
gpg --card-status
gpg --list-secret
```

# Google test

Test some critical parts of code

## install

`sudo apt-get install libgtest-dev`

## check

`cd gtest`

`make test`

# TODO

1. Change name from `Applet` to `Application`
2. ~~test via virtual USB in linux~~
3. Add tests for:
  - ~~init card at the begining of tests~~
  - access rights to commands and DO
  - refactor some tests and change some "magic" values in them
  - ~~test RSA4096 generation and increase interface timeouts~~
4. Add tests and functionality for:
  - ECDSA
  - ~~reset card~~
  - ~~user DO (0101-0104) and check access rights~~
  - add user DO length check
  - PSO:ENCIPHER and DECIPHER with AES
  - Secure messaging????
  - ALGO_ED25519 (EdDSA), ALGO_CURVE25519(ECDH)???


