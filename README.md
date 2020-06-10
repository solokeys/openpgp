This repository contains a portable implementation for OpenPGP and will be
able to run on PC for testing and development, and can run on Solo.

# Requirements

This should run fine on Linux, OS X, or Ubuntu on Windows.

# Set up

Clone Gnuk to get their testing suite.  Note, there are symlinks in the repo, so
make sure you clone using a \*nix environment!

```
git clone --recurse-submodules https://github.com/solokeys/openpgp.git
```

Install Python test tools to run Gnuk tests.

```
sudo apt install python3-pytest python3-usb python3-cffi libmbedtls-dev linux-tools-common linux-tools-generic linux-cloud-tools-generic
python -m pip install pycryptodome
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

# Ed25519 to Curve25519 conversion

https://moderncrypto.org/mail-archive/curves/2014/000205.html

https://moderncrypto.org/mail-archive/curves/2014/000293.html

https://crypto.stackexchange.com/questions/13077/can-curve25519-keys-be-used-with-ed25519-keys

https://docs.rs/exonum/0.9.3/exonum/crypto/x25519/fn.into_x25519_keypair.html

# TODO

1. RSA generation waiting for USB stack (now - timeout)
2. brainpool ecdsa curves
3. Ed25519 to Curve25519 conversion and vice versa (as in yubikey)
4. Add tests for:
  - access rights to commands and DO
  - refactor some tests and change some "magic" values in them
  - refactor ECDSA tests for using cryptography package
5. Add tests and functionality for:
  - ~~ECDSA~~
  - ED25519 (EdDSA), ~~CURVE25519(ECDH)~~
  - Secure messaging????
6. fix:
  - ~~ansix9p384r1, ansix9p521r1 curves~~
  - remove "magic" printf in flash write function)

