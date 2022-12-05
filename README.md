
APC tools
============

The target of this project is to provide a CLI alternative for the APC Security Wizard.

The project started with a fork of the [pemtrans project form Abhijit Menon-Sen](https://github.com/amenonsen/pemtrans).
pemtrans is essentially exactly what we need but the result doesn't work yet with APC devices.

## APC specific details
* APC uses [cryptlib](http://www.cryptlib.com/) as crypto lib.
* At the time of this writing the latest version (1.04) of the APC Security Wizard is using an ancient version of cryptlib (version 3.1.1).
 * It seems like there are some compatibility issues between files created by different versions of cryptlib.
* The "CA Root certificate" files generated by the Security Wizard are unmodified p15 files.
 * The key label is "Private key" and the password is "root".
* The final files for the devices generated by the "SSL Server Certificate"/"Import Signed Certificate" options are p15 files with an additional APC Header.
 * The header is always 228 bytes long (See [apcheader.c](apcheader.c) for details).
 * The remaining data of the file is the p15 files generated by cryptlib.
 * The key label is "Private key" and the password is "user".

## Usage
* Remove APC header from server certificate
 * `dd if=server-apc.p15 of=server.p15 bs=228 skip=1`
* Add APC header to a standard p15 file containing a 1024 bit key
 * `apcheader server.p15 server-apc.p15 1`

## Build
(in Fedora 37, There will be lots of warnings, but it will build)
```
yum install cryptlib cryptlib-devel
make
```

## Convert openssl certificates to p15 (PKCS #15) Format for APC/Schneider UPS Network Management Card 2
```
./pemtrans privatekey.crt certificate.crt outfile.p15 "commonname.example.com" "password"
```
