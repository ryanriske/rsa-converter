pubkey-converter
================
This is a script that will convert RSA public keys to and from various formats.

    usage: ./pubkey-converter.pl [-hrcp] < file
     -h : print this message
     -r : output public key in Base64 RFC 3110 format
     -d : output public key in hexadecimal DER format
     -p : output public key in PEM format

## System requirements
* OpenSSL
* Perl
* CPAN modules:
  * Crypt::OpenSSL::RSA
  * Crypt::OpenSSL::Bignum
  * Parse::RecDescent

### Debian-based systems
`apt-get install libcrypt-openssl-bignum-perl libcrypt-openssl-rsa-perl libparse-recdescent-perl`
