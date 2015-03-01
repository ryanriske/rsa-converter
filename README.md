rsa-converter
================
This is a script that will convert RSA keys between various formats.

    usage: ./rsa-converter [-hrdpqs] < file
     -h : print this message
     -r : output public key in Base64 RFC 3110 format
     -d : output public key in hexadecimal DER format
     -p : output public key in PEM format
     -q : output private key in PEM format (must supply a private key)
     -s : output private key in Racoon/strongSwan < 5.0 format (must supply a private key)

## System requirements
* OpenSSL
* Perl
* CPAN modules:
  * Crypt::OpenSSL::RSA
  * Crypt::OpenSSL::Bignum
  * Parse::RecDescent

### Debian-based systems
`apt-get install libcrypt-openssl-bignum-perl libcrypt-openssl-rsa-perl libparse-recdescent-perl`

### CPAN
`cpan install Crypt::OpenSSL::RSA Crypt::OpenSSL::Bignum Parse::RecDescent`
