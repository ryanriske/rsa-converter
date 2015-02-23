#!/usr/bin/perl -w
# Convert RSA public keys from and to various formats.
#
# Copyright © 2014 Ryan Riske <ryan@r1ske.net>
# This work is free. You can redistribute it and/or modify it under the
# terms of the Do What The Fuck You Want To Public License, Version 2,
# as published by Sam Hocevar. See the COPYING file for more details.

use strict;

use Parse::RecDescent;
use Crypt::OpenSSL::RSA;
use MIME::Base64;
use Getopt::Std;

use vars qw/ %opt /;

# Command line options processing
sub init() {
    my $opts = 'hrdp';
    getopts( "$opts", \%opt ) or usage();
    usage() if $opt{h} or !($opt{r} or $opt{d} or $opt{p});
}

sub usage() {
    print STDERR << "EOF";
This program converts RSA public keys from and to various formats.
You must specify at least one output format.

usage: $0 [-hrcp] < file
 -h : print this message
 -r : output public key in Base64 RFC 3110 format
 -d : output public key in hexadecimal DER format
 -p : output public key in PEM format
EOF
    exit;
}

sub input_pem {
    my $key = shift;
    return Crypt::OpenSSL::RSA->new_public_key($key);
}

sub input_rfc {
    my $key = shift;
    my $decoded = decode_base64($key);
    my $len = unpack("C", substr($decoded, 0, 1));
    my $e = Crypt::OpenSSL::Bignum->new_from_bin(substr($decoded, 1, $len));
    my $n = Crypt::OpenSSL::Bignum->new_from_bin(substr($decoded, 1 + $len));
    return Crypt::OpenSSL::RSA->new_key_from_parameters($n, $e);
}

sub input_hex {
    my $key = shift;
    $key =~ s/\s+//g;
    my @bytes = map { pack("C", hex($_)) } ($key =~ /(..)/g);
    my $encoded = encode_base64(join("", @bytes));
    $encoded =~ s/\s+//g;
    $encoded =~ s/(.{64})/$1\n/g;
    my $pem = "-----BEGIN PUBLIC KEY-----\n" . $encoded . "\n-----END PUBLIC KEY-----\n";
    return input_pem($pem);
}

sub output_rfc {
    my $rsa_pub = shift;
    my ($n, $e) = $rsa_pub->get_key_parameters();
    my $eb = $e->to_bin();
    return "0s" . encode_base64(pack("C", length($eb)) . $eb . $n->to_bin(), '') . "\n";
}

sub output_pem {
    my $rsa_pub = shift;
    return $rsa_pub->get_public_key_x509_string();
}

sub output_hex {
    my $rsa_pub = shift;
    my $key = output_pem($rsa_pub);
    $key =~ s/-----BEGIN PUBLIC KEY-----(.*?)-----END PUBLIC KEY-----/$1/s;
    my $hex = uc(unpack("H*", decode_base64($key)));
    $hex =~ s/(.{64})/$1\n/g;
    $hex =~ s/(.{8})/$1 /g;
    return $hex . "\n";
}

init();

my $grammar = q {
    input: item
    item: pempubkey | rfcpubkey | hexpubkey | other
    pempubkey: m{-----BEGIN PUBLIC KEY-----.*?-----END PUBLIC KEY-----}s
               { $return = ::input_pem($item[1]); }
    rfcpubkey: m{0s[A-Za-z0-9+/=]+}
               { $return = ::input_rfc(substr($item[1], 2)); }
    hexpubkey: m{^\s*(?:[A-Z0-9]{2}\s*)+}s
               { $return = ::input_hex($item[1]); }
    other: /.*/ { undef $return; }
};

my $parser = new Parse::RecDescent($grammar);
undef $/;
my $input = <>;
my $pubkey = $parser->input($input);
if (defined $pubkey) {
    print output_rfc($pubkey) if $opt{r};
    print output_pem($pubkey) if $opt{p};
    print output_hex($pubkey) if $opt{d};
} else {
    usage();
}
