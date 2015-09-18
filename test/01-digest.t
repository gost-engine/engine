#!/usr/bin/perl 
use Test::More tests => 3;
use Cwd 'abs_path';

# prepare data for 

open F,">","testdata.dat";
print F "12345670" x 128;
close F;

# Set OPENSSL_ENGINES environment variable to just build engine
$ENV{'OPENSSL_ENGINES'} = abs_path("../.libs");
# Set engine name from environment to allow testing of different engines
$engine=$ENV{'ENGINE_NAME'}||"gost";
# Reopen STDERR to eliminate extra output
open STDERR, ">>","tests.err";

is(`openssl dgst -engine ${engine} -md_gost94 testdata.dat`,
"md_gost94(testdata.dat)= f7fc6d16a6a5c12ac4f7d320e0fd0d8354908699125e09727a4ef929122b1cae\n",
"GOST R 34.11-94");

is(`openssl dgst -engine ${engine} -md_gost12_256 testdata.dat`,
"md_gost12_256(testdata.dat)= d38a79cb15db40651051ef6879881fe25d84cdbb23ecec9f56126f8803f5fc88\n",
"GOST R 34.11-2012 256bit");

is(`openssl dgst -engine ${engine} -md_gost12_512 testdata.dat`,
"md_gost12_512(testdata.dat)= ac48be903716d9b9701fd8cdd75417b9085b5b642191926afd92310e645c52d465e36bbd5ccb356c5b1b8020a868915d5d8cc18ed2c07c28d24ba914b867f144\n",
"GOST R 34.11-2012 512bit");

unlink("testdata.dat");
