#!/usr/bin/perl 
use Test::More tests => 12;
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
"GOST R 34.11-94 1K ascii");

is(`openssl dgst -engine ${engine} -md_gost12_256 testdata.dat`,
"md_gost12_256(testdata.dat)= d38a79cb15db40651051ef6879881fe25d84cdbb23ecec9f56126f8803f5fc88\n",
"GOST R 34.11-2012 256bit 1K ascii");

is(`openssl dgst -engine ${engine} -md_gost12_512 testdata.dat`,
"md_gost12_512(testdata.dat)= ac48be903716d9b9701fd8cdd75417b9085b5b642191926afd92310e645c52d465e36bbd5ccb356c5b1b8020a868915d5d8cc18ed2c07c28d24ba914b867f144\n",
"GOST R 34.11-2012 512bit 1K ascii");

unlink("testdata.dat");

open F,">","testdata2.dat";
print F "\x00\x01\x02\x15\x84\x67\x45\x31" x 128;
close F;

is(`openssl dgst -engine ${engine} -md_gost94 testdata2.dat`,
"md_gost94(testdata2.dat)= 69f529aa82d9344ab0fa550cdf4a70ecfd92a38b5520b1906329763e09105196\n",
"GOST R 34.11-94 1K binary");

is(`openssl dgst -engine ${engine} -md_gost12_256 testdata2.dat`,
"md_gost12_256(testdata2.dat)= 88fb2a93873befc1712c96c6e151223b18798de4601448efe2836dbfa53a55f2\n",
"GOST R 34.11-2012 256bit 1K binary");

is(`openssl dgst -engine ${engine} -md_gost12_512 testdata2.dat`,
"md_gost12_512(testdata2.dat)= 559b71aaad8e0e749cbac47ff1eaa48471bafaf81e648b234c456e5d25538c32a61d04e3f5863301fdf1f289efc286cb1c317aba3e6425bece26e8cfe35a4074\n",
"GOST R 34.11-2012 512bit 1K binary");

unlink("testdata2.dat");

open F, ">","testdata3.dat";
print F substr("12345670" x 128,0,539);
close F;

is(`openssl dgst -engine ${engine} -md_gost94 testdata3.dat`,
"md_gost94(testdata3.dat)= bd5f1e4b539c7b00f0866afdbc8ed452503a18436061747a343f43efe888aac9\n",
"GOST R 34.11-94 539 bytes");

is(`openssl dgst -engine ${engine} -md_gost12_256 testdata3.dat`,
"md_gost12_256(testdata3.dat)= 3791fa0d152ee406be966c1ef2729ea1dcac370556971cfb08123100735d476c\n",
"GOST R 34.11-2012 256bit 539 bytes");

is(`openssl dgst -engine ${engine} -md_gost12_512 testdata3.dat`,
"md_gost12_512(testdata3.dat)= 62a09dfad97d84b2020a4ab464c878933210b6d23cbfe0c1d1e7fb9093e360fc052e30c5b7bc27ac7d207fcf51ab59058fb2474d08e664cd040c3b8d2d2f49d6\n",
"GOST R 34.11-2012 512bit 539 bytes");

unlink "testdata3.dat";
open F , ">","bigdata.dat";
print F  ("121345678" x 7 . "1234567\n") x 4096,"12345\n";
close F;

is(`openssl dgst -engine ${engine} -md_gost94 bigdata.dat`,
"md_gost94(bigdata.dat)= e5d3ac4ea3f67896c51ff919cedb9405ad771e39f0f2eab103624f9a758e506f\n",
"GOST R 34.11-94 128K");

is(`openssl dgst -engine ${engine} -md_gost12_256 bigdata.dat`,
"md_gost12_256(bigdata.dat)= d50eeeff483f8b5f550d944decb60846f0a6b34f2f7d44a6f725af1578385d47\n",
"GOST R 34.11-2012 256bit 128K");

is(`openssl dgst -engine ${engine} -md_gost12_512 bigdata.dat`,
"md_gost12_512(bigdata.dat)= d57b8b8ea4061822b47df128fe92bd6db4fd6c8e3c537806ae1782ba67fab474c390b9564c3e4867562e0c3ad974d37d5fa6c5b5a3699e984b45845acbcf298a\n",
"GOST R 34.11-2012 512bit 128K");

unlink "bigdata.dat";
