#!/usr/bin/perl 
use Test2::V0;
plan(19);

# prepare data for 
my $F;
open $F,">","testdata.dat";
print $F "12345670" x 128;
close $F;

open $F,">","testbig.dat";
print $F ("12345670" x 8 . "\n") x  4096;
close $F;

my $key='0123456789abcdef' x 2;

my $engine=$ENV{'ENGINE_NAME'}||"gost";

# Reopen STDERR to eliminate extra output
open STDERR, ">>","tests.err";

is(`openssl dgst -engine ${engine} -mac gost-mac -macopt key:${key} testdata.dat`,
"GOST-MAC-gost-mac(testdata.dat)= 2ee8d13d\n",
"GOST MAC - default size");

my $i;
for ($i=1;$i<=8; $i++) {
	is(`openssl dgst -engine ${engine} -mac gost-mac -macopt key:${key} -sigopt size:$i testdata.dat`,
"GOST-MAC-gost-mac(testdata.dat)= ".substr("2ee8d13dff7f037d",0,$i*2)."\n",
"GOST MAC - size $i bytes");
}



is(`openssl dgst -engine ${engine} -mac gost-mac -macopt key:${key} testbig.dat`,
"GOST-MAC-gost-mac(testbig.dat)= 5efab81f\n",
"GOST MAC - big data");

is(`openssl dgst -engine ${engine} -mac gost-mac-12 -macopt key:${key} testdata.dat`,
"GOST-MAC-12-gost-mac-12(testdata.dat)= be4453ec\n",
"GOST MAC - parameters 2012");


for ($i=1;$i<=8; $i++) {
	is(`openssl dgst -engine ${engine} -mac gost-mac-12 -macopt key:${key} -sigopt size:$i testdata.dat`,
"GOST-MAC-12-gost-mac-12(testdata.dat)= ".substr("be4453ec1ec327be",0,$i*2)."\n",
"GOST MAC parameters 2012 - size $i bytes");
}
unlink('testdata.dat');
unlink('testbig.dat');
