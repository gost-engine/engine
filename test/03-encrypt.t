#!/usr/bin/perl
use Test2::V0;
plan(48);
use Cwd 'abs_path';

#
# If this variable is set, engine would be loaded via configuration
# file. Otherwise - via command line
# 
my $use_config = 1;

# prepare data for 

my $key='0123456789abcdef' x 2;

#
# You can redefine engine to use using ENGINE_NAME environment variable
# 
my $engine=$ENV{'ENGINE_NAME'}||"gost";

# Reopen STDERR to eliminate extra output
open STDERR, ">>","tests.err";

our $count=0;

#
# parameters -paramset = oid of the parameters
# -cleartext - data to encrypt
# -ciphertext - expected ciphertext (hex-encoded)
# -key - key (hex-encoded)
# -iv  - IV (hex-encoded)
# 
my $F;
my $eng_param;

open $F,">","test.cnf";
if (defined($use_config) && $use_config) {
	$eng_param = "";
	open $F,">","test.cnf";
	print $F <<EOCFG
openssl_conf = openssl_def
[openssl_def]
engines = engines
[engines]
${engine}=gost_conf
[gost_conf]
default_algorithms = ALL

EOCFG
} else {
	$eng_param = "-engine $engine"
}
close $F;
$ENV{'OPENSSL_CONF'}=abs_path('test.cnf');
	
sub crypt_test {
	my %p = @_;
	our $count++;
	open my $f, ">", "test$count.clear";
	print $f $p{-cleartext};
	close $f;
	
	$ENV{'CRYPT_PARAMS'} = $p{-paramset} if exists $p{-paramset};
	my $ctext = `openssl enc ${eng_param} -e -$p{-alg} -K $p{-key} -iv $p{-iv} -in test$count.clear`;
	is($?,0,"$p{-name} - encrypt successful");
	is(unpack("H*",$ctext),$p{-ciphertext},"$p{-name} - ciphertext expected");
	open $f, ">", "test$count.enc";
	print $f $ctext;
	close $f;
	my $otext = `openssl enc ${eng_param} -d -$p{-alg} -K $p{-key} -iv $p{-iv} -in test$count.enc`;
	is($?,0,"$p{-name} - decrypt successful");
	is($otext,$p{-cleartext},"$p{-name} - decrypted correctly");
	unlink "test$count.enc";
	unlink "test$count.clear";
	delete $ENV{'CRYPT_PARAMS'};
}

$key = '0123456789ABCDEF' x 4;
my $iv =  '0000000000000000';
my $clear1 = "The quick brown fox jumps over the lazy dog\n";

crypt_test(-paramset=> "1.2.643.2.2.31.1", -key => $key, -iv => $iv,
		   -cleartext => $clear1,
		   -ciphertext => '07f4102c6185c4a09e676e269bfa4bc9c5df6575916b879bd13a893a2285ee6690107cdeef7a315d2eb54bfa', 
		   -alg => 'gost89',
		   -name=> 'CFB short text, paramset A');

crypt_test(-paramset=> "1.2.643.2.2.31.2", -key => $key, -iv => $iv,
		   -cleartext => $clear1,
		   -ciphertext => '11465c1c9708033e784fbb5536f2719c38353cb488b01f195c20d4c027022e8300d98bb66c138afbe878c88b', 
		   -alg => 'gost89',
		   -name=> 'CFB short text, paramset B');

crypt_test(-paramset=> "1.2.643.2.2.31.3", -key => $key, -iv => $iv,
		   -cleartext => $clear1,
		   -ciphertext => '2f213b390c9b6ceb18de479686d23f4f03c76644a0aab8894b50b71a3bbb3c027ec4c2d569ba0e6a873bd46e', 
		   -alg => 'gost89',
		   -name=> 'CFB short text, paramset C');

crypt_test(-paramset=> "1.2.643.2.2.31.4", -key => $key, -iv => $iv,
		   -cleartext => $clear1,
		   -ciphertext => 'e835f59a7fdfd84764efe1e987660327f5d0de187afea72f9cd040983a5e5bbeb4fe1aa5ff85d623ebc4d435', 
		   -alg => 'gost89',
		   -name=> 'CFB short text, paramset D');


crypt_test(-paramset=> "1.2.643.2.2.31.1", -key => $key, -iv => $iv,
		   -cleartext => $clear1,
		   -ciphertext => 'bcb821452e459f10f92019171e7c3b27b87f24b174306667f67704812c07b70b5e7420f74a9d54feb4897df8', 
		   -alg => 'gost89-cnt',
		   -name=> 'CNT short text');

crypt_test(-paramset=> "1.2.643.2.2.31.2", -key => $key, -iv => $iv,
		   -cleartext => $clear1,
		   -ciphertext => 'bcb821452e459f10f92019171e7c3b27b87f24b174306667f67704812c07b70b5e7420f74a9d54feb4897df8', 
		   -alg => 'gost89-cnt',
		   -name=> 'CNT short text, paramset param doesnt affect cnt');

		   
crypt_test(-paramset=> "1.2.643.2.2.31.1", -key => $key, -iv => $iv,
		   -cleartext => $clear1,
		   -ciphertext => 'cf3f5f713b3d10abd0c6f7bafb6aaffe13dfc12ef5c844f84873aeaaf6eb443a9747c9311b86f97ba3cdb5c4',
		   -alg => 'gost89-cnt-12',
		   -name=> 'CNT-12 short text');

crypt_test(-paramset=> "1.2.643.2.2.31.2", -key => $key, -iv => $iv,
		   -cleartext => $clear1,
		   -ciphertext => 'cf3f5f713b3d10abd0c6f7bafb6aaffe13dfc12ef5c844f84873aeaaf6eb443a9747c9311b86f97ba3cdb5c4',
		   -alg => 'gost89-cnt-12',
		   -name=> 'CNT-12 short text, paramset param doesnt affect cnt');


crypt_test(-paramset=> "1.2.643.2.2.31.1", -key => $key, -iv => $iv,
		   -cleartext => $clear1,
		   -ciphertext => '3a3293e75089376572da44966cd1759c29d2f1e5e1c3fa9674909a63026da3dc51a4266bff37fb74a3a07155c9ca8fcf', 
		   -alg => 'gost89-cbc',
		   -name=> 'CBC short text, paramset A');


crypt_test(-paramset=> "1.2.643.2.2.31.2", -key => $key, -iv => $iv,
		   -cleartext => $clear1,
		   -ciphertext => 'af2a2167b75852378af176ac9950e3c4bffc94d3d4355191707adbb16d6c8e3f3a07868c4702babef18393edfac60a6d', 
		   -alg => 'gost89-cbc',
		   -name=> 'CBC short text, paramset B');

crypt_test(-paramset=> "1.2.643.2.2.31.3", -key => $key, -iv => $iv,
		   -cleartext => $clear1,
		   -ciphertext => '987c0fb3d84530467a1973791e0a25e33c5d14591976f8c1573bdb9d056eb7b353f66fef3ffe2e3524583b3997123c8a', 
		   -alg => 'gost89-cbc',
		   -name=> 'CBC short text, paramset C');

crypt_test(-paramset=> "1.2.643.2.2.31.4", -key => $key, -iv => $iv,
		   -cleartext => $clear1,
		   -ciphertext => 'e076b09822d4786a2863125d16594d765d8acd0f360e52df42e9d52c8e6c0e6595b5f6bbecb04a22c8ae5f4f87c1523b', 
		   -alg => 'gost89-cbc',
		   -name=> 'CBC short text, paramset D');

unlink "test.cnf";
