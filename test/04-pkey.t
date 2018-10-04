#!/usr/bin/perl
use Test2::V0;
plan(15);
use Cwd 'abs_path';

#
# If this variable is set, engine would be loaded via configuration
# file. Otherwise - via command line
# 
my $use_config = 1;

# prepare data for 


# Set OPENSSL_ENGINES environment variable to just built engine
if(!defined $ENV{'OPENSSL_ENGINES'}){
        $ENV{'OPENSSL_ENGINES'} = abs_path("../.libs");
}

my $engine=$ENV{'ENGINE_NAME'}||"gost";

# Reopen STDERR to eliminate extra output
open STDERR, ">>","tests.err";

my $F;
my $eng_param;

open $F,">","test.cnf";
if (defined($use_config) && $use_config) {
	$eng_param = "";
	open $F,">","test.cnf";
	print $F <<EOCFG;
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


my @keys=(['gost2001','A',"-----BEGIN PRIVATE KEY-----
MEUCAQAwHAYGKoUDAgITMBIGByqFAwICIwEGByqFAwICHgEEIgIgRhUDJ1WQASIf
nx+aUM2eagzV9dCt6mQ5wdtenr2ZS/Y=
-----END PRIVATE KEY-----
","Private key: 46150327559001221F9F1F9A50CD9E6A0CD5F5D0ADEA6439C1DB5E9EBD994BF6
","Public key:
   X:789094AF6386A43AF191210FFED0AEA5D1D9750D8FF8BCD1B584BFAA966850E4
   Y:25ED63EE42624403D08FC60E5F8130F121ECDC5E297D9E3C7B106C906E0855E9
Parameter set: id-GostR3410-2001-CryptoPro-A-ParamSet
","-----BEGIN PUBLIC KEY-----
MGMwHAYGKoUDAgITMBIGByqFAwICIwEGByqFAwICHgEDQwAEQORQaJaqv4S10bz4
jw112dGlrtD+DyGR8TqkhmOvlJB46VUIbpBsEHs8nn0pXtzsIfEwgV8Oxo/QA0Ri
Qu5j7SU=
-----END PUBLIC KEY-----
"],
['gost2001','B'=>'-----BEGIN PRIVATE KEY-----
MEUCAQAwHAYGKoUDAgITMBIGByqFAwICIwIGByqFAwICHgEEIgIgImwnCcqcfuXK
MVYg+UWQhiXYKz1yQ8kDSB7Ly515XH4=
-----END PRIVATE KEY-----
','Private key: 226C2709CA9C7EE5CA315620F945908625D82B3D7243C903481ECBCB9D795C7E
','Public key:
   X:59C15439385CBE790274D6537D318A35B27413D265FFDC5FBE5354DF8C7AC591
   Y:11B771AC016AA817542184D05F2C7DDD0F9A5A5C9F840A79B5B7A73658F3048A
Parameter set: id-GostR3410-2001-CryptoPro-B-ParamSet
','-----BEGIN PUBLIC KEY-----
MGMwHAYGKoUDAgITMBIGByqFAwICIwIGByqFAwICHgEDQwAEQJHFeozfVFO+X9z/
ZdITdLI1ijF9U9Z0Anm+XDg5VMFZigTzWDant7V5CoSfXFqaD919LF/QhCFUF6hq
AaxxtxE=
-----END PUBLIC KEY-----
'],
['gost2001','C'=>'-----BEGIN PRIVATE KEY-----
MEUCAQAwHAYGKoUDAgITMBIGByqFAwICIwMGByqFAwICHgEEIgIgKKUJVY2xlp24
mky1F9inWeq3mm0J/uza6HsDvspgSzY=
-----END PRIVATE KEY-----
','Private key: 28A509558DB1969DB89A4CB517D8A759EAB79A6D09FEECDAE87B03BECA604B36
','Public key:
   X:58154320380CCFD2A101D2B7844516984023CF5A38610C4F98220E017270B2D4
   Y:14C6977A6E9C0412DF5B53E69CD48DAF2B5805F55F6ACBEB4E01BA7B2BF84FC8
Parameter set: id-GostR3410-2001-CryptoPro-C-ParamSet
','-----BEGIN PUBLIC KEY-----
MGMwHAYGKoUDAgITMBIGByqFAwICIwMGByqFAwICHgEDQwAEQNSycHIBDiKYTwxh
OFrPI0CYFkWEt9IBodLPDDggQxVYyE/4K3u6AU7ry2pf9QVYK6+N1JzmU1vfEgSc
bnqXxhQ=
-----END PUBLIC KEY-----
'],
['gost2001','XA'=>,'-----BEGIN PRIVATE KEY-----
MEUCAQAwHAYGKoUDAgITMBIGByqFAwICJAAGByqFAwICHgEEIgIgOFuMMveKUx/C
BOSjl9XCepDCHWHv/1bcjdKexKGJkZw=
-----END PRIVATE KEY-----
','Private key: 385B8C32F78A531FC204E4A397D5C27A90C21D61EFFF56DC8DD29EC4A189919C
','Public key:
   X:FA969CB29310E897978A1C9245107B46499D5C14A3975BF8E10EF5F613BE4EC6
   Y:17FCFACCB0F838AE730E8B4021E880937824214DFF5365A61576AC5E72F92E35
Parameter set: id-GostR3410-2001-CryptoPro-XchA-ParamSet
','-----BEGIN PUBLIC KEY-----
MGMwHAYGKoUDAgITMBIGByqFAwICJAAGByqFAwICHgEDQwAEQMZOvhP29Q7h+FuX
oxRcnUlGexBFkhyKl5foEJOynJb6NS75cl6sdhWmZVP/TSEkeJOA6CFAiw5zrjj4
sMz6/Bc=
-----END PUBLIC KEY-----
'],
['gost2001','XB'=>,'-----BEGIN PRIVATE KEY-----
MEUCAQAwHAYGKoUDAgITMBIGByqFAwICJAEGByqFAwICHgEEIgIgE7WWqiYWoKLs
7ezZ8L8Q9JcT73Jf5NYfFnlnoKRIQGg=
-----END PRIVATE KEY-----
','Private key: 13B596AA2616A0A2ECEDECD9F0BF10F49713EF725FE4D61F167967A0A4484068
','Public key:
   X:1D33A01774E501EFADD6C7A936728AF644749E98FEF5AE77A25E185955ED2E14
   Y:FAD2D8101A99EDE8FBDF118B70A9894F4E6DE962B68D27E39B057624A51727
Parameter set: id-GostR3410-2001-CryptoPro-XchB-ParamSet
','-----BEGIN PUBLIC KEY-----
MGMwHAYGKoUDAgITMBIGByqFAwICJAEGByqFAwICHgEDQwAEQBQu7VVZGF6id671
/piedET2inI2qcfWre8B5XQXoDMdJxelJHYFm+MnjbZi6W1OT4mpcIsR3/vo7Zka
ENjS+gA=
-----END PUBLIC KEY-----
']
);
for my $keyinfo (@keys) {
	my ($alg,$paramset,$seckey,$sectext,$pubtext,$pubkey) = @$keyinfo;
	open $F,">",'tmp.pem';
	print $F $seckey;
	close $F;
	#1.  Прочитать секретный ключ и напечатать публичный и секретный ключи
	is(`openssl pkey -noout -text -in tmp.pem`,$sectext . $pubtext,
		"Print key pair $alg:$paramset");
	#2. Прочитать секретный ключ и вывести публичный (все алгоритмы)
    is(`openssl pkey -pubout -in tmp.pem`,$pubkey,
		"Compute public key $alg:$paramset");
	open $F,">","tmp.pem";
	print $F $pubkey;
	close $F;
	#3. Прочитать публичный и напечать его в виде текста
	is(`openssl pkey -pubin -noout -in tmp.pem -text`,$pubtext,
		"Read and print public key $alg:paramset");

}
unlink "tmp.pem";
#4. Сгенерировать ключ два раза (для всех алгоритов и параметров).
# Проверить что получились числа требуемой длины и они не совпадают


#5. Проверить эталонную подпись

#6. Выработать подпись и проверить её

#7. Выработать подпись, поменять в ней один бит и убедиться что она
# перестала проверяться

# 8. Выработать подпись, поменять 1 бит в подписываемых данных и
# убедитсья, что подпись перестала быть корректной.

# 9. Выработать shared ключ по vko

# 10. Разобрать стандартый encrypted key

# 11. Сгенерирвоать encrypted key и его разобрать.

unlink "test.cnf";

