#!/usr/bin/perl

open F,"<","gost_obj.txt" or die "Cannot open gost_obj.txt:$!";

open H,">","newnids.h" or die "Cannot open newnids.h:$!";
open C,">","newnids.c" or die "Cannot open newnids.c:$!";

print H <<EOHH;

#ifndef NEWNIDS_H
#define NEWNIDS_H
/* This file declare variables for  NIDs of new OIDs they are not already
 * definded as preprocessor symbols in openss core
 */

#include <openssl/objects.h>

EOHH

print C <<EOCH;
#include <openssl/objects.h>
#include "gost_lcl.h"

EOCH

$defn = "";

while (<F>)  {
	chomp;
	next if /^\s*#/;
	s/^\s*//;
	s/\s*#.*$//;
	($oid,$sn,$ln) = split(/\s*:\s*/);
	die "Empty short name in line $." unless $sn;
	$nid = "NID_" . $sn;
	$nid =~ tr/-/_/;
	
	if (!$oid ) {
		$oid = 'NULL';
    } else {
		$oid = '"'.$oid.'"';
	}
	$ln ||= $sn;
	print H "#ifndef $nid\nextern int $nid;\n#endif\n";
	print C "#ifndef $nid\nint $nid = NID_undef;\n#endif\n";
	$defn  .= "#ifndef $nid\n    $nid = gost_add_obj($oid,\"$sn\",\"$ln\");\n    if ($nid == NID_undef) return 0;\n#endif\n";
}
	print H "#endif\n";
	print C "\nint gost_define_nids()\n{\n$defn;    return 1;\n}\n";
