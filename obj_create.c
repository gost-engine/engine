#include "gost_lcl.h"
#include <openssl/objects.h>
#include <string.h>

int gost_add_obj(const char *oid, const char *sn, const char *ln)
{
   	int nid;
	char *oidtemp=NULL,*sntemp=NULL,*lntemp=NULL;
	
   	if (oid) {
   		nid = OBJ_txt2nid(oid);
	} else {
		nid = OBJ_txt2nid(sn);
	}
   	if (nid != NID_undef) {
		return nid;
	}
	if (oid) {
		oidtemp=OPENSSL_malloc(strlen(oid) + 2);
		strcpy(oidtemp, oid);
	}

	if (sn) {
		sntemp=OPENSSL_malloc(strlen(sn) + 2);
		strcpy(sntemp, sn);
	}

	if (ln) {
		lntemp=OPENSSL_malloc(strlen(ln) + 2);
		strcpy(lntemp, ln);
	}
	return OBJ_create(oid,sn,ln);
}

