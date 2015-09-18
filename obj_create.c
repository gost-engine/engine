#include "gost_lcl.h"
#include <openssl/objects.h>
#include <string.h>

int gost_add_obj(const char *oid, const char *sn, const char *ln)
{
   	int nid;
   	if (oid) {
   		nid = OBJ_txt2nid(oid);
	} else {
		nid = OBJ_txt2nid(sn);
	}
   	if (nid != NID_undef) {
		return nid;
	}
	return OBJ_create(oid,sn,ln);
}

