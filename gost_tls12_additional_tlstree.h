#pragma once

int gost_tlstree_magma_cbc(const unsigned char *in, unsigned char *out,
                           const unsigned char *tlsseq, int mode);
int gost_tlstree_grasshopper_cbc(const unsigned char *in, unsigned char *out,
                                 const unsigned char *tlsseq, int mode);
int gost_tlstree_magma_mgm(const unsigned char *in, unsigned char *out,
                           const unsigned char *tlsseq, int mode);
int gost_tlstree_grasshopper_mgm(const unsigned char *in, unsigned char *out,
                                 const unsigned char *tlsseq, int mode);

#define TLSTREE_MODE_NONE                                  0
#define TLSTREE_MODE_S                                     1
#define TLSTREE_MODE_L                                     2
