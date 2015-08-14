/**********************************************************************
 *                        gost_params.h                               *
 *             Copyright (c) 2005-2013 Cryptocom LTD                  *
 *       This file is distributed under the same license as OpenSSL   *
 *                                                                    *
 *       Declaration of structures used to represent  GOST R 34.10    *
 *                    parameter sets, defined in RFC 4357             *
 *         OpenSSL 1.0.0+ libraries required to compile and use       *
 *                              this code                             *
 **********************************************************************/
#ifndef GOST_PARAMSET_H
# define GOST_PARAMSET_H

typedef struct R3410 {
    int nid;
    char *a;
    char *p;
    char *q;
} R3410_params;

extern R3410_params R3410_paramset[];

typedef struct R3410_ec {
    int nid;
    char *a;
    char *b;
    char *p;
    char *q;
    char *x;
    char *y;
} R3410_ec_params;

extern R3410_ec_params R3410_2001_paramset[],
                      *R3410_2012_256_paramset,
                       R3410_2012_512_paramset[];

#endif
