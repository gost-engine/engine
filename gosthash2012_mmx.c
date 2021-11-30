/*
 * Copyright (c) 2013, Alexey Degtyarev <alexey@renatasystems.org>.
 * Implementation fixed based on php-stribog:
 *     Copyright (c) 2013 Vladimir Kolesnikov.
 *     SPDX-License-Identifier: BSD-2-Clause AND MIT
 * Copyright (c) 2021 Vitaly Chikunov <vt@altlinux.org>.
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0+
 */

#include "gosthash2012.h"
#ifdef __GOST3411_HAS_MMX__

#include <mmintrin.h>

#define XLPS XLPS32

#define X(x, y, z) { \
    z->QWORD[0] = x->QWORD[0] ^ y->QWORD[0]; \
    z->QWORD[1] = x->QWORD[1] ^ y->QWORD[1]; \
    z->QWORD[2] = x->QWORD[2] ^ y->QWORD[2]; \
    z->QWORD[3] = x->QWORD[3] ^ y->QWORD[3]; \
    z->QWORD[4] = x->QWORD[4] ^ y->QWORD[4]; \
    z->QWORD[5] = x->QWORD[5] ^ y->QWORD[5]; \
    z->QWORD[6] = x->QWORD[6] ^ y->QWORD[6]; \
    z->QWORD[7] = x->QWORD[7] ^ y->QWORD[7]; \
}

#define XLOAD(x, y, mm0, mm1, mm2, mm3, mm4, mm5, mm6, mm7) { \
    const __m64 *px = (const __m64 *) &x[0]; \
    const __m64 *py = (const __m64 *) &y[0]; \
    mm0 = _mm_xor_si64(px[0], py[0]); \
    mm1 = _mm_xor_si64(px[1], py[1]); \
    mm2 = _mm_xor_si64(px[2], py[2]); \
    mm3 = _mm_xor_si64(px[3], py[3]); \
    mm4 = _mm_xor_si64(px[4], py[4]); \
    mm5 = _mm_xor_si64(px[5], py[5]); \
    mm6 = _mm_xor_si64(px[6], py[6]); \
    mm7 = _mm_xor_si64(px[7], py[7]); \
}

#define STORE(P, mm0, mm1, mm2, mm3, mm4, mm5, mm6, mm7) { \
    unsigned long long *__m64p = &P->QWORD[0]; \
    __m64p[0] = (unsigned long long)(mm0); \
    __m64p[1] = (unsigned long long)(mm1); \
    __m64p[2] = (unsigned long long)(mm2); \
    __m64p[3] = (unsigned long long)(mm3); \
    __m64p[4] = (unsigned long long)(mm4); \
    __m64p[5] = (unsigned long long)(mm5); \
    __m64p[6] = (unsigned long long)(mm6); \
    __m64p[7] = (unsigned long long)(mm7); \
}

#define TRANSPOSE(mm0, mm1, mm2, mm3, mm4, mm5, mm6, mm7) { \
    __m64 tm0, tm1, tm2, tm3, tm4, tm5, tm6, tm7; \
    tm0 = _mm_unpacklo_pi8(mm0, mm2); \
    tm1 = _mm_unpackhi_pi8(mm0, mm2); \
    tm2 = _mm_unpacklo_pi8(mm1, mm3); \
    tm3 = _mm_unpackhi_pi8(mm1, mm3); \
    tm4 = _mm_unpacklo_pi8(mm4, mm6); \
    tm5 = _mm_unpackhi_pi8(mm4, mm6); \
    tm6 = _mm_unpacklo_pi8(mm5, mm7); \
    tm7 = _mm_unpackhi_pi8(mm5, mm7); \
    \
    mm0 = _mm_unpacklo_pi8(tm0, tm2); \
    mm1 = _mm_unpackhi_pi8(tm0, tm2); \
    mm2 = _mm_unpacklo_pi8(tm1, tm3); \
    mm3 = _mm_unpackhi_pi8(tm1, tm3); \
    mm4 = _mm_unpacklo_pi8(tm4, tm6); \
    mm5 = _mm_unpackhi_pi8(tm4, tm6); \
    mm6 = _mm_unpacklo_pi8(tm5, tm7); \
    mm7 = _mm_unpackhi_pi8(tm5, tm7); \
    \
    tm2 = _mm_unpacklo_pi32(mm1, mm5); \
    tm3 = _mm_unpackhi_pi32(mm1, mm5); \
    tm0 = _mm_unpacklo_pi32(mm0, mm4); \
    tm1 = _mm_unpackhi_pi32(mm0, mm4); \
    mm4 = _mm_unpacklo_pi32(mm2, mm6); \
    mm5 = _mm_unpackhi_pi32(mm2, mm6); \
    mm6 = _mm_unpacklo_pi32(mm3, mm7); \
    mm7 = _mm_unpackhi_pi32(mm3, mm7); \
    mm0 = tm0; \
    mm1 = tm1; \
    mm2 = tm2; \
    mm3 = tm3; \
}

#define XTRANSPOSE(x, y, z) { \
    __m64 mm0, mm1, mm2, mm3, mm4, mm5, mm6, mm7; \
    XLOAD(x, y, mm0, mm1, mm2, mm3, mm4, mm5, mm6, mm7); \
    TRANSPOSE(mm0, mm1, mm2, mm3, mm4, mm5, mm6, mm7); \
    STORE(z, mm0, mm1, mm2, mm3, mm4, mm5, mm6, mm7); \
}
#define XLPS32(x, y, data) { \
    unsigned int xi; \
    unsigned char *p; \
    ALIGN(16) union uint512_u buf; \
    XTRANSPOSE(x, y, (&buf)); \
    p = (unsigned char *) &buf; \
    for (xi = 0; xi < 8; xi++) \
    { \
	__m64 mm0 =             (__m64)(Ax[0][*(p++)]); \
	mm0 = _mm_xor_si64(mm0, (__m64)(Ax[1][*(p++)])); \
	mm0 = _mm_xor_si64(mm0, (__m64)(Ax[2][*(p++)])); \
	mm0 = _mm_xor_si64(mm0, (__m64)(Ax[3][*(p++)])); \
	mm0 = _mm_xor_si64(mm0, (__m64)(Ax[4][*(p++)])); \
	mm0 = _mm_xor_si64(mm0, (__m64)(Ax[5][*(p++)])); \
	mm0 = _mm_xor_si64(mm0, (__m64)(Ax[6][*(p++)])); \
	mm0 = _mm_xor_si64(mm0, (__m64)(Ax[7][*(p++)])); \
        data->QWORD[xi] = (unsigned long long) mm0; \
    } \
}

#define ROUND(i, Ki, data) { \
    XLPS(Ki, (&C[i]), Ki); \
    XLPS(Ki, data, data); \
}

void g_mmx(union uint512_u *h, const union uint512_u * RESTRICT N,
              const union uint512_u * RESTRICT m)
{
    union uint512_u Ki, data;
    unsigned int i;

    XLPS(h, N, (&data));

    /* Starting E() */
    Ki = data;
    XLPS((&Ki), ((const union uint512_u *)&m[0]), (&data));

    for (i = 0; i < 11; i++)
        ROUND(i, (&Ki), (&data));

    XLPS((&Ki), (&C[11]), (&Ki));
    X((&Ki), (&data), (&data));
    /* E() done */

    X((&data), h, (&data));
    X((&data), m, h);
    _mm_empty();
}
#endif /* __GOST3411_HAS_MMX__ */
