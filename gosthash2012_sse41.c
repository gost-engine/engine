/*
 * Copyright (c) 2013, Alexey Degtyarev <alexey@renatasystems.org>.
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0+
 */

#include "gosthash2012.h"
#ifdef __GOST3411_HAS_SSE41__

#include <mmintrin.h>
#include <emmintrin.h>
#include <smmintrin.h>

#ifdef __i386__
#define EXTRACT EXTRACT32
#else
#define EXTRACT EXTRACT64
#endif

#ifndef __ICC
#define _mm_cvtsi64_m64(v) (__m64) v
#define _mm_cvtm64_si64(v) (long long) v
#endif

#define LOAD(P, xmm0, xmm1, xmm2, xmm3) { \
    const __m128i *__m128p = (const __m128i *) &P[0]; \
    xmm0 = _mm_loadu_si128(&__m128p[0]); \
    xmm1 = _mm_loadu_si128(&__m128p[1]); \
    xmm2 = _mm_loadu_si128(&__m128p[2]); \
    xmm3 = _mm_loadu_si128(&__m128p[3]); \
}

#define UNLOAD(P, xmm0, xmm1, xmm2, xmm3) { \
    __m128i *__m128p = (__m128i *) &P[0]; \
    _mm_store_si128(&__m128p[0], xmm0); \
    _mm_store_si128(&__m128p[1], xmm1); \
    _mm_store_si128(&__m128p[2], xmm2); \
    _mm_store_si128(&__m128p[3], xmm3); \
}

#define X128R(xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7) { \
    xmm0 = _mm_xor_si128(xmm0, xmm4); \
    xmm1 = _mm_xor_si128(xmm1, xmm5); \
    xmm2 = _mm_xor_si128(xmm2, xmm6); \
    xmm3 = _mm_xor_si128(xmm3, xmm7); \
}

#define X128M(P, xmm0, xmm1, xmm2, xmm3) { \
    const __m128i *__m128p = (const __m128i *) &P[0]; \
    xmm0 = _mm_xor_si128(xmm0, _mm_loadu_si128(&__m128p[0])); \
    xmm1 = _mm_xor_si128(xmm1, _mm_loadu_si128(&__m128p[1])); \
    xmm2 = _mm_xor_si128(xmm2, _mm_loadu_si128(&__m128p[2])); \
    xmm3 = _mm_xor_si128(xmm3, _mm_loadu_si128(&__m128p[3])); \
}

#define _mm_xor_64(mm0, mm1) _mm_xor_si64(mm0, _mm_cvtsi64_m64(mm1))

#define _mm_extract_char(src, ndx) (unsigned char) _mm_extract_epi8(src, ndx)

#define EXTRACT32(row, xmm0, xmm1, xmm2, xmm3, xmm4) { \
    __m64 mm0, mm1; \
     \
    mm0 = _mm_cvtsi64_m64(Ax[0][_mm_extract_char(xmm0, row + 0)]); \
    mm0 = _mm_xor_64(mm0, Ax[1][_mm_extract_char(xmm0, row + 8)]); \
    mm0 = _mm_xor_64(mm0, Ax[2][_mm_extract_char(xmm1, row + 0)]); \
    mm0 = _mm_xor_64(mm0, Ax[3][_mm_extract_char(xmm1, row + 8)]); \
    mm0 = _mm_xor_64(mm0, Ax[4][_mm_extract_char(xmm2, row + 0)]); \
    mm0 = _mm_xor_64(mm0, Ax[5][_mm_extract_char(xmm2, row + 8)]); \
    mm0 = _mm_xor_64(mm0, Ax[6][_mm_extract_char(xmm3, row + 0)]); \
    mm0 = _mm_xor_64(mm0, Ax[7][_mm_extract_char(xmm3, row + 8)]); \
    \
    mm1 = _mm_cvtsi64_m64(Ax[0][_mm_extract_char(xmm0, row + 1)]); \
    mm1 = _mm_xor_64(mm1, Ax[1][_mm_extract_char(xmm0, row + 9)]); \
    mm1 = _mm_xor_64(mm1, Ax[2][_mm_extract_char(xmm1, row + 1)]); \
    mm1 = _mm_xor_64(mm1, Ax[3][_mm_extract_char(xmm1, row + 9)]); \
    mm1 = _mm_xor_64(mm1, Ax[4][_mm_extract_char(xmm2, row + 1)]); \
    mm1 = _mm_xor_64(mm1, Ax[5][_mm_extract_char(xmm2, row + 9)]); \
    mm1 = _mm_xor_64(mm1, Ax[6][_mm_extract_char(xmm3, row + 1)]); \
    mm1 = _mm_xor_64(mm1, Ax[7][_mm_extract_char(xmm3, row + 9)]); \
    \
    xmm4 = _mm_set_epi64(mm1, mm0); \
}

#define EXTRACT64(row, xmm0, xmm1, xmm2, xmm3, xmm4) { \
    register unsigned long long r0, r1; \
    r0  = Ax[0][_mm_extract_char(xmm0, row + 0)]; \
    r0 ^= Ax[1][_mm_extract_char(xmm0, row + 8)]; \
    r0 ^= Ax[2][_mm_extract_char(xmm1, row + 0)]; \
    r0 ^= Ax[3][_mm_extract_char(xmm1, row + 8)]; \
    r0 ^= Ax[4][_mm_extract_char(xmm2, row + 0)]; \
    r0 ^= Ax[5][_mm_extract_char(xmm2, row + 8)]; \
    r0 ^= Ax[6][_mm_extract_char(xmm3, row + 0)]; \
    r0 ^= Ax[7][_mm_extract_char(xmm3, row + 8)]; \
    \
    r1  = Ax[0][_mm_extract_char(xmm0, row + 1)]; \
    r1 ^= Ax[1][_mm_extract_char(xmm0, row + 9)]; \
    r1 ^= Ax[2][_mm_extract_char(xmm1, row + 1)]; \
    r1 ^= Ax[3][_mm_extract_char(xmm1, row + 9)]; \
    r1 ^= Ax[4][_mm_extract_char(xmm2, row + 1)]; \
    r1 ^= Ax[5][_mm_extract_char(xmm2, row + 9)]; \
    r1 ^= Ax[6][_mm_extract_char(xmm3, row + 1)]; \
    r1 ^= Ax[7][_mm_extract_char(xmm3, row + 9)]; \
    \
    xmm4 = _mm_cvtsi64_si128((long long) r0); \
    xmm4 = _mm_insert_epi64(xmm4, (long long) r1, 1); \
}

#define XLPS128M(P, xmm0, xmm1, xmm2, xmm3) { \
    __m128i tmm0, tmm1, tmm2, tmm3; \
    X128M(P, xmm0, xmm1, xmm2, xmm3); \
    \
    EXTRACT(0, xmm0, xmm1, xmm2, xmm3, tmm0); \
    EXTRACT(2, xmm0, xmm1, xmm2, xmm3, tmm1); \
    EXTRACT(4, xmm0, xmm1, xmm2, xmm3, tmm2); \
    EXTRACT(6, xmm0, xmm1, xmm2, xmm3, tmm3); \
    \
    xmm0 = tmm0; \
    xmm1 = tmm1; \
    xmm2 = tmm2; \
    xmm3 = tmm3; \
}

#define XLPS128R(xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7) { \
    __m128i tmm0, tmm1, tmm2, tmm3; \
    X128R(xmm4, xmm5, xmm6, xmm7, xmm0, xmm1, xmm2, xmm3); \
    \
    EXTRACT(0, xmm4, xmm5, xmm6, xmm7, tmm0); \
    EXTRACT(2, xmm4, xmm5, xmm6, xmm7, tmm1); \
    EXTRACT(4, xmm4, xmm5, xmm6, xmm7, tmm2); \
    EXTRACT(6, xmm4, xmm5, xmm6, xmm7, tmm3); \
    \
    xmm4 = tmm0; \
    xmm5 = tmm1; \
    xmm6 = tmm2; \
    xmm7 = tmm3; \
}

#define ROUND128(i, xmm0, xmm2, xmm4, xmm6, xmm1, xmm3, xmm5, xmm7) { \
    XLPS128M((&C[i]), xmm0, xmm2, xmm4, xmm6); \
    XLPS128R(xmm0, xmm2, xmm4, xmm6, xmm1, xmm3, xmm5, xmm7); \
}

void g_sse41(union uint512_u *h, const union uint512_u * RESTRICT N,
              const union uint512_u * RESTRICT m)
{
    __m128i xmm0, xmm2, xmm4, xmm6; /* XMMR0-quadruple */
    __m128i xmm1, xmm3, xmm5, xmm7; /* XMMR1-quadruple */
    unsigned int i;

    LOAD(N, xmm0, xmm2, xmm4, xmm6);
    XLPS128M(h, xmm0, xmm2, xmm4, xmm6);

    LOAD(m, xmm1, xmm3, xmm5, xmm7);
    XLPS128R(xmm0, xmm2, xmm4, xmm6, xmm1, xmm3, xmm5, xmm7);

    for (i = 0; i < 11; i++)
        ROUND128(i, xmm0, xmm2, xmm4, xmm6, xmm1, xmm3, xmm5, xmm7);

    XLPS128M((&C[11]), xmm0, xmm2, xmm4, xmm6);
    X128R(xmm0, xmm2, xmm4, xmm6, xmm1, xmm3, xmm5, xmm7);

    X128M(h, xmm0, xmm2, xmm4, xmm6);
    X128M(m, xmm0, xmm2, xmm4, xmm6);

    UNLOAD(h, xmm0, xmm2, xmm4, xmm6);
# ifdef __i386__
    /* Restore the Floating-point status on the CPU */
    /* This is only required on MMX, but EXTRACT32 is using MMX */
    _mm_empty();
# endif
}
#endif /* __GOST3411_HAS_SSE41__ */
