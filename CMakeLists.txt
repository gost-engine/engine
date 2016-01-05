cmake_minimum_required(VERSION 3.3)
project(gost_engine)

# should be relative
set(OPENSSL_PATH ../..)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c98")

include_directories(${OPENSSL_PATH}/include)
include_directories(${OPENSSL_PATH}/crypto)
include_directories(${OPENSSL_PATH}/crypto/include/internal)

set(GOST_ENGINE_SOURCE_FILES
        e_gost_err.c
        e_gost_err.h
        e_gost_err.proto
        gost89.c
        gost89.h
        gost_ameth.c
        gost_asn1.c
        gost_crypt.c
        gost_ctl.c
        gost_ec_keyx.c
        gost_ec_sign.c
        gost_eng.c
        gost_keywrap.c
        gost_keywrap.h
        gost_lcl.h
        gost_md.c
        gost_md2012.c
        gost_params.c
        gost_pmeth.c
        gosthash.c
        gosthash.h
        gosthash2012.c
        gosthash2012.h
        gosthash2012_const.h
        gosthash2012_precalc.h
        gosthash2012_ref.h
        gosthash2012_sse2.h)

set(GOSTSUM_SOURCE_FILES gostsum.c)
set(GOSTSUM12_SOURCE_FILES gostsum12.c)
set(GOST12SUM_SOURCE_FILES gost12sum.c)

file(GLOB_RECURSE OPENSSL_OBJS RELATIVE ${CMAKE_SOURCE_DIR} "${OPENSSL_PATH}/crypto/libcrypto.a" "${OPENSSL_PATH}/crypto/*.o" )
list(REMOVE_ITEM OPENSSL_OBJS "${OPENSSL_PATH}/crypto/engine/eng_all.o")
list(REMOVE_ITEM OPENSSL_OBJS "${OPENSSL_PATH}/crypto/conf/conf_sap.o")
list(REMOVE_ITEM OPENSSL_OBJS "${OPENSSL_PATH}/crypto/evp/evp_acnf.o")
#message(WARNING ${OPENSSL_OBJS})

set(SOURCE_FILES ${GOST_ENGINE_SOURCE_FILES} ${OPENSSL_OBJS})

add_library(gost SHARED ${SOURCE_FILES})
add_executable(gostsum_engine ${SOURCE_FILES} ${GOSTSUM_SOURCE_FILES})
add_executable(gostsum12_engine ${SOURCE_FILES} ${GOSTSUM12_SOURCE_FILES})
add_executable(gost12sum_engine ${SOURCE_FILES} ${GOST12SUM_SOURCE_FILES})
