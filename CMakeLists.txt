cmake_minimum_required(VERSION 3.0 FATAL_ERROR)
project(gost-engine LANGUAGES C)

include(GNUInstallDirs)

find_package(OpenSSL 1.1 REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

if (CMAKE_C_COMPILER_ID MATCHES "Clang")
 add_compile_options(-Qunused-arguments)
elseif(CMAKE_C_COMPILER_ID MATCHES "GNU")
 add_compile_options(-O2 -Werror -Wall -Wno-unused-parameter -Wno-unused-function -Wno-missing-braces -ggdb)
elseif(CMAKE_C_COMPILER_ID MATCHES "MSVC")
 add_definitions(-D_CRT_SECURE_NO_WARNINGS)
 add_definitions(-D_CRT_DEPRECATED_NO_WARNINGS)
 add_definitions(-D_CRT_NONSTDC_NO_WARNINGS)
 add_compile_options(/MP /WX /W4 /wd4100 /wd4267 /wd4206 /wd4706 /wd4244 /wd4115)
endif()

set(CMAKE_C_STANDARD 90)

include (TestBigEndian)
TEST_BIG_ENDIAN(IS_BIG_ENDIAN)
if(IS_BIG_ENDIAN)
 message(STATUS "BIG_ENDIAN")
else()
 message(STATUS "LITTLE_ENDIAN")
 add_definitions(-DL_ENDIAN)
endif()

set(BIN_DIRECTORY bin)

set(OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/${BIN_DIRECTORY})

#set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${OUTPUT_DIRECTORY})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${OUTPUT_DIRECTORY})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${OUTPUT_DIRECTORY})

set(GOST_89_SOURCE_FILES
        gost89.c
        gost89.h
        )

set(GOST_HASH_SOURCE_FILES
        gosthash.c
        gosthash.h
        )

set(GOST_HASH_2012_SOURCE_FILES
        gosthash2012.c
        gosthash2012.h
        gosthash2012_const.h
        gosthash2012_precalc.h
        gosthash2012_ref.h
        gosthash2012_sse2.h
        )

set(GOST_GRASSHOPPER_SOURCE_FILES
        gost_grasshopper.h
        gost_grasshopper_core.h
        gost_grasshopper_core.c
        gost_grasshopper_defines.h
        gost_grasshopper_defines.c
        gost_grasshopper_math.h
        gost_grasshopper_galois_precompiled.c
        gost_grasshopper_precompiled.c
        gost_grasshopper_cipher.h
        gost_grasshopper_cipher.c
        gost_grasshopper_mac.h
        gost_grasshopper_mac.c
        )

set(GOST_CORE_SOURCE_FILES
        e_gost_err.c
        e_gost_err.h
        gost_asn1.c
        gost_crypt.c
        gost_ctl.c
        gost_eng.c
        gost_keywrap.c
        gost_keywrap.h
        gost_lcl.h
        gost_params.c
        )

set(GOST_EC_SOURCE_FILES
        gost_ec_keyx.c
        gost_ec_sign.c
        )

set(GOST_LIB_SOURCE_FILES
        ${GOST_89_SOURCE_FILES}
        ${GOST_HASH_SOURCE_FILES}
        ${GOST_HASH_2012_SOURCE_FILES}
        ${GOST_GRASSHOPPER_SOURCE_FILES}
        ${GOST_EC_SOURCE_FILES}
        )

set(GOST_ENGINE_SOURCE_FILES
        ${GOST_CORE_SOURCE_FILES}
        gost_ameth.c
        gost_md.c
        gost_md2012.c
        gost_pmeth.c
        )

add_library(gost_core STATIC ${GOST_LIB_SOURCE_FILES})
set_target_properties(gost_core PROPERTIES POSITION_INDEPENDENT_CODE ON)

add_library(gost_engine MODULE ${GOST_ENGINE_SOURCE_FILES})
set_target_properties(gost_engine PROPERTIES PREFIX "" OUTPUT_NAME "gost")
target_link_libraries(gost_engine gost_core ${OPENSSL_CRYPTO_LIBRARY})

set(GOST_SUM_SOURCE_FILES
        gostsum.c
        )

add_executable(gostsum ${GOST_SUM_SOURCE_FILES})
target_link_libraries(gostsum gost_core)

set(GOST_12_SUM_SOURCE_FILES
        gost12sum.c
        )

add_executable(gost12sum ${GOST_12_SUM_SOURCE_FILES})
target_link_libraries(gost12sum gost_core)

# install
set(OPENSSL_ENGINES_INSTALL_DIR ${CMAKE_INSTALL_LIBDIR}/engines-${OPENSSL_VERSION_MAJOR}_${OPENSSL_VERSION_MINOR})
set(OPENSSL_MAN_INSTALL_DIR ${CMAKE_INSTALL_MANDIR}/man1)

install(TARGETS gost_engine gostsum gost12sum EXPORT GostEngineConfig
        LIBRARY  DESTINATION ${OPENSSL_ENGINES_INSTALL_DIR}
        RUNTIME  DESTINATION ${CMAKE_INSTALL_BINDIR})
install(FILES gostsum.1 gost12sum.1 DESTINATION ${OPENSSL_MAN_INSTALL_DIR})
if (MSVC)
 install(FILES $<TARGET_PDB_FILE:gost_engine> DESTINATION ${OPENSSL_ENGINES_INSTALL_DIR} OPTIONAL)
 install(FILES $<TARGET_PDB_FILE:gostsum> $<TARGET_PDB_FILE:gost12sum> DESTINATION ${CMAKE_INSTALL_BINDIR} OPTIONAL)
endif()