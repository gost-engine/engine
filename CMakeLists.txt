cmake_minimum_required(VERSION 3.0 FATAL_ERROR)
project(gost-engine LANGUAGES C)

include(GNUInstallDirs)
include(CheckLibraryExists)
include(CheckFunctionExists)
include(CheckCSourceRuns)

enable_testing()

find_package(OpenSSL 1.1.1 REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

if (CMAKE_C_COMPILER_ID MATCHES "Clang")
 add_compile_options(-O2 -Werror -Wall -Wno-unused-parameter -Wno-unused-function -Wno-missing-braces -ggdb -Qunused-arguments -Wno-deprecated-declarations -Wno-incompatible-pointer-types)
elseif(CMAKE_C_COMPILER_ID MATCHES "GNU")
add_compile_options(-O2 -Werror -Wall -Wno-discarded-qualifiers -Wno-incompatible-pointer-types -Wno-unused-parameter -Wno-unused-function -Wno-missing-braces -ggdb -Wno-error=unknown-pragmas -Wno-deprecated-declarations)
elseif(CMAKE_C_COMPILER_ID MATCHES "MSVC")
 add_definitions(-D_CRT_SECURE_NO_WARNINGS)
 add_definitions(-D_CRT_DEPRECATED_NO_WARNINGS)
 add_definitions(-D_CRT_NONSTDC_NO_WARNINGS)
 add_compile_options(/MP /WX /W4 /wd4100 /wd4267 /wd4206 /wd4706 /wd4244 /wd4115)
endif()

if (ASAN)
  message(STATUS "address sanitizer enabled")
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=address -g3 -fno-omit-frame-pointer")
  set(SKIP_PERL_TESTS 1)
endif()

# DEPRECATEDIN_3_0 CMAC
set_source_files_properties(gost_omac.c PROPERTIES COMPILE_FLAGS -Wno-error=deprecated-declarations)
# DEPRECATEDIN_3_0 HMAC
set_source_files_properties(gost_keyexpimp.c PROPERTIES COMPILE_FLAGS -Wno-error=deprecated-declarations)

set(CMAKE_C_STANDARD 90)
CHECK_FUNCTION_EXISTS(clock_gettime HAVE_CLOCK_GETTIME_C)
CHECK_LIBRARY_EXISTS(rt clock_gettime "" HAVE_CLOCK_GETTIME_RT)
if(HAVE_CLOCK_GETTIME_RT AND NOT HAVE_CLOCK_GETTIME_C)
  set(CLOCK_GETTIME_LIB rt)
endif()

include (TestBigEndian)
TEST_BIG_ENDIAN(IS_BIG_ENDIAN)
if(IS_BIG_ENDIAN)
 message(STATUS "BIG_ENDIAN")
else()
 message(STATUS "LITTLE_ENDIAN")
 add_definitions(-DL_ENDIAN)
endif()

check_c_source_runs("
  #ifdef _MSC_VER
  # include <intrin.h>
  #else
  # include <x86intrin.h>
  #endif
  int main(void) {
    unsigned long long x = -1, y = 1, r;
    unsigned char cf;
    cf = _addcarry_u64(1, x, y, &r);
    return !(cf == 1 && r == 1);
  }
  " ADDCARRY_U64)
if (ADDCARRY_U64)
  add_definitions(-DHAVE_ADDCARRY_U64)
endif()

check_c_source_runs("
  int main(void) {
    char buf[16] = { 0, 1, 2 };
    int *p = buf + 1;
    int *q = buf + 2;
    return (*p == *q);
  }
  " RELAXED_ALIGNMENT)
if (NOT RELAXED_ALIGNMENT)
  add_definitions(-DSTRICT_ALIGNMENT)
endif()

set(BIN_DIRECTORY bin)

# Same soversion as OpenSSL
set(GOST_SOVERSION "${OPENSSL_VERSION_MAJOR}.${OPENSSL_VERSION_MINOR}")

set(OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/${BIN_DIRECTORY})

#set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${OUTPUT_DIRECTORY})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${OUTPUT_DIRECTORY})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${OUTPUT_DIRECTORY})

# Remove when https://gitlab.kitware.com/cmake/cmake/issues/18525 is addressed
set(OPENSSL_ENGINES_DIR "" CACHE PATH "OpenSSL Engines Directory")
if ("${OPENSSL_ENGINES_DIR}" STREQUAL "")
	include(FindPkgConfig)
	pkg_get_variable(OPENSSL_ENGINES_DIR libcrypto enginesdir)
	if ("${OPENSSL_ENGINES_DIR}" STREQUAL "")
		message( FATAL_ERROR "Unable to discover the OpenSSL engines directory. Provide the path using -DOPENSSL_ENGINES_DIR" )
	endif()
endif()

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
        gost_keyexpimp.c
        )

set(GOST_EC_SOURCE_FILES
        gost_ec_keyx.c
        gost_ec_sign.c
        ecp_id_GostR3410_2001_CryptoPro_A_ParamSet.c
        ecp_id_GostR3410_2001_CryptoPro_B_ParamSet.c
        ecp_id_GostR3410_2001_CryptoPro_C_ParamSet.c
        ecp_id_GostR3410_2001_TestParamSet.c
        ecp_id_tc26_gost_3410_2012_256_paramSetA.c
        ecp_id_tc26_gost_3410_2012_512_paramSetA.c
        ecp_id_tc26_gost_3410_2012_512_paramSetB.c
        ecp_id_tc26_gost_3410_2012_512_paramSetC.c
        )

set (GOST_OMAC_SOURCE_FILES
        gost_omac.c
        gost_omac_acpkm.c
        )

set(GOST_LIB_SOURCE_FILES
        ${GOST_89_SOURCE_FILES}
        ${GOST_HASH_SOURCE_FILES}
        ${GOST_HASH_2012_SOURCE_FILES}
        ${GOST_GRASSHOPPER_SOURCE_FILES}
        ${GOST_EC_SOURCE_FILES}
        ${GOST_OMAC_SOURCE_FILES}
        )

set(GOST_ENGINE_SOURCE_FILES
        ${GOST_CORE_SOURCE_FILES}
        gost_ameth.c
        gost_md.c
        gost_md2012.c
        gost_pmeth.c
        gost_omac.c
        gost_omac_acpkm.c
        gost_gost2015.c
        )

add_executable(test_digest test_digest.c)
target_link_libraries(test_digest gost_engine gost_core ${OPENSSL_CRYPTO_LIBRARY})
add_test(NAME digest
	COMMAND test_digest)

add_executable(test_ciphers test_ciphers.c)
target_link_libraries(test_ciphers gost_engine gost_core ${OPENSSL_CRYPTO_LIBRARY})
add_test(NAME ciphers
	COMMAND test_ciphers)

add_executable(test_curves test_curves.c)
target_link_libraries(test_curves gost_engine gost_core ${OPENSSL_CRYPTO_LIBRARY})
add_test(NAME curves
	COMMAND test_curves)

add_executable(test_params test_params.c)
target_link_libraries(test_params gost_engine gost_core ${OPENSSL_CRYPTO_LIBRARY})
add_test(NAME parameters
	COMMAND test_params)

add_executable(test_derive test_derive.c)
target_link_libraries(test_derive gost_engine gost_core ${OPENSSL_CRYPTO_LIBRARY})
add_test(NAME derive
	COMMAND test_derive)

add_executable(test_sign test_sign.c)
target_link_libraries(test_sign gost_engine gost_core ${OPENSSL_CRYPTO_LIBRARY})
add_test(NAME sign/verify
	COMMAND test_sign)

add_executable(test_tls test_tls.c)
target_link_libraries(test_tls gost_engine gost_core ${OPENSSL_CRYPTO_LIBRARY} ${OPENSSL_SSL_LIBRARY})
add_test(NAME TLS
	COMMAND test_tls)

add_executable(test_context test_context.c)
target_link_libraries(test_context gost_engine gost_core ${OPENSSL_CRYPTO_LIBRARY})
add_test(NAME context
	COMMAND test_context)

add_executable(test_keyexpimp test_keyexpimp.c)
#target_compile_definitions(test_keyexpimp PUBLIC -DOPENSSL_LOAD_CONF)
target_link_libraries(test_keyexpimp gost_engine gost_core ${OPENSSL_CRYPTO_LIBRARY})
add_test(NAME keyexpimp
	COMMAND test_keyexpimp)

add_executable(test_gost89 test_gost89.c)
target_link_libraries(test_gost89 gost_engine gost_core ${OPENSSL_CRYPTO_LIBRARY})
add_test(NAME gost89
	COMMAND test_gost89)

if(NOT SKIP_PERL_TESTS)
    execute_process(COMMAND perl -MTest2::V0 -e ""
	ERROR_QUIET RESULT_VARIABLE HAVE_TEST2_V0)
    if(NOT HAVE_TEST2_V0)
	add_test(NAME engine
	    COMMAND perl run_tests
	    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/test)
	set_tests_properties(engine PROPERTIES ENVIRONMENT
	    "OPENSSL_ROOT_DIR=${OPENSSL_ROOT_DIR};OPENSSL_ENGINES=${OUTPUT_DIRECTORY};OPENSSL_CONF=${CMAKE_SOURCE_DIR}/test/empty.cnf")
    else()
      message(STATUS "No Test2::V0 perl module (engine tests skipped)")
    endif()
endif()

add_executable(sign benchmark/sign.c)
target_link_libraries(sign gost_engine gost_core ${OPENSSL_CRYPTO_LIBRARY} ${CLOCK_GETTIME_LIB})

# All that may need to load just built engine will have path to it defined.
set(BINARY_TESTS_TARGETS
        test_digest
        test_ciphers
        test_curves
        test_params
        test_derive
        test_sign
        test_context
        test_keyexpimp
        test_gost89
	test_tls
        )
set_property(TARGET ${BINARY_TESTS_TARGETS} APPEND PROPERTY COMPILE_DEFINITIONS ENGINE_DIR="${OUTPUT_DIRECTORY}")

add_library(gost_core STATIC ${GOST_LIB_SOURCE_FILES})
set_target_properties(gost_core PROPERTIES POSITION_INDEPENDENT_CODE ON)

add_library(gost_engine SHARED ${GOST_ENGINE_SOURCE_FILES})
set_target_properties(gost_engine PROPERTIES PREFIX "" OUTPUT_NAME "gost")
set_target_properties(gost_engine PROPERTIES VERSION ${GOST_SOVERSION} SOVERSION ${GOST_SOVERSION})
target_link_libraries(gost_engine gost_core ${OPENSSL_CRYPTO_LIBRARY})

set(GOST_SUM_SOURCE_FILES
        gostsum.c
        )

add_executable(gostsum ${GOST_SUM_SOURCE_FILES})
target_link_libraries(gostsum gost_core ${OPENSSL_CRYPTO_LIBRARY})

set(GOST_12_SUM_SOURCE_FILES
        gost12sum.c
        )

add_executable(gost12sum ${GOST_12_SUM_SOURCE_FILES})
target_link_libraries(gost12sum gost_core)

set_source_files_properties(tags PROPERTIES GENERATED true)
add_custom_target(tags
    COMMAND ctags -R . ${OPENSSL_ROOT_DIR}
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})

add_custom_target(tcl_tests
    COMMAND ENGINE_DIR=${OUTPUT_DIRECTORY} sh ./runtest.sh
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/tcl_tests)

add_executable(test_tlstree test_tlstree.c)
target_link_libraries(test_tlstree PUBLIC ${OPENSSL_CRYPTO_LIBRARY})

# install
set(OPENSSL_MAN_INSTALL_DIR ${CMAKE_INSTALL_MANDIR}/man1)

install(TARGETS gost_engine gostsum gost12sum EXPORT GostEngineConfig
        LIBRARY  DESTINATION ${OPENSSL_ENGINES_DIR}
        RUNTIME  DESTINATION ${CMAKE_INSTALL_BINDIR})
install(FILES gostsum.1 gost12sum.1 DESTINATION ${OPENSSL_MAN_INSTALL_DIR})
if (MSVC)
 install(FILES $<TARGET_PDB_FILE:gost_engine> DESTINATION ${OPENSSL_ENGINES_DIR} OPTIONAL)
 install(FILES $<TARGET_PDB_FILE:gostsum> $<TARGET_PDB_FILE:gost12sum> DESTINATION ${CMAKE_INSTALL_BINDIR} OPTIONAL)
endif()
