cmake_minimum_required(VERSION 3.18 FATAL_ERROR)
project(gost-engine LANGUAGES C)

include(GNUInstallDirs)
include(CheckLibraryExists)
include(CheckFunctionExists)
include(CheckCSourceRuns)
include(CheckCSourceCompiles)

find_package(OpenSSL 3.4 REQUIRED)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  message(STATUS "Setting build type to 'RelWithDebInfo' as none was specified.")
  set(CMAKE_BUILD_TYPE "RelWithDebInfo" CACHE STRING "Choose the type of build." FORCE)
endif()

if (NOT DEFINED OPENSSL_ROOT_DIR)
  get_filename_component(OPENSSL_ROOT_DIR ${OPENSSL_INCLUDE_DIR} DIRECTORY)
  message(STATUS "Setting OpenSSL root: ${OPENSSL_ROOT_DIR}")
endif()
find_program(OPENSSL_PROGRAM openssl
  PATHS ${OPENSSL_ROOT_DIR} PATH_SUFFIXES apps bin NO_DEFAULT_PATH)
message(STATUS "Found OpenSSL application: ${OPENSSL_PROGRAM}")
include_directories(${OPENSSL_INCLUDE_DIR})
set(OPENSSL_MODULES_DIR ${CMAKE_INSTALL_LIBDIR}/ossl-modules)

include("cmake/utils.cmake")
check_have_engine_api(HAVE_ENGINE_API)

option(GOST_BUILD_ENGINE   "Build gost engine module"   ${HAVE_ENGINE_API})
option(GOST_BUILD_PROVIDER "Build gost provider module" ON)

if(GOST_BUILD_ENGINE AND NOT HAVE_ENGINE_API)
  message(FATAL_ERROR
    "GOST_BUILD_ENGINE=ON, but libcrypto has no ENGINE API. "
    "Rebuild OpenSSL without no-engine, or pass -DGOST_BUILD_ENGINE=OFF.")
endif()

if(NOT GOST_BUILD_ENGINE)
  # We may depend on ENGINE API only if there is an engine target
  add_compile_definitions(OPENSSL_NO_ENGINE)
  set(HAVE_ENGINE_API FALSE)
endif()

add_compile_definitions(HAVE_ENGINE=$<BOOL:${HAVE_ENGINE_API}>)

if (CMAKE_C_COMPILER_ID MATCHES "Clang")
  set(CMAKE_C_FLAGS_RELEASE -O2)
  set(CMAKE_C_FLAGS_DEBUG "-O0 -ggdb")
  set(CMAKE_C_FLAGS_RELWITHDEBINFO "-O2 -ggdb")
  add_compile_options(-Werror -Wall -Wno-unused-parameter -Wno-unused-function -Wno-missing-braces -Qunused-arguments -Wno-deprecated-declarations -Wno-error=\#warnings)
elseif(CMAKE_C_COMPILER_ID MATCHES "GNU")
  set(CMAKE_C_FLAGS_RELEASE -O2)
  set(CMAKE_C_FLAGS_DEBUG "-O0 -ggdb")
  set(CMAKE_C_FLAGS_RELWITHDEBINFO "-O2 -ggdb")
  add_compile_options(-Werror -Wall -Wno-unused-parameter -Wno-unused-function -Wno-missing-braces -Wno-error=unknown-pragmas -Wno-error=pragmas -Wno-deprecated-declarations -Wno-error=cpp)
elseif(CMAKE_C_COMPILER_ID MATCHES "MSVC")
  add_definitions(-D_CRT_SECURE_NO_WARNINGS)
  add_definitions(-D_CRT_DEPRECATED_NO_WARNINGS)
  add_definitions(-D_CRT_NONSTDC_NO_WARNINGS)
  add_compile_options(/MP /WX /W4 /wd4100 /wd4267 /wd4206 /wd4706 /wd4244 /wd4115 /wd4996)
endif()

if (ASAN)
  message(STATUS "address sanitizer enabled")
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=address -g3 -fno-omit-frame-pointer")
  set(SKIP_PERL_TESTS 1)
endif()

if (CMAKE_SYSTEM_NAME STREQUAL "Windows")
  set(SKIP_PERL_TESTS 1)
endif()

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
    int *p = (int *)(buf + 1);
    int *q = (int *)(buf + 2);
    return (*p == *q);
  }
  " RELAXED_ALIGNMENT)
if (NOT RELAXED_ALIGNMENT)
  add_definitions(-DSTRICT_ALIGNMENT)
endif()

if(MSVC)
  set(BIN_DIRECTORY bin/$<CONFIG>/)
else()
  set(BIN_DIRECTORY bin)
endif()

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

set(GOST_TLS12_ADDITIONAL_SOURCE_FILES
        gost_tls12_additional_kdftree.c
        gost_tls12_additional_kexpimp.c
        gost_tls12_additional_tlstree.c
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

set(GOST_ERR_SOURCE_FILES
        e_gost_err.c
        e_gost_err.h
        )

set(GOST_CORE_SOURCE_FILES
        gost_ameth.c
        gost_pmeth.c
        gost_ctl.c
        gost_asn1.c
        gost_crypt.c
        gost_keywrap.c
        gost_keywrap.h
        gost_md.c
        gost_md2012.c
        gost_omac.c
        gost_omac_acpkm.c
        gost_gost2015.c
        gost_lcl.h
        gost_params.c
        gost_keyexpimp.c
        gost_digest.c
        gost_digest_ctx.c
        gost_cipher.c
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
        ${GOST_CORE_SOURCE_FILES}
        ${GOST_GRASSHOPPER_SOURCE_FILES}
        ${GOST_EC_SOURCE_FILES}
        ${GOST_OMAC_SOURCE_FILES}
        )

add_library(gost89 STATIC ${GOST_89_SOURCE_FILES})
set_target_properties(gost89 PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_link_libraries(gost89 PRIVATE OpenSSL::Crypto)

add_library(gosthash STATIC ${GOST_HASH_SOURCE_FILES})
set_target_properties(gosthash PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_link_libraries(gosthash PRIVATE OpenSSL::Crypto gost89)

add_library(gosthash2012 STATIC ${GOST_HASH_2012_SOURCE_FILES})
set_target_properties(gosthash2012 PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_link_libraries(gosthash2012 PRIVATE OpenSSL::Crypto)

add_library(gosttls12additional STATIC ${GOST_TLS12_ADDITIONAL_SOURCE_FILES})
set_target_properties(gosttls12additional PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_link_libraries(gosttls12additional PRIVATE OpenSSL::Crypto gost_err)

add_library(gost_core STATIC ${GOST_LIB_SOURCE_FILES})
set_target_properties(gost_core PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_link_libraries(gost_core PRIVATE OpenSSL::Crypto gost89 gosthash gosthash2012 gosttls12additional)

add_library(gost_core_additional_for_unittests STATIC gost_cipher_ctx.c)
set_target_properties(gost_core_additional_for_unittests PROPERTIES POSITION_INDEPENDENT_CODE ON)

add_library(gost_err STATIC ${GOST_ERR_SOURCE_FILES})
set_target_properties(gost_err PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_link_libraries(gost_err PRIVATE OpenSSL::Crypto)

set(GOST_SUM_SOURCE_FILES
        gostsum.c
        )

add_executable(gostsum ${GOST_SUM_SOURCE_FILES})
target_link_libraries(gostsum gost89 gosthash)

set(GOST_12_SUM_SOURCE_FILES
        gost12sum.c
        )

add_executable(gost12sum ${GOST_12_SUM_SOURCE_FILES})
target_link_libraries(gost12sum gosthash2012)

set_source_files_properties(tags PROPERTIES GENERATED true)
add_custom_target(tags
    COMMAND ctags -R . ${OPENSSL_ROOT_DIR}
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})

list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)
if(GOST_BUILD_ENGINE)
  include(engine)
endif()
if(GOST_BUILD_PROVIDER)
  include(provider)
endif()
include(tests)

if(NOT MSVC)
  add_executable(sign benchmark/sign.c)
  target_link_libraries(sign gost_core gost_core_additional_for_unittests gost_err ${CLOCK_GETTIME_LIB})
endif()

# install programs and manuals
install(TARGETS gostsum gost12sum RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(FILES gostsum.1 gost12sum.1 DESTINATION ${CMAKE_INSTALL_MANDIR}/man1)
