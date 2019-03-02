cmake_minimum_required(VERSION 3.0 FATAL_ERROR)
project(gost-engine LANGUAGES C)

include(GNUInstallDirs)
include(CheckLibraryExists)
include(CheckFunctionExists)

enable_testing()

find_package(OpenSSL 1.1.1 REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

if (CMAKE_C_COMPILER_ID MATCHES "Clang")
 add_compile_options(-O2 -Werror -Wall -Wno-unused-parameter -Wno-unused-function -Wno-missing-braces -ggdb -Qunused-arguments)
elseif(CMAKE_C_COMPILER_ID MATCHES "GNU")
 add_compile_options(-O2 -Werror -Wall -Wno-unused-parameter -Wno-unused-function -Wno-missing-braces -ggdb)
elseif(CMAKE_C_COMPILER_ID MATCHES "MSVC")
 add_definitions(-D_CRT_SECURE_NO_WARNINGS)
 add_definitions(-D_CRT_DEPRECATED_NO_WARNINGS)
 add_definitions(-D_CRT_NONSTDC_NO_WARNINGS)
 add_compile_options(/MP /WX /W4 /wd4100 /wd4267 /wd4206 /wd4706 /wd4244 /wd4115)
endif()

if (ASAN)
  message(STATUS "address sanitizer enabled")
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=address -g3 -fno-omit-frame-pointer")
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

set(BIN_DIRECTORY bin)

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
        )

add_executable(test_curves test_curves.c)
target_link_libraries(test_curves gost_engine gost_core ${OPENSSL_CRYPTO_LIBRARY})
add_test(NAME curves
	COMMAND test_curves)

add_executable(test_params test_params.c)
target_link_libraries(test_params gost_engine gost_core ${OPENSSL_CRYPTO_LIBRARY})
add_test(NAME parameters
	COMMAND test_params)

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

add_executable(test_grasshopper test_grasshopper.c)
target_link_libraries(test_grasshopper gost_engine gost_core ${OPENSSL_CRYPTO_LIBRARY})
add_test(NAME grasshopper
	COMMAND test_grasshopper)

add_executable(test_keyexpimp test_keyexpimp.c)
#target_compile_definitions(test_keyexpimp PUBLIC -DOPENSSL_LOAD_CONF)
target_link_libraries(test_keyexpimp gost_engine gost_core ${OPENSSL_CRYPTO_LIBRARY})
add_test(NAME keyexpimp
	COMMAND test_keyexpimp)

add_executable(test_gost89 test_gost89.c)
target_link_libraries(test_gost89 gost_engine gost_core ${OPENSSL_CRYPTO_LIBRARY})
add_test(NAME gost89
	COMMAND test_gost89)

if(NOT ASAN)
add_test(NAME engine
	COMMAND perl run_tests
	WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/test)
set_tests_properties(engine PROPERTIES ENVIRONMENT
	"OPENSSL_ROOT_DIR=${OPENSSL_ROOT_DIR};OPENSSL_ENGINES=${OUTPUT_DIRECTORY}")
endif()

add_executable(sign benchmark/sign.c)
target_link_libraries(sign gost_engine gost_core ${OPENSSL_CRYPTO_LIBRARY} ${CLOCK_GETTIME_LIB})

# All that may need to load just built engine will have path to it defined.
set(BINARY_TESTS_TARGETS
        test_curves
        test_params
        test_sign
        test_context
        test_grasshopper
        test_keyexpimp
        test_gost89
	test_tls
        )
set_property(TARGET ${BINARY_TESTS_TARGETS} APPEND PROPERTY COMPILE_DEFINITIONS ENGINE_DIR="${OUTPUT_DIRECTORY}")

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

set_source_files_properties(tags PROPERTIES GENERATED true)
add_custom_target(tags
    COMMAND ctags -R . ${OPENSSL_ROOT_DIR}
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})

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
