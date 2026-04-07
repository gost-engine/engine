enable_testing()

set(TEST_ENVIRONMENT_COMMON
        TLS13_PATCHED_OPENSSL=${TLS13_PATCHED_OPENSSL}
        CMAKE_CURRENT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        PERL5LIB=${CMAKE_CURRENT_SOURCE_DIR}/test
        OPENSSL_PROGRAM=${OPENSSL_PROGRAM}
        OPENSSL_MODULES=${CMAKE_RUNTIME_OUTPUT_DIRECTORY}
        OPENSSL_CRYPTO_LIBRARY=${OPENSSL_CRYPTO_LIBRARY}
        )

set(TEST_ENVIRONMENT_ENGINE
        ${TEST_ENVIRONMENT_COMMON}
        OPENSSL_ENGINES=${CMAKE_RUNTIME_OUTPUT_DIRECTORY}
        OPENSSL_CONF=${CMAKE_CURRENT_SOURCE_DIR}/test/engine.cnf
        )

set(TEST_ENVIRONMENT_PROVIDER
        ${TEST_ENVIRONMENT_COMMON}
        OPENSSL_MODULES=${CMAKE_RUNTIME_OUTPUT_DIRECTORY}
        OPENSSL_CONF=${CMAKE_CURRENT_SOURCE_DIR}/test/provider.cnf
        )

# Function depends on global TEST_ENVIRONMENT_ENGINE and TEST_ENVIRONMENT_PROVIDER
function(add_integration_test)
    set(_options WITH_ENGINE WITH_PROVIDER)
    set(_oneValueArgs NAME)
    set(_multiValueArgs SOURCES LINK_LIBS)

    include(CMakeParseArguments)
    cmake_parse_arguments(_CRT "${_options}" "${_oneValueArgs}" "${_multiValueArgs}" ${ARGN})

    if(NOT _CRT_NAME)
        message(FATAL_ERROR "add_integration_test(): NAME is required")
    endif()
    if(NOT _CRT_SOURCES)
        set(_CRT_SOURCES ${_CRT_NAME}.c)
    endif()

    if(NOT _CRT_LINK_LIBS)
        set(_CRT_LINK_LIBS OpenSSL::Crypto)
    endif()

    add_executable(${_CRT_NAME} ${_CRT_SOURCES})
    target_link_libraries(${_CRT_NAME} PRIVATE ${_CRT_LINK_LIBS})

    function(_add_one_test TEST_SUFFIX ENV_VAR)
        set(TEST_NAME "${_CRT_NAME}-${TEST_SUFFIX}")
        add_test(NAME ${TEST_NAME} COMMAND ${_CRT_NAME})
        set_tests_properties(${TEST_NAME}
            PROPERTIES ENVIRONMENT "${${ENV_VAR}}")
    endfunction()

    if(_CRT_WITH_ENGINE)
        _add_one_test("with-engine" "TEST_ENVIRONMENT_ENGINE")
    endif()

    if(_CRT_WITH_PROVIDER)
        _add_one_test("with-provider" "TEST_ENVIRONMENT_PROVIDER")
    endif()
endfunction()

function(add_unit_test)
    set(_oneValueArgs NAME)
    set(_multiValueArgs SOURCES LINK_LIBS)

    include(CMakeParseArguments)
    cmake_parse_arguments(_CRT "${_options}" "${_oneValueArgs}" "${_multiValueArgs}" ${ARGN})

    if(NOT _CRT_NAME)
        message(FATAL_ERROR "add_unit_test(): NAME is required")
    endif()
    if(NOT _CRT_SOURCES)
        set(_CRT_SOURCES ${_CRT_NAME}.c)
    endif()

    if(NOT _CRT_LINK_LIBS)
        set(_CRT_LINK_LIBS OpenSSL::Crypto gost_core gost_core_additional_for_unittests)
    endif()

    add_executable(${_CRT_NAME} ${_CRT_SOURCES})
    target_link_libraries(${_CRT_NAME} PRIVATE ${_CRT_LINK_LIBS})
    add_test(NAME ${_CRT_NAME} COMMAND ${_CRT_NAME})
endfunction()

if (GOST_BUILD_ENGINE)
  set(WITH_ENGINE WITH_ENGINE)
endif()

if (GOST_BUILD_PROVIDER)
  set(WITH_PROVIDER WITH_PROVIDER)
endif()

add_integration_test(NAME test_digest ${WITH_ENGINE} ${WITH_PROVIDER})
add_integration_test(NAME test_ciphers ${WITH_ENGINE} ${WITH_PROVIDER})
add_integration_test(NAME test_params ${WITH_ENGINE})
add_integration_test(NAME test_derive ${WITH_ENGINE})
add_integration_test(NAME test_sign ${WITH_ENGINE})
add_integration_test(NAME test_tls ${WITH_ENGINE} LINK_LIBS OpenSSL::Crypto OpenSSL::SSL)
add_integration_test(NAME test_context ${WITH_ENGINE} ${WITH_PROVIDER})
# add_integration_test(NAME test_tlstree ${WITH_ENGINE} ${WITH_PROVIDER}) # TODO: https://github.com/gost-engine/engine/issues/524
add_integration_test(NAME test_tls12additional ${WITH_ENGINE} ${WITH_PROVIDER}
                     LINK_LIBS OpenSSL::Crypto gost_core gost_core_additional_for_unittests)
add_integration_test(NAME test_ecdhe ${WITH_ENGINE}
                     LINK_LIBS OpenSSL::Crypto gost_core gost_core_additional_for_unittests)

if(TLS13_PATCHED_OPENSSL)
  add_integration_test(NAME test_mgm ${WITH_ENGINE} ${WITH_PROVIDER})
  add_integration_test(NAME test_tls13handshake ${WITH_PROVIDER} LINK_LIBS OpenSSL::Crypto OpenSSL::SSL)
endif()

add_unit_test(NAME test_curves)
add_unit_test(NAME test_gost89)
add_unit_test(NAME test_gosthash)
add_unit_test(NAME test_gosthash2012)

if(NOT SKIP_PERL_TESTS)
    execute_process(COMMAND perl -MTest2::V0 -e ""
       ERROR_QUIET RESULT_VARIABLE MISSING_TEST2_V0)
    find_program(HAVE_PROVE NAMES prove)
    if(NOT MISSING_TEST2_V0 AND HAVE_PROVE)
      if (GOST_BUILD_ENGINE)
        add_test(NAME engine
            COMMAND prove --merge -PWrapOpenSSL ${CMAKE_CURRENT_SOURCE_DIR}/test :: engine)
        set_tests_properties(engine PROPERTIES ENVIRONMENT "${TEST_ENVIRONMENT_ENGINE}")
      endif()
      if (GOST_BUILD_PROVIDER)
        add_test(NAME provider
            COMMAND prove --merge -PWrapOpenSSL ${CMAKE_CURRENT_SOURCE_DIR}/test :: provider)
        set_tests_properties(provider PROPERTIES ENVIRONMENT "${TEST_ENVIRONMENT_PROVIDER}")
      endif()
    else()
      message(STATUS "No Test2::V0 perl module (engine and provider tests skipped)")
    endif()
endif()

add_custom_target(tcl_tests_provider
    COMMAND TLS13_PATCHED_OPENSSL=${TLS13_PATCHED_OPENSSL}
            OPENSSL_LIBCRYPTO=${OPENSSL_CRYPTO_LIBRARY}
            OPENSSL_APP=${OPENSSL_PROGRAM}
            TESTSRC=${CMAKE_SOURCE_DIR}/tcl_tests
            TESTDIR=${CMAKE_BINARY_DIR}/tcl_tests_provider
            OPENSSL_MODULES_DIR=${CMAKE_RUNTIME_OUTPUT_DIRECTORY}
            OPENSSL_CONF=${CMAKE_SOURCE_DIR}/tcl_tests/openssl-gost-provider.cnf
            sh ./runtest.sh
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/tcl_tests)

add_custom_target(tcl_tests_engine
  COMMAND TLS13_PATCHED_OPENSSL=${TLS13_PATCHED_OPENSSL}
          OPENSSL_LIBCRYPTO=${OPENSSL_CRYPTO_LIBRARY}
          OPENSSL_APP=${OPENSSL_PROGRAM}
          TESTSRC=${CMAKE_SOURCE_DIR}/tcl_tests
          TESTDIR=${CMAKE_BINARY_DIR}/tcl_tests
          ENGINE_DIR=${CMAKE_RUNTIME_OUTPUT_DIRECTORY}
          OPENSSL_CONF=${CMAKE_SOURCE_DIR}/tcl_tests/openssl-gost-engine.cnf
          sh ./runtest.sh
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/tcl_tests)

add_custom_target(tcl_tests)
if (GOST_BUILD_PROVIDER)
  add_dependencies(tcl_tests tcl_tests_provider)
endif()
if (GOST_BUILD_ENGINE)
  add_dependencies(tcl_tests tcl_tests_engine)
endif()
