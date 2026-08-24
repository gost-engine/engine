set(GOST_ENGINE_SOURCE_FILES
        gost_eng.c
        gost_eng_ameth.c
        gost_eng_digest.c
        gost_eng_digest_define.c
        gost_eng_cipher.c
        gost_eng_cmd.c
        gost_cipher_ctx_evp.c
        gost_eng_pmeth.c
        )

if(GOST_BUILD_ENGINE)
  # The GOST engine in module form
  add_library(gost_engine MODULE ${GOST_ENGINE_SOURCE_FILES})
  set_target_properties(gost_engine PROPERTIES
    PREFIX "" OUTPUT_NAME "gost" SUFFIX ${CMAKE_SHARED_LIBRARY_SUFFIX})
  target_link_libraries(gost_engine PRIVATE gost_core gost_err)

  if(NOT MSVC)
    # The GOST engine in shared-library form
    add_library(lib_gost_engine SHARED ${GOST_ENGINE_SOURCE_FILES})
    set_target_properties(lib_gost_engine PROPERTIES
      COMPILE_DEFINITIONS "BUILDING_ENGINE_AS_LIBRARY"
      PUBLIC_HEADER gost-engine.h
      OUTPUT_NAME "gost")
    target_link_libraries(lib_gost_engine PRIVATE gost_core gost_err)
  endif()

  install(TARGETS gost_engine EXPORT GostEngineConfig
          LIBRARY DESTINATION ${OPENSSL_ENGINES_DIR}
          RUNTIME DESTINATION ${OPENSSL_ENGINES_DIR})

  if(NOT MSVC)
    install(TARGETS lib_gost_engine EXPORT GostEngineConfig
            LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR})
  endif()
endif()

if(GOST_BUILD_STATIC_ENGINE)
  set(GOST_ENGINE_STATIC_SOURCE_FILES
      ${GOST_ENGINE_SOURCE_FILES}
      ${GOST_89_SOURCE_FILES}
      ${GOST_HASH_SOURCE_FILES}
      ${GOST_HASH_2012_SOURCE_FILES}
      ${GOST_TLS12_ADDITIONAL_SOURCE_FILES}
      ${GOST_LIB_SOURCE_FILES}
      ${GOST_ERR_SOURCE_FILES})
  list(REMOVE_DUPLICATES GOST_ENGINE_STATIC_SOURCE_FILES)

  add_library(gost_engine_static STATIC ${GOST_ENGINE_STATIC_SOURCE_FILES})
  set_target_properties(gost_engine_static PROPERTIES
    COMPILE_DEFINITIONS "BUILDING_ENGINE_AS_LIBRARY"
    OUTPUT_NAME "gost")
  target_link_libraries(gost_engine_static PUBLIC OpenSSL::Crypto)

  install(TARGETS gost_engine_static EXPORT GostEngineConfig
          ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
  install(FILES gost-engine.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
endif()

if(GOST_BUILD_ENGINE OR GOST_BUILD_STATIC_ENGINE)
  install(EXPORT GostEngineConfig DESTINATION share/cmake/GostEngine)
endif()

if(MSVC AND GOST_BUILD_ENGINE)
  install(FILES $<TARGET_PDB_FILE:gostsum> $<TARGET_PDB_FILE:gost12sum>
    EXPORT GostEngineConfig DESTINATION ${CMAKE_INSTALL_BINDIR} OPTIONAL)
  install(FILES $<TARGET_PDB_FILE:gost_engine>
    EXPORT GostEngineConfig DESTINATION ${OPENSSL_ENGINES_DIR} OPTIONAL)
endif()
