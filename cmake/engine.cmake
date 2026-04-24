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

# The GOST engine in module form
add_library(gost_engine MODULE ${GOST_ENGINE_SOURCE_FILES})
# Set the suffix explicitly to adapt to OpenSSL's idea of what a
# module suffix should be
set_target_properties(gost_engine PROPERTIES
PREFIX "" OUTPUT_NAME "gost" SUFFIX ${CMAKE_SHARED_LIBRARY_SUFFIX})
target_link_libraries(gost_engine PRIVATE gost_core gost_err)

if (NOT MSVC)
  # The GOST engine in library form
  add_library(lib_gost_engine SHARED ${GOST_ENGINE_SOURCE_FILES})
  set_target_properties(lib_gost_engine PROPERTIES
  COMPILE_DEFINITIONS "BUILDING_ENGINE_AS_LIBRARY"
  PUBLIC_HEADER gost-engine.h
  OUTPUT_NAME "gost")
  target_link_libraries(lib_gost_engine PRIVATE gost_core gost_err)
endif()

install(TARGETS gost_engine EXPORT GostEngineConfig
        LIBRARY  DESTINATION ${OPENSSL_ENGINES_DIR}
        RUNTIME  DESTINATION ${OPENSSL_ENGINES_DIR})

if (NOT MSVC)
  install(TARGETS lib_gost_engine EXPORT GostEngineConfig
          LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR})
endif()

if (MSVC)
  install(FILES $<TARGET_PDB_FILE:gostsum> $<TARGET_PDB_FILE:gost12sum>
    EXPORT GostEngineConfig DESTINATION ${CMAKE_INSTALL_BINDIR} OPTIONAL)
  install(FILES $<TARGET_PDB_FILE:gost_engine>
    EXPORT GostEngineConfig DESTINATION ${OPENSSL_ENGINES_DIR} OPTIONAL)
endif()

install(EXPORT GostEngineConfig DESTINATION share/cmake/GostEngine)
