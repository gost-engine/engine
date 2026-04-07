set(GOST_PROV_SOURCE_FILES
        gost_prov.c
        gost_prov.h
        gost_prov_cipher.c
        gost_prov_digest.c
        gost_prov_mac.c
        gost_prov_keymgmt.c
        gost_prov_encoder.c
        gost_prov_signature.c
        gost_prov_decoder.c
        gost_prov_keyexch.c
        gost_prov_tls.c
        gost_prov_tls.h
        gost_cipher_ctx.c
        )

# The GOST provider uses this
add_subdirectory(libprov)

# The GOST provider in module form
add_library(gost_prov MODULE
  ${GOST_PROV_SOURCE_FILES}
)
set_target_properties(gost_prov PROPERTIES
  PREFIX "" OUTPUT_NAME "gostprov" SUFFIX ${CMAKE_SHARED_LIBRARY_SUFFIX}
  COMPILE_DEFINITIONS "BUILDING_GOST_PROVIDER;OPENSSL_NO_DYNAMIC_ENGINE"
  )
target_link_libraries(gost_prov PRIVATE gost_core libprov)

if (NOT MSVC)
  # The GOST provider in library form
  add_library(lib_gost_prov SHARED
    ${GOST_PROV_SOURCE_FILES}
  )
  set_target_properties(lib_gost_prov PROPERTIES
    OUTPUT_NAME "gostprov"
    COMPILE_DEFINITIONS "BUILDING_GOST_PROVIDER;BUILDING_PROVIDER_AS_LIBRARY;OPENSSL_NO_DYNAMIC_ENGINE"
    )
  target_link_libraries(lib_gost_prov PRIVATE gost_core libprov)
endif()

install(TARGETS gost_prov EXPORT GostProviderConfig
        LIBRARY  DESTINATION ${OPENSSL_MODULES_DIR}
        RUNTIME  DESTINATION ${OPENSSL_MODULES_DIR})

if (NOT MSVC)
  install(TARGETS lib_gost_prov EXPORT GostProviderConfig
          LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR})
endif()

if (MSVC)
  install(FILES $<TARGET_PDB_FILE:gost_prov>
      EXPORT GostProviderConfig DESTINATION ${OPENSSL_MODULES_DIR} OPTIONAL)
endif()

install(EXPORT GostProviderConfig DESTINATION share/cmake/GostProvider)
