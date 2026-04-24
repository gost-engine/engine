function(check_have_engine_api out_var)
    list(APPEND CMAKE_REQUIRED_INCLUDES ${OPENSSL_INCLUDE_DIR})
    set(CMAKE_REQUIRED_LIBRARIES OpenSSL::Crypto)

    check_c_source_compiles("
        #include <openssl/engine.h>
        int main(void) {
            ENGINE *e = ENGINE_new();
            ENGINE_free(e);
            return 0;
        }
    " ${out_var})

    set(${out_var} ${${out_var}} PARENT_SCOPE)
endfunction()