# Sample toolchain file for building for Windows from an Ubuntu Linux system.
#
# Typical usage:
#    *) install cross compiler: `sudo apt-get install mingw-w64`
#    *) cd build
#    *) cmake -DCMAKE_TOOLCHAIN_FILE=~/mingw-w64-x86_64.cmake ..

set(CMAKE_SYSTEM_NAME Windows)
if (DEFINED WIN32_TARGET_CPU)
 set(TOOLCHAIN_PREFIX ${WIN32_TARGET_CPU}-w64-mingw32)
else()
 set(TOOLCHAIN_PREFIX i686-w64-mingw32)
endif()

# cross compilers to use for C, C++ and Fortran
set(CMAKE_C_COMPILER ${TOOLCHAIN_PREFIX}-gcc)
set(CMAKE_CXX_COMPILER ${TOOLCHAIN_PREFIX}-g++)
set(CMAKE_Fortran_COMPILER ${TOOLCHAIN_PREFIX}-gfortran)
set(CMAKE_RC_COMPILER ${TOOLCHAIN_PREFIX}-windres)

set(RELAXED_ALIGNMENT_EXITCODE FALSE)
set(RELAXED_ALIGNMENT_EXITCODE__TRYRUN_OUTPUT = "gost-engine")

set(ADDCARRY_U64_EXITCODE FALSE)
set(ADDCARRY_U64_EXITCODE__TRYRUN_OUTPUT = "gost-engine")

