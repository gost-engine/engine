It can be build via Visual Studio.

1. Clone repository
C:
cd /projects/openssl/out32
git clone git@github.com:gost-engine/engine.git

2. Add to CMakeLists.txt references to OpenSSL

 include_directories("C:/projects/openssl/out32/openssl-x86-shared-release-vs2015/include")

link_libraries("C:/projects/openssl/out32/openssl-x86-shared-release-vs2015/lib/libcrypto.lib", "C:/projects/openssl/out32/openssl-x86-shared-release-vs2015/lib/libssl.lib")

3. At CMakeLists.txt replace rows

add_library(gost STATIC ${GOST_LIB_SOURCE_FILES})
set_target_properties(gost PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_link_libraries(gost_engine gost)
target_link_libraries(gost12sum gost)
target_link_libraries(gostsum gost)

with

add_library(libgost STATIC ${GOST_LIB_SOURCE_FILES})
set_target_properties(libgost PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_link_libraries(gost_engine libgost)
target_link_libraries(gost12sum libgost)
target_link_libraries(gostsum libgost)

4. Generate project for Visual Studio 14 (2015)

cd /projects/openssl/tmp32
mkdir engine
cd engine
cmake -G "Visual Studio 14" --build /projects/openssl/out32/engine
In gost_engine.vcxproj replace
;,.lib; to ;

5. Open solution ccgost.sln into Visual Studio, select configuration Release and build solution.

6. Use C:\projects\openssl\out32\engine\bin\Release\gost.dll


