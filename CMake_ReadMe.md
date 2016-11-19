## CMake Config

Required variables:
1. `OPENSSL_PATH` - full path to local [openssl](https://github.com/openssl/openssl) source tree

For Example:

~~~bash
cmake -DOPENSSL_PATH=/home/user/openssl .
~~~

Build Example:

~~~bash
cd ~/gost-engine
mkdir build
cd build
cmake -DOPENSSL_PATH=/home/user/openssl ..
make -j 8
cd ../bin
~~~
