Building and Installation
=========================

How to Build
------------

To build and install OpenSSL GOST Engine, you will need

* OpenSSL 1.1.*
* an ANSI C compiler
* CMake (2.8 or newer)

Here is a quick build guide:

    $ mkdir build
    $ cd build
    $ cmake ..
    $ make

You will find built binaries in `../bin` directory.

If you want to build against a specific OpenSSL instance (you will need it
if you have more than one OpenSSL instance for example), you can use
the `cmake` variable `CMAKE_C_FLAGS` to specify path to include files and
shared libraries of the desirable OpenSSL instance

    $ cmake -DCMAKE_C_FLAGS='-I/PATH/TO/OPENSSL/include -L/PATH/TO/OPENSSL/lib' ..

If you use Visual Studio, see READMEWIN.txt for details.

How to Install
--------------

For now OpenSSL GOST Engine does not have an installation script, so you have to
do it manually.

Copy `gostsum` and `gost12sum` binaries to your binary directory. For example
`/usr/local/bin`:

    # cd ../bin
    # cp gostsum gost12sum /usr/local/bin

Then, if you like to install man files properly, you can do it as follows:

    # cd ..
    # mkdir -p /usr/local/man/man1
    # cp gost12sum.1 gostsum.1 /usr/local/man/man1

The engine library `gost.so` should be installed into OpenSSL engine directory.
Use the following command to get its name:

    $ openssl version -e
    ENGINESDIR: "/usr/lib/i386-linux-gnu/engines-1.1"

Then simply copy `gost.so` there

    # cp bin/gost.so /usr/lib/i386-linux-gnu/engines-1.1


Finally, to start using GOST Engine through OpenSSL, you should edit
`openssl.cnf` configuration file as specified below.


How to Configure
----------------

The very minimal example of the configuration file is provided in this
distribution and named `example.conf`.

Configuration file should include following statement in the global
section, i.e. before first bracketed section header (see config(5) for details)

    openssl_conf = openssl_def

where `openssl_def` is name of the section in configuration file which
describes global defaults.

This section should contain following statement:

    [openssl_def]
    engines = engine_section

which points to the section which describes list of the engines to be
loaded. This section should contain:

    [engine_section]
    gost = gost_section

And section which describes configuration of the engine should contain

    [gost_section]
    engine_id = gost
    dynamic_path = /usr/lib/ssl/engines/libgost.so
    default_algorithms = ALL
    CRYPT_PARAMS = id-Gost28147-89-CryptoPro-A-ParamSet

BouncyCastle cryptoprovider has some problems with private key parsing from
PrivateKeyInfo, so if you want to use old private key representation format,
which supported by BC, you must add:

    PK_PARAMS = LEGACY_PK_WRAP

to `[gost_section]`.

Where `engine_id` parameter specifies name of engine (should be `gost`).

`dynamic_path is` a location of the loadable shared library implementing the
engine. If the engine is compiled statically or is located in the OpenSSL
engines directory, this line can be omitted.

`default_algorithms` parameter specifies that all algorithms, provided by
engine, should be used.

The `CRYPT_PARAMS` parameter is engine-specific. It allows the user to choose
between different parameter sets of symmetric cipher algorithm. [RFC 4357][1]
specifies several parameters for the GOST 28147-89 algorithm, but OpenSSL
doesn't provide user interface to choose one when encrypting. So use engine
configuration parameter instead.

Value of this parameter can be either short name, defined in OpenSSL
`obj_dat.h` header file or numeric representation of OID, defined in
[RFC 4357][1].

[1]:https://tools.ietf.org/html/rfc4357 "RFC 4357"
