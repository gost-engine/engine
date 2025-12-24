# engine

A reference implementation of the Russian GOST crypto algorithms for OpenSSL

Compatibility: OpenSSL 3.0 and later

License: same as the corresponding version of OpenSSL.

Mailing list: http://www.wagner.pp.ru/list-archives/openssl-gost/

Some useful links: https://www.altlinux.org/OSS-GOST-Crypto

DO NOT TRY BUILDING MASTER BRANCH AGAINST openssl 1.1.1! Use 1_1_1 branch instead!

## Building for OpenSSL 3.x

By default, both the GOST engine and provider are built. You can control this using CMake options:

- `GOST_ENGINE_ENABLE` - Build the GOST engine (default: ON for OpenSSL 3.x, OFF for OpenSSL 4.x)
- `GOST_PROVIDER_ENABLE` - Build the GOST provider (default: ON)

### Building both Engine and Provider (OpenSSL 3.x)

```bash
cmake -DCMAKE_BUILD_TYPE=Release ..
cmake --build . --config Release
```

### Building only the Provider (for OpenSSL 4.x compatibility)

Since OpenSSL 4.x removed the Engine API, use this configuration:

```bash
cmake -DCMAKE_BUILD_TYPE=Release -DGOST_ENGINE_ENABLE=OFF ..
cmake --build . --config Release
```

### Building only the Engine (OpenSSL 3.x)

```bash
cmake -DCMAKE_BUILD_TYPE=Release -DGOST_PROVIDER_ENABLE=OFF ..
cmake --build . --config Release
```

The build system will automatically detect if the Engine API is available in your OpenSSL version.

# provider

A reference implementation in the same spirit as the engine, specified
above.

This is currently work in progress, with only a subset of all intended
functionality implemented: symmetric ciphers, hashes and MACs.

For more information, see [README.prov.md](README.prov.md)
