# GOST provider

The GOST provider is currently built in parallell with the GOST
engine, and is implemented like a wrapper around the engine code.

## Currently implemented

Symmetric ciphers:

-   gost89
-   gost89-cnt
-   gost89-cnt-12
-   gost89-cbc
-   kuznyechik-ecb
-   kuznyechik-cbc
-   kuznyechik-cfb
-   kuznyechik-ofb
-   kuznyechik-ctr
-   magma-cbc
-   magma-ctr
-   magma-ctr-acpkm
-   magma-ctr-acpkm-omac
-   kuznyechik-ctr-acpkm
-   kuznyechik-ctr-acpkm-omac

Hashes:

-   id-tc26-gost3411-12-256 (md_gost12_256)
-   id-tc26-gost3411-12-512 (md_gost12_512)
-   id-GostR3411-94 (md_gost94)

MACs:

-   gost-mac
-   gost-mac-12
-   magma-mac
-   kuznyechik-mac
-   kuznyechik-ctr-acpkm-omac

Keymgmt:

- id-GostR3410-2001 ("GOST R 34.10-2001", "1.2.643.2.2.19")
- id-GostR3410-2001DH ("GOST R 34.10-2001 DH", "1.2.643.2.2.98")
- gost2012_256 ("GOST R 34.10-2012 with 256 bit modulus", "1.2.643.7.1.1.1.1")
- gost2012_512 ("GOST R 34.10-2012 with 512 bit modulus", "1.2.643.7.1.1.1.2")

Encoder:
- id-GostR3410-2001 ("GOST R 34.10-2001", "1.2.643.2.2.19") with structure format = pem/der/text
- id-GostR3410-2001DH ("GOST R 34.10-2001 DH", "1.2.643.2.2.98") with structure format = pem/der/text
- gost2012_256 ("GOST R 34.10-2012 with 256 bit modulus", "1.2.643.7.1.1.1.1") with structure format = pem/der/text
- gost2012_512 ("GOST R 34.10-2012 with 512 bit modulus", "1.2.643.7.1.1.1.2") with structure format = pem/der/text

PrivateKeyInfo can only be saved in pkcs8 format without encryption.

Decoder:
- id-GostR3410-2001 ("GOST R 34.10-2001", "1.2.643.2.2.19") with structure format = der
- id-GostR3410-2001DH ("GOST R 34.10-2001 DH", "1.2.643.2.2.98") with structure format = der
- gost2012_256 ("GOST R 34.10-2012 with 256 bit modulus", "1.2.643.7.1.1.1.1") with structure format = der
- gost2012_512 ("GOST R 34.10-2012 with 512 bit modulus", "1.2.643.7.1.1.1.2") with structure format = der

pem2der decoder already implemented by OpenSSL default provider.

PrivateKeyInfo can only be loaded in pkcs8 format without decryption.

Signature:
- SN_id_GostR3410_2001, "id-GostR3411-94-with-GostR3410-2001", "GOST R 34.11-94 with GOST R 34.10-2001", "1.2.643.2.2.3"
- SN_id_GostR3410_2012_256, "id-tc26-signwithdigest-gost3410-2012-256", "GOST R 34.10-2012 with GOST R 34.11-2012 (256 bit)", "1.2.643.7.1.1.3.2"
- gost2012_256, "id-tc26-signwithdigest-gost3410-2012-512", "GOST R 34.10-2012 with GOST R 34.11-2012 (512 bit)", "1.2.643.7.1.1.3.3"

Keyexchange:
- ECDHE

TLS1.3:
- OpenSSL patch has been implemented that allows to connect TLS1.3 using a provider.

## TODO, not requiring additional OpenSSL support

-   Support for these operations using GOST keys:
    -   ASYM_CIPHER (encryption and decryption using GOST keys)
    
## TODO, which requires additional OpenSSL support

-   PKCS7 and CMS support.  This requires OpenSSL PKCS7 and CMS code
    to change for better interfacing with providers.

## TODO, far future

-   Refactor the code into being just a provider.  This is to be done
    when engines aren't supported any more.
