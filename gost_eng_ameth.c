#include <openssl/evp.h>
#include <openssl/objects.h>

#include "gost_ameth.h"
#include "gost_eng_ameth.h"

/* ----------------------------------------------------------------------*/
int register_ameth_gost(int nid, EVP_PKEY_ASN1_METHOD **ameth,
                        const char *pemstr, const char *info)
{
    *ameth = EVP_PKEY_asn1_new(nid, ASN1_PKEY_SIGPARAM_NULL, pemstr, info);
    if (!*ameth)
        return 0;
    switch (nid) {
    case NID_id_GostR3410_2001:
    case NID_id_GostR3410_2001DH:
        EVP_PKEY_asn1_set_free(*ameth, pkey_free_gost_ec);
        EVP_PKEY_asn1_set_private(*ameth,
                                  priv_decode_gost, priv_encode_gost,
                                  priv_print_gost_ec);

        EVP_PKEY_asn1_set_param(*ameth,
                                gost2001_param_decode, gost2001_param_encode,
                                param_missing_gost_ec, param_copy_gost_ec,
                                param_cmp_gost_ec, param_print_gost_ec);
        EVP_PKEY_asn1_set_public(*ameth,
                                 pub_decode_gost_ec, pub_encode_gost_ec,
                                 pub_cmp_gost_ec, pub_print_gost_ec,
                                 pkey_size_gost, pkey_bits_gost);

        EVP_PKEY_asn1_set_ctrl(*ameth, pkey_ctrl_gost);
        EVP_PKEY_asn1_set_security_bits(*ameth, pkey_bits_gost);
        break;
    case NID_id_GostR3410_2012_256:
    case NID_id_GostR3410_2012_512:
        EVP_PKEY_asn1_set_free(*ameth, pkey_free_gost_ec);
        EVP_PKEY_asn1_set_private(*ameth,
                                  priv_decode_gost, priv_encode_gost,
                                  priv_print_gost_ec);

        EVP_PKEY_asn1_set_param(*ameth,
                                NULL, NULL,
                                param_missing_gost_ec, param_copy_gost_ec,
                                param_cmp_gost_ec, NULL);

        EVP_PKEY_asn1_set_public(*ameth,
                                 pub_decode_gost_ec, pub_encode_gost_ec,
                                 pub_cmp_gost_ec, pub_print_gost_ec,
                                 pkey_size_gost, pkey_bits_gost);

        EVP_PKEY_asn1_set_set_pub_key(*ameth, gost_set_raw_pub_key);
        EVP_PKEY_asn1_set_get_priv_key(*ameth, gost_get_raw_priv_key);
        EVP_PKEY_asn1_set_get_pub_key(*ameth, gost_get_raw_pub_key);

        EVP_PKEY_asn1_set_ctrl(*ameth, pkey_ctrl_gost);
        EVP_PKEY_asn1_set_security_bits(*ameth, pkey_bits_gost);
        break;
    case NID_id_Gost28147_89_MAC:
        EVP_PKEY_asn1_set_free(*ameth, mackey_free_gost);
        EVP_PKEY_asn1_set_ctrl(*ameth, mac_ctrl_gost);
        break;
    case NID_gost_mac_12:
        EVP_PKEY_asn1_set_free(*ameth, mackey_free_gost);
        EVP_PKEY_asn1_set_ctrl(*ameth, mac_ctrl_gost_12);
        break;
    case NID_magma_mac:
        EVP_PKEY_asn1_set_free(*ameth, mackey_free_gost);
        EVP_PKEY_asn1_set_ctrl(*ameth, mac_ctrl_magma);
        break;
    case NID_grasshopper_mac:
        EVP_PKEY_asn1_set_free(*ameth, mackey_free_gost);
        EVP_PKEY_asn1_set_ctrl(*ameth, mac_ctrl_grasshopper);
        break;
    }
    return 1;
}
