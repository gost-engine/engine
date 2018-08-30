#include <string.h>
#include <openssl/evp.h>

#include "gost_lcl.h"
#include "e_gost_err.h"

/*
 * Function expects that out is a preallocated buffer of length
 * defined as sum of shared_len and mac length defined by mac_nid
 * */
int gost_kexp15(const unsigned char *shared_key, const int shared_len, 
    int cipher_nid, const unsigned char *cipher_key, const size_t cipher_key_len,
    int mac_nid, unsigned char *mac_key, const size_t mac_key_len,
    const char *iv, const size_t ivlen, 
    unsigned char *out, int *out_len
)
{
  /* out_len = key_len + mac_len */
  unsigned char iv_full[16], mac_buf[8];
  unsigned int mac_len;

  EVP_CIPHER_CTX *ciph = NULL;
  EVP_MD_CTX *mac = NULL;

	int ret = 0;

	/* we expect IV of half length */
  memset(iv_full, 0, 16);
  memcpy(iv_full, iv, ivlen);

  mac = EVP_MD_CTX_new();
	if (mac == NULL) {
		GOSTerr(GOST_F_GOST_KEXP15, ERR_R_MALLOC_FAILURE);
		goto err;
	}

  if(EVP_DigestInit_ex(mac, EVP_get_digestbynid(mac_nid), NULL) <= 0 
	|| EVP_MD_CTX_ctrl(mac, EVP_MD_CTRL_SET_KEY, mac_key_len, mac_key) <= 0
  || EVP_DigestUpdate(mac, shared_key, shared_len) <= 0
  || EVP_DigestFinal_ex(mac, mac_buf, &mac_len) <= 0) {
		GOSTerr(GOST_F_GOST_KEXP15, ERR_R_INTERNAL_ERROR);
		goto err;
	}

  ciph = EVP_CIPHER_CTX_new();
	if (ciph == NULL) {
		GOSTerr(GOST_F_GOST_KEXP15, ERR_R_MALLOC_FAILURE);
		goto err;
	}

  if (EVP_CipherInit_ex(ciph, EVP_get_cipherbynid(cipher_nid), NULL, NULL, NULL, 1) <= 0
  || EVP_CipherInit_ex(ciph, NULL, NULL, cipher_key, iv_full, 1) <= 0
  || EVP_CipherUpdate(ciph, out, out_len, shared_key, shared_len) <= 0
  || EVP_CipherFinal_ex(ciph, out, out_len) <= 0) {
		GOSTerr(GOST_F_GOST_KEXP15, ERR_R_INTERNAL_ERROR);
		goto err;
	}

	memcpy(out + *out_len, mac_buf, mac_len);
	*out_len += mac_len;

	ret = 1;

 err:
  EVP_MD_CTX_free(mac);
  EVP_CIPHER_CTX_free(ciph);

  return ret;
}

int gost_kimp15(const char *expkey, const size_t expkeylen, 
    int cipher_nid, const char *cipher_key, const size_t cipher_key_len,
    int mac_nid, const char *mac_key, const size_t mac_key_len,
    const char *iv, const size_t ivlen, 
    char *shared_key, size_t *shared_len
)
{
  return 0;
}

