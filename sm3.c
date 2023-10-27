#include <openssl/evp.h>
int sm3(const unsigned char *in, unsigned long long inlen, unsigned char *out) {
    EVP_MD_CTX *mdctx;
    mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, EVP_sm3(), NULL);
    EVP_DigestUpdate(mdctx, in, inlen);

    unsigned int md_len = 0;
    EVP_DigestFinal_ex(mdctx, out, &md_len);

    EVP_MD_CTX_free(mdctx);

    return md_len;
}