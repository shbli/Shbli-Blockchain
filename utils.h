#ifndef UTILS_H
#define UTILS_H

#include <iostream>
#include <string>
#include <sstream>
#include <openssl/sha.h>
#include <openssl/bn.h>
#include <openssl/ecdsa.h>
#include <openssl/rand.h>
#include <openssl/obj_mac.h>
#include <openssl/ripemd.h>
#include <iomanip>
#include <QByteArray>
#include <QCryptographicHash>
#include "limits.h"

using namespace std;


// Generate a private key from just the secret parameter
int EC_KEY_regenerate_key(EC_KEY *eckey, BIGNUM *priv_key)
{
    int ok = 0;
    BN_CTX *ctx = NULL;
    EC_POINT *pub_key = NULL;

    if (!eckey) return 0;

    const EC_GROUP *group = EC_KEY_get0_group(eckey);

    if ((ctx = BN_CTX_new()) == NULL)
        goto err;

    pub_key = EC_POINT_new(group);

    if (pub_key == NULL)
        goto err;

    if (!EC_POINT_mul(group, pub_key, priv_key, NULL, NULL, ctx))
        goto err;

    EC_KEY_set_private_key(eckey,priv_key);
    EC_KEY_set_public_key(eckey,pub_key);

    ok = 1;

err:

    if (pub_key)
        EC_POINT_free(pub_key);
    if (ctx != NULL)
        BN_CTX_free(ctx);

    return(ok);
}

QByteArray SHA256(QByteArray input) {
    return QCryptographicHash::hash(input, QCryptographicHash::Sha256);
}

QByteArray RIPEMD160(QByteArray input) {
    unsigned char digest[RIPEMD160_DIGEST_LENGTH];

    RIPEMD160_CTX ctx;
    RIPEMD160_Init(&ctx);
    RIPEMD160_Update(&ctx, input.data(), input.size());
    RIPEMD160_Final(digest, &ctx);

    return QByteArray::fromRawData((char*)digest, RIPEMD160_DIGEST_LENGTH);
}


#endif // UTILS_H
