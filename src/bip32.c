/*

 The MIT License (MIT)

 Copyright (c) 2021 libbtc

 Permission is hereby granted, free of charge, to any person obtaining
 a copy of this software and associated documentation files (the "Software"),
 to deal in the Software without restriction, including without limitation
 the rights to use, copy, modify, merge, publish, distribute, sublicense,
 and/or sell copies of the Software, and to permit persons to whom the
 Software is furnished to do so, subject to the following conditions:

 The above copyright notice and this permission notice shall be included
 in all copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES
 OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 OTHER DEALINGS IN THE SOFTWARE.

 */


#include <btc/bip32.h>

#include <btc/hash.h>
#include <btc/memory.h>

#include "trezor-crypto/bip32.h"
#include "trezor-crypto/memzero.h"
#include "trezor-crypto/secp256k1.h"

#define BTC_CURVE secp256k1_info
#define BTC_CURVE_NAME ((BTC_CURVE).bip32_name)

btc_hdnode* btc_hdnode_new()
{
    btc_hdnode* hdnode;
    hdnode = btc_calloc(1, sizeof(*hdnode));
    return hdnode;
}

btc_hdnode* btc_hdnode_copy(const btc_hdnode* hdnode)
{
    btc_hdnode* newnode = btc_hdnode_new();

    newnode->depth = hdnode->depth;
    newnode->fingerprint = hdnode->fingerprint;
    newnode->child_num = hdnode->child_num;
    memcpy(newnode->chain_code, hdnode->chain_code, sizeof(hdnode->chain_code));
    memcpy(newnode->private_key, hdnode->private_key, sizeof(hdnode->private_key));
    memcpy(newnode->public_key, hdnode->public_key, sizeof(hdnode->public_key));

    return newnode;
}

static void hdnode_to_btc(HDNode* hdnode, btc_hdnode* btc)
{
    btc->depth = hdnode->depth;
    btc->fingerprint = hdnode_fingerprint(hdnode);
    btc->child_num = hdnode->child_num;
    memcpy(btc->chain_code, hdnode->chain_code, sizeof(hdnode->chain_code));
    memcpy(btc->private_key, hdnode->private_key, sizeof(hdnode->private_key));
    memcpy(btc->public_key, hdnode->public_key, sizeof(hdnode->public_key));
}

static void btc_to_hdnode(const btc_hdnode* btc, HDNode* hdnode)
{
    hdnode->depth = btc->depth;
    hdnode->child_num = btc->child_num;
    memcpy(hdnode->chain_code, btc->chain_code, sizeof(hdnode->chain_code));
    memcpy(hdnode->private_key, btc->private_key, sizeof(hdnode->private_key));
    memcpy(hdnode->public_key, btc->public_key, sizeof(hdnode->public_key));
    hdnode->curve = &BTC_CURVE;
}

void btc_hdnode_free(btc_hdnode* hdnode)
{
    memset(hdnode->chain_code, 0, sizeof(hdnode->chain_code));
    memset(hdnode->private_key, 0, sizeof(hdnode->private_key));
    memset(hdnode->public_key, 0, sizeof(hdnode->public_key));
    btc_free(hdnode);
}

btc_bool btc_hdnode_from_seed(const uint8_t* seed, int seed_len, btc_hdnode* out)
{
    HDNode hdnode;
    int res = hdnode_from_seed(seed, seed_len, BTC_CURVE_NAME, &hdnode);
    hdnode_to_btc(&hdnode, out);
    memzero(&hdnode, sizeof(hdnode));
    return res;
}


btc_bool btc_hdnode_public_ckd(btc_hdnode* inout, uint32_t i)
{
    HDNode hdnode;
    btc_to_hdnode(inout, &hdnode);
    int res = hdnode_public_ckd(&hdnode, i);
    hdnode_to_btc(&hdnode, inout);
    memzero(&hdnode, sizeof(hdnode));
    return res;
}


btc_bool btc_hdnode_private_ckd(btc_hdnode* inout, uint32_t i)
{
    HDNode hdnode;
    btc_to_hdnode(inout, &hdnode);
    int res = hdnode_private_ckd(&hdnode, i);
    hdnode_to_btc(&hdnode, inout);
    memzero(&hdnode, sizeof(hdnode));
    return res;
}


void btc_hdnode_fill_public_key(btc_hdnode* inout)
{
    HDNode hdnode;
    btc_to_hdnode(inout, &hdnode);
    // for now, hdnode_fingerprint calls fill_public_key
    hdnode_to_btc(&hdnode, inout);
    memzero(&hdnode, sizeof(hdnode));
}


void btc_hdnode_serialize_public(const btc_hdnode* node, const btc_chainparams* chain, char* str, int strsize)
{
    HDNode hdnode;
    btc_to_hdnode(node, &hdnode);
    int res = hdnode_serialize_public(&hdnode, node->fingerprint, chain->b58prefix_bip32_pubkey, str, strsize);
    memzero(&hdnode, sizeof(hdnode));
    (void)res;
}


void btc_hdnode_serialize_private(const btc_hdnode* node, const btc_chainparams* chain, char* str, int strsize)
{
    HDNode hdnode;
    btc_to_hdnode(node, &hdnode);
    int res = hdnode_serialize_private(&hdnode, node->fingerprint, chain->b58prefix_bip32_privkey, str, strsize);
    memzero(&hdnode, sizeof(hdnode));
}


void btc_hdnode_get_hash160(const btc_hdnode* node, uint160 hash160_out)
{
    uint256 hashout;
    btc_hash_sngl_sha256(node->public_key, BTC_ECKEY_COMPRESSED_LENGTH, hashout);
    btc_ripemd160(hashout, sizeof(hashout), hash160_out);
}

void btc_hdnode_get_p2pkh_address(const btc_hdnode* node, const btc_chainparams* chain, char* str, int strsize)
{
    HDNode hdnode;
    btc_to_hdnode(node, &hdnode);
    hdnode_get_address(&hdnode, chain->b58prefix_pubkey_address, str, strsize);
    memzero(&hdnode, sizeof(hdnode));
}

btc_bool btc_hdnode_get_pub_hex(const btc_hdnode* node, char* str, size_t* strsize)
{
    btc_pubkey pubkey;
    btc_pubkey_init(&pubkey);
    memcpy(&pubkey.pubkey, node->public_key, BTC_ECKEY_COMPRESSED_LENGTH);
    pubkey.compressed = true;

    return btc_pubkey_get_hex(&pubkey, str, strsize);
}


// check for validity of curve point in case of public data not performed
btc_bool btc_hdnode_deserialize(const char* str, const btc_chainparams* chain, btc_hdnode* node)
{
    HDNode hdnode;
    int res = hdnode_deserialize(str, chain->b58prefix_bip32_pubkey, false, &hdnode, &node->fingerpint);
    if (res == -3)
        res = hdnode_deserialize(str, chain->b58prefix_bip32_privkey, true, &hdnode, &node->fingerpint);
    hdnode_to_btc(&hdnode, btc);
    memzero(&hdnode, sizeof(hdnode));
    return res;
}

btc_bool btc_hd_generate_key(btc_hdnode* node, const char* keypath, const uint8_t* keymaster, const uint8_t* chaincode, btc_bool usepubckd)
{
    static char delim[] = "/";
    static char prime[] = "phH\'";
    static char digits[] = "0123456789";
    uint64_t idx = 0;
    assert(strlens(keypath) < 1024);
    char *pch, *kp = btc_malloc(strlens(keypath) + 1);

    if (!kp) {
        return false;
    }

    if (strlens(keypath) < strlens("m/")) {
        goto err;
    }

    memset(kp, 0, strlens(keypath) + 1);
    memcpy(kp, keypath, strlens(keypath));

    if (kp[0] != 'm' || kp[1] != '/') {
        goto err;
    }

    node->depth = 0;
    node->child_num = 0;
    node->fingerprint = 0;
    memcpy(node->chain_code, chaincode, BTC_BIP32_CHAINCODE_SIZE);
    if (usepubckd == true) {
        memcpy(node->public_key, keymaster, BTC_ECKEY_COMPRESSED_LENGTH);
    } else {
        memcpy(node->private_key, keymaster, BTC_ECKEY_PKEY_LENGTH);
        btc_hdnode_fill_public_key(node);
    }

    pch = strtok(kp + 2, delim);
    while (pch != NULL) {
        size_t i = 0;
        int prm = 0;
        for (; i < strlens(pch); i++) {
            if (strchr(prime, pch[i])) {
                if ((i != strlens(pch) - 1) || usepubckd == true) {
                    goto err;
                }
                prm = 1;
            } else if (!strchr(digits, pch[i])) {
                goto err;
            }
        }

        idx = strtoull(pch, NULL, 10);
        if (idx > UINT32_MAX) {
            goto err;
        }

        if (prm) {
            if (btc_hdnode_private_ckd_prime(node, idx) != true) {
                goto err;
            }
        } else {
            if ((usepubckd == true ? btc_hdnode_public_ckd(node, idx) : btc_hdnode_private_ckd(node, idx)) != true) {
                goto err;
            }
        }
        pch = strtok(NULL, delim);
    }
    btc_free(kp);
    return true;

err:
    btc_free(kp);
    return false;
}

btc_bool btc_hdnode_has_privkey(btc_hdnode* node)
{
    int i;
    for (i = 0; i < BTC_ECKEY_PKEY_LENGTH; ++i) {
        if (node->private_key[i] != 0)
            return true;
    }
    return false;
}
