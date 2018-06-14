#include <QCoreApplication>
#include <QList>
#include <QDebug>
#include <iostream>
#include <string>
#include <sstream>
#include <openssl/sha.h>
#include <openssl/bn.h>
#include <openssl/ecdsa.h>
#include <openssl/rand.h>
#include <openssl/obj_mac.h>
#include <iomanip>

//refrence block to test computing merkle tree on https://blockchain.info/block/000000000003ba27aa200b1cecaad478d2b00432346c3f1f3986da1afd33e506

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

string sha256(const string str)
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, str.c_str(), str.size());
    SHA256_Final(hash, &sha256);
    stringstream ss;
    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        ss << hex << setw(2) << setfill('0') << (int)hash[i];
    }
    return ss.str();
}


uint8_t* twoSHA256(uint8_t* hashA, uint8_t* hashB) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, hashA, 32);
    SHA256_Update(&sha256, hashB, 32);
    SHA256_Final(hash, &sha256);
    return hash;
}

string byte2hex(uint8_t* data, int size = SHA256_DIGEST_LENGTH) {
    stringstream ss;
    for(int i = 0; i < size; i++)
    {
        ss << hex << setw(2) << setfill('0') << (int)data[i];
    }
    return ss.str();
}

static const signed char phexdigit[256] =
{ -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  0,1,2,3,4,5,6,7,8,9,-1,-1,-1,-1,-1,-1,
  -1,0xa,0xb,0xc,0xd,0xe,0xf,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,0xa,0xb,0xc,0xd,0xe,0xf,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1, };

vector<unsigned char> ParseHex(const char* psz)
{
    // convert hex dump to vector
    vector<unsigned char> vch;
    while (true)
    {
        while (isspace(*psz))
            psz++;
        signed char c = phexdigit[(unsigned char)*psz++];
        if (c == (signed char)-1)
            break;
        unsigned char n = (c << 4);
        c = phexdigit[(unsigned char)*psz++];
        if (c == (signed char)-1)
            break;
        n |= c;
        vch.push_back(n);
    }
    return vch;
}

vector<unsigned char> ParseHex(const string& str)
{
    return ParseHex(str.c_str());
}

//For hash function refere to https://stackoverflow.com/questions/2262386/

/*

Given an array of byte objects generate a Merkle root hash using the SHA256 algorithm.

Time: 15 minutes

Input: ["a", "b", "c", "d"]
Output: 14ede5e8e97ad9372327728f5099b95604a39593cac3bd38a343ad76205213e7

Input: ["a", "b", "c"]
Output: e76328b6ca10676c686a0d534e8222ad8da04fdfe14c6f6ff67d08cbbd24c605

*/

static void MerkleTree(QList<string> inputStrings) {
    QList<string> hashesCombined;

    for (int i = 0; i < inputStrings.size(); i++) {
        //take first transaction
        cout << "hashing " << inputStrings[i] << endl;
        string hashString = sha256(inputStrings[i]);
        cout << "result " << hashString << endl;
        i++;
        //combine the transaction with the next one if possible
        if (i < inputStrings.size()) {
            cout << "hashing " << inputStrings[i] << endl;
            hashString += sha256(inputStrings[i]);
            cout << "result " << hashString << endl;
        }

        //add the combined transaction to the list
        hashesCombined.append(hashString);
    }

    if (hashesCombined.size() > 1) {
        MerkleTree(hashesCombined);
    }
    else {
        //done
        string finalOutput = sha256(hashesCombined.at(0));
        cout << "Fina output " << finalOutput << endl;
    }
}


void merkleTreeHashTests() {
    cout << " ** HASHES WHEN COMBINED AS STRINGS ** " << endl;

    string HA = sha256("a");
    cout << "HA     " << HA << endl;

    string HB = sha256("b");
    cout << "HB     " << HB << endl;

    string HC = sha256("c");
    cout << "HC     " << HC << endl;

    string HD = sha256("d");
    cout << "HD     " << HD << endl;

    string HAB = sha256(HA + HB);
    cout << "HAB    " << HAB << endl;

    string HCD = sha256(HC + HD);
    cout << "HCD    " << HCD << endl;

    string HABCD = sha256(HAB + HCD);
    cout << "HABCD  " << HABCD << endl;

    cout << " ** HASHES WHEN COMBINED AS BYTES ** " << endl;

    string txa = "a";
    std::vector<uint8_t> aBytes(txa.begin(), txa.end());
    uint8_t hashA[32];
    SHA256(&aBytes[0], aBytes.size(), (uint8_t*)hashA);
    cout << "HA     " << byte2hex(hashA) << endl;

    string txb = "b";
    std::vector<uint8_t> bBytes(txb.begin(), txb.end());
    uint8_t hashB[32];
    SHA256(&bBytes[0], bBytes.size(), (uint8_t*)hashB);
    cout << "HB     " << byte2hex(hashB) << endl;

    string txc = "c";
    std::vector<uint8_t> cBytes(txc.begin(), txc.end());
    uint8_t hashC[32];
    SHA256(&cBytes[0], cBytes.size(), (uint8_t*)hashC);
    cout << "HC     " << byte2hex(hashC) << endl;

    string txd = "d";
    std::vector<uint8_t> dBytes(txd.begin(), txd.end());
    uint8_t hashD[32];
    SHA256(&dBytes[0], dBytes.size(), (uint8_t*)hashD);
    cout << "HD     " << byte2hex(hashD) << endl;

    const int hashSize = 32;
    uint8_t *hashABConc = new uint8_t[hashSize * 2];
    copy(hashA, hashA + hashSize, hashABConc);
    copy(hashB, hashB + hashSize, hashABConc + hashSize);
    uint8_t hashAB[32];
    SHA256(&hashABConc[0], hashSize * 2, (uint8_t*)hashAB);
    cout << "HAB    " << byte2hex(hashAB) << endl;

    uint8_t *hashCDConc = new uint8_t[hashSize * 2];
    copy(hashC, hashC + hashSize, hashCDConc);
    copy(hashD, hashD + hashSize, hashCDConc + hashSize);
    uint8_t hashCD[32];
    SHA256(&hashCDConc[0], hashSize * 2, (uint8_t*)hashCD);
    cout << "HCD    " << byte2hex(hashCD) << endl;

    uint8_t *hashABCDConc = new uint8_t[hashSize * 2];
    copy(hashAB, hashAB + hashSize, hashABCDConc);
    copy(hashCD, hashCD + hashSize, hashABCDConc + hashSize);
    uint8_t hashABCD[32];
    SHA256(&hashABCDConc[0], hashSize * 2, (uint8_t*)hashABCD);
    cout << "HABCD  " << byte2hex(hashABCD) << endl;
}

uint8_t priv[32];

void createPrivatePublicKeyPairTest() {
    cout << " ** CREATE PRIVATE KEY **" << endl;
    //create a private key
    EC_KEY *pkey;
    pkey = EC_KEY_new_by_curve_name(NID_secp256k1);

    // The actual byte data
    unsigned char vch[32];
    //fill it with random bytes. the random function is provided by OpenSSL. Must use a secure random function
    RAND_bytes(vch, sizeof(vch));

    BIGNUM *bn;
    bn = BN_new();
    assert(BN_bin2bn(vch, 32, bn));
    assert(EC_KEY_regenerate_key(pkey, bn));
    BN_clear_free(bn);

    //get private key
    const BIGNUM *priv_bn = EC_KEY_get0_private_key(pkey);
    if (!priv_bn) {
        cout << "Unable to decode private key" << endl;
        return;
    }
    BN_bn2bin(priv_bn, priv);

    //examples
    //8262b0cceb4f174efe5f37d36e8a18f236568b402969f6b28fe8af8a18e46daa
    cout << "PRKEY  " << byte2hex(priv) << endl;

    //get public key from the private key
    //PRKEY  3df2a83cb6a5c54615e1fd310a24b57e69db3cdc916b9a987df7994fada8e77c
    //PUKEY  02ee978588f548379b58d30ed4165de9d985adc53b97e0c569abfb77f992a175
    bool fCompressed = true;
    EC_KEY_set_conv_form(pkey, fCompressed ? POINT_CONVERSION_COMPRESSED : POINT_CONVERSION_UNCOMPRESSED);
    int nSize = i2o_ECPublicKey(pkey, NULL);
    assert(nSize);
    assert(nSize <= 65);
    unsigned char pubc[65];
    unsigned char *pbegin = pubc;
    int nSize2 = i2o_ECPublicKey(pkey, &pbegin);
    assert(nSize == nSize2);

    cout << "PUKEY  " << byte2hex(pubc) << endl;
}

void loadPrivateKeyAndGeneratePublicKeyTest() {
    cout << " ** LOAD PRIVATE KEY **" << endl;
    //load private key
    EC_KEY *pkey;
    pkey = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (pkey == NULL) {
        cout << "EC_KEY_new_by_curve_name failed";
        return;
    }

    cout << "PRKEY  " << byte2hex(priv) << endl;
    string hexKey = byte2hex(priv);
    vector<unsigned char> parsedKey = ParseHex(hexKey);
    const uint8_t* pbegin = &parsedKey[0];
    if (d2i_ECPrivateKey(&pkey, &pbegin, parsedKey.size())) {
        // d2i_ECPrivateKey returns true if parsing succeeds.
        // This doesn't necessarily mean the key is valid.
        if (!EC_KEY_check_key(pkey)) {
            cout << "EC_KEY_check_key failed" << endl;
            return;
        }
    } else {
        cout << "d2i_ECPrivateKey failed" << endl;
        return;
    }

    //get private key
    uint8_t priv[32];
    const BIGNUM *priv_bn = EC_KEY_get0_private_key(pkey);
    if (!priv_bn) {
        cout << "Unable to decode private key" << endl;
        return;
    }
    BN_bn2bin(priv_bn, priv);

    unsigned char vch[32];
    int nBytes = BN_num_bytes(priv_bn);
    int n=BN_bn2bin(priv_bn,&vch[32 - nBytes]);
    assert(n == nBytes);
    memset(vch, 0, 32 - nBytes);

    //examples
    //PRKEY  3df2a83cb6a5c54615e1fd310a24b57e69db3cdc916b9a987df7994fada8e77c
    cout << "PRKEY  " << byte2hex(priv) << endl;

    //get public key from the private key. Example of input and output is
    //PRKEY  3df2a83cb6a5c54615e1fd310a24b57e69db3cdc916b9a987df7994fada8e77c
    //PUKEY  02ee978588f548379b58d30ed4165de9d985adc53b97e0c569abfb77f992a175
    bool fCompressed = true;
    EC_KEY_set_conv_form(pkey, fCompressed ? POINT_CONVERSION_COMPRESSED : POINT_CONVERSION_UNCOMPRESSED);
    int nSize = i2o_ECPublicKey(pkey, NULL);
    assert(nSize);
    assert(nSize <= 65);
    unsigned char pubc[65];
    unsigned char *pubbegin = pubc;
    int nSize2 = i2o_ECPublicKey(pkey, &pubbegin);
    assert(nSize == nSize2);

    cout << "PUKEY  " << byte2hex(pubc) << endl;
}


int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);

    cout << "App start in main.cpp " << endl;
    printf("OpenSSL version: %s\n",OPENSSL_VERSION_TEXT);

    merkleTreeHashTests();
    createPrivatePublicKeyPairTest();
    loadPrivateKeyAndGeneratePublicKeyTest();

    return 0;
    return a.exec();
}
