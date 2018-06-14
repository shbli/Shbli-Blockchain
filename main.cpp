#include <QCoreApplication>
#include <QList>
#include <QDebug>
#include <QCryptographicHash>
#include "utils.h"
//refrence block to test computing merkle tree on https://blockchain.info/block/000000000003ba27aa200b1cecaad478d2b00432346c3f1f3986da1afd33e506

using namespace std;

//For hash function refere to https://stackoverflow.com/questions/2262386/

/*

Given an array of byte objects generate a Merkle root hash using the SHA256 algorithm.

Time: 15 minutes

Input: ["a", "b", "c", "d"]
Output: 14ede5e8e97ad9372327728f5099b95604a39593cac3bd38a343ad76205213e7

Input: ["a", "b", "c"]
Output: e76328b6ca10676c686a0d534e8222ad8da04fdfe14c6f6ff67d08cbbd24c605

*/

//static void MerkleTree(QList<string> inputStrings) {
//    QList<string> hashesCombined;

//    for (int i = 0; i < inputStrings.size(); i++) {
//        //take first transaction
//        cout << "hashing " << inputStrings[i] << endl;
//        string hashString = sha256(inputStrings[i]);
//        cout << "result " << hashString << endl;
//        i++;
//        //combine the transaction with the next one if possible
//        if (i < inputStrings.size()) {
//            cout << "hashing " << inputStrings[i] << endl;
//            hashString += sha256(inputStrings[i]);
//            cout << "result " << hashString << endl;
//        }

//        //add the combined transaction to the list
//        hashesCombined.append(hashString);
//    }

//    if (hashesCombined.size() > 1) {
//        MerkleTree(hashesCombined);
//    }
//    else {
//        //done
//        string finalOutput = sha256(hashesCombined.at(0));
//        cout << "Fina output " << finalOutput << endl;
//    }
//}


void merkleTreeHashTests() {
    cout << " ** HASHES OF MERKLE TREE TEST ** " << endl;

    QByteArray txa = QCryptographicHash::hash(QByteArray("a"), QCryptographicHash::Sha256);
    cout << "HA     " << txa.toHex().toStdString() << endl;

    QByteArray txb = QCryptographicHash::hash(QByteArray("b"), QCryptographicHash::Sha256);
    cout << "HB     " << txb.toHex().toStdString() << endl;

    QByteArray txc = QCryptographicHash::hash(QByteArray("c"), QCryptographicHash::Sha256);
    cout << "HC     " << txc.toHex().toStdString() << endl;

    QByteArray txd = QCryptographicHash::hash(QByteArray("d"), QCryptographicHash::Sha256);
    cout << "HD     " << txd.toHex().toStdString() << endl;

    QByteArray txab = QCryptographicHash::hash(txa + txb, QCryptographicHash::Sha256);
    cout << "HAB    " << txab.toHex().toStdString() << endl;

    QByteArray txcd = QCryptographicHash::hash(txc + txd, QCryptographicHash::Sha256);
    cout << "HCD    " << txcd.toHex().toStdString() << endl;

    QByteArray txabcd = QCryptographicHash::hash(txab + txcd, QCryptographicHash::Sha256);
    cout << "HABCD  " << txabcd.toHex().toStdString() << endl;
}


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

    uint8_t priv[32];
    BN_bn2bin(priv_bn, priv);

    vector<unsigned char> vpriv(priv, priv + 32);

    QByteArray privbyteArray = QByteArray::fromRawData((char*)priv, 32);

    //examples
    //8262b0cceb4f174efe5f37d36e8a18f236568b402969f6b28fe8af8a18e46daa
    cout << "PRKEY  " << privbyteArray.toHex().toUpper().toStdString() << endl;

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

    QByteArray pubcbyteArray = QByteArray::fromRawData((char*)pubc, 32);
    QByteArray addrbyteArray = QCryptographicHash::hash(pubcbyteArray, QCryptographicHash::Sha256);
    cout << "PRKEY  " << pubcbyteArray.toHex().toUpper().toStdString() << endl;
    cout << "ADDRS  " << addrbyteArray.toHex().toUpper().toStdString() << endl;
}

//void loadPrivateKeyAndGeneratePublicKeyTest() {
//    cout << " ** LOAD PRIVATE KEY **" << endl;
//    //load private key
//    EC_KEY *pkey;
//    pkey = EC_KEY_new_by_curve_name(NID_secp256k1);
//    if (pkey == NULL) {
//        cout << "EC_KEY_new_by_curve_name failed";
//        return;
//    }

//    uint8_t priv[32];
//    cout << "PRKEY  " << byte2hex(priv) << endl;
//    string hexKey = byte2hex(priv);
//    vector<unsigned char> parsedKey = ParseHex(hexKey);
//    const uint8_t* pbegin = &parsedKey[0];
//    if (d2i_ECPrivateKey(&pkey, &pbegin, parsedKey.size())) {
//        // d2i_ECPrivateKey returns true if parsing succeeds.
//        // This doesn't necessarily mean the key is valid.
//        if (!EC_KEY_check_key(pkey)) {
//            cout << "EC_KEY_check_key failed" << endl;
//            return;
//        }
//    } else {
//        cout << "d2i_ECPrivateKey failed" << endl;
//        return;
//    }

//    //get private key

//    const BIGNUM *priv_bn = EC_KEY_get0_private_key(pkey);
//    if (!priv_bn) {
//        cout << "Unable to decode private key" << endl;
//        return;
//    }
//    BN_bn2bin(priv_bn, priv);

//    unsigned char vch[32];
//    int nBytes = BN_num_bytes(priv_bn);
//    int n=BN_bn2bin(priv_bn,&vch[32 - nBytes]);
//    assert(n == nBytes);
//    memset(vch, 0, 32 - nBytes);

//    //examples
//    //PRKEY  3df2a83cb6a5c54615e1fd310a24b57e69db3cdc916b9a987df7994fada8e77c
//    cout << "PRKEY  " << byte2hex(priv) << endl;
//    cout << "PRKEY  " << EncodeBase64(priv, 32) << endl;

//    //get public key from the private key. Example of input and output is
//    //PRKEY  3df2a83cb6a5c54615e1fd310a24b57e69db3cdc916b9a987df7994fada8e77c
//    //PUKEY  02ee978588f548379b58d30ed4165de9d985adc53b97e0c569abfb77f992a175
//    bool fCompressed = true;
//    EC_KEY_set_conv_form(pkey, fCompressed ? POINT_CONVERSION_COMPRESSED : POINT_CONVERSION_UNCOMPRESSED);
//    int nSize = i2o_ECPublicKey(pkey, NULL);
//    assert(nSize);
//    assert(nSize <= 65);
//    unsigned char pubc[65];
//    unsigned char *pubbegin = pubc;
//    int nSize2 = i2o_ECPublicKey(pkey, &pubbegin);
//    assert(nSize == nSize2);

//    cout << "PUKEY  " << byte2hex(pubc) << endl;
//}


int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);

    cout << "App start in main.cpp " << endl;
    printf("OpenSSL version: %s\n",OPENSSL_VERSION_TEXT);

    merkleTreeHashTests();
    createPrivatePublicKeyPairTest();
    //loadPrivateKeyAndGeneratePublicKeyTest();

    return 0;
    return a.exec();
}
