#include <QCoreApplication>
#include <QList>
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

    QByteArray txa = SHA256(QByteArray("a"));
    cout << "HA     " << txa.toHex().toStdString() << endl;

    QByteArray txb = SHA256(QByteArray("b"));
    cout << "HB     " << txb.toHex().toStdString() << endl;

    QByteArray txc = SHA256(QByteArray("c"));
    cout << "HC     " << txc.toHex().toStdString() << endl;

    QByteArray txd = SHA256(QByteArray("d"));
    cout << "HD     " << txd.toHex().toStdString() << endl;

    QByteArray txab = SHA256(txa + txb);
    cout << "HAB    " << txab.toHex().toStdString() << endl;

    QByteArray txcd = SHA256(txc + txd);
    cout << "HCD    " << txcd.toHex().toStdString() << endl;

    QByteArray txabcd = SHA256(txab + txcd);
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

    QByteArray privbyteArray = QByteArray::fromRawData((char*)priv, 32);

    //examples
    //8262b0cceb4f174efe5f37d36e8a18f236568b402969f6b28fe8af8a18e46daa
    cout << "PRKEY  " << privbyteArray.toHex().toStdString() << endl;

    bool fCompressed = true;
    EC_KEY_set_conv_form(pkey, fCompressed ? POINT_CONVERSION_COMPRESSED : POINT_CONVERSION_UNCOMPRESSED);
    int nSize = i2o_ECPublicKey(pkey, NULL);
    assert(nSize);
    unsigned char pubc[nSize];
    unsigned char *pbegin = pubc;
    int nSize2 = i2o_ECPublicKey(pkey, &pbegin);
    assert(nSize == nSize2);

    QByteArray pubcbyteArray = QByteArray::fromRawData((char*)pubc, nSize);
    QByteArray addrbyteArray = SHA256(pubcbyteArray);
    cout << "PUKEY  " << pubcbyteArray.toHex().toStdString() << endl;
    cout << "ADDRS  " << addrbyteArray.toHex().toStdString() << endl;

    //sign a messgae
    char* hash = addrbyteArray.data();
    ECDSA_SIG *signature = ECDSA_do_sign((unsigned char*) hash, addrbyteArray.size(), pkey);
    if (signature == NULL) {
        cout << "Unable to create signature";
    }

    std::vector<unsigned char> vchSig;
    nSize = ECDSA_size(pkey);
    vchSig.resize(nSize); // Make sure it is big enough
    unsigned char *pos = &vchSig[0];
    nSize = i2d_ECDSA_SIG(signature, &pos);
    vchSig.resize(nSize); // Shrink to fit actual size

    QByteArray decSignature = QByteArray::fromRawData((char*)&vchSig[0], vchSig.size());
    cout << "SGDEC  " << decSignature.toHex().toStdString() << endl;


    const BIGNUM *pr = NULL;
    const BIGNUM *ps = NULL;
    ECDSA_SIG_get0(signature, &pr, &ps);

    string rHex = BN_bn2hex(pr);
    string sHex = BN_bn2hex(ps);

    cout << "RHEX  " << rHex << endl;
    cout << "SHEX  " << sHex << endl;

    ECDSA_SIG_free(signature);
}

void loadPrivateKeyAndGeneratePublicKeyTest() {
    cout << " ** LOAD PRIVATE KEY **" << endl;
//      TEST PRIVATE PUBLIC ADDRESS
    //    PRKEY  76bc5d790827afb6d9858d8e84d9d1077356e3cdc491d1c7333185b527261b45
    //    PUKEY  02a1a59f8e922eee0d8a678b08a25c546ba329d9dc617cdb700b71b969effa3a0a
    //    ADDRS  6bf349ad7b5029650ac1bc6e1256e602afdb032f6cdba631c2e36e8156dd4d70
    //    RHEX  0D607DAAB9221424B3B9EF0E4DE87F61B8E885906B335D36F53936CF55352472
    //    SHEX  A0F31DD521E5DE290405326813FFA0A1BEAD7A6BC7AF2FFCBE6FCF02AC8AB19B

    //load private key
    //get public key from the private key
    string priv_hex = "76bc5d790827afb6d9858d8e84d9d1077356e3cdc491d1c7333185b527261b45";
    cout << "PRKEY  " << priv_hex << endl;


    EC_KEY *pkey;
    pkey = EC_KEY_new_by_curve_name(NID_secp256k1);

    // convert priv key from hexadecimal to BIGNUM
    BIGNUM *priv_bn = BN_new();
    BN_hex2bn( &priv_bn, priv_hex.c_str() );

    assert(EC_KEY_regenerate_key(pkey, priv_bn));

    bool fCompressed = true;
    EC_KEY_set_conv_form(pkey, fCompressed ? POINT_CONVERSION_COMPRESSED : POINT_CONVERSION_UNCOMPRESSED);
    int nSize = i2o_ECPublicKey(pkey, NULL);
    assert(nSize);
    unsigned char pubc[nSize];
    unsigned char *pbegin = pubc;
    int nSize2 = i2o_ECPublicKey(pkey, &pbegin);
    assert(nSize == nSize2);

    QByteArray pubcbyteArray = QByteArray::fromRawData((char*)pubc, nSize);
    QByteArray addrbyteArray = SHA256(pubcbyteArray);
    cout << "PUKEY  " << pubcbyteArray.toHex().toStdString() << endl;
    cout << "ADDRS  " << addrbyteArray.toHex().toStdString() << endl;
    assert(pubcbyteArray.toHex().toStdString() == "02a1a59f8e922eee0d8a678b08a25c546ba329d9dc617cdb700b71b969effa3a0a");
    assert(addrbyteArray.toHex().toStdString() == "6bf349ad7b5029650ac1bc6e1256e602afdb032f6cdba631c2e36e8156dd4d70");
}

void verifySignautre() {
    //test values (We shall not use the private key to validate a signature. the test values here are just available for validation
//    PRKEY  b236c288a84073f2de6f04ec367e39892984ad19c44da7b0f6a697f5b0de594d
//    PUKEY  02023349ab48f6a5e28aec00dfbee344cd1f8af0410837ac6857efd0735dc0105d
//    ADDRS  29a521d3b9200ada112e1c9dc25c341e25617de8d11d2c1199f6c604ec33d2a4
//    SGDEC  304402201a38a76a7c15baa58fd840a44527e1c0ee01fa96003d1744932784fdb09bd39d02201a9f91410f5e7edee0593eb878ad6c8e5ac7ab164260119ea3720ca8a10e64d8
//    RHEX  1A38A76A7C15BAA58FD840A44527E1C0EE01FA96003D1744932784FDB09BD39D
//    SHEX  1A9F91410F5E7EDEE0593EB878AD6C8E5AC7AB164260119EA3720CA8A10E64D8

    cout << " ** VERIFY SIGNATURE **" << endl;

    //Load our public key
    EC_KEY *pkey;
    pkey = EC_KEY_new_by_curve_name(NID_secp256k1);

    QByteArray pubKeyByte = QByteArray::fromHex(QByteArray::fromStdString("02023349ab48f6a5e28aec00dfbee344cd1f8af0410837ac6857efd0735dc0105d"));
    char* data = pubKeyByte.data();
    const char** dataP = (const char **)(&data);
    const unsigned char **pbegin = (const unsigned char **)(dataP);
    pkey = o2i_ECPublicKey(&pkey, pbegin, pubKeyByte.size());

    if (!EC_KEY_check_key(pkey)) {
        cout << "EC_KEY_check_key failed" << endl;
        return;
    }

    QByteArray addrByteArray = QByteArray::fromHex( QByteArray::fromStdString("29a521d3b9200ada112e1c9dc25c341e25617de8d11d2c1199f6c604ec33d2a4") );
    QByteArray sgdecByteArray = QByteArray::fromHex( QByteArray::fromStdString("304402201a38a76a7c15baa58fd840a44527e1c0ee01fa96003d1744932784fdb09bd39d02201a9f91410f5e7edee0593eb878ad6c8e5ac7ab164260119ea3720ca8a10e64d8") );

    if (ECDSA_verify(0, (const unsigned char*) addrByteArray.data(), addrByteArray.size(), (const unsigned char*) sgdecByteArray.data(), sgdecByteArray.size(), pkey)) {
        cout << "ECDSA_verify passed!" << endl;
    } else {
        cout << "ECDSA_verify failed!" << endl;
    }
}

int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);

    cout << "App start in main.cpp " << endl;
    printf("OpenSSL version: %s\n",OPENSSL_VERSION_TEXT);

    merkleTreeHashTests();
    createPrivatePublicKeyPairTest();
    loadPrivateKeyAndGeneratePublicKeyTest();
    verifySignautre();

    return 0;
    return a.exec();
}
