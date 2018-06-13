#include <QCoreApplication>
#include <QList>
#include <QDebug>
#include <iostream>
#include <string>
#include <sstream>
#include <openssl/sha.h>
#include <iomanip>

//refrence block to test computing merkle tree on https://blockchain.info/block/000000000003ba27aa200b1cecaad478d2b00432346c3f1f3986da1afd33e506

using namespace std;

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

string hashToString(uint8_t* hash) {
    stringstream ss;
    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        ss << hex << setw(2) << setfill('0') << (int)hash[i];
    }
    return ss.str();
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


//static void MerkleTreeBytes(QList<string> inputStrings) {
//    QList<string> hashesCombined;

//    for (int i = 0; i < inputStrings.size(); i++) {
//        //take first transaction
//        string txa = inputStrings[i];
//        std::vector<uint8_t> aBytes(txa.begin(), txa.end());
//        uint8_t hashA[32];

//        SHA256(&aBytes[0], aBytes.size(), (uint8_t*)hashA);
//        cout << "result " << hashToString(hashA) << endl;
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


int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);

    cout << "App start in main.cpp " << endl;

//    QList<string> transactions;
//    transactions.append("a");
//    transactions.append("b");
//    transactions.append("c");
//    transactions.append("d");

//    MerkleTree(transactions);

    cout << " ** HASHES AS STRINGS ** " << endl;

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

    cout << " ** HASHES AS BYTES ** " << endl;

    string txa = "a";
    std::vector<uint8_t> aBytes(txa.begin(), txa.end());
    uint8_t hashA[32];
    SHA256(&aBytes[0], aBytes.size(), (uint8_t*)hashA);
    cout << "HA     " << hashToString(hashA) << endl;

    string txb = "b";
    std::vector<uint8_t> bBytes(txb.begin(), txb.end());
    uint8_t hashB[32];
    SHA256(&bBytes[0], bBytes.size(), (uint8_t*)hashB);
    cout << "HB     " << hashToString(hashB) << endl;

    string txc = "c";
    std::vector<uint8_t> cBytes(txc.begin(), txc.end());
    uint8_t hashC[32];
    SHA256(&cBytes[0], cBytes.size(), (uint8_t*)hashC);
    cout << "HC     " << hashToString(hashC) << endl;

    string txd = "d";
    std::vector<uint8_t> dBytes(txd.begin(), txd.end());
    uint8_t hashD[32];
    SHA256(&dBytes[0], dBytes.size(), (uint8_t*)hashD);
    cout << "HD     " << hashToString(hashD) << endl;

    const int hashSize = 32;
    uint8_t *hashABConc = new uint8_t[hashSize * 2];
    copy(hashA, hashA + hashSize, hashABConc);
    copy(hashB, hashB + hashSize, hashABConc + hashSize);
    uint8_t hashAB[32];
    SHA256(&hashABConc[0], hashSize * 2, (uint8_t*)hashAB);
    cout << "HAB    " << hashToString(hashAB) << endl;

    uint8_t *hashCDConc = new uint8_t[hashSize * 2];
    copy(hashC, hashC + hashSize, hashCDConc);
    copy(hashD, hashD + hashSize, hashCDConc + hashSize);
    uint8_t hashCD[32];
    SHA256(&hashCDConc[0], hashSize * 2, (uint8_t*)hashCD);
    cout << "HCD    " << hashToString(hashCD) << endl;

    uint8_t *hashABCDConc = new uint8_t[hashSize * 2];
    copy(hashAB, hashAB + hashSize, hashABCDConc);
    copy(hashCD, hashCD + hashSize, hashABCDConc + hashSize);
    uint8_t hashABCD[32];
    SHA256(&hashABCDConc[0], hashSize * 2, (uint8_t*)hashABCD);
    cout << "HABCD  " << hashToString(hashABCD) << endl;

    return 0;
    return a.exec();
}
