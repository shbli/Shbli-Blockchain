#include <QCoreApplication>
#include <QList>
#include <QDebug>
#include <iostream>
#include <string>
#include <sstream>
#include <openssl/sha.h>
#include <iomanip>


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


    //0d54cada63fe4f032265dcb10126a524f86a19c8a7f78e86d899a30a08b99d3d
    //7b80916a55fe09ce239d3d2c90f7bbf2ca3e5debea28f42eaae8d05bcab79c05
    //
    //combine A + B into one hash
    uint8_t hashAB[64];
    stringstream ss;
    ss << hashA << hashB;
    ss >> hashAB;
    uint8_t ABHashed[32];
    SHA256(&hashAB[0], 64, (uint8_t*)ABHashed);
    cout << "HAB    " << hashToString(ABHashed) << endl;


//    //combine C + D into one hash
//    uint8_t hashCD[64];
//    ss.clear();
//    ss << hashC << hashD;
//    ss >> hashCD;
//    uint8_t CDHashed[32];
//    SHA256(&hashCD[0], 64, (uint8_t*)CDHashed);
//    cout << "HCD    " << hashToString(CDHashed) << endl;

    return a.exec();
}
