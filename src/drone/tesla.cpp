#include <boost/multi_index_container.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/multi_index/member.hpp>
#include "drone.hpp"

/*
Create a queue for RERRs. Queue is sorted FIFO
Every time we recieve TESLA msg, check if queue has elements. (Do nothing if not)
If element has time sync past the bounds of current message, delete all elements in queue.
Else, if it fits, pop more recent RERR and process.

Data Structures: 
Multi-Index Container to hold pending RERRs (within TESLA class)
Place TESLA key msgs in circular buffer (within TESLA class)
*/

std::string drone::TESLA::createHMAC(const std::string& key, const std::string& data) {
    unsigned char* digest;
    digest = HMAC(EVP_sha256(), key.c_str(), key.length(),
                  reinterpret_cast<const unsigned char*>(data.c_str()), data.length(), NULL, NULL);

    std::stringstream ss;
    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)digest[i];

    return ss.str();
}

std::string drone::TESLA::sha256(const std::string& inn) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, inn.c_str(), inn.size());
    SHA256_Final(hash, &sha256);
    std::stringstream ss;
    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    return ss.str();
}

drone::TESLA::TESLA() {
    // hashChain = new unsigned char[numKeys][SHA256_DIGEST_LENGTH];
    generateHashChain();
    // assume time synchro has happened
}

drone::TESLA::~TESLA() {
    std::cout << "TESLA Destructor" << std::endl;
    // delete[] hashChain;
}

TESLA_MESSAGE drone::TESLA::init_tesla(const std::string &addr) {
    this->addr = addr;
    
    TESLA_MESSAGE init_msg;
    init_msg.set_init(this->addr, this->hash_chain.back(), this->disclosure_time);
    this->hash_chain.pop_back();
    // make a function that opens another thread to perodically disclose messages (done in drone.cpp)
    // make a function that opens another thread to perodically process MACs

    return init_msg;
}

void drone::TESLA::generateHashChain() {
    /* Assumptions: We are not doing any wrap arounds for now
    New key is disclosed every **disclosure_time** seconds
    numKeys  = lifetime / disclosure_time
    */
    unsigned char buffer[56];
    RAND_bytes(buffer, sizeof(buffer));
    std::stringstream ss;
    for (int i = 0; i < sizeof(buffer); ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(buffer[i]);
    }
    string hash = ss.str();
    for (int i = 0; i < numKeys; ++i) {
        hash = sha256(hash);
        this->hash_chain.push_front(hash);
        // cout << "Hash: " << hash << endl;
    }
}

void drone::TESLA::compareHashes(const unsigned char *hash1, const unsigned char *hash2) {
    if (memcmp(hash1, hash2, SHA256_DIGEST_LENGTH) == 0) {
        std::cout << "Hashes match" << std::endl;
    } else {
        std::cout << "Hashes do not match" << std::endl;
    }
}

std::string drone::TESLA::hash_disclosure() {
    if (this->hash_chain.empty()) {
        cout << "No more keys to disclose" << endl;
        return "ERR"; // temp
    }
    std::string hash = this->hash_chain.back();
    this->hash_chain.pop_back();

    return hash;
}

void drone::TESLA::recv(json& jsonData) {
    TESLA_MESSAGE msg;
    msg.deserialize(jsonData);

    if (msg.mode == TESLA_MESSAGE::DISCLOSE) {
        if (this->routingTable.find(msg.srcAddr) && this->routingTable[msg.srcAddr].has_mac) {
            std::string mac = createHMAC(msg.hashKey, msg.data);
            if (mac == msg.mac) {
                cout << "MAC is valid" << endl;
                // do whatever processing for RERRs
                // remove that element from the queue
            }
        } else {
            cout << "No need for this MAC" << endl;
        }
        return; // what consequences for mac being too late or not existing?
    } else if (msg.mode == TESLA_MESSAGE::DATA) { // <---- TODO: IMPLEMENT THIS PART AND THEN TEST
        if (this->routingTable.find(msg.srcAddr)) {
            auto now = std::chrono::steady_clock::now();
            auto ttl = now + this->routingTable[msg.srcAddr].tesla_disclosure_time;
            TESLA::msg m(msg.data, msg.mac, ttl);
            this->mac_q.insert(m);
        }
    } else if (msg.mode == TESLA_MESSAGE::INIT) {
        // Just updates routing table
        auto now = std::chrono::steady_clock::now();
        auto ttl = now + std::chrono::seconds(msg.disclosure_time);
        this->routingTable[msg.srcAddr].setTeslaInfo(msg.hashKey, std::chrono::seconds(this->disclosure_time));
    }


//     /*
//     1) Recieve message [const std::string& addr, const std::string& MAC]
//     2) Access drone routing table, where each entry has its own mac queue (This requires us to create a method in drone which allows routing table access)
//     3) (How should we most quickly clean the queue?)
//     4) 
//     */
}