// #include "tesla.hpp"
#include "drone.hpp"

// void MAC_Q::push_msg(std::string data, std::string MAC){
//     auto now = std::chrono::steady_clock::now();
//     auto ttl = now + this->mac_ttl;
//     q.push_back({data, MAC, ttl});
// }

// /*FIX: This can cause issues if queue is cluttered*/
// void MAC_Q::cleanqueue(){
//     auto now = std::chrono::steady_clock::now();
//     while (!q.empty() && q.front().ttl < now) {
//         q.pop_front();
//     }
// }

// /*FIX: Same issue as clean queue*/
// std::string MAC_Q::getNextMessage(std::string MAC) {
//     cleanqueue();
//     for (auto it = q.begin(); it != q.end(); ++it) {
//         if (it->MAC == MAC) {
//             return it->data;
//         }
//     }

//     return "";
// }

std::string drone::TESLA::createHMAC(const std::string& key, const std::string& data) {
    unsigned char* digest;
    digest = HMAC(EVP_sha256(), key.c_str(), key.length(),
                  reinterpret_cast<const unsigned char*>(data.c_str()), data.length(), NULL, NULL);

    std::stringstream ss;
    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)digest[i];

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

void drone::TESLA::generateHashChain() {
    /* Assumptions: We are not doing any wrap arounds for now
    New key is disclosed every **disclosure_time** seconds
    numKeys  = lifetime / disclosure_time
    */

    unsigned char buffer[56];
    RAND_bytes(buffer, sizeof(buffer));
    memcpy(&this->hash_chain[0][0], buffer, SHA256_DIGEST_LENGTH);

    for (unsigned int i = 1; i < numKeys; i++) {
        unsigned char prevHash[SHA256_DIGEST_LENGTH];
        memcpy(prevHash, this->hash_chain[i - 1].data(), SHA256_DIGEST_LENGTH);
        SHA256_CTX ctx;
        SHA256_Init(&ctx);
        SHA256_Update(&ctx, prevHash, SHA256_DIGEST_LENGTH);
        SHA256_Final(reinterpret_cast<unsigned char*>(&this->hash_chain[i][0]), &ctx);
    }
}

void drone::TESLA::compareHashes(const unsigned char *hash1, const unsigned char *hash2) {
    if (memcmp(hash1, hash2, SHA256_DIGEST_LENGTH) == 0) {
        std::cout << "Hashes match" << std::endl;
    } else {
        std::cout << "Hashes do not match" << std::endl;
    }
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
        if ((this->routingTable.find(msg.srcAddr) != this->routingTable.end()) && this->routingTable[msg.srcAddr].has_mac) {
            std::string mac = createHMAC(msg.hashKey, msg.data);
            if (mac == msg.mac) {
                cout << "MAC is valid" << endl;
                // do whatever processing for RERRs
                // remove that element from the queue
            }
        }
        return; // what consequences for mac being too late or not existing?
    } else if (msg.mode == TESLA_MESSAGE::DATA) { // <---- TODO: IMPLEMENT THIS PART AND THEN TEST
        if (this->routingTable.find(msg.srcAddr) != this->routingTable.end()) {
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


    /*
    1) Recieve message [const std::string& addr, const std::string& MAC]
    2) Access drone routing table, where each entry has its own mac queue (This requires us to create a method in drone which allows routing table access)
    3) (How should we most quickly clean the queue?)
    4) 
    */
}