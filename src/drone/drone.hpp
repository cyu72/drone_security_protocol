#ifndef DRONE_HPP
#define DRONE_HPP
#define PORT_NUMBER 80
#define BRDCST_PORT 65457
#include <iostream>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <tuple>
#include <thread>
#include <set>
#include <deque>
#include <unordered_map>
#include <unordered_set>
#include <stdexcept>
#include <sstream>
#include <iomanip>
#include <netdb.h>
#include <nlohmann/json.hpp>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <chrono>
#include <sys/time.h>
#include <ctime>
#include "hashTree.hpp"
#include "messages.hpp"

using json = nlohmann::json;
using std::cout;
using std::endl;
using std::string;

struct ROUTING_TABLE_ENTRY {
    /*TODO: Add TESLA MAC QUEUE and ENSUING INFORMATION AND NEW VARIABLE OF HOW OFTEN THIS TABLE GETS CLEANED UP*/
    string destAddr;
    string nextHopID; // srcAddr = destAddr if neighbor
    int seqNum; // the destinations seqNum
    int cost; // The inital cost to reach the destination (?)
    int ttl;
    string tesla_hash;
    std::chrono::seconds tesla_disclosure_time;
    string hash;
    bool has_mac = false; // tells us if we are waiting for a haskey to decrypt a mac message for this node

    ROUTING_TABLE_ENTRY(){
        this->destAddr = "ERR";
        this->nextHopID = "ERR";
        this->seqNum = -1;
        this->cost = -1;
        this->ttl = -1;
        this->hash = "";
        this->tesla_hash = "ERR";
        this->tesla_disclosure_time = std::chrono::seconds(0);
    }

    // TODO: Must fix all instances of ttl
    ROUTING_TABLE_ENTRY(string destAddr, string nextHopID, int seqNum, int cost, int ttl, string hash){
        this->destAddr = destAddr;
        this->nextHopID = nextHopID;
        this->seqNum = seqNum;
        this->cost = cost;
        this->ttl = ttl;
        this->hash = hash; // What is this field supposed to contain again
    }

    void print() {
        cout << "Routing entry: " << "destAddr: " << destAddr << ", nextHopID: " << nextHopID << ", seqNum: " << seqNum << ", cost: " << cost << ", ttl: " << ttl << ", hash: " << hash << endl;
    }

    std::tuple<string, std::chrono::seconds> getTeslaInfo() {
        if (tesla_hash.compare("ERR") == 0 || tesla_disclosure_time.count() == 0) {
            throw std::runtime_error("TESLA info not found");
        }
        return std::make_tuple(tesla_hash, tesla_disclosure_time);
    }

    void setTeslaInfo(string hash, std::chrono::seconds ttl) {
        this->tesla_hash = hash;
        this->tesla_disclosure_time = ttl;
    }
};

class drone {
    public: // everything public for now
        drone(){
            this->addr = -1;
            this->port = -999;
            this->nodeID = -1;
            this->seqNum = 0;
        }

        drone(int port, int nodeID){
            cout << "Drone constructor called" << endl;
            this->addr = "drone" + std::to_string(nodeID) + "-service.default";
            this->port = port;
            this->nodeID = nodeID;
            this->seqNum = 0;
        }
        string addr;
        int port;
        int msgTTL = 3; // Hardcoded value for message ttl
        unsigned long seqNum;
        int nodeID;
        std::deque<string> hashChainCache; 
        class TESLA {
            struct msg {
                std::string data; // Type: RERR, assume the data is in string form
                std::string MAC; // temp: assume MAC is in string form
                std::chrono::steady_clock::time_point tstamp;
                msg(string, string, std::chrono::steady_clock::time_point){
                    this->data = data;
                    this->MAC = MAC;
                    this->tstamp = tstamp;
                }
                bool operator<(const msg& other) const {
                    return tstamp > other.tstamp;
                }
            };

            public:
                TESLA();
                ~TESLA();

                std::unordered_map<string, ROUTING_TABLE_ENTRY> routingTable;
                const unsigned int disclosure_time = 10; // every 10 seconds (hard coded value)

                TESLA_MESSAGE init_tesla(const string&);
                // need function to disclose hashes ever t
                std::string hash_disclosure();
                // need to function that actually allows us to send messages with MACs
                void recv(json&);
                std::set<msg> mac_q;
            private:
                string addr;
                const unsigned int key_lifetime = 10800; // 10800 seconds
                const unsigned int numKeys = key_lifetime / disclosure_time;
                // unsigned char (*hashChain)[SHA256_DIGEST_LENGTH];
                std::deque<std::string> hash_chain;

                void send(int);
                std::string sha256(const std::string&);
                std::string createHMAC(const std::string& key, const std::string& data);
                void generateHashChain();
                void compareHashes(const unsigned char *hash1, const unsigned char *hash2);
        };

        TESLA tesla;

        int broadcastMessage(const string& msg);
        void sendData(string containerName, const string& msg);
        void setupPhase();
        string sha256(const string& inn);
        void initMessageHandler(json& data);
        void routeRequestHandler(json& data);
        void routeReplyHandler(json& data);
        void routeErrorHandler(MESSAGE &msg);
        void clientResponseThread(int newSD, const string& msg);
        void initRouteDiscovery(json& data);
        void verifyRouteHandler(json& data);
        void neighborDiscoveryUDPHANDLER();
    private:
        const uint8_t max_hop_count = 8; // hardcoded for a max hop count to be 8; meaning 8 drones can be in a chain at one time

};

#endif