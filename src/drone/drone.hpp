#ifndef DRONE_HPP
#define DRONE_HPP
#define PORT_NUMBER 80
#define BRDCST_PORT 65457
#include <iostream>
#include <cstring>
#include <mutex>
#include <cstdlib>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <tuple>
#include <thread>
#include <set>
#include <deque>
#include <queue>
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
#include "routingMap.hpp"
#include "routingTableEntry.hpp"
#include "multi_index_container.hpp"

using json = nlohmann::json;
using std::cout;
using std::endl;
using std::string;

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

                RoutingMap<string, ROUTING_TABLE_ENTRY> routingTable;
                const unsigned int disclosure_time = std::stoul((std::getenv("TESLA_DISCLOSE")));

                TESLA_MESSAGE init_tesla(const string&);
                // need function to disclose hashes ever t
                std::string hash_disclosure();
                // need to function that actually allows us to send messages with MACs
                void recv(json&);
                std::set<msg> mac_q;
            private:
                string addr;
                const unsigned int key_lifetime = 10800; // Hardcoded: 10800 seconds
                PacketStore packetStore;
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

        void broadcastUDP(const string& msg); // This function will be replaced with just sending data through the broadcast address outside simulation
        void sendData(string containerName, const string& msg);
        int sendDataUDP(const string&, const string&);
        string sha256(const string& inn);
        void initMessageHandler(json& data);
        void routeRequestHandler(json& data);
        void routeReplyHandler(json& data);
        void routeErrorHandler(MESSAGE &msg);
        void clientResponseThread(const string& msg);
        void initRouteDiscovery(json& data);
        void verifyRouteHandler(json& data);
        void neighborDiscoveryFunction();
        void neighborDiscoveryHelper();
    private:
        const uint8_t max_hop_count = std::stoul((std::getenv("MAX_HOP_COUNT")));; // Maximum number of nodes we can/allow route through

        std::chrono::steady_clock::time_point helloRecvTimer = std::chrono::steady_clock::now();
        const unsigned int helloRecvTimeout = 5; // Acceptable time to wait for a hello message
        std::mutex helloRecvTimerMutex, routingTableMutex;
 
};

#endif