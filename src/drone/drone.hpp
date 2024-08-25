#ifndef DRONE_HPP
#define DRONE_HPP
#define PORT_NUMBER 80
#define BRDCST_PORT 65457
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
#include <vector>
#include <random>
#include <sstream>
#include <iostream>
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
#include "network_adapters/kube_udp_interface.hpp"
#include "network_adapters/tcp_interface.hpp"

using json = nlohmann::json;
using std::cout;
using std::endl;
using std::string;

class drone {
    public:
        drone();
        drone(int port, int nodeID);
        void start();
        int send(const string&, const string&);

    private:
        class TESLA {
            public:
                TESLA();
                ~TESLA();

                RoutingMap<string, ROUTING_TABLE_ENTRY> routingTable;
                const std::chrono::seconds disclosure_interval = std::chrono::seconds(std::stoul(std::getenv("TESLA_DISCLOSE")));
                INIT_MESSAGE init_tesla(const string&);
                string getCurrentHash();

            private:
                struct TimedHash {
                    std::chrono::system_clock::time_point disclosure_time;
                    std::string hash;
                };

                string addr;
                const unsigned int key_lifetime = 10800; // Hardcoded: 10800 seconds
                const unsigned int numKeys = key_lifetime / disclosure_interval.count();
                // unsigned char (*hashChain)[SHA256_DIGEST_LENGTH];

                std::string sha256(const std::string&);
                std::string createHMAC(const std::string& key, const std::string& data);
                void generateHashChain();
                void compareHashes(const unsigned char *hash1, const unsigned char *hash2);

                /* We can associate each nonce/auth with the specific disclosure time, starting with the beginning of the array at time 0, time n, time 2n, etc. where n is the disclosure time */
                std::vector<string> nonce_list;
                std::deque<TimedHash> timed_hash_chain;
        };
        TESLA tesla;

        string addr;
        int port;
        unsigned long seqNum;
        int nodeID;
        std::deque<string> hashChainCache; 

        void broadcast(const string& msg); // This function will be replaced with just sending data through the broadcast address outside simulation
        void sendData(string containerName, const string& msg);
        void sendDataUDP(const string&, const string&);
        string sha256(const string& inn);
        void initMessageHandler(json& data);
        void routeRequestHandler(json& data);
        void routeReplyHandler(json& data);
        void routeErrorHandler(MESSAGE &msg);
        void clientResponseThread(const string& msg);
        void initRouteDiscovery(const string&);
        void verifyRouteHandler(json& data);
        void neighborDiscoveryFunction();
        void neighborDiscoveryHelper();

        const uint8_t max_hop_count = std::stoul((std::getenv("MAX_HOP_COUNT")));; // Maximum number of nodes we can/allow route through
        UDPInterface udpInterface;
        TCPInterface tcpInterface;

        std::chrono::steady_clock::time_point helloRecvTimer = std::chrono::steady_clock::now();
        const unsigned int helloRecvTimeout = 5; // Acceptable time to wait for a hello message
        std::mutex helloRecvTimerMutex, routingTableMutex;

        string generate_nonce(const size_t length = 16);
 
};

#endif