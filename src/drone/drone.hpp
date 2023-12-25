#ifndef DRONE_HPP
#define DRONE_HPP
#define PORT_NUMBER 80
#include <iostream>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <thread>
#include <vector>
#include <unordered_set>
#include <stdexcept>
#include <sstream>
#include <iomanip>
#include <netdb.h>
#include <nlohmann/json.hpp>
#include <openssl/sha.h>
#include <openssl/rand.h>

using json = nlohmann::json;
using std::cout;
using std::endl;
using std::string;

enum MESSAGE_TYPE {
    ROUTE_REQUEST = 0,
    ROUTE_REPLY, 
    ROUTE_ERROR,
    DATA,
    INIT_ROUTE_DISCOVERY, // temp
    NEIGHBOR_PING, // temp
    TEST,
    INIT_MSG, // used to init drone swarm
    EXIT
};

struct MESSAGE {
    MESSAGE_TYPE type;
    virtual string serialize() const = 0;
    virtual void deserialize(json& j) = 0;
    virtual ~MESSAGE() = default;
};

struct GCS_MESSAGE : public MESSAGE { // used as a means to send gcs msgs
    std::string srcAddr;
    std::string destAddr;

    GCS_MESSAGE() {
        this->type = DATA;
        this->srcAddr = "NILL";
        this->destAddr = "NILL";
    }

    GCS_MESSAGE(std::string srcAddr, std::string destAddr, std::string msg) {
        this->type = DATA;
        this->srcAddr = srcAddr;
        this->destAddr = destAddr;
    }

    std::string serialize() const override {
        json j = json{
            {"type", this->type},
            {"srcAddr", this->srcAddr},
            {"destAddr", this->destAddr},
        };
        cout << j.dump() << endl;
        return j.dump();
    }

    void deserialize(json& j) override {
        this->type = j["type"];
        this->srcAddr = j["srcAddr"];
        this->destAddr = j["destAddr"];
    }
};

struct RREQ : public MESSAGE {
    string srcAddr;
    string destAddr; 
    unsigned long RREQ_ID;
    unsigned long srcSeqNum;
    unsigned long destSeqNum;
    int hashFunction; // temp placeholder for what hashfunction should be
    unsigned long hopCount;
    int HERR; // temp placeholder for what HERR should be

    RREQ() {
        this->type = ROUTE_REQUEST;
        this->RREQ_ID = 0;
        this->srcSeqNum = 0;
        this->destSeqNum = 0;
        this->hashFunction = 0;
        this->hopCount = 0;
        this->HERR = 0;
    }

    RREQ(string srcAddr, string destAddr, unsigned long RREQ_ID, unsigned long srcSeqNum, unsigned long destSeqNum, int hashFunction, unsigned long hopCount, int HERR) {
        this->type = ROUTE_REQUEST;
        this->srcAddr = srcAddr;
        this->destAddr = destAddr;
        this->RREQ_ID = RREQ_ID;
        this->srcSeqNum = srcSeqNum;
        this->destSeqNum = destSeqNum;
        this->hashFunction = hashFunction;
        this->hopCount = hopCount;
        this->HERR = HERR;
    }

    string serialize() const override {
        json j = json{
            {"type", this->type},
            {"srcAddr", this->srcAddr},
            {"destAddr", this->destAddr},
            {"RREQ_ID", this->RREQ_ID},
            {"srcSeqNum", this->srcSeqNum},
            {"destSeqNum", this->destSeqNum},
            {"hashFunction", this->hashFunction},
            {"hopCount", this->hopCount},
            {"HERR", this->HERR}
        };
        return j.dump();
    }

    void deserialize(json& j) override {
        this->type = j["type"];
        this->srcAddr = j["srcAddr"];
        this->destAddr = j["destAddr"];
        this->RREQ_ID = j["RREQ_ID"];
        this->srcSeqNum = j["srcSeqNum"];
        this->destSeqNum = j["destSeqNum"];
        this->hashFunction = j["hashFunction"];
        this->hopCount = j["hopCount"];
        this->HERR = j["HERR"];
    }
};

struct INIT_MESSAGE : public MESSAGE {
    string hash;

    INIT_MESSAGE() {
        this->type = INIT_MSG;
        hash = "";
    }

    INIT_MESSAGE(string hash) {
        this->type = INIT_MSG;
        this->hash = hash;
    }

    string serialize() const override {
        json j = json{
            {"type", this->type},
            {"hash", this->hash}
        };
        return j.dump();
    }

    void deserialize(json& j) override {
        this->type = j["type"];
        this->hash = j["hash"];
    }
    
};

struct ROUTING_TABLE_ENTRY {
    int destID;
    int nextHopID;
    int seqNum;
    int cost;
    int ttl;
};

class drone {
    public: // everything public for now
        string addr;
        int port;
        unsigned long seqNum;
        int nodeID;
        std::vector<drone> neighbors; // each int represnets a droneID
        std::vector<ROUTING_TABLE_ENTRY> routingTable;
        std::vector<string> hashChainCache; // I dont know if we want to actually store them or not 
        std::unordered_set<unsigned long> RREQ_cache; // TODO: temp: will find more space efficent way to cache
        std::unordered_set<unsigned long> RREP_cache; // TODO: temp: will find more space efficent way to cache

        drone(){
            this->addr = -1;
            this->port = -999;
            this->nodeID = -1;
            this->seqNum = 0;
        }

        drone(string addr, int port, int nodeID){
            this->addr = "drone" + std::to_string(nodeID) + "-service.default";
            this->port = port;
            this->nodeID = nodeID;
            this->seqNum = 1;
        }

        int broadcastMessage(const string& msg);
        void setupPhase();
        string sha256(const string& inn);
        void initMessageHandler(json& data, const int& newSD);
        void routeRequestHandler(MESSAGE& msg, const int& newSD);
        void routeReplyHandler(MESSAGE &msg, const int& newSD);
        void routeErrorHandler(MESSAGE &msg, const int& newSD);
        void clientResponseThread(int newSD, const string& msg);
        void initRouteDiscovery(const string& srcNodeID, const string& destNodeID);

};

#endif