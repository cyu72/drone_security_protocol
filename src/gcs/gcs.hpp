#ifndef GCS_HPP
#define GCS_HPP
#define PORT_NUMBER 80
#include <iostream>
#include <cstring>
#include <cstdlib>
#include <vector>
#include <csignal>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <netdb.h>
#include <nlohmann/json.hpp>

using json = nlohmann::json;
using std::cout;
using std::endl;
using std::string;

enum MESSAGE_TYPE {
    ROUTE_REQUEST = 0,
    ROUTE_REPLY, 
    ROUTE_ERROR,
    DATA,
    INIT_ROUTE_DISCOVERY, // GCS -> Drone to initiate route discovery
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

    GCS_MESSAGE(std::string srcAddr, std::string destAddr, MESSAGE_TYPE type) {
        this->type = type;
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
    unsigned long srcSeqNum;
    unsigned long destSeqNum;
    string hash;
    unsigned long hopCount;
    int HERR; // temp placeholder for what HERR should be

    RREQ() {
        this->type = ROUTE_REQUEST;
        this->srcSeqNum = 0;
        this->destSeqNum = 0;
        this->hash = "";
        this->hopCount = 0;
        this->HERR = 0;
    }

    RREQ(string srcAddr, string destAddr, unsigned long srcSeqNum, unsigned long destSeqNum, string hash, unsigned long hopCount, int HERR) {
        this->type = ROUTE_REQUEST;
        this->srcAddr = srcAddr;
        this->destAddr = destAddr;
        this->srcSeqNum = srcSeqNum;
        this->destSeqNum = destSeqNum;
        this->hash = hash;
        this->hopCount = hopCount;
        this->HERR = HERR;
    }

    string serialize() const override {
        json j = json{
            {"type", this->type},
            {"srcAddr", this->srcAddr},
            {"destAddr", this->destAddr},
            {"srcSeqNum", this->srcSeqNum},
            {"destSeqNum", this->destSeqNum},
            {"hash", this->hash},
            {"hopCount", this->hopCount},
            {"HERR", this->HERR}
        };
        return j.dump();
    }

    void deserialize(json& j) override {
        this->type = j["type"];
        this->srcAddr = j["srcAddr"];
        this->destAddr = j["destAddr"];
        this->srcSeqNum = j["srcSeqNum"];
        this->destSeqNum = j["destSeqNum"];
        this->hash = j["hash"];
        this->hopCount = j["hopCount"];
        this->HERR = j["HERR"];
    }
};

struct RREP : public MESSAGE {
    string srcAddr;
    string destAddr;
    unsigned long srcSeqNum;
    unsigned long destSeqNum;
    string hash;
    unsigned long hopCount;
    int HERR; // temp placeholder for what HERR should be

    RREP() {
        this->type = ROUTE_REPLY;
        this->srcSeqNum = 0;
        this->destSeqNum = 0;
        this->hash = "";
        this->hopCount = 0;
        this->HERR = 0;
    }

    RREP(string srcAddr, string destAddr, unsigned long RREQ_ID, unsigned long srcSeqNum, unsigned long destSeqNum, string hash, unsigned long hopCount, int HERR) {
        this->type = ROUTE_REPLY;
        this->srcAddr = srcAddr;
        this->destAddr = destAddr;
        this->srcSeqNum = srcSeqNum;
        this->destSeqNum = destSeqNum;
        this->hash = hash;
        this->hopCount = hopCount;
        this->HERR = HERR;
    }

    string serialize() const override {
        json j = json{
            {"type", this->type},
            {"srcAddr", this->srcAddr},
            {"destAddr", this->destAddr},
            {"srcSeqNum", this->srcSeqNum},
            {"destSeqNum", this->destSeqNum},
            {"hash", this->hash},
            {"hopCount", this->hopCount},
            {"HERR", this->HERR}
        };
        return j.dump();
    }

    void deserialize(json& j) override {
        this->type = j["type"];
        this->srcAddr = j["srcAddr"];
        this->destAddr = j["destAddr"];
        this->srcSeqNum = j["srcSeqNum"];
        this->destSeqNum = j["destSeqNum"];
        this->hash = j["hash"];
        this->hopCount = j["hopCount"];
        this->HERR = j["HERR"];
    }

};

struct INIT_MESSAGE : public MESSAGE {
    string hash;
    string srcAddr;

    INIT_MESSAGE() {
        this->type = INIT_MSG;
        hash = "";
        srcAddr = "";
    }

    INIT_MESSAGE(string hash, string addr) {
        this->type = INIT_MSG;
        this->hash = hash;
        this->srcAddr = addr;
    }

    string serialize() const override {
        json j = json{
            {"type", this->type},
            {"hash", this->hash},
            {"srcAddr", this->srcAddr}
        };
        return j.dump();
    }

    void deserialize(json& j) override {
        this->type = j["type"];
        this->hash = j["hash"];
        this->srcAddr = j["srcAddr"];
    }
    
};

struct ROUTING_TABLE_ENTRY {
    string destID;
    int nextHopID;
    int seqNum;
    int cost;
    int ttl;
    string hash;

    ROUTING_TABLE_ENTRY(){
        this->destID = "";
        this->nextHopID = -1;
        this->seqNum = -1;
        this->cost = -1;
        this->ttl = -1;
        this->hash = "";
    }

    ROUTING_TABLE_ENTRY(string destID, int nextHopID, int seqNum, int cost, int ttl, string hash){
        this->destID = destID;
        this->nextHopID = nextHopID;
        this->seqNum = seqNum;
        this->cost = cost;
        this->ttl = ttl;
        this->hash = hash;
    }
};


#endif