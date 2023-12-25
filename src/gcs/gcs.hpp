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

    virtual std::string serialize() const = 0;
    virtual void deserialize(json&j) = 0;
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
    std::string srcAddr;
    std::string destAddr; 
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

    RREQ(std::string srcAddr, std::string destAddr, unsigned long RREQ_ID, unsigned long srcSeqNum, unsigned long destSeqNum, int hashFunction, unsigned long hopCount, int HERR) {
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

    void print() {
        std::cout << "RREQ: " << std::endl;
        std::cout << "srcAddr: " << srcAddr << std::endl;
        std::cout << "destAddr: " << destAddr << std::endl;
        std::cout << "RREQ_ID: " << RREQ_ID << std::endl;
        std::cout << "srcSeqNum: " << srcSeqNum << std::endl;
        std::cout << "destSeqNum: " << destSeqNum << std::endl;
        std::cout << "hashFunction: " << hashFunction << std::endl;
        std::cout << "hopCount: " << hopCount << std::endl;
        std::cout << "HERR: " << HERR << std::endl;
    }

    std::string serialize() const override {
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


#endif