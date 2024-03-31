#ifndef MESSAGES_HPP
#define MESSAGES_HPP
#include <string>
#include <iostream>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <stdexcept>
#include <sstream>
#include <iomanip>
#include <netdb.h>
#include <nlohmann/json.hpp>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <chrono>

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
    VERIFY_ROUTE,
    TEST,
    INIT_MSG, // used to init drone swarm
    TESLA_MSG,
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
    string intermediateAddr; // temp field used to store next hop addr, since we are using services, cannnot directly extract last recieved ip
    string destAddr; 
    unsigned long srcSeqNum;
    unsigned long destSeqNum;
    string hash;
    std::vector<string> hashTree; // can optimize later to use memory more efficiently
    unsigned long hopCount;
    int HERR; // temp placeholder for what HERR should be

    RREQ() {
        this->type = ROUTE_REQUEST;
        this->srcSeqNum = 0;
        this->destSeqNum = 0;
        this->hash = "";
        this->hopCount = 0;
        this->HERR = 0;
        this->hashTree = {};
    }

    RREQ(string srcAddr, string destAddr, unsigned long srcSeqNum, unsigned long destSeqNum, string hash, unsigned long hopCount, int HERR, std::vector<string> hashTree) {
        this->type = ROUTE_REQUEST;
        this->srcAddr = srcAddr;
        this->destAddr = destAddr;
        this->srcSeqNum = srcSeqNum;
        this->destSeqNum = destSeqNum;
        this->hash = hash;
        this->hopCount = hopCount;
        this->HERR = HERR;
        this->hashTree = hashTree;
    }

    string serialize() const override {
        json j = json{
            {"type", this->type},
            {"srcAddr", this->srcAddr},
            {"destAddr", this->destAddr},
            {"intermediateAddr", this->intermediateAddr},
            {"srcSeqNum", this->srcSeqNum},
            {"destSeqNum", this->destSeqNum},
            {"hash", this->hash},
            {"hopCount", this->hopCount},
            {"HERR", this->HERR},
            {"hashTree", this->hashTree}

        };
        return j.dump();
    }

    void deserialize(json& j) override {
        this->type = j["type"];
        this->srcAddr = j["srcAddr"];
        this->destAddr = j["destAddr"];
        this->intermediateAddr = j["intermediateAddr"];
        this->srcSeqNum = j["srcSeqNum"];
        this->destSeqNum = j["destSeqNum"];
        this->hash = j["hash"];
        this->hopCount = j["hopCount"];
        this->HERR = j["HERR"];
        this->hashTree = j["hashTree"].get<std::vector<string>>();
    }
};

struct RREP : public MESSAGE {
    string srcAddr;
    string intermediateAddr; // same temp field as RREQ
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

    RREP(string srcAddr, string destAddr, unsigned long srcSeqNum, unsigned long destSeqNum, string hash, unsigned long hopCount, int HERR) {
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
            {"intermediateAddr", this->intermediateAddr},
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
        this->intermediateAddr = j["intermediateAddr"];
        this->srcSeqNum = j["srcSeqNum"];
        this->destSeqNum = j["destSeqNum"];
        this->hash = j["hash"];
        this->hopCount = j["hopCount"];
        this->HERR = j["HERR"];
    }

};

struct INIT_MESSAGE : public MESSAGE { // Can possibly collapse this in the future with TESLA_MESSAGE
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

struct RERR : public MESSAGE { // INCOMPLETE
    string srcAddr;
    string destAddr;
    unsigned long destSeqNum;
    string auth;
    string MAC;
    unsigned long hopCount;
    int HERR;

    RERR() {
        this->type = ROUTE_ERROR;
        this->destSeqNum = 0;
        this->auth = "";
        this->MAC = "";
        this->hopCount = 0;
        this->HERR = 0;
    }

    string serialize() const override {
        json j = json{
            {"type", this->type},
            {"srcAddr", this->srcAddr},
            {"destAddr", this->destAddr},
            {"destSeqNum", this->destSeqNum},
            {"auth", this->auth},
            {"MAC", this->MAC},
            {"hopCount", this->hopCount},
            {"HERR", this->HERR}
        };
        return j.dump();
    }

    void deserialize(json& j) override {
        this->type = j["type"];
        this->srcAddr = j["srcAddr"];
        this->destAddr = j["destAddr"];
        this->destSeqNum = j["destSeqNum"];
        this->auth = j["auth"];
        this->MAC = j["MAC"];
        this->hopCount = j["hopCount"];
        this->HERR = j["HERR"];
    }
};

struct TESLA_MESSAGE : public MESSAGE {
    enum TSLA_MODE {
        INIT,
        DATA, // for case RERR
        DISCLOSE
    };

    string srcAddr;
    string hashKey;
    string mac;
    string data;
    int disclosure_time;
    TSLA_MODE mode;

    TESLA_MESSAGE() {
        this->type = TESLA_MSG;
        this->hashKey = "ERR";
    }
    
    void set_init(string srcAddr, string hashKey, int disclosure_time) {
        this->srcAddr = srcAddr;
        this->mode = INIT;
        this->hashKey = hashKey;
        this->disclosure_time = disclosure_time;
    }

    void set_disclose(string srcAddr, string hashKey) {
        this->srcAddr = srcAddr;
        this->mode = DISCLOSE;
        this->hashKey = hashKey;
    }

    void set_data(string srcAddr, string mac, string data) {
        this->srcAddr = srcAddr;
        this->mode = DATA;
        this->mac = mac;
        this->data = data;
    }

    string serialize() const override {
        json j = json{
            {"srcAddr", this->srcAddr},
            {"type", this->type},
            {"hashKey", this->hashKey},
            {"disclosure_time", this->disclosure_time},
            {"mode", this->mode},
            {"mac", this->mac},
            {"data", this->data}
        };
        return j.dump();
    }

    void deserialize(json& j) override {
        this->srcAddr = j["srcAddr"];
        this->type = j["type"];
        this->hashKey = j["hashKey"];
        this->disclosure_time = j["disclosure_time"];
        this->mode = j["mode"];
        this->mac = j["mac"];
        this->data = j["data"];
    }
};

#endif