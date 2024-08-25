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
#include <vector>

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
    HELLO, // Broadcast Msg
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

struct RERR : public MESSAGE {
    std::vector<string> nonce_list;
    std::vector<string> tsla_list;
    std::vector<string> dst_list;
    std::vector<string> auth_list;

    RERR() {}

    RERR(std::vector<string> nonce_list, std::vector<string> tsla_list, std::vector<string> dst_list, std::vector<string> auth_list) {
        this->nonce_list = nonce_list;
        this->tsla_list = tsla_list;
        this->dst_list = dst_list;
        this->auth_list = auth_list;
    }

    void create_rerr(const std::vector<string>& nonce_list, 
                            const std::vector<string>& tsla_list, 
                            const std::vector<string>& dst_list, 
                            const std::vector<string>& auth_list) {
        this->nonce_list = nonce_list;
        this->tsla_list = tsla_list;
        this->dst_list = dst_list;
        this->auth_list = auth_list;
    }

    void create_rerr_prime(const string& nonce, const string& dst, const string& auth) {
        this->nonce_list = {nonce};
        this->tsla_list = {};  // Empty for RERR'
        this->dst_list = {dst};
        this->auth_list = {auth};
    }

    string serialize() const override {
        json j = json{
            {"type", this->type},
            {"nonce_list", this->nonce_list},
            {"tsla_list", this->tsla_list},
            {"dst_list", this->dst_list},
            {"auth_list", this->auth_list}
        };
        return j.dump();
    }

    void deserialize(json& j) override {
        this->type = j["type"];
        this->nonce_list = j["nonce_list"].get<std::vector<string>>();
        this->tsla_list = j["tsla_list"].get<std::vector<string>>();
        this->dst_list = j["dst_list"].get<std::vector<string>>();
        this->auth_list = j["auth_list"].get<std::vector<string>>();
    }
};

struct HERR {
    string hRERR;
    string mac_t;

    HERR() {}

    HERR(string hash, string mac){
        this->hRERR = hash;
        this->mac_t = mac;
    }

    static HERR create(const RERR& future_rerr, const string& tesla_key) {
        string hash = compute_hash(future_rerr);
        string mac = compute_mac(hash, tesla_key);
        return HERR(hash, mac);
    }

    bool verify(const RERR& rerr, const string& tesla_key) const {
        string computed_hash = compute_hash(rerr);
        string computed_mac = compute_mac(computed_hash, tesla_key);
        return (computed_hash == hRERR) && (computed_mac == mac_t);
    }
    
    json to_json() const {
        return json{
            {"hRERR", hRERR},
            {"mac_t", mac_t}
        };
    }

    static HERR from_json(const json& j) {
        return HERR(j["hRERR"], j["mac_t"]);
    }

    private:
    static string compute_hash(const RERR& rerr) {
        string serialized_rerr = rerr.serialize();
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256_CTX sha256;
        SHA256_Init(&sha256);
        SHA256_Update(&sha256, serialized_rerr.c_str(), serialized_rerr.size());
        SHA256_Final(hash, &sha256);
        std::stringstream ss;
        for(int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
            ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
        }
        return ss.str();
    }

    static string compute_mac(const std::string& data, const std::string& key) {
        unsigned char digest[EVP_MAX_MD_SIZE];
        unsigned int digest_len;

        HMAC(EVP_sha256(), 
            key.c_str(), key.length(),
            reinterpret_cast<const unsigned char*>(data.c_str()), data.length(),
            digest, &digest_len);

        std::stringstream ss;
        for(unsigned int i = 0; i < digest_len; i++) {
            ss << std::hex << std::setw(2) << std::setfill('0') << (int)digest[i];
        }
        return ss.str();
    }

};

struct RREQ : public MESSAGE {
    string srcAddr;
    string intermediateAddr; // temp field used to store next hop addr, since we are using services, cannnot directly extract last recieved ip
    string destAddr; 
    unsigned long srcSeqNum;
    unsigned long destSeqNum;
    string hash;
    string rootHash;
    std::vector<string> hashTree; // can optimize later to use memory more efficiently
    unsigned long hopCount;
    HERR herr;
    int ttl; // Max number of hops allowed for RREQ to propagate through network

    RREQ() {
        this->type = ROUTE_REQUEST;
        this->srcSeqNum = 0;
        this->destSeqNum = 0;
        this->hash = "";
        this->hopCount = 0;
        this->rootHash = "";
        this->ttl = 0;
    }

    RREQ(string srcAddr, string interAddr, string destAddr, unsigned long srcSeqNum, unsigned long destSeqNum, 
         string hash, unsigned long hopCount, HERR herr, std::vector<string> hashTree, int ttl, string rootHash) {
        this->type = ROUTE_REQUEST;
        this->srcAddr = srcAddr;
        this->intermediateAddr = interAddr;
        this->destAddr = destAddr;
        this->srcSeqNum = srcSeqNum;
        this->destSeqNum = destSeqNum;
        this->hash = hash;
        this->hopCount = hopCount;
        this->herr = herr;
        this->hashTree = hashTree;
        this->ttl = ttl;
        this->rootHash = rootHash;
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
            {"hashTree", this->hashTree},
            {"ttl", this->ttl},
            {"rootHash", this->rootHash},
            {"herr", this->herr.to_json()}
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
        this->hashTree = j["hashTree"].get<std::vector<string>>();
        this->ttl = j["ttl"];
        this->rootHash = j["rootHash"];
        this->herr = HERR::from_json(j["herr"]);
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
    HERR herr;
    int ttl;

    RREP() {
        this->type = ROUTE_REPLY;
        this->srcSeqNum = 0;
        this->destSeqNum = 0;
        this->hash = "";
        this->hopCount = 0;
        this->ttl = 0;
    }

    RREP(string srcAddr, string destAddr, unsigned long srcSeqNum, unsigned long destSeqNum, string hash, unsigned long hopCount, HERR herr, int ttl) {
        this->type = ROUTE_REPLY;
        this->srcAddr = srcAddr;
        this->destAddr = destAddr;
        this->srcSeqNum = srcSeqNum;
        this->destSeqNum = destSeqNum;
        this->hash = hash;
        this->hopCount = hopCount;
        this->herr = herr;
        this->ttl = ttl;
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
            {"herr", this->herr.to_json()},
            {"ttl", this->ttl}
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
        this->herr = HERR::from_json(j["herr"]);
        this->ttl = j["ttl"];
    }

};

struct INIT_MESSAGE : public MESSAGE { // Can possibly collapse this in the future with TESLA_MESSAGE
    enum INIT_MODE {
        AUTH,
        TESLA
    };
    INIT_MODE mode;
    string hash;
    string srcAddr;
    int disclosure_time;

    INIT_MESSAGE() {
        this->type = HELLO;
        hash = "";
        srcAddr = "";
    }

    INIT_MESSAGE(string hash, string addr) {
        this->type = HELLO;
        this->hash = hash;
        this->srcAddr = addr;
    }

    void set_tesla_init(string srcAddr, string hash, int disclosure_time) {
        this->srcAddr = srcAddr;
        this->hash = hash;
        this->disclosure_time = disclosure_time;
        this->mode = TESLA;
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

struct DATA_MESSAGE : public MESSAGE {
    string destAddr;
    string data;

    DATA_MESSAGE() {
        this->type = DATA;
        this->destAddr = "";
        this->data = "";
    }

    DATA_MESSAGE(string srcAddr, string destAddr, string data) {
        this->type = DATA;
        this->destAddr = destAddr;
        this->data = data;
    }

    string serialize() const override {
        json j = json{
            {"type", this->type},
            {"destAddr", this->destAddr},
            {"data", this->data}
        };
        return j.dump();
    }

    void deserialize(json& j) override {
        this->type = j["type"];
        this->destAddr = j["destAddr"];
        this->data = j["data"];
    }
};

#endif