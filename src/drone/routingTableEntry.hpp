#pragma once
#include <iostream>
#include <tuple>
#include <chrono>

using std::string;
using std::cout;
using std::endl;

struct ROUTING_TABLE_ENTRY {
    /*TODO: Add TESLA MAC QUEUE and ENSUING INFORMATION AND NEW VARIABLE OF HOW OFTEN THIS TABLE GETS CLEANED UP*/
    string destAddr;
    string nextHopID; // srcAddr = destAddr if neighbor
    int seqNum; // Destination SeqNum
    int cost; // HopCount to reach destination
    std::chrono::system_clock::time_point ttl; // Starting Timestamp at which this entry was created
    string tesla_hash;
    std::chrono::seconds tesla_disclosure_time;
    string hash;
    bool has_mac = false; // tells us if we are waiting for a haskey to decrypt a mac message for this node

    ROUTING_TABLE_ENTRY(){
        this->destAddr = "ERR";
        this->nextHopID = "ERR";
        this->seqNum = -1;
        this->cost = -1;
        this->ttl = std::chrono::system_clock::now(); // Starting Timestamp at which this entry was created
        this->hash = "";
        this->tesla_hash = "ERR";
        this->tesla_disclosure_time = std::chrono::seconds(0);
    }

    // TODO: Must fix all instances of ttl
    ROUTING_TABLE_ENTRY(string destAddr, string nextHopID, int seqNum, int cost, std::chrono::system_clock::time_point ttl, string hash){
        this->destAddr = destAddr;
        this->nextHopID = nextHopID;
        this->seqNum = seqNum;
        this->cost = cost;
        this->ttl = ttl;
        this->hash = hash; // What is this field supposed to contain again
    }

    void print() {
        auto ttl_seconds = std::chrono::duration_cast<std::chrono::seconds>(ttl.time_since_epoch()).count();
        cout << "Routing entry: " << "destAddr: " << destAddr << ", nextHopID: " << nextHopID << ", seqNum: " << seqNum << ", cost: " << cost << ", ttl: " << ttl_seconds << " seconds, hash: " << hash << endl;
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

    friend std::ostream& operator<<(std::ostream& os, const ROUTING_TABLE_ENTRY& entry) {
        os << "{ destAddr: " << entry.destAddr << ", nextHopID: " << entry.nextHopID
           << ", seqNum: " << entry.seqNum << ", cost: " << entry.cost
           << ", ttl: " << std::chrono::duration_cast<std::chrono::seconds>(entry.ttl.time_since_epoch()).count() << " seconds, hash: " << entry.hash << " }";
        return os;
    }
};
