#ifndef DRONE_HPP
#define DRONE_HPP
#include <iostream>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <thread>
#include <vector>
#include <unordered_set>

enum MESSAGE_TYPE {
    ROUTE_REQUEST = 0,
    ROUTE_REPLY, 
    ROUTE_ERROR,
    DATA,
    INIT_ROUTE_DISCOVERY, // temp
    NEIGHBOR_PING, // temp
    TEST,
    EXIT
};

// using a generic message type for now
struct MESSAGE {
    MESSAGE_TYPE type;
    int srcID;
    int destID;
    unsigned long MAC;
    std::string srcIP;
    std::string destIP;
    int ttl;
    std::vector<std::string> path; // TODO: temporary, will find more space efficient/time efficient way to store routing address
    int iteration;
};

struct ROUTING_TABLE_ENTRY {
    int destID;
    int nextHopID;
    int cost;
    int ttl;
};

class drone {
    public: // everything public for now
        std::string addr;
        int port; // modify these values to fit sendto() function
        std::string nodeIP;
        int nodeID;
        std::vector<drone> neighbors; // each int represnets a droneID
        std::unordered_set<unsigned long> RREQ_cache; // TODO: temp: will find more space efficent way to cache
        std::unordered_set<unsigned long> RREP_cache; // TODO: temp: will find more space efficent way to cache

        drone(){
            this->addr = -1;
            this->port = -999;
            this->nodeID = -1;
        }

        drone(std::string addr, int port, int nodeID){
            this->addr = addr;
            this->port = port;
            this->nodeID = nodeID;
            this->nodeIP = "drone_security_protocol-drone" + std::to_string(nodeID) + "-1";
        }

        int broadcastMessage(const int& sockfd, const MESSAGE& msg);
        void routeRequestHandler(MESSAGE& msg, const int& newSD);
        void routeReplyHandler(MESSAGE &msg, const int& newSD);
        void clientResponseThread(int newSD, MESSAGE &msg);
        void hostResponseThread(int newSD); // i dont remember what this was supposed to do
        void initRouteDiscovery(const int& newSD, const int& srcNodeID, const int& destNodeID);

};

#endif