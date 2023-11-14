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

enum MESSAGE_TYPE {
    ROUTE_REQUEST = 0,
    ROUTE_REPLY, 
    ROUTE_ERROR,
    DATA,
    INIT_ROUTE_DISCOVERY, // temp
    NEIGHBOR_PING, // temp
    TEST
};

// using a generic message type for now
struct MESSAGE {
    MESSAGE_TYPE type;
    int hopCount;
    int RRQID; // is this supposed to be int?
    int srcID;
    std::string srcIP;
    int srcSeqNum;
    int destID;
    int destSeqNum;
    int ttl;
    int length;
    char data[1024];
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
        int nodeID;
        std::vector<drone> neighbors; // each int represnets a droneID

        drone(){
            this->addr = -1;
            this->port = -999;
            this->nodeID = -1;
        }

        drone(std::string addr, int port, int nodeID){
            this->addr = addr;
            this->port = port;
            this->nodeID = nodeID;
        }

        void findNeighbors(int socket);
        void routeRequestHandler(MESSAGE& msg, const int& newSD);
        void routeReplyHandler(MESSAGE &msg, const int& newSD);
        void clientResponseThread(int newSD, MESSAGE &msg);
        void hostResponseThread(int newSD); // i dont remember what this was supposed to do
        void initRouteDiscovery(const int& newSD, const int& srcNodeID, const int& destNodeID);

};

#endif