#ifndef GCS_HPP
#define GCS_HPP
#define PORT_NUMBER 65456
#include <iostream>
#include <cstring>
#include <cstdlib>
#include <vector>
#include <csignal>
#include <unistd.h>
#include <string>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <netdb.h>


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

// copied over generic message type for now
struct MESSAGE {
    MESSAGE_TYPE type;
    int srcID;
    unsigned long MAC;
    std::string srcIP;
    int destID;
    int ttl;
    std::vector<int> path; // TODO: temporary, will find more space efficient/time efficient way to store routing address
};

// class GCS{
//     public:
//         void initalizeServer();
// }


#endif