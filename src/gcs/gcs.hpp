#ifndef GCS_HPP
#define GCS_HPP
#define PORT_NUMBER 65456
#include <iostream>
#include <cstring>
#include <cstdlib>
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
    ROUTE_REQUEST,
    ROUTE_REPLY, 
    ROUTE_ERROR,
    DATA,
    TEST
};

// copied over generic message type for now
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

// class GCS{
//     public:
//         void initalizeServer();
// }


#endif