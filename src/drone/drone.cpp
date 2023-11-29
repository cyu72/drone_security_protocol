#include "drone.hpp"

void drone::clientResponseThread(int newSD, MESSAGE &msg){
    // function to handle all incoming messages from the client
    // check what type of message it is; launch the function to handle whatever type it is
    std::cout << "Recieved a message." << std::endl; 
    std::cout << "Message type: " << msg.type << std::endl;
    switch(msg.type){
        case ROUTE_REQUEST:
            routeRequestHandler(msg, newSD);
            break;
        case ROUTE_REPLY:
            // std::cout << "RREP recieved." << std::endl;
            routeReplyHandler(msg, newSD);
            break;
        case ROUTE_ERROR:
            // routeErrorHandler(msg, newSD);
            break;
        case DATA:
            // dataHandler(msg, newSD);
            break;
        case INIT_ROUTE_DISCOVERY:
            initRouteDiscovery(newSD, msg.srcID, msg.destID);
            break;
        case EXIT:
            std::exit(0); // temp, need to resolve mem leaks before actually closing
            break;
        default:
            std::cout << "Message type not recognized." << std::endl; 
            break;
    }
}

int drone::broadcastMessage(const int& sockfd, const MESSAGE& msg){
    int broadcastEnable = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_BROADCAST, &broadcastEnable, sizeof(broadcastEnable)) == -1) {
        perror("setsockopt");
        close(sockfd);
        return 0;
    }

    struct sockaddr_in broadcastAddress;
    memset(&broadcastAddress, 0, sizeof(broadcastAddress));
    broadcastAddress.sin_family = AF_INET;
    broadcastAddress.sin_port = htons(this->port);
    inet_pton(AF_INET, "172.18.255.255", &(broadcastAddress.sin_addr)); // TODO: Automate retrieving this docker network address

    ssize_t bytesSent = sendto(sockfd, &msg, sizeof(msg), 0, (struct sockaddr*)&broadcastAddress, sizeof(broadcastAddress));
    if (bytesSent == -1) {
        perror("sendto");
        return 0;
    } else {
        return 1;
    }
    
}

void drone::initRouteDiscovery(const int& newSD, const int& srcNodeID, const int& destNodeID){
    MESSAGE rreq;
    rreq.type = ROUTE_REQUEST;
    // how to init the RREQID?
    rreq.srcID = srcNodeID;
    rreq.destID = destNodeID;
    rreq.ttl = 1; // temp value

    int res = this->broadcastMessage(newSD, rreq);
    if (res == 0){
        std::cerr << "Error broadcasting message." << std::endl;
        return;
    }
}

void drone::routeRequestHandler(MESSAGE& msg, const int& newSD){ 
    struct sockaddr_in addr; // return address setup
    addr.sin_family = AF_INET;
    addr.sin_port = htons(this->port); 

    // check if we just recieved a rreq from ourself
    if (msg.srcIP == this->nodeIP){
        return;
    }
    // check if we've already seen this rreq, discard
    if (this->RREQ_cache.count(msg.MAC) > 0){
        return;
    }
    // check if we are the destination
    if (msg.destID == this->nodeID){
        // if we are, send the message to the host
        MESSAGE RREP;
        RREP.type = ROUTE_REPLY;
        RREP.srcID = this->nodeID;
        RREP.destID = msg.srcID;
        RREP.ttl = 1; // temp value
        RREP.path = msg.path;
        RREP.iteration = 0; // to mark where we are in the path
        addr.sin_addr.s_addr = inet_addr(msg.path.back().c_str()); 
        sendto(newSD, &RREP, sizeof(RREP), 0, (struct sockaddr*)&addr, sizeof(addr));
    }

    // else rebroadcast
    addr.sin_addr.s_addr = inet_addr(msg.srcIP.c_str()); 
    msg.path.push_back(this->nodeIP); // add ourself to the path
    RREQ_cache.insert(msg.MAC); // add the MAC to the cache
    this->broadcastMessage(newSD, msg); // TODO: how to prevent rebroadcast back to the source node?
}

void drone::routeReplyHandler(MESSAGE& msg, const int& newSD){
    std::cout << "RREP recieved." << std::endl;
    if (msg.destID == this->nodeID){
        std::cout << "RREP recieved at destination." << std::endl;
        return;
    }
    // check if we've already seen this rrep, discard
    if (this->RREP_cache.count(msg.MAC) > 0){
        return;
    }

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(this->port); 
    msg.iteration++;
    addr.sin_addr.s_addr = inet_addr(msg.path[msg.path.size() - msg.iteration].c_str()); 
    sendto(newSD, &msg, sizeof(msg), 0, (struct sockaddr*)&addr, sizeof(addr));
}

int main(int argc, char* argv[]) {
    const std::string param1 = std::getenv("PARAM1");
    const char* param2 = std::getenv("PARAM2");
    const char* param3 = std::getenv("PARAM3");
    drone node(param1, std::stoi(param2), std::stoi(param3)); // temp parameters defined in docker compose to init drone properties (addr, port, nodeID)

    int sockfd;
    struct sockaddr_in server_addr, client_addr;
    MESSAGE msg;

    //// Setup Begin
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        std::cerr << "Error in socket creation." << std::endl;
        exit(EXIT_FAILURE);
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(node.port);
    server_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        std::cerr << "Error in binding." << std::endl;
        exit(EXIT_FAILURE);
    }
    //// Setup End

    listen(sockfd, SOMAXCONN); // temp accept max conn -> change to current network + 5
    std::cout << "Entering server loop " << std::endl;
    while (true) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        ssize_t bytesRead = recvfrom(sockfd, &msg, sizeof(msg), 0, (struct sockaddr*)&client_addr, &client_len);
        if (bytesRead == -1) {
            std::cerr << "Error receiving data" << std::endl;
            continue;
        }

        // Create a new thread using a lambda function that calls the member function.
        std::thread([&node, sockfd, &msg](){
            node.clientResponseThread(sockfd, msg);
        }).detach();         // temp; eventually thread "better" with rest api 

        // have some sort of flag to check when we should do route maitence and other timely things?    
    }

    close(sockfd);

    return 0;
}
