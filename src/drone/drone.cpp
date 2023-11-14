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
            // routeReplyHandler(msg, newSD);
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
        default:
            std::cout << "Message type not recognized." << std::endl; 
            break;
    }
}

void drone::initRouteDiscovery(const int& newSD, const int& srcNodeID, const int& destNodeID){
    MESSAGE rreq;
    rreq.type = ROUTE_REQUEST;
    // how to init the RREQID?
    rreq.srcID = srcNodeID;
    rreq.srcSeqNum = 0;
    rreq.destID = destNodeID;
    rreq.destSeqNum = -1; // undefined until we get a reply
    rreq.ttl = 1; // temp value

    int broadcastEnable = 1;
    if (setsockopt(newSD, SOL_SOCKET, SO_BROADCAST, &broadcastEnable, sizeof(broadcastEnable)) == -1) {
        perror("setsockopt");
        close(newSD);
        return;
    }

    struct sockaddr_in broadcastAddress;
    memset(&broadcastAddress, 0, sizeof(broadcastAddress));
    broadcastAddress.sin_family = AF_INET;
    broadcastAddress.sin_port = htons(this->port);
    inet_pton(AF_INET, "172.18.255.255", &(broadcastAddress.sin_addr)); // TODO: Automate retrieving this docker network address

    ssize_t bytesSent = sendto(newSD, &rreq, sizeof(rreq), 0, (struct sockaddr*)&broadcastAddress, sizeof(broadcastAddress));
    if (bytesSent == -1) {
        perror("sendto");
    } else {
        std::cout << "Sent " << bytesSent << " bytes to the broadcast address." << std::endl;
    }

    // add all resonses to neighbor list -> done in routeReplyHandler
}

void drone::routeRequestHandler(MESSAGE& msg, const int& newSD){ 
    // check if we just recieved a rreq from ourself
    if (msg.srcID == this->nodeID){
        return;
    }

    struct sockaddr_in addr; // return address setup
    addr.sin_family = AF_INET;
    addr.sin_port = htons(this->port); 
    addr.sin_addr.s_addr = inet_addr(msg.srcIP.c_str()); 

    MESSAGE RREP, recievedMessage;
    RREP.type = ROUTE_REPLY;
    RREP.hopCount = msg.hopCount + 1; // leave other fields blank until we need to actually init them
    // sends RREP with info on current drone, if we are the destination include that info as well
    sendto(newSD, &RREP, sizeof(RREP), 0, (struct sockaddr*)&addr, sizeof(addr));

    // check if we are the destination
    if (msg.destID == this->nodeID){
        // if we are, send the message to the host

    }
    // if not, send the message back down the chain
    else {
        // modify rrep fields as required and forward to neighbors
        msg.hopCount++;
        sendto(newSD, &msg, sizeof(msg), 0, (struct sockaddr*)&addr, sizeof(addr));
    }

    // modify rreq fields as required and forward to neighbors
    msg.hopCount++;
    sendto(newSD, &msg, sizeof(msg), 0, (struct sockaddr*)&addr, sizeof(addr));
}

void drone::routeReplyHandler(MESSAGE& msg, const int& newSD){
    // TODO: Prevent rebroadcast of RREP back to sender node 
    // for each response, build the route, if we recieve the correct destination, delete the other routes and end the route discovery


    std::cout << "RREP recieved." << std::endl;
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
