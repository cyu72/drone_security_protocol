#include "drone.hpp"

void drone::clientResponseThread(int newSD, const string& buffer){
    // function to handle all incoming messages from the client
    // check what type of message it is; launch the function to handle whatever type it is
    cout << "Handling client response." << endl;
    json jsonData = json::parse(buffer);

    switch(jsonData["type"].get<int>()){
        case ROUTE_REQUEST:
            cout << "RREQ recieved." << endl;
            routeRequestHandler(jsonData, newSD);
            break;
        case ROUTE_REPLY:
            cout << "RREP recieved." << endl;
            // routeReplyHandler(msg, newSD);
            break;
        case ROUTE_ERROR:
            // routeErrorHandler(msg, newSD);
            break;
        case DATA:
            // dataHandler(msg, newSD);
            break;
        case INIT_ROUTE_DISCOVERY:
            cout << "Initiating route discovery." << endl;
            initRouteDiscovery(jsonData, newSD);
            break;
        case EXIT:
            std::exit(0); // temp, need to resolve mem leaks before actually closing
            break;
        case INIT_MSG:
            cout << "Init message recieved." << endl;
            initMessageHandler(jsonData, newSD);
            break;
        default:
            cout << "Message type not recognized." << endl; 
            break;
    }
}

void drone::sendData(string containerName, const string& msg){
    // sends data to drone
    // create message, DNS resolution, then send to drone
    struct addrinfo hints, *result;
    std::memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET; // Use IPv4
    hints.ai_socktype = SOCK_DGRAM;
    
    int status = getaddrinfo(containerName.c_str(), std::to_string(PORT_NUMBER).c_str(), &hints, &result);
    if (status != 0) {
        std::cerr << "Error resolving host: " << gai_strerror(status) << endl;
        return;
    }

    int sockfd = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (sockfd == -1) {
        std::cerr << "Error creating socket" << endl;
        freeaddrinfo(result);
        return;
    }

    ssize_t bytesSent = sendto(sockfd, msg.c_str(), msg.size(), 0, (struct sockaddr*) result->ai_addr, result->ai_addrlen);
    if (bytesSent == -1) {
        std::cerr << "Error: " << strerror(errno) << endl;
    }

    freeaddrinfo(result);
    close(sockfd);
}

int drone::broadcastMessage(const string& msg){
    // Sends message to broadcast service rather than using socket broadcast
    int swarmSize = 20; // temp
    for (int i = 1; i <= swarmSize; ++i){
        string containerName = "drone" + std::to_string(i) + "-service.default";
        sendData(containerName, msg);
    }
    cout << "Broadcast Message sent." << endl;
    return 1;
}

void drone::initRouteDiscovery(json& data, const int& newSD){
// Constructs an RREQ and broadcast to neighbors

    GCS_MESSAGE ctl;
    ctl.deserialize(data);

    RREQ msg;
    msg.type = ROUTE_REQUEST;
    msg.srcAddr = this->addr;
    msg.destAddr = ctl.destAddr;
    msg.srcSeqNum = ++this->seqNum;
    msg.destSeqNum = (this->routingTable[msg.destAddr].seqNum > 0) ? this->routingTable[msg.srcAddr].seqNum : -1;
    msg.hopCount = 0; // 0 = broadcast range
    // sumn about HERR
    if (this->hashChainCache.size() >= 2) {
        msg.hash = this->hashChainCache[this->hashChainCache.size() - 2];
        cout << msg.hash << endl;
        this->hashChainCache.pop_back();
    } else {
        // Handle the case when the vector has less than 2 elements
        cout << "Hash chain cache is empty." << endl;
    }

    string buf = msg.serialize();
    cout << "Broadcasting message: " << buf << endl;
    int res = this->broadcastMessage(buf);
    if (res == 0){
        std::cerr << "Error broadcasting message." << endl;
        return;
    }
}

void drone::initMessageHandler(json& data, const int& newSD){
    INIT_MESSAGE msg;
    msg.deserialize(data);
    // create a routing table entry for each one recieved
    // entry(srcAddr, nextHop, seqNum, cost, ttl, hash)
    ROUTING_TABLE_ENTRY entry(msg.srcAddr, 0, 1, 0, 10, msg.hash);
    this->routingTable[msg.srcAddr] = entry;
}

void drone::routeRequestHandler(json& data, const int& newSD){ 
    RREQ msg;
    msg.deserialize(data);

    // check sha256(recieved hash) == cached hash for that node
    unsigned char preHash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(msg.hash.c_str()), msg.hash.size(), preHash);
    std::string hashRes(reinterpret_cast<const char*>(preHash), SHA256_DIGEST_LENGTH);

    if (this->routingTable.find(msg.srcAddr) == this->routingTable.end()){
        if (msg.srcSeqNum < routingTable[msg.srcAddr].seqNum || hashRes != routingTable[msg.srcAddr].hash){ // check if recieved seqNum > cached seqNum
        return; // drop packet
        } else { // create entry if it doesnt exist
            ROUTING_TABLE_ENTRY entry(msg.srcAddr, 0, 1, 0, 10, msg.hash);
            this->routingTable[msg.srcAddr] = entry;
        }
    }

    // TODO: cache source addr as a reachable destination in the cache with the sender of the RREQ as the intermediary (if this->addr != msg.srcAddr)

    // if true, check if cache has fresh route to dest
    if (msg.destAddr == this->addr || this->routingTable.find(msg.destAddr) != this->routingTable.end()){
        cout << "Constucting RREP" << endl;
        if (this->routingTable[msg.destAddr].ttl > 0){
            // send rrep
            RREP rrep;
            rrep.type = ROUTE_REPLY;
            rrep.srcAddr = this->addr;
            rrep.destAddr = msg.srcAddr;
            rrep.srcSeqNum = ++this->seqNum;
            rrep.destSeqNum = this->routingTable[msg.destAddr].seqNum;
            rrep.hopCount = msg.hopCount;
            rrep.hash = this->hashChainCache[this->hashChainCache.size() - 2]; // TODO: unsure what the hash should be 
            this->hashChainCache.pop_back(); // TODO: unsure what the hash should be 

            string buf = rrep.serialize();
            sendData(rrep.destAddr, buf); // TODO: Change to check cache for next hop backwards
            return;
        }
    } else {     // else increment hop count and forward rreq
        msg.hopCount++;
        string buf = msg.serialize();
        cout << "forwarding RREQ : " << buf << endl;
        int res = this->broadcastMessage(buf);
        if (res == 0){
            std::cerr << "Error broadcasting message." << endl;
            return;
        }
    }
}

void drone::routeReplyHandler(MESSAGE& msg, const int& newSD){

}

void drone::routeErrorHandler(MESSAGE& msg, const int& newSD){

}

string drone::sha256(const string& inn){
// Computes the hash X times, returns final hash
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, inn.c_str(), inn.size());
    SHA256_Final(hash, &sha256);
    std::stringstream ss;
    for(int i = 0; i < SHA256_DIGEST_LENGTH; ++i)
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    return ss.str();
}

void drone::setupPhase(){
    // Hash 100x (Unsure as to how many times are recommended)
    // What happens when we reach the end of the hash chain?
    // Skipping the step to verify authenticity of drone (implement later, not very important)

    sleep(5); // ensure all nodes are listenting first
    unsigned char buffer[56];
    RAND_bytes(buffer, sizeof(buffer));
    std::stringstream ss;
    for (int i = 0; i < sizeof(buffer); ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(buffer[i]);
    }
    string hash = ss.str();
    for (int i = 0; i < 100; ++i) {
        hash = sha256(hash);
        this->hashChainCache.push_back(hash);
    }
    string msg = INIT_MESSAGE(hash, this->addr).serialize();
    this->broadcastMessage(msg);
}

int main(int argc, char* argv[]) {
    const string param1 = std::getenv("PARAM1");
    const char* param2 = std::getenv("PARAM2");
    const char* param3 = std::getenv("PARAM3");
    drone node(param1, std::stoi(param2), std::stoi(param3)); // temp parameters defined in docker compose to init drone properties (addr, port, nodeID)

    int sockfd;
    struct sockaddr_in server_addr, client_addr;
    char buffer[5000];
    string msg;

    //// Setup Begin
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        std::cerr << "Error in socket creation." << endl;
        exit(EXIT_FAILURE);
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(node.port);
    server_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        std::cerr << "Error in binding." << endl;
        exit(EXIT_FAILURE);
    }

    std::thread setupThread([&node]() {
        node.setupPhase();
    });
    setupThread.detach();
    //// Setup End

    listen(sockfd, SOMAXCONN); // temp accept max conn -> change to current network + 5
    cout << "Entering server loop " << endl;
    while (true) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        ssize_t bytesRead = recvfrom(sockfd, buffer, sizeof(buffer) - 1, 0, (struct sockaddr*)&client_addr, &client_len);
        if (bytesRead == -1) {
            std::cerr << "Error receiving data" << endl;
            continue;
        }

        buffer[bytesRead] = '\0'; // Null-terminate the received data
        msg = std::string(buffer);

        cout << "Message recieved." << endl;
        cout << msg << endl;
        // Create a new thread using a lambda function that calls the member function.
        std::thread([&node, sockfd, &msg](){
            node.clientResponseThread(sockfd, msg);
        }).detach();   

        // have some sort of flag to check when we should do route maitence and other timely things?    
    }

    close(sockfd);

    return 0;
}
