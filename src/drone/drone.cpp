#include "drone.hpp"

void drone::clientResponseThread(int newSD, const string& buffer){
    /* function to handle all incoming messages from the client
    check what type of message it is; launch the function to handle whatever type it is */
    json jsonData = json::parse(buffer);

    switch(jsonData["type"].get<int>()){
        case ROUTE_REQUEST:
            cout << "RREQ recieved." << endl;
            routeRequestHandler(jsonData);
            break;
        case ROUTE_REPLY:
            cout << "RREP recieved." << endl;
            routeReplyHandler(jsonData);
            break;
        case ROUTE_ERROR:
            // routeErrorHandler(jsonData);
            break;
        case DATA:
            // dataHandler(msg, newSD);
            break;
        case INIT_ROUTE_DISCOVERY:
            cout << "Initiating route discovery." << endl;
            initRouteDiscovery(jsonData);
            break;
        case EXIT:
            std::exit(0); // temp, need to resolve mem leaks before actually closing
            break;
        case VERIFY_ROUTE:
            verifyRouteHandler(jsonData);
            break;
        case INIT_MSG:
            cout << "Init message recieved." << endl;
            initMessageHandler(jsonData);
            break;
        default:
            cout << "Message type not recognized." << endl; 
            break;
    }
}

void drone::verifyRouteHandler(json& data){
    for (auto& [key, value] : this->routingTable){
        value.print();
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
    /*Sends message to broadcast service rather than using socket broadcast*/
    int swarmSize = 15; // temp
    for (int i = 1; i <= swarmSize; ++i){
        string containerName = "drone" + std::to_string(i) + "-service.default";
        sendData(containerName, msg);
    }
    cout << "Broadcast Message sent." << endl;
    return 1;
}

void drone::initRouteDiscovery(json& data){
// Constructs an RREQ and broadcast to neighbors

    GCS_MESSAGE ctl;
    ctl.deserialize(data);

    RREQ msg;
    msg.type = ROUTE_REQUEST;
    msg.srcAddr = this->addr;
    msg.intermediateAddr = this->addr;
    msg.destAddr = ctl.destAddr;
    msg.srcSeqNum = ++this->seqNum;

    auto it = this->routingTable.find(msg.destAddr);
    msg.destSeqNum = (it != this->routingTable.end()) ? it->second.seqNum : 0;
    msg.hopCount = 0; // 0 = broadcast range
    // sumn about HERR
    msg.hash = this->hashChainCache[(msg.srcSeqNum - 1) * (8) + msg.hopCount + 1]; // TODO: Wrap around the cache when needed // NOTE: 8 = hardcoded max hop

    // init hash tree
    


    string buf = msg.serialize();
    int res = this->broadcastMessage(buf);
    if (res == 0){
        std::cerr << "Error broadcasting message." << endl;
        return;
    }
}

void drone::initMessageHandler(json& data){
    INIT_MESSAGE msg;
    msg.deserialize(data);
    // create a routing table entry for each one recieved
    // entry(srcAddr, nextHop, seqNum, hopCount, ttl, hash)
    ROUTING_TABLE_ENTRY entry(msg.srcAddr, msg.srcAddr, 1, 0, 10, msg.hash); // TODO: Incorporate ttl mechanics
    this->routingTable[msg.srcAddr] = entry;
}

void drone::routeRequestHandler(json& data){ 
    /*
    Conditions checked before forwarding:
    1) If the srcAddr is the same as the current node, drop the packet (To be removed in testing)
    2) If the seqNum is less than the seqNum already received, drop the packet
    3a) Calculate hash based on hopCount * seqNum (comparison with routing table is optinol because of hash tree)
    3b) Calculate hashTree where lastElement = H[droneName || hash] (hash = hashIterations * baseHash) (hashIterations = hopCount * seqNum)
    */
    cout << "Handling RREQ." << endl;
    RREQ msg;
    msg.deserialize(data);

    if (msg.srcAddr == this->addr) return; // Drop Packet Condition: If the srcAddr is the same as the current node
    if (this->routingTable.find(msg.intermediateAddr) != this->routingTable.end()){
        if (msg.srcSeqNum < routingTable[msg.intermediateAddr].seqNum) return; // Drop Packet Condition: If the seqNum is less than the seqNum already received
        string hashRes = msg.hash;
        int hashIterations = msg.srcSeqNum * msg.hopCount;
        for (int i = routingTable[msg.intermediateAddr].cost; i <= hashIterations; i++) {
            hashRes = sha256(hashRes);
        }
        if (hashRes != routingTable[msg.intermediateAddr].hash) return; // Drop Packet Condition: If the hash does not match the hash for the seqNum
    }

    // Cache source addr as a reachable destination in the cache with the sender of the RREQ as the intermediary (if this->addr != msg.srcAddr)
    // if (msg.hopCount != 0) this->routingTable[msg.srcAddr] = ROUTING_TABLE_ENTRY(msg.srcAddr, msg.intermediateAddr, msg.srcSeqNum, msg.hopCount, 10, msg.hash); // TODO: Fix the hash that is stored here, it should be the inital commit, not this

    // if true, check if currNode is the dest {Can also send back RREP if cached, should weigh pros/cons}
    if (msg.destAddr == this->addr){
        // send rrep
        RREP rrep;
        rrep.srcAddr = this->addr;
        rrep.destAddr = msg.srcAddr;
        rrep.srcSeqNum = msg.srcSeqNum; // Maintain src Seqnum
        rrep.intermediateAddr = this->addr;

        auto it = this->routingTable.find(msg.destAddr);
        rrep.destSeqNum = (it != this->routingTable.end()) ? this->routingTable[msg.destAddr].seqNum : this->seqNum;

        rrep.hopCount = 0;
        rrep.hash = this->hashChainCache[(msg.srcSeqNum - 1) * (8) + rrep.hopCount + 1];

        string buf = rrep.serialize();
        cout << "Constructed RREP: " << buf << endl;
        if (msg.hopCount == 0){
            sendData(rrep.destAddr, buf); // Send back directly if neighbor
        } else {
            cout << "Sending RREP to next hop: " << routingTable[msg.srcAddr].nextHopID << endl;
            sendData(routingTable[msg.srcAddr].nextHopID, buf); // send to next hop stored
        }
        // TODO: Check ttl 
    }
    else {     // else increment hop count and forward rreq
        msg.hopCount++;
        msg.intermediateAddr = this->addr;

        auto it = this->routingTable.find(msg.destAddr);
        msg.destSeqNum = (it != this->routingTable.end()) ? this->routingTable[msg.destAddr].seqNum : this->seqNum;

        msg.hash = this->hashChainCache[(msg.srcSeqNum - 1) * (8) + msg.hopCount + 1];
        string buf = msg.serialize();
        cout << "forwarding RREQ : " << buf << endl;
        int res = this->broadcastMessage(buf);
        if (res == 0){
            std::cerr << "Error broadcasting message." << endl;
            return;
        }
    }
    // update cached seqNum
    cout << "Finished handling RREQ." << endl;
}

void drone::routeReplyHandler(json& data){
    RREP msg;
    msg.deserialize(data);

    // check sha256(recieved hash) == cached hash for that node
    string hashRes = msg.hash;
    int hashIterations = msg.srcSeqNum * msg.hopCount;
    for (int i = routingTable[msg.intermediateAddr].cost; i <= hashIterations; i++) {
        hashRes = sha256(hashRes);
    }

    if (hashRes != routingTable[msg.intermediateAddr].hash){ // code is expanded for debugging purposes
        cout << "Incorrect hash, dropping RREP." << endl;
        return;
    } else if (msg.srcSeqNum < routingTable[msg.intermediateAddr].seqNum){
        cout << "Smaller seqNum, dropping RREP." << endl;
        return;
    }

    if (msg.destAddr == this->addr){ 
        routingTable[msg.srcAddr] = ROUTING_TABLE_ENTRY(msg.srcAddr, msg.intermediateAddr, msg.srcSeqNum, msg.hopCount, 10, msg.hash);
        cout << "Successfully completed route" << endl;
    } else {
        msg.hopCount++;
        msg.hash = this->hashChainCache[(msg.srcSeqNum - 1) * (8) + msg.hopCount + 1];
        msg.intermediateAddr = this->addr; // update intermediate addr so final node can add to cache
        string buf = msg.serialize();
        sendData(routingTable[msg.destAddr].nextHopID, buf);
    }
}

void drone::routeErrorHandler(MESSAGE& msg){
    // this is not the correct place to write this but
    // generate RERRs under the following conditions:
    // A node detects link breakage of active route
    // Node cannot detects link breakage with neighbor
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
    /* HashChain is generated where the most recent hashes are stored in the front (Eg. 0th index is the most recent hash)
    
    Temp: Hardcoding number of hashes in hashChain (10 seqNums * 8 max hop distance) = 80x hashed
        What happens when we reach the end of the hash chain?
        Skipping the step to verify authenticity of drone (implement later, not very important) */

    unsigned char buffer[56];
    RAND_bytes(buffer, sizeof(buffer));
    std::stringstream ss;
    for (int i = 0; i < sizeof(buffer); ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(buffer[i]);
    }
    string hash = ss.str();
    for (int i = 0; i < 80; ++i) {
        hash = sha256(hash);
        this->hashChainCache.push_front(hash);
    }
    string msg = INIT_MESSAGE(this->hashChainCache.front(), this->addr).serialize();

    /*Temp code to make all drones start at the same time
    Waits until the nearest 30 seconds to start code*/

    auto now = std::chrono::system_clock::now();
    auto now_sec = std::chrono::time_point_cast<std::chrono::seconds>(now);
    int currSecond = now_sec.time_since_epoch().count() % 60;
    int secsToWait = 30 - currSecond;
    sleep(secsToWait);
    
    this->broadcastMessage(msg);
}

int main(int argc, char* argv[]) {
    const string param1 = std::getenv("PARAM1");
    const char* param2 = std::getenv("PARAM2");
    const char* param3 = std::getenv("PARAM3");
    drone node(param1, std::stoi(param2), std::stoi(param3)); // env vars for init

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

        buffer[bytesRead] = '\0';
        msg = std::string(buffer); // TODO: Remove to reduce string usage

        cout << "Message recieved. ";
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
