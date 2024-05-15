#include "drone.hpp"

std::chrono::high_resolution_clock::time_point globalStartTime;
std::chrono::high_resolution_clock::time_point globalEndTime;

void drone::clientResponseThread(int newSD, const string& buffer){
    /* function to handle all incoming messages from the client
    check what type of message it is; launch the function to handle whatever type it is */
    json jsonData = json::parse(buffer);

    switch(jsonData["type"].get<int>()){
        case ROUTE_REQUEST:
            cout << "RREQ received." << endl;
            routeRequestHandler(jsonData);
            break;
        case ROUTE_REPLY:
            cout << "RREP received." << endl;
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
        case BRDCST_MSG:
            cout << "Neighbor Discovery/Broadcast message received." << endl;
            initMessageHandler(jsonData);
            break;
        case TESLA_MSG:
            cout << "Tesla message received." << endl;
            // this->tesla.recv(jsonData);
            break;
        default:
            cout << "Message type not recognized." << endl; 
            break;
    }
}

void drone::verifyRouteHandler(json& data){
    for (auto& [key, value] : this->tesla.routingTable){
        value.print();
    }
    cout << "\n";
    for (const auto& element : this->tesla.mac_q) {
        std::cout << element.data << " " << element.MAC << " " << element.tstamp.time_since_epoch().count() << std::endl;
    }
}

void drone::sendData(string containerName, const string& msg) {
    struct addrinfo hints, *result;
    std::memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    int status = getaddrinfo(containerName.c_str(), std::to_string(PORT_NUMBER).c_str(), &hints, &result);
    if (status != 0) {
        std::cerr << "Error resolving host " << containerName << ": " << gai_strerror(status) << std::endl;
        return;
    }

    int sockfd = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (sockfd == -1) {
        std::cerr << "Error creating socket for " << containerName << std::endl;
        freeaddrinfo(result);
        return;
    }

    struct timeval timeout;
    timeout.tv_sec = 1; // TEMP: Set timeout to 1 seconds
    timeout.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

    if (connect(sockfd, result->ai_addr, result->ai_addrlen) == -1) {
        std::cerr << "Error connecting to " << containerName << ": " << strerror(errno) << std::endl;
        close(sockfd);
        freeaddrinfo(result);
        return;
    }

    ssize_t bytesSent = send(sockfd, msg.c_str(), msg.size(), 0);
    if (bytesSent == -1) {
        std::cerr << "Error sending message to " << containerName << ": " << strerror(errno) << std::endl;
    } else {
        std::cout << "Sent " << bytesSent << " bytes to " << containerName << std::endl;
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

    RREQ msg; msg.type = ROUTE_REQUEST; msg.srcAddr = this->addr; msg.intermediateAddr = this->addr; msg.destAddr = ctl.destAddr; msg.srcSeqNum = ++this->seqNum; msg.ttl = this->msgTTL;

    auto it = this->tesla.routingTable.find(msg.destAddr);
    msg.destSeqNum = (it != this->tesla.routingTable.end()) ? it->second.seqNum : 0;
    msg.hopCount = 1; // 1 = broadcast range
    // sumn about HERR
    msg.hash = (msg.srcSeqNum == 1) ? this->hashChainCache[1] : this->hashChainCache[(msg.srcSeqNum - 1) * 8 + 1]; // TODO: Wrap around the cache when needed // NOTE: 8 = hardcoded max hop

    HashTree tree = HashTree(msg.srcAddr); // init HashTree
    msg.hashTree = tree.toVector();
    msg.rootHash = tree.getRoot()->hash;

    globalStartTime = std::chrono::high_resolution_clock::now();
    string buf = msg.serialize();
    int res = this->broadcastMessage(buf);
    if (res == 0){
        std::cerr << "Error broadcasting message." << endl;
        return;
    }
}

void drone::initMessageHandler(json& data){
    /*Creates a routing table entry for each authenticator received*/
    INIT_MESSAGE msg;
    msg.deserialize(data);
    // entry(srcAddr, nextHop, seqNum, hopCount/cost(?), ttl, hash)
    ROUTING_TABLE_ENTRY entry(msg.srcAddr, msg.srcAddr, 0, 1, 10, msg.hash); // TODO: Incorporate ttl mechanics
    this->tesla.routingTable[msg.srcAddr] = entry;
}

void drone::routeRequestHandler(json& data){ 
    /*
    Conditions checked before forwarding:
    1) If the srcAddr is the same as the current node, drop the packet (To be removed in testing)
    2) If the seqNum is less than the seqNum already received, drop the packet
    3a) Calculate hash based on hopCount * seqNum (comparison with routing table is optional because of hash tree)
    3b) Calculate hashTree where lastElement = H[droneName || hash] (hash = hashIterations * baseHash) (hashIterations = hopCount * seqNum)
    */
    cout << "Handling RREQ." << endl;
    RREQ msg;
    msg.deserialize(data);

    if (msg.srcAddr == this->addr) return; // Drop Packet Condition: If the srcAddr is the same as the current node
    // TODO: Add case to drop packet if this RREQ has already been seen
    // if (msg.ttl == 0) return; // Drop Packet Condition: If the ttl is 0
    if (this->tesla.routingTable.find(msg.srcAddr) != this->tesla.routingTable.end() && this->tesla.routingTable.find(msg.intermediateAddr) != this->tesla.routingTable.end()){
        if (msg.srcSeqNum <= this->tesla.routingTable[msg.srcAddr].seqNum) return; // Drop Packet Condition: If the seqNum is less than the seqNum already received
        string hashRes = msg.hash;
        int hashIterations = (8 * (msg.srcSeqNum - 1)) + 1 + msg.hopCount;
        for (int i = 1; i < hashIterations; i++) {
            hashRes = sha256(hashRes);
            cout << "Calculated Hash " << hashRes << endl;
        }
        if (hashRes != this->tesla.routingTable[msg.intermediateAddr].hash) return; // Drop Packet Condition: If the hash does not match the hash for the seqNum
    }

    // Rebuild hash tree and then check if it's correct
    // TODO: Do a check where we make sure the last node being added is in fact the last node placed in the tree
    HashTree tree = HashTree(msg.hashTree, msg.hopCount, msg.intermediateAddr);
    tree.printTree(tree.getRoot());
    if (!tree.verifyTree(msg.rootHash)){
        cout << "HashTree verification failed, dropping RREQ." << endl;
        return;
    }

    // TODO: Cache source addr as a reachable destination in the cache with the sender of the RREQ as the intermediary (if this->addr != msg.srcAddr)
    // if (msg.hopCount != 0) this->routingTable[msg.srcAddr] = ROUTING_TABLE_ENTRY(msg.srcAddr, msg.intermediateAddr, msg.srcSeqNum, msg.hopCount, 10, msg.hash); // TODO: This doesn't work...

    // if true, check if currNode is the dest {Can also send back RREP if cached, should weigh pros/cons}
    if (msg.destAddr == this->addr){ // Sends RREP
        RREP rrep; rrep.srcAddr = this->addr; rrep.destAddr = msg.srcAddr; rrep.intermediateAddr = this->addr;
        rrep.srcSeqNum = msg.srcSeqNum; // Maintain src Seqnum

        auto it = this->tesla.routingTable.find(msg.destAddr);
        if (it != this->tesla.routingTable.end()) {
            rrep.destSeqNum = this->tesla.routingTable[msg.destAddr].seqNum;
        } else {
            rrep.destSeqNum = this->seqNum;
            this->tesla.routingTable[msg.srcAddr] = ROUTING_TABLE_ENTRY(msg.srcAddr, msg.intermediateAddr, this->seqNum, 0, 10, msg.hash); // TODO: Check what is the hash field supposed to contain again?
        }

        rrep.hopCount = 1;
        rrep.hash = this->hashChainCache[(msg.srcSeqNum - 1) * (8) + rrep.hopCount];

        string buf = rrep.serialize();
        cout << "Constructed RREP: " << buf << endl;
        if (msg.hopCount == 1){
            sendData(rrep.destAddr, buf); // Send back directly if neighbor
        } else {
            cout << "Sending RREP to next hop: " << this->tesla.routingTable[msg.srcAddr].nextHopID << endl;
            sendData(this->tesla.routingTable[msg.srcAddr].nextHopID, buf); // send to next hop stored
        }
        // TODO: Check ttl 
    }
    else {     // else increment hop count and forward rreq
        msg.hopCount++;
        msg.ttl--;

        auto it = this->tesla.routingTable.find(msg.destAddr);
        if (it != this->tesla.routingTable.end()) {
            msg.destSeqNum = this->tesla.routingTable[msg.destAddr].seqNum;
        } else {
            msg.destSeqNum = this->seqNum;
        }
        cout << "Adding to routing table. " << this->tesla.routingTable[msg.srcAddr].destAddr << " " << this->tesla.routingTable[msg.srcAddr].nextHopID << " " << this->tesla.routingTable[msg.srcAddr].seqNum << " " << this->tesla.routingTable[msg.srcAddr].cost << " " << this->tesla.routingTable[msg.srcAddr].hash << endl;
        this->tesla.routingTable[msg.srcAddr] = ROUTING_TABLE_ENTRY(msg.srcAddr, msg.intermediateAddr, msg.srcSeqNum, msg.hopCount, 10, msg.hash); // TODO: DONT UPDATE THE HASH HERE LEAVE IT
        cout << "Added to routing table." << this->tesla.routingTable[msg.srcAddr].destAddr << " " << this->tesla.routingTable[msg.srcAddr].nextHopID << " " << this->tesla.routingTable[msg.srcAddr].seqNum << " " << this->tesla.routingTable[msg.srcAddr].cost << " " << this->tesla.routingTable[msg.srcAddr].hash << endl;

        msg.hash = this->hashChainCache[(msg.srcSeqNum - 1) * (8) + msg.hopCount];

        // Add self to hashTree & update rootHash
        tree.addSelf(this->addr, msg.hopCount);
        msg.hashTree = tree.toVector();
        msg.rootHash = tree.getRoot()->hash;

        msg.intermediateAddr = this->addr;
        string buf = msg.serialize();
        cout << "forwarding RREQ : " << buf << endl;
        int res = this->broadcastMessage(buf); // Add condition where we directly send to the neighbor if we have it cached. Else, broadcast
        if (res == 0){
            std::cerr << "Error broadcasting message." << endl;
            return;
        }
    }
    // update cached seqNum
    cout << "Finished handling RREQ." << endl;
}

void drone::routeReplyHandler(json& data){
    cout << "Handling RREP." << endl;
    RREP msg;
    msg.deserialize(data);

    // check sha256(received hash) == cached hash for that node
    string hashRes = msg.hash;
    int hashIterations = (8 * (msg.srcSeqNum - 1)) + 1 + msg.hopCount;
    for (int i = this->tesla.routingTable[msg.intermediateAddr].cost; i < hashIterations; i++) {
        hashRes = sha256(hashRes);
    }

    if (hashRes != this->tesla.routingTable[msg.intermediateAddr].hash){ // code is expanded for debugging purposes
        cout << "Calculated Hash " << hashRes << endl;
        cout << "Incorrect hash, dropping RREP." << endl;
        return;
    } else if (msg.srcSeqNum < this->tesla.routingTable[msg.intermediateAddr].seqNum){
        cout << "Smaller seqNum, dropping RREP." << endl;
        return;
    }

    if (msg.destAddr == this->addr){ 
        this->tesla.routingTable[msg.srcAddr] = ROUTING_TABLE_ENTRY(msg.srcAddr, msg.intermediateAddr, msg.srcSeqNum, msg.hopCount, 10, msg.hash);
        cout << "Successfully completed route" << endl;
        globalEndTime = std::chrono::high_resolution_clock::now();
        cout << "Elapsed Time: " << std::chrono::duration_cast<std::chrono::milliseconds>(globalEndTime - globalStartTime).count() << " ms" << endl;
        return;
    } else {
        cout << "Forwarding RREP to next hop." << endl;
        msg.hopCount++;
        msg.hash = this->hashChainCache[(msg.srcSeqNum - 1) * (8) + msg.hopCount];
        msg.intermediateAddr = this->addr; // update intermediate addr so final node can add to cache
        string buf = msg.serialize();
        sendData(this->tesla.routingTable[msg.destAddr].nextHopID, buf);
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
        Skipping the step to verify authenticity of drone (implement later, not very important) 
        
    TODO: Include function that dynamically generates hashChain upon nearing depletion    
        */

    cout << "Setting up drone in setup function." << endl;
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
        // cout << "Hash: " << hash << endl;
    }
    string msg = INIT_MESSAGE(this->hashChainCache.front(), this->addr).serialize();

    /*Temp code to make all drones start at the same time
    Waits until the nearest 30 seconds to start code*/

    auto now = std::chrono::system_clock::now();
    auto now_sec = std::chrono::time_point_cast<std::chrono::seconds>(now);
    int currSecond = now_sec.time_since_epoch().count() % 60;
    int secsToWait = 0;

    if (currSecond > 30) {
        secsToWait = 60 - currSecond + 30;
    } else {
        secsToWait = 30 - currSecond;
    }

    cout << "Waiting for " << secsToWait << " seconds." << endl;
    sleep(secsToWait);
    
    this->broadcastMessage(msg);
    msg = this->tesla.init_tesla(this->addr).serialize();
    this->broadcastMessage(msg);

    // // Setup a thread that is dedicated to sending out hash disclosures
    // std::thread hashDisclosureThread([&](){
    //     while (true) {
    //         sleep(this->tesla.disclosure_time);
    //         // build the tesla message
    //         TESLA_MESSAGE teslaMsg;
    //         teslaMsg.set_disclose(this->addr, this->tesla.hash_disclosure());
    //         string buf = teslaMsg.serialize();
    //         this->broadcastMessage(buf);
    //     }
    // });
    // hashDisclosureThread.detach(); // How do I stop a thread later on..?
}

void drone::neighborDiscoveryUDPHANDLER(){
    int udp_sock;
    struct sockaddr_in server_addr, client_addr;
    char buffer[1024];
    socklen_t addr_len = sizeof(client_addr);

    // Create UDP socket
    if ((udp_sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("UDP socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Bind the socket to the port
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(BRDCST_PORT);

    if (bind(udp_sock, (const struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("UDP bind failed");
        close(udp_sock);
        exit(EXIT_FAILURE);
    }

    std::cout << "Listening for UDP messages on port " << BRDCST_PORT << "..." << std::endl;

    while (true) {
        // Receive message
        int n = recvfrom(udp_sock, buffer, sizeof(buffer) - 1, 0, (struct sockaddr *)&client_addr, &addr_len);
        if (n < 0) {
            perror("recvfrom failed");
            break;
        }
        buffer[n] = '\0';  // Null-terminate the received data

        // Print received message and sender's address
        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(client_addr.sin_addr), client_ip, INET_ADDRSTRLEN);
        int client_port = ntohs(client_addr.sin_port);
        std::cout << "Received UDP message: " << buffer << std::endl;
        std::cout << "From: " << client_ip << ":" << client_port << std::endl;

        // Utilize the original message format from before to unjsonify the message and recieve it
        // Also recieve TESLA messages in UDP
        // This way, we can repurpose setupPhase() function into UDP broadcast function
    }

    close(udp_sock);
}

int main(int argc, char* argv[]) {
    cout << "Starting drone." << endl;
    const string param1 = std::getenv("PARAM1");
    const char* param2 = std::getenv("PARAM2");
    const char* param3 = std::getenv("PARAM3");
    drone node(std::stoi(param2), std::stoi(param3)); // env vars for init
    cout << "Drone object created." << endl;

    int listenSock;
    struct sockaddr_in server_addr;
    char buffer[5000];
    string msg;

    //// Setup Begin
    listenSock = socket(AF_INET, SOCK_STREAM, 0);
    if (listenSock < 0) {
        std::cerr << "Error in socket creation." << endl;
        exit(EXIT_FAILURE);
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(node.port);
    server_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(listenSock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        std::cerr << "Error in binding." << endl;
        exit(EXIT_FAILURE);
    }

    if (listen(listenSock, 5) < 0) {
        std::cerr << "Error in listening." << endl;
        exit(EXIT_FAILURE);
    }

    std::thread setupThread([&node]() {
        cout << "Created a thread" << endl;
        node.setupPhase();
    });
    setupThread.detach();
    //// Setup End

    std::thread udpThread([&node](){
        node.neighborDiscoveryUDPHANDLER();
    });

    cout << "Entering server loop " << endl;
    while (true) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int newSock = accept(listenSock, (struct sockaddr*)&client_addr, &client_len);
        if (newSock < 0) {
            std::cerr << "Error accepting connection" << endl;
            continue;
        }

        ssize_t bytesRead = recv(newSock, buffer, sizeof(buffer) - 1, 0);
        if (bytesRead == -1) {
            std::cerr << "Error receiving data" << endl;
            close(newSock);
            continue;
        }

        buffer[bytesRead] = '\0';
        msg = std::string(buffer); // TODO: Remove to reduce string usage

        cout << "Message received at: ";
        auto now = std::chrono::system_clock::now();
        std::time_t timestamp = std::chrono::system_clock::to_time_t(now);
        cout << std::ctime(&timestamp);
        cout << msg << endl;

        // Temp: Used to check IP addresses of recieved message
        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(client_addr.sin_addr), client_ip, INET_ADDRSTRLEN);
        int client_port = ntohs(client_addr.sin_port);

        std::cout << "Connection accepted from " << client_ip << ":" << client_port << std::endl;

        // Create a new thread using a lambda function that calls the member function.
        std::thread([&node, newSock, &msg](){
            node.clientResponseThread(newSock, msg);
            close(newSock);
        }).detach();   

        // have some sort of flag to check when we should do route maintenance and other timely things?    
    }

    close(listenSock);

    return 0;
}
