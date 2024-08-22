#include "drone.hpp"

std::chrono::high_resolution_clock::time_point globalStartTime;
std::chrono::high_resolution_clock::time_point globalEndTime;

drone::drone() : udpInterface(BRDCST_PORT), tcpInterface(PORT_NUMBER) {
    cout << "Default drone constructor called" << endl;
    this->addr = "";
    this->port = -1;
    this->nodeID = -1;
    this->seqNum = 0;
}

drone::drone(int port, int nodeID) : udpInterface(BRDCST_PORT), tcpInterface(port) {
    cout << "Drone constructor called" << endl;
    this->addr = "drone" + std::to_string(nodeID) + "-service.default";
    this->port = port;
    this->nodeID = nodeID;
    this->seqNum = 0;
}

void drone::clientResponseThread(const string& buffer){
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
        case HELLO:
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
    this->tesla.routingTable.print();
}

void drone::sendData(string containerName, const string& msg) {
    try {
        TCPInterface clientSocket(0, false); // 0 for port, false for is_server
        clientSocket.connect_to(containerName, PORT_NUMBER);
        clientSocket.send_data(msg);

    } catch (const std::exception& e) {
        std::cerr << "Error sending data to " << containerName << ": " << e.what() << std::endl;
    }
}

void drone::initRouteDiscovery(json& data){
    /* Constructs an RREQ and broadcast to neighbors
    It is worth noting that routes may sometimes be incorrectly not found because a routing table clear may occur during the route discovery process. To mitagate this issue, we can try any or all of the following: 1) Retry the route discovery process X times before giving up. 2) Increase the amount of time before a routing table clear occurs (Currently at 30 seconds). Check github issue for full description.
    */

    GCS_MESSAGE ctl;
    ctl.deserialize(data);

    RREQ msg; msg.type = ROUTE_REQUEST; msg.srcAddr = this->addr; msg.intermediateAddr = this->addr; msg.destAddr = ctl.destAddr; msg.srcSeqNum = ++this->seqNum; msg.ttl = this->max_hop_count;

    {   
        std::lock_guard<std::mutex> lock(this->routingTableMutex);
        auto it = this->tesla.routingTable.get(msg.destAddr);
        msg.destSeqNum = (it) ? it->seqNum : 0;
    }
    msg.hopCount = 1; // 1 = broadcast range
    // sumn about HERR
    msg.hash = (msg.srcSeqNum == 1) ? this->hashChainCache[1] : this->hashChainCache[(msg.srcSeqNum - 1) * this->max_hop_count + 1]; // TODO: Wrap around the cache when needed

    HashTree tree = HashTree(msg.srcAddr); // init HashTree
    msg.hashTree = tree.toVector();
    msg.rootHash = tree.getRoot()->hash;

    globalStartTime = std::chrono::high_resolution_clock::now();
    string buf = msg.serialize();
    udpInterface.broadcast(buf);
}

void drone::initMessageHandler(json& data){
    /*Creates a routing table entry for each authenticator received*/
    {
        std::lock_guard<std::mutex> lock(this->helloRecvTimerMutex);
        if (std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - helloRecvTimer).count() > helloRecvTimeout) return;
    }
    INIT_MESSAGE msg;
    msg.deserialize(data);
    // entry(srcAddr, nextHop, seqNum, hopCount/cost(?), ttl, hash)
    ROUTING_TABLE_ENTRY entry(msg.srcAddr, msg.srcAddr, 0, 1, std::chrono::system_clock::now(), msg.hash); // TODO: Incorporate ttl mechanics
    std::lock_guard<std::mutex> lock(this->routingTableMutex);
    this->tesla.routingTable.insert(msg.srcAddr, entry);
    // this->tesla.routingTable[msg.srcAddr] = entry;
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
    std::lock_guard<std::mutex> lock(this->routingTableMutex);
    RREQ msg;
    msg.deserialize(data);

    if (msg.srcAddr == this->addr) return; // Drop Packet Condition: If the srcAddr is the same as the current node
    // TODO: Add case to drop packet if this RREQ has already been seen
    // if (msg.ttl == 0) return; // Drop Packet Condition: If the ttl is 0
    if (this->tesla.routingTable.find(msg.srcAddr) && this->tesla.routingTable.find(msg.intermediateAddr)){
        if (msg.srcSeqNum <= this->tesla.routingTable.get(msg.srcAddr)->seqNum) return; // Drop Packet Condition: If the seqNum is less than the seqNum already received
        string hashRes = msg.hash;
        int hashIterations = (8 * (msg.srcSeqNum - 1)) + 1 + msg.hopCount;
        for (int i = 1; i < hashIterations; i++) {
            hashRes = sha256(hashRes);
            cout << "Calculated Hash " << hashRes << endl;
        }
        if (hashRes != this->tesla.routingTable.get(msg.intermediateAddr)->hash) return; // Drop Packet Condition: If the hash does not match the hash for the seqNum
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

        if (this->tesla.routingTable.find(msg.destAddr)) {
            rrep.destSeqNum = this->tesla.routingTable.get(msg.destAddr)->seqNum;
        } else {
            rrep.destSeqNum = this->seqNum;
            this->tesla.routingTable.insert(msg.srcAddr, ROUTING_TABLE_ENTRY(msg.srcAddr, msg.intermediateAddr, this->seqNum, 0, std::chrono::system_clock::now(), msg.hash));
            // this->tesla.routingTable[msg.srcAddr] = ROUTING_TABLE_ENTRY(msg.srcAddr, msg.intermediateAddr, this->seqNum, 0, std::chrono::system_clock::now(), msg.hash); // TODO: Check what is the hash field supposed to contain again?
        }

        rrep.hopCount = 1;
        rrep.hash = this->hashChainCache[(msg.srcSeqNum - 1) * (8) + rrep.hopCount];

        string buf = rrep.serialize();
        cout << "Constructed RREP: " << buf << endl;
        if (msg.hopCount == 1){
            sendData(rrep.destAddr, buf); // Send back directly if neighbor
        } else {
            cout << "Sending RREP to next hop: " << this->tesla.routingTable.get(msg.srcAddr)->nextHopID << endl;
            sendData(this->tesla.routingTable.get(msg.srcAddr)->nextHopID, buf); // send to next hop stored
        }
        
        // TODO: Check ttl 
        // TODO: Attach HERR
    }
    else {     // else increment hop count and forward rreq
        msg.hopCount++;
        msg.ttl--;

        if (this->tesla.routingTable.find(msg.destAddr)) {
            msg.destSeqNum = this->tesla.routingTable.get(msg.destAddr)->seqNum;
        } else {
            msg.destSeqNum = this->seqNum;
        }
        cout << "Adding to routing table. "; this->tesla.routingTable[msg.srcAddr].print();
        this->tesla.routingTable.insert(msg.srcAddr, ROUTING_TABLE_ENTRY(msg.srcAddr, msg.intermediateAddr, msg.srcSeqNum, msg.hopCount, std::chrono::system_clock::now(), msg.hash));
        // this->tesla.routingTable[msg.srcAddr] = ROUTING_TABLE_ENTRY(msg.srcAddr, msg.intermediateAddr, msg.srcSeqNum, msg.hopCount, std::chrono::system_clock::now(), msg.hash); // TODO: DONT UPDATE THE HASH HERE LEAVE IT
        cout << "Added to routing table."; this->tesla.routingTable[msg.srcAddr].print();

        msg.hash = this->hashChainCache[(msg.srcSeqNum - 1) * (8) + msg.hopCount];

        // Add self to hashTree & update rootHash
        tree.addSelf(this->addr, msg.hopCount);
        msg.hashTree = tree.toVector();
        msg.rootHash = tree.getRoot()->hash;

        msg.intermediateAddr = this->addr;
        string buf = msg.serialize();
        cout << "forwarding RREQ : " << buf << endl;
        udpInterface.broadcast(buf); // Add condition where we directly send to the neighbor if we have it cached. Else, broadcast
    }
    // update cached seqNum
    cout << "Finished handling RREQ." << endl;
}

void drone::routeReplyHandler(json& data){
    cout << "Handling RREP." << endl;
    std::lock_guard<std::mutex> lock(this->routingTableMutex);
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
        this->tesla.routingTable.print();
        return;
    } else if (msg.srcSeqNum < this->tesla.routingTable[msg.intermediateAddr].seqNum){
        cout << "Smaller seqNum, dropping RREP." << endl;
        return;
    }

    if (msg.destAddr == this->addr){ 
        this->tesla.routingTable.insert(msg.srcAddr, ROUTING_TABLE_ENTRY(msg.srcAddr, msg.intermediateAddr, msg.srcSeqNum, msg.hopCount, std::chrono::system_clock::now(), msg.hash));
        // this->tesla.routingTable[msg.srcAddr] = ROUTING_TABLE_ENTRY(msg.srcAddr, msg.intermediateAddr, msg.srcSeqNum, msg.hopCount, std::chrono::system_clock::now(), msg.hash);
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
        sendData(this->tesla.routingTable.get(msg.destAddr)->nextHopID, buf);
        // TODO: Attach HERR
    }
}

void drone::routeErrorHandler(MESSAGE& msg){
    // this is not the correct place to write this but
    // generate RERRs under the following conditions:
    // A node detects link breakage of active route
    // Node cannot detects link breakage with neighbor
}

string drone::generate_nonce(const size_t length = 16) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);

    std::vector<unsigned char> random_bytes(length);
    for (size_t i = 0; i < length; ++i) {
        random_bytes[i] = static_cast<unsigned char>(dis(gen));
    }

    std::stringstream ss;
    for (const auto &byte : random_bytes) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }

    return ss.str();
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

void drone::sendDataUDP(const string& containerName, const string& msg) {
    try {
        udpInterface.sendTo(containerName, msg, BRDCST_PORT);
    } catch (const std::exception& e) {
        std::cerr << "Error sending UDP data: " << e.what() << std::endl;
    }
}

void drone::neighborDiscoveryHelper(){
    /* Function on another thread to repeatedly send authenticator and TESLA broadcasts */
    string msg;
    msg = this->tesla.init_tesla(this->addr).serialize();
    udpInterface.broadcast(msg);
    msg = INIT_MESSAGE(this->hashChainCache.front(), this->addr).serialize();

    while(true){
        sleep(5); // TODO: Change to TESLA/Authenticator disclosure time?
        {
            std::lock_guard<std::mutex> lock(this->routingTableMutex);
            this->tesla.routingTable.cleanup();
        }

        {
            std::lock_guard<std::mutex> lock(this->helloRecvTimerMutex);
            helloRecvTimer = std::chrono::steady_clock::now();
            udpInterface.broadcast(msg);
        }
    }
}

void drone::neighborDiscoveryFunction(){
    /* HashChain is generated where the most recent hashes are stored in the front (Eg. 0th index is the most recent hash)
    
    Temp: Hardcoding number of hashes in hashChain (10 seqNums * 8 max hop distance) = 80x hashed
        What happens when we reach the end of the hash chain?
        Skipping the step to verify authenticity of drone (implement later, not very important) 
        
    TODO: Include function that dynamically generates hashChain upon nearing depletion    
        */
    unsigned char hBuf[56];
    RAND_bytes(hBuf, sizeof(hBuf));
    std::stringstream ss;
    for (int i = 0; i < sizeof(hBuf); ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hBuf[i]);
    }
    string hash = ss.str();
    for (int i = 0; i < 80; ++i) {
        hash = sha256(hash);
        this->hashChainCache.push_front(hash);
        // cout << "Hash: " << hash << endl;
    }

    auto resetTableTimer = std::chrono::steady_clock::now();
    std::thread neighborDiscoveryThread([&](){
        this->neighborDiscoveryHelper();
    });
    
    while (true) {
        try {
            struct sockaddr_in client_addr;
            string receivedMsg = udpInterface.receiveFrom(client_addr);

            char client_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(client_addr.sin_addr), client_ip, INET_ADDRSTRLEN);
            int client_port = ntohs(client_addr.sin_port);

            // std::cout << "Received UDP message: " << receivedMsg << std::endl;
            // std::cout << "From: " << client_ip << ":" << client_port << std::endl;
            this->clientResponseThread(receivedMsg);
        } catch (const std::exception& e) {
            std::cerr << "Error in neighborDiscoveryFunction: " << e.what() << std::endl;
            break;
        }
    }

        /*
        The Plan: We ourselves, send out a HELLO that recieves broadcast messages, with a ttl or time limit of a certain point so we can't get spoofed messages (Make this a seperate thread from neighbor discovery function?)
        Repurpose setupFunction() to send broadcast its TESLA message and authenticator hash chain, in doing so broadcasting itself in the process
        In neighborDiscoveryFunction() we process those messages and add the routing entry for authenticator hash chain and TESLA hash chain, as well as adding to our neighbor list that we have a new (or exisiting neighbor). Ignore message if we already have neighbor
        - We may also want to reset the list every number of intervals, requiring us to lock the list to prevent sending data to stale neighbors
        - Issue of generating new hash chain; how does the host node decide when they should create a new hash chain and send it out? In this scenario, should we just always modify our routing entries to accept the latest message? That could end up being a lot of processing
        */
    // Add some check to close this function if drone is closed
}

void drone::start() {
    std::thread udpThread([this](){
        this->neighborDiscoveryFunction();
    });

    cout << "Entering server loop " << endl;
    while (true) {
        try {
            int clientSock = this->tcpInterface.accept_connection();
            
            std::thread([this, clientSock](){
                try {
                    string msg = this->tcpInterface.receive_data(clientSock);
                    
                    cout << "Message received at: ";
                    auto now = std::chrono::system_clock::now();
                    std::time_t timestamp = std::chrono::system_clock::to_time_t(now);
                    cout << std::ctime(&timestamp);
                    cout << msg << endl;

                    this->clientResponseThread(msg);
                } catch (const std::exception& e) {
                    std::cerr << "Error handling client: " << e.what() << std::endl;
                }
                close(clientSock);
            }).detach();
        } catch (const std::exception& e) {
            std::cerr << "Error accepting connection: " << e.what() << std::endl;
        }
    }
}

int main(int argc, char* argv[]) {
    cout << "Starting drone." << endl;
    const string param1 = std::getenv("PARAM1");
    const char* param2 = std::getenv("PARAM2");
    const char* param3 = std::getenv("PARAM3");
    drone node(std::stoi(param2), std::stoi(param3)); // env vars for init
    cout << "Drone object created." << endl;

    node.start();

    /*Temp code to make all drones start at the same time
    Waits until the nearest 30 seconds to start code*/
    // auto now = std::chrono::system_clock::now();
    // auto now_sec = std::chrono::time_point_cast<std::chrono::seconds>(now);
    // int currSecond = now_sec.time_since_epoch().count() % 60;
    // int secsToWait = 0;

    // if (currSecond > 30) {
    //     secsToWait = 60 - currSecond + 30;
    // } else {
    //     secsToWait = 30 - currSecond;
    // }

    // cout << "Waiting for " << secsToWait << " seconds." << endl;
    // sleep(secsToWait);
    // Reminder to set up phase 1 and phase 2 to only allow tesla init messages in phase 1

    return 0;
}
