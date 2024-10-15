#include <routing/drone.hpp>

std::chrono::high_resolution_clock::time_point globalStartTime;
std::chrono::high_resolution_clock::time_point globalEndTime;

drone::drone(int port, int nodeID) : udpInterface(BRDCST_PORT), tcpInterface(port) {
    cout << "Drone constructor called" << endl;
    this->addr = "drone" + std::to_string(nodeID) + "-service.default";
    this->port = port;
    this->nodeID = nodeID;
    this->seqNum = 0;
}

void drone::clientResponseThread(){
    /* function to handle all incoming messages from the client
    check what type of message it is; launch the function to handle whatever type it is */
    
    while (running) {
        json jsonData;

        {
            std::unique_lock<std::mutex> lock(queueMutex);
            cv.wait(lock, [this] { return !messageQueue.empty() || !running; });
            
            if (!running && messageQueue.empty()) {
                break;
            }
            
            if (!messageQueue.empty()) {
                jsonData = json::parse(messageQueue.front());
                messageQueue.pop();
            } else {
                continue;
            }
        }

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
                    cout << "RERR Handler Called" << endl;
                    routeErrorHandler(jsonData);
                    break;
                case DATA:
                    cout << "Data message received." << endl;
                    dataHandler(jsonData);
                    break;
                case INIT_AUTO_DISCOVERY:
                {
                    cout << "Initiating auto discovery." << endl;
                    GCS_MESSAGE ctl; ctl.deserialize(jsonData);
                    DATA_MESSAGE data; data.data = "Hello from drone " + std::to_string(this->nodeID); data.destAddr = ctl.destAddr; data.srcAddr = this->addr;
                    send(ctl.destAddr, data.serialize());
                    break;
                }
                case INIT_ROUTE_DISCOVERY:
                {
                    cout << "Initiating route discovery." << endl;
                    GCS_MESSAGE ctl;
                    ctl.deserialize(jsonData);
                    initRouteDiscovery(ctl.destAddr);
                    break;
                }
                case EXIT:
                    std::exit(0); // temp, need to resolve mem leaks before actually closing
                    break;
                case VERIFY_ROUTE:
                    verifyRouteHandler(jsonData);
                    break;
                case HELLO:
                    initMessageHandler(jsonData);
                    break;
                default:
                    cout << "Message type not recognized." << endl; 
                    break;
            }
    }
}

void drone::dataHandler(json& data){
    /*Forwards data to next hop, or passes up to application layer if destination*/
    DATA_MESSAGE msg;
    msg.deserialize(data);

    if (msg.isBroadcast || (msg.destAddr == this->addr)) {
        if (this->ipcServer) {
            this->ipcServer->sendData(msg.data + "\n");
        } else {
            cout << "IPC Server not initialized" << endl;
        }
    } else {
        cout << "Forwarding data to next hop." << endl;
        if (this->tesla.routingTable.find(msg.destAddr)) {
            cout << "Route found, sending data." << endl;

            if (sendData(this->tesla.routingTable.get(msg.destAddr)->intermediateAddr, msg.serialize()) != 0){
                RERR rerr;
                // Attach information here for RERR
                TESLA::nonce_data data = this->tesla.getNonceData(msg.srcAddr);
                rerr.create_rerr(data.nonce, data.tesla_key, data.destination, data.auth);
                rerr.addRetAddr(msg.srcAddr);

                sendData(this->tesla.routingTable.get(msg.srcAddr)->intermediateAddr, rerr.serialize());
            }
        } else {
            // we also send a route error?
        }
    }
}

void drone::broadcast(const std::string& msg) {
    DATA_MESSAGE data("BRDCST", this->addr, msg, true);
    cout << "Printing routing table." << endl;
    this->tesla.routingTable.print();
    this->udpInterface.broadcast(data.serialize());
}

int drone::send(const string& destAddr, string msg, bool isExternal){ 
    /*Checks if entry in routing table; else initiates route discovery*/
    if (isExternal){
        DATA_MESSAGE data; data.destAddr = destAddr; data.srcAddr = this->addr; data.data = std::move(msg);
        msg = data.serialize();
    }

    if (!this->tesla.routingTable.find(destAddr)) {
        cout << "Route not found, initiating route discovery." << endl;
        cout << "Destination: " << destAddr << " (Size: " << destAddr.size() << " bytes)" << endl;
        cout << "Message: " << msg << " (Size: " << msg.size() << " bytes)" << endl;
        this->initRouteDiscovery(destAddr);
        // TODO: Once completed, send that data through the route
        // Alternatively, return an error of route cannot be found
        // Start timer after this, and return 0 if rrep not recieved in time (how to catch rrep here?)
    }
    cout << "Sending data." << endl;
    if (sendData(this->tesla.routingTable.get(destAddr)->intermediateAddr, msg) != 0){
        // Remove this entry from our own table, start route discovery again
    }

    return 1;
}

void drone::routeErrorHandler(json& data){
    RERR msg; msg.deserialize(data);

    HERR currHERR = this->tesla.routingTable[msg.dst_list[0]].getMostRecentHERR();
    RERR rerr_prime; string nonce = msg.nonce_list[0]; string tsla_key = msg.tsla_list[0]; // TODO: Replace hardcoded zero indexed references
    rerr_prime.create_rerr_prime(nonce, msg.dst_list[0], msg.auth_list[0]);

    // std::cout << "DEBUG: currHERR.hash = " << currHERR.hRERR << ", currHERR.mac = " << currHERR.mac_t << std::endl;
    // std::cout << "DEBUG: rerr_prime.nonce = " << rerr_prime.nonce_list[0] << ", rerr_prime.dst = " << rerr_prime.dst_list[0] << ", rerr_prime.auth = " << rerr_prime.auth_list[0] << std::endl;
    // std::cout << "DEBUG: tsla_key = " << tsla_key << std::endl;

    if (currHERR.verify(rerr_prime, tsla_key)) {
        cout << "DEBUG: Successful Tesla Verification" << endl;

        try {
            TESLA::nonce_data data = this->tesla.getNonceData(msg.retAddr);
            msg.create_rerr(data.nonce, data.tesla_key, data.destination, data.auth);
            sendData(this->tesla.routingTable.get(msg.retAddr)->intermediateAddr, msg.serialize());
            // TODO: Remove entry from table
        } catch (std::runtime_error& e) {
            std::cout << "End of backpropagation reached." << std::endl;
        }
    } else {
        cout << "DEBUG: FAILURE, Invalid Tesla Verification" << endl; // What to do in failure scenario?
    }

    // extra step: if it does, back check the tesla key until we reach the original key; (if it does replace it?) 

    // neighbor case
}

void drone::verifyRouteHandler(json& data){
    this->tesla.routingTable.print();
    this->tesla.printNonceMap();
}

int drone::sendData(string containerName, const string& msg) {
    TCPInterface clientSocket(0, false); // 0 for port, false for is_server
    if (clientSocket.connect_to(containerName, PORT_NUMBER) == -1) {
        cout << "Error connecting to " << containerName << endl;
        return -1;
    }
    if (clientSocket.send_data(msg) == -1) {
        cout << "Error sending data to " << containerName << endl;
        return -1;
    }
    cout << "Data sent to " << containerName << endl;
    return 0;
}

void drone::initRouteDiscovery(const string& destAddr){
    /* Constructs an RREQ and broadcast to neighbors
    It is worth noting that routes may sometimes be incorrectly not found because a routing table clear may occur during the route discovery process. To mitagate this issue, we can try any or all of the following: 1) Retry the route discovery process X times before giving up. 2) Increase the amount of time before a routing table clear occurs (Currently at 30 seconds). Check github issue for full description.
    */

    RREQ msg; msg.type = ROUTE_REQUEST; msg.srcAddr = this->addr; msg.recvAddr = this->addr; msg.destAddr = destAddr; msg.srcSeqNum = ++this->seqNum; msg.ttl = this->max_hop_count;

    {   
        std::lock_guard<std::mutex> lock(this->routingTableMutex);
        auto it = this->tesla.routingTable.get(msg.destAddr);
        msg.destSeqNum = (it) ? it->seqNum : 0;
    }
    msg.hopCount = 1; // 1 = broadcast range
    msg.hash = (msg.srcSeqNum == 1) ? this->hashChainCache[1] : this->hashChainCache[(msg.srcSeqNum - 1) * this->max_hop_count + 1]; // TODO: Wrap around the cache when needed

    HashTree tree = HashTree(msg.srcAddr); // init HashTree
    msg.hashTree = tree.toVector();
    msg.rootHash = tree.getRoot()->hash;

    RERR rerr_prime; string nonce = generate_nonce(); string tsla_hash = this->tesla.getCurrentHash();
    rerr_prime.create_rerr_prime(nonce, msg.srcAddr, msg.hash);
    msg.herr = HERR::create(rerr_prime, tsla_hash);
    this->tesla.insert(msg.destAddr, TESLA::nonce_data{nonce, tsla_hash, msg.hash, msg.srcAddr});

    globalStartTime = std::chrono::high_resolution_clock::now();
    string buf = msg.serialize();
    udpInterface.broadcast(buf);
}

void drone::initMessageHandler(json& data){
    /*Creates a routing table entry for each authenticator & tesla msg received*/
    {
        std::lock_guard<std::mutex> lock(this->helloRecvTimerMutex);
        if (std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - helloRecvTimer).count() > helloRecvTimeout) return;
    }
    INIT_MESSAGE msg;
    msg.deserialize(data);
    if (msg.mode == INIT_MESSAGE::TESLA) {
        cout << "Inserting tesla info into routing table." << endl;
        this->tesla.routingTable[msg.srcAddr].setTeslaInfo(msg.hash, std::chrono::seconds(msg.disclosure_time));
        this->tesla.routingTable[msg.srcAddr].print();
    } else {
        // entry(srcAddr, nextHop, seqNum, hopCount/cost(?), ttl, hash)
        cout << "Creating routing table entry for " << msg.srcAddr << endl;
        ROUTING_TABLE_ENTRY entry(msg.srcAddr, msg.srcAddr, 0, 1, std::chrono::system_clock::now(), msg.hash);
        std::lock_guard<std::mutex> lock(this->routingTableMutex);
        this->tesla.routingTable.insert(msg.srcAddr, entry);
    }
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
    if (this->tesla.routingTable.find(msg.srcAddr) && this->tesla.routingTable.find(msg.recvAddr)){
        if (msg.srcSeqNum <= this->tesla.routingTable.get(msg.srcAddr)->seqNum) return; // Drop Packet Condition: If the seqNum is less than the seqNum already received
        string hashRes = msg.hash;
        int hashIterations = (8 * (msg.srcSeqNum - 1)) + 1 + msg.hopCount;
        for (int i = 1; i < hashIterations; i++) {
            hashRes = sha256(hashRes);
            cout << "Calculated Hash " << hashRes << endl;
        }
        if (hashRes != this->tesla.routingTable.get(msg.recvAddr)->hash) return; // Drop Packet Condition: If the hash does not match the hash for the seqNum
    }

    // Rebuild hash tree and then check if it's correct
    // TODO: Do a check where we make sure the last node being added is in fact the last node placed in the tree
    HashTree tree = HashTree(msg.hashTree, msg.hopCount, msg.recvAddr);
    tree.printTree(tree.getRoot());
    if (!tree.verifyTree(msg.rootHash)){
        cout << "HashTree verification failed, dropping RREQ." << endl;
        return;
    }

    // TODO: Cache source addr as a reachable destination in the cache with the sender of the RREQ as the intermediary (if this->addr != msg.srcAddr)
    // if (msg.hopCount != 0) this->routingTable[msg.srcAddr] = ROUTING_TABLE_ENTRY(msg.srcAddr, msg.recvAddr, msg.srcSeqNum, msg.hopCount, 10, msg.hash); // TODO: This doesn't work...

    // if true, check if currNode is the dest {Can also send back RREP if cached, should weigh pros/cons}
    if (msg.destAddr == this->addr){ // Sends RREP
        RREP rrep; rrep.srcAddr = this->addr; rrep.destAddr = msg.srcAddr; rrep.recvAddr = this->addr;
        rrep.srcSeqNum = msg.srcSeqNum; // Maintain src Seqnum

        if (this->tesla.routingTable.find(msg.destAddr)) {
            rrep.destSeqNum = this->tesla.routingTable.get(msg.destAddr)->seqNum;
        } else {
            rrep.destSeqNum = this->seqNum;
            this->tesla.routingTable.insert(msg.srcAddr, ROUTING_TABLE_ENTRY(msg.srcAddr, msg.recvAddr, this->seqNum, 0, std::chrono::system_clock::now(), msg.hash), msg.herr);
        }

        rrep.hopCount = 1;
        rrep.hash = this->hashChainCache[(msg.srcSeqNum - 1) * (8) + rrep.hopCount];

        RERR rerr_prime;string nonce = generate_nonce(); string tsla_hash = this->tesla.getCurrentHash();
        rerr_prime.create_rerr_prime(nonce, rrep.srcAddr, rrep.hash);
        rrep.herr = HERR::create(rerr_prime, tsla_hash);
        this->tesla.insert(rrep.destAddr, TESLA::nonce_data{nonce, tsla_hash, rrep.hash, rrep.srcAddr});

        string buf = rrep.serialize();
        cout << "Constructed RREP: " << buf << endl;
        if (msg.hopCount == 1){
            sendData(rrep.destAddr, buf); // Send back directly if neighbor
        } else {
            cout << "Sending RREP to next hop: " << this->tesla.routingTable.get(msg.srcAddr)->intermediateAddr << endl;
            sendData(this->tesla.routingTable.get(msg.srcAddr)->intermediateAddr, buf); // send to next hop stored
        }
        
        // TODO: Check ttl
    }
    else {     // else increment hop count and forward rreq
        msg.hopCount++;
        msg.ttl--;

        if (this->tesla.routingTable.find(msg.destAddr)) {
            msg.destSeqNum = this->tesla.routingTable.get(msg.destAddr)->seqNum;
        } else {
            msg.destSeqNum = this->seqNum;
        }
        this->tesla.routingTable.insert(msg.srcAddr, ROUTING_TABLE_ENTRY(msg.srcAddr, msg.recvAddr, msg.srcSeqNum, msg.hopCount, std::chrono::system_clock::now(), msg.hash), msg.herr);

        msg.hash = this->hashChainCache[(msg.srcSeqNum - 1) * (8) + msg.hopCount];

        // Add self to hashTree & update rootHash
        tree.addSelf(this->addr, msg.hopCount);
        msg.hashTree = tree.toVector();
        msg.rootHash = tree.getRoot()->hash;
        
        RERR rerr_prime; string nonce = generate_nonce(); string tsla_hash = this->tesla.getCurrentHash();
        rerr_prime.create_rerr_prime(nonce, msg.srcAddr, msg.hash);
        msg.herr = HERR::create(rerr_prime, tsla_hash);
        this->tesla.insert(msg.destAddr, TESLA::nonce_data{nonce, tsla_hash, msg.hash, msg.srcAddr});

        msg.recvAddr = this->addr;
        string buf = msg.serialize();
        cout << "forwarding RREQ : " << buf << endl;
        udpInterface.broadcast(buf); // Add condition where we directly send to the neighbor if we have it cached. Else, broadcast
    }
    // update cached seqNum
}

void drone::routeReplyHandler(json& data){
    cout << "Handling RREP." << endl;
    std::lock_guard<std::mutex> lock(this->routingTableMutex);
    RREP msg;
    msg.deserialize(data);

    // check sha256(received hash) == cached hash for that node
    string hashRes = msg.hash;
    int hashIterations = (8 * (msg.srcSeqNum - 1)) + 1 + msg.hopCount;
    for (int i = this->tesla.routingTable[msg.recvAddr].cost; i < hashIterations; i++) {
        hashRes = sha256(hashRes);
    }

    if (hashRes != this->tesla.routingTable[msg.recvAddr].hash){ // code is expanded for debugging purposes
        cout << "Calculated Hash " << hashRes << endl;
        cout << "Incorrect hash, dropping RREP." << endl;
        return;
    } else if (msg.srcSeqNum < this->tesla.routingTable[msg.recvAddr].seqNum){
        cout << "Smaller seqNum, dropping RREP." << endl;
        return;
    }

    if (msg.destAddr == this->addr){ 
        cout << "Inserting routing entry for " << msg.srcAddr << endl;
        this->tesla.routingTable.insert(msg.srcAddr, ROUTING_TABLE_ENTRY(msg.srcAddr, msg.recvAddr, msg.srcSeqNum, msg.hopCount, std::chrono::system_clock::now(), msg.hash), msg.herr);
        cout << "Successfully completed route" << endl;
        globalEndTime = std::chrono::high_resolution_clock::now();
        cout << "Elapsed Time: " << std::chrono::duration_cast<std::chrono::milliseconds>(globalEndTime - globalStartTime).count() << " ms" << endl;
        return;
    } else {
        cout << "Forwarding RREP to next hop." << endl;
        this->tesla.routingTable.insert(msg.srcAddr, ROUTING_TABLE_ENTRY(msg.srcAddr, msg.recvAddr, msg.srcSeqNum, msg.hopCount, std::chrono::system_clock::now(), msg.hash), msg.herr);
        msg.hopCount++;
        msg.hash = this->hashChainCache[(msg.srcSeqNum - 1) * (8) + msg.hopCount];
        msg.recvAddr = this->addr; // update intermediate addr so final node can add to cache
        
        RERR rerr_prime; string nonce = generate_nonce(); string tsla_hash = this->tesla.getCurrentHash();
        rerr_prime.create_rerr_prime(nonce, msg.srcAddr, msg.hash);
        msg.herr = HERR::create(rerr_prime, tsla_hash);
        this->tesla.insert(msg.destAddr, TESLA::nonce_data{nonce, tsla_hash, msg.hash, msg.srcAddr});

        cout << "Sending RREP to next hop" << endl;

        string buf = msg.serialize();
        sendData(this->tesla.routingTable.get(msg.destAddr)->intermediateAddr, buf);
    }
}

string drone::generate_nonce(const size_t length) {
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
    cout << "Broadcasting TESLA Init Message: " << msg << endl;
    udpInterface.broadcast(msg);
    msg = INIT_MESSAGE(this->hashChainCache.front(), this->addr).serialize();

    while(true){
        sleep(5); // TODO: Change to TESLA/Authenticator disclosure time?
        {
            std::lock_guard<std::mutex> lock(this->routingTableMutex);
            // this->tesla.routingTable.cleanup();
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
            // this->clientResponseThread(receivedMsg);
            {
                std::lock_guard<std::mutex> lock(queueMutex);
                this->messageQueue.push(receivedMsg);
                std::cout << "Received message: " << receivedMsg << std::endl;
            }
            cv.notify_one();
        } catch (const std::exception& e) {
            std::cerr << "Error in neighborDiscoveryFunction: " << e.what() << std::endl;
            break;
        }
    }
}

void drone::start() {
    cout << "Starting drone." << endl;

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

    std::thread udpThread([this](){
        this->neighborDiscoveryFunction();
    });

    std::thread processThread([this](){
        this->clientResponseThread();
    });

    cout << "Entering server loop " << endl;
    this->ipcServer = new IPCServer(60137);
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

                {
                    std::lock_guard<std::mutex> lock(queueMutex);
                    this->messageQueue.push(msg);
                    std::cout << "Received message: " << msg << std::endl;
                }
                cv.notify_one();
                } catch (const std::exception& e) {
                    std::cerr << "Error handling client: " << e.what() << std::endl;
                }
                close(clientSock);
            }).detach();
        } catch (const std::exception& e) {
            std::cerr << "Error accepting TCP connection: " << e.what() << std::endl;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}