#include <routing/drone.hpp>

std::chrono::high_resolution_clock::time_point globalStartTime;
std::chrono::high_resolution_clock::time_point globalEndTime;

drone::drone(int port, int nodeID) : udpInterface(BRDCST_PORT), tcpInterface(port) {
    logger = createLogger(fmt::format("drone_{}", nodeID));

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
                    logger->info("RREQ received");
                    routeRequestHandler(jsonData);
                    break;
                case ROUTE_REPLY:
                    logger->info("RREP received");  
                    routeReplyHandler(jsonData);
                    break;
                case ROUTE_ERROR:
                    logger->info("RERR received");
                    routeErrorHandler(jsonData);
                    break;
                case DATA:
                    logger->info("Data message received");
                    dataHandler(jsonData);
                    break;
                case INIT_AUTO_DISCOVERY:
                {
                    logger->info("Initiating auto discovery.");
                    GCS_MESSAGE ctl; ctl.deserialize(jsonData);
                    DATA_MESSAGE data; data.data = "Hello from drone " + std::to_string(this->nodeID); data.destAddr = ctl.destAddr; data.srcAddr = this->addr;
                    send(ctl.destAddr, data.serialize());
                    break;
                }
                case INIT_ROUTE_DISCOVERY:
                {
                    logger->info("Initiating route discovery.");
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
                    logger->warn("Message type not recognized.");
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
            logger->error("IPC Server not initialized");
        }
    } else {
        logger->debug("Forwarding data to next hop");
        if (this->tesla.routingTable.find(msg.destAddr)) {
            logger->debug("Route found, sending data");

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
    logger->debug("Broadcasting data");
    this->udpInterface.broadcast(data.serialize());
}

int drone::send(const string& destAddr, string msg, bool isExternal){ 
    /*Checks if entry in routing table; else initiates route discovery*/
    logger->debug("Preparing to send data: {}", msg);
    if (isExternal){
        DATA_MESSAGE data; data.destAddr = destAddr; data.srcAddr = this->addr; data.data = std::move(msg);
        msg = data.serialize();
    }

    if (!this->tesla.routingTable.find(destAddr)) {
        logger->info("Route not found, initiating route discovery.");
        logger->trace("Destination: {}", destAddr, " (Size: ", destAddr.size(), " bytes)");
        logger->trace("Message: {}", msg, " (Size: ", msg.size(), " bytes)");

        // TODO: return an error of route cannot be found

        PendingRoute pendingRoute;
        pendingRoute.destAddr = destAddr;
        pendingRoute.msg = msg;
        pendingRoute.expirationTime = std::chrono::steady_clock::now() + std::chrono::seconds(this->timeout_sec);
        {
            std::lock_guard<std::mutex> lock(pendingRoutesMutex);
            pendingRoutes.push_back(pendingRoute);
        }
        this->initRouteDiscovery(destAddr);
    } else {
        sendData(this->tesla.routingTable.get(destAddr)->intermediateAddr, msg) != 0;
    }

    return 1;
}

void drone::routeErrorHandler(json& data){
    RERR msg; msg.deserialize(data);

    HERR currHERR = this->tesla.routingTable[msg.dst_list[0]].getMostRecentHERR();
    RERR rerr_prime; string nonce = msg.nonce_list[0]; string tsla_key = msg.tsla_list[0]; // TODO: Replace hardcoded zero indexed references
    rerr_prime.create_rerr_prime(nonce, msg.dst_list[0], msg.auth_list[0]);

    logger->trace("currHERR.hash = {}", currHERR.hRERR, "currHERR.mac = {}", currHERR.mac_t);
    logger->trace("rerr_prime.nonce = {}, rerr_prime.dst = {}, rerr_prime.auth = {}", 
              rerr_prime.nonce_list[0], 
              rerr_prime.dst_list[0], 
              rerr_prime.auth_list[0]);
    logger->trace("tsla_key = {}", tsla_key);

    if (currHERR.verify(rerr_prime, tsla_key)) {
        logger->debug("Successful Tesla Verification");

        try {
            TESLA::nonce_data data = this->tesla.getNonceData(msg.retAddr);
            msg.create_rerr(data.nonce, data.tesla_key, data.destination, data.auth);
            sendData(this->tesla.routingTable.get(msg.retAddr)->intermediateAddr, msg.serialize());
            // TODO: Remove entry from table
        } catch (std::runtime_error& e) {
            logger->debug("End of backpropagation reached.");
        }
    } else {
        logger->error("Invalid Tesla Verification");
    }

    // extra step: if it does, back check the tesla key until we reach the original key; (if it does replace it?) 

    // neighbor case
}

void drone::verifyRouteHandler(json& data){
    this->tesla.routingTable.print();
    this->tesla.printNonceMap();
}

int drone::sendData(string containerName, const string& msg) {
    logger->debug("Attempting to connect to {} on port {}", containerName, PORT_NUMBER);
    TCPInterface clientSocket(0, false); // 0 for port, false for is_server
    if (clientSocket.connect_to(containerName, PORT_NUMBER) == -1) {
        logger->error("Error connecting to {}", containerName);
        return -1;
    }

    logger->debug("Sending data: {}", msg);

    if (clientSocket.send_data(msg) == -1) {
        logger->error("Error sending data to {}", containerName);
        return -1;
    }
    logger->info("Data sent to {}", containerName);
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
        logger->debug("Inserting tesla info into routing table.");
        this->tesla.routingTable[msg.srcAddr].setTeslaInfo(msg.hash, std::chrono::seconds(msg.disclosure_time));
        this->tesla.routingTable[msg.srcAddr].print();
    } else {
        // entry(srcAddr, nextHop, seqNum, hopCount/cost(?), ttl, hash)
        logger->debug("Creating routing table entry for {}", msg.srcAddr);
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
    logger->debug("=== Starting RREQ Handler ===");
    try {
        std::lock_guard<std::mutex> lock(this->routingTableMutex);
        RREQ msg;
        
        msg.deserialize(data);
        
        logger->debug("RREQ Details - SrcAddr: {}, DestAddr: {}, HopCount: {}", 
                     msg.srcAddr, msg.destAddr, msg.hopCount);

        if (msg.srcAddr == this->addr) { // Drop Packet Condition: If the srcAddr is the same as the current node
        // TODO: Add case to drop packet if this RREQ has already been seen
        // if (msg.ttl == 0) return; // Drop Packet Condition: If the ttl is 0
            logger->debug("Dropping RREQ: Source address matches current node");
            return;
        }

        // Add validation for message fields
        if (msg.hashTree.empty()) {
            logger->error("Invalid RREQ: Empty hash tree");
            return;
        }

        logger->debug("Checking routing table entries");
        if (this->tesla.routingTable.find(msg.srcAddr) && this->tesla.routingTable.find(msg.recvAddr)) {
            logger->debug("Found routing entries for src and recv addresses");
            
            if (msg.srcSeqNum <= this->tesla.routingTable.get(msg.srcAddr)->seqNum) { // Drop Packet Condition: If the seqNum is less than the seqNum already received
                logger->debug("Dropping RREQ: Smaller sequence number");
                return;
            }

            string hashRes = msg.hash;
            int hashIterations = (8 * (msg.srcSeqNum - 1)) + 1 + msg.hopCount;
            
            logger->debug("Calculating hash iterations: {}", hashIterations);
            for (int i = 1; i < hashIterations; i++) {
                hashRes = sha256(hashRes);
                logger->trace("Hash iteration {}: {}", i, hashRes);
            }

            if (hashRes != this->tesla.routingTable.get(msg.recvAddr)->hash) {
                logger->error("Hash verification failed");
                logger->debug("Expected: {}", this->tesla.routingTable.get(msg.recvAddr)->hash);
                logger->debug("Calculated: {}", hashRes);
                return;
            }
        }

        // Protect against null pointer dereference
        if (msg.hashTree.empty()) {
            logger->error("Empty hash tree in RREQ");
            return;
        }

        logger->debug("Building HashTree with {} elements", msg.hashTree.size());
        HashTree tree(msg.hashTree, msg.hopCount, msg.recvAddr);
        
        logger->debug("Verifying HashTree");
        if (!tree.verifyTree(msg.rootHash)){
            logger->error("HashTree verification failed - Root hash mismatch");
            logger->debug("Expected root hash: {}", msg.rootHash);
            logger->debug("Calculated root hash: {}", tree.getRoot()->hash);
            return;
        }

        // Check if we're the destination
        if (msg.destAddr == this->addr) {
            logger->info("This node is the destination, preparing RREP");
            try {
                RREP rrep;
                rrep.srcAddr = this->addr;
                rrep.destAddr = msg.srcAddr;
                rrep.recvAddr = this->addr;
                rrep.srcSeqNum = msg.srcSeqNum;

                if (this->tesla.routingTable.find(msg.destAddr)) {
                    rrep.destSeqNum = this->tesla.routingTable.get(msg.destAddr)->seqNum;
                } else {
                    rrep.destSeqNum = this->seqNum;
                    logger->debug("Creating new routing table entry");
                    this->tesla.routingTable.insert(msg.srcAddr, 
                        ROUTING_TABLE_ENTRY(msg.srcAddr, msg.recvAddr, this->seqNum, 0, 
                        std::chrono::system_clock::now(), msg.hash), msg.herr);
                }

                rrep.hopCount = 1;
                rrep.hash = this->hashChainCache[(msg.srcSeqNum - 1) * (8) + rrep.hopCount];

                RERR rerr_prime;
                string nonce = generate_nonce();
                string tsla_hash = this->tesla.getCurrentHash();
                
                logger->debug("Creating RERR prime with nonce");
                rerr_prime.create_rerr_prime(nonce, rrep.srcAddr, rrep.hash);
                rrep.herr = HERR::create(rerr_prime, tsla_hash);
                
                this->tesla.insert(rrep.destAddr, 
                    TESLA::nonce_data{nonce, tsla_hash, rrep.hash, rrep.srcAddr});

                string buf = rrep.serialize();
                logger->info("Sending RREP: {}", buf);

                if (msg.hopCount == 1) {
                    sendData(rrep.destAddr, buf);
                } else {
                    auto nextHop = this->tesla.routingTable.get(msg.srcAddr)->intermediateAddr;
                    logger->info("Sending RREP to next hop: {}", nextHop);
                    sendData(nextHop, buf);
                }
            } catch (const std::exception& e) {
                logger->error("Exception while creating RREP: {}", e.what());
                return;
            }
        } else {
            logger->debug("Forwarding RREQ");
            try {
                msg.hopCount++;
                msg.ttl--;

                if (this->tesla.routingTable.find(msg.destAddr)) {
                    msg.destSeqNum = this->tesla.routingTable.get(msg.destAddr)->seqNum;
                } else {
                    msg.destSeqNum = this->seqNum;
                }

                logger->debug("Inserting routing table entry");
                this->tesla.routingTable.insert(msg.srcAddr, 
                    ROUTING_TABLE_ENTRY(msg.srcAddr, msg.recvAddr, msg.srcSeqNum, 
                    msg.hopCount, std::chrono::system_clock::now(), msg.hash), 
                    msg.herr);

                msg.hash = this->hashChainCache[(msg.srcSeqNum - 1) * (8) + msg.hopCount];

                logger->debug("Updating HashTree");
                tree.addSelf(this->addr, msg.hopCount);
                msg.hashTree = tree.toVector();
                msg.rootHash = tree.getRoot()->hash;
                
                RERR rerr_prime;
                string nonce = generate_nonce();
                string tsla_hash = this->tesla.getCurrentHash();
                
                rerr_prime.create_rerr_prime(nonce, msg.srcAddr, msg.hash);
                msg.herr = HERR::create(rerr_prime, tsla_hash);
                this->tesla.insert(msg.destAddr, 
                    TESLA::nonce_data{nonce, tsla_hash, msg.hash, msg.srcAddr});

                msg.recvAddr = this->addr;
                string buf = msg.serialize();
                logger->debug("Broadcasting updated RREQ");
                udpInterface.broadcast(buf); // Add condition where we directly send to the neighbor if we have it cached. Else, broadcast
            } catch (const std::exception& e) {
                logger->error("Exception while forwarding RREQ: {}", e.what());
                return;
            }
        }
    } catch (const std::exception& e) {
        logger->error("Critical error in routeRequestHandler: {}", e.what());
    }
    logger->debug("=== Finished RREQ Handler ===");
}

void drone::routeReplyHandler(json& data) {
    logger->debug("=== Starting RREP Handler ===");
    try {
        logger->debug("Handling RREP payload: {}", data.dump());
        std::lock_guard<std::mutex> lock(this->routingTableMutex);
        RREP msg;
        
        msg.deserialize(data);
        
        logger->debug("RREP Details - SrcAddr: {}, DestAddr: {}, HopCount: {}, SeqNum: {}", 
                     msg.srcAddr, msg.destAddr, msg.hopCount, msg.srcSeqNum);

        // Validate message fields
        if (msg.hash.empty()) {
            logger->error("Invalid RREP: Empty hash");
            return;
        }

        // Check if we have routing table entries for validation
        logger->debug("Checking routing table entries for addr: {}", msg.recvAddr);
        if (!this->tesla.routingTable.find(msg.recvAddr)) {
            logger->error("No routing table entry found for receiver address");
            return;
        }

        // Hash verification
        string hashRes = msg.hash;
        int hashIterations = (8 * (msg.srcSeqNum - 1)) + 1 + msg.hopCount;
        
        logger->debug("Calculating hash iterations: {}", hashIterations);
        for (int i = this->tesla.routingTable[msg.recvAddr].cost; i < hashIterations; i++) {
            hashRes = sha256(hashRes);
            logger->trace("Hash iteration {}: {}", i, hashRes);
            logger->debug("Expected: {}", this->tesla.routingTable.get(msg.recvAddr)->hash);
            logger->debug("Calculated: {}", hashRes);
        }

        if (hashRes != this->tesla.routingTable.get(msg.recvAddr)->hash) {
            logger->error("Hash verification failed");
            logger->debug("Expected: {}", this->tesla.routingTable.get(msg.recvAddr)->hash);
            logger->debug("Calculated: {}", hashRes);
            return;
        }

        if (msg.srcSeqNum < this->tesla.routingTable[msg.recvAddr].seqNum) {
            logger->error("Dropping RREP: Smaller sequence number");
            logger->debug("Received seqNum: {}, Current seqNum: {}", 
                        msg.srcSeqNum, this->tesla.routingTable[msg.recvAddr].seqNum);
            return;
        }

        if (msg.destAddr == this->addr) {
            logger->info("This node is the destination for RREP");
            try {
                logger->debug("Creating routing table entry for source: {}", msg.srcAddr);
                this->tesla.routingTable.insert(
                    msg.srcAddr, 
                    ROUTING_TABLE_ENTRY(
                        msg.srcAddr,
                        msg.recvAddr,
                        msg.srcSeqNum,
                        msg.hopCount,
                        std::chrono::system_clock::now(),
                        msg.hash
                    ),
                    msg.herr
                );
                
                logger->info("Route successfully established to {}", msg.srcAddr);
                globalEndTime = std::chrono::high_resolution_clock::now();
                auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
                    globalEndTime - globalStartTime).count();
                logger->info("Total route establishment time: {} ms", duration);
                
                logger->debug("Processing any pending routes");
                this->processPendingRoutes();
                
            } catch (const std::exception& e) {
                logger->error("Exception while handling destination RREP: {}", e.what());
                return;
            }
        } else {
            logger->info("Forwarding RREP to next hop");
            try {
                logger->debug("Creating routing table entry for source: {}", msg.srcAddr);
                if (!this->tesla.routingTable.find(msg.srcAddr)) {
                    this->tesla.routingTable.insert(
                        msg.srcAddr,
                        ROUTING_TABLE_ENTRY(
                            msg.srcAddr,
                            msg.recvAddr,
                            msg.srcSeqNum,
                            msg.hopCount,
                            std::chrono::system_clock::now(),
                            msg.hash
                        ),
                        msg.herr
                    );
                }

                msg.hopCount++;
                msg.hash = this->hashChainCache[(msg.srcSeqNum - 1) * (8) + msg.hopCount];
                msg.recvAddr = this->addr;

                logger->debug("Creating RERR prime with nonce");
                RERR rerr_prime;
                string nonce = generate_nonce();
                string tsla_hash = this->tesla.getCurrentHash();
                
                rerr_prime.create_rerr_prime(nonce, msg.srcAddr, msg.hash);
                msg.herr = HERR::create(rerr_prime, tsla_hash);
                
                this->tesla.insert(
                    msg.destAddr,
                    TESLA::nonce_data{nonce, tsla_hash, msg.hash, msg.srcAddr}
                );

                string buf = msg.serialize();
                auto nextHop = this->tesla.routingTable.get(msg.destAddr)->intermediateAddr;
                logger->info("Forwarding RREP to next hop: {}", nextHop);
                sendData(nextHop, buf);
                
            } catch (const std::exception& e) {
                logger->error("Exception while forwarding RREP: {}", e.what());
                return;
            }
        }
    } catch (const std::exception& e) {
        logger->error("Critical error in routeReplyHandler: {}", e.what());
    }
    logger->debug("=== Finished RREP Handler ===");
}

void drone::processPendingRoutes(){
        std::vector<PendingRoute> routesToProcess;

        {
            std::lock_guard<std::mutex> lock(pendingRoutesMutex);
            routesToProcess = std::move(pendingRoutes);
            pendingRoutes.clear();
        }

        auto now = std::chrono::steady_clock::now();

        for (const auto& route : routesToProcess) {
            if (now < route.expirationTime && this->tesla.routingTable.find(route.destAddr)) {
                sendData(this->tesla.routingTable.get(route.destAddr)->intermediateAddr, route.msg);
            } else if (now < route.expirationTime) {
                // If the route is not expired but still not found, re-add it to pendingRoutes
                std::lock_guard<std::mutex> lock(pendingRoutesMutex);
                pendingRoutes.push_back(route);
            }
            // If the route is expired, it's simply discarded
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
        logger->error("Error sending UDP data: {}", e.what());
    }
}

void drone::neighborDiscoveryHelper(){
    /* Function on another thread to repeatedly send authenticator and TESLA broadcasts */
    string msg;
    msg = this->tesla.init_tesla(this->addr).serialize();
    logger->trace("Broadcasting TESLA Init Message: {}", msg);
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
            // this->clientResponseThread(receivedMsg);
            {
                std::lock_guard<std::mutex> lock(queueMutex);
                this->messageQueue.push(receivedMsg);
                logger->info("Received message: {}", receivedMsg);
            }
            cv.notify_one();
        } catch (const std::exception& e) {
            std::cerr << "Error in neighborDiscoveryFunction: " << e.what() << std::endl;
            break;
        }
    }
}

void drone::start() {
    logger->info("Starting drone.");

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

    logger->info("Entering server loop");
    this->ipcServer = new IPCServer(60137);
    while (true) {
        try {
            int clientSock = this->tcpInterface.accept_connection();
            
            std::thread([this, clientSock](){
                try {
                    string msg = this->tcpInterface.receive_data(clientSock);
                    
                    auto now = std::chrono::system_clock::now();
                    logger->info("Received TCP message: {}", msg);

                {
                    std::lock_guard<std::mutex> lock(queueMutex);
                    this->messageQueue.push(msg);
                }
                cv.notify_one();
                } catch (const std::exception& e) {
                    logger->error("Error handling client: {}", e.what());
                }
                close(clientSock);
            }).detach();
        } catch (const std::exception& e) {
            logger->error("Error accepting TCP connection: {}", e.what());  
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}