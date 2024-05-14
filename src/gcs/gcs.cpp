#include "gcs.hpp"

const int BUFFER_SIZE = 1024;

void signalHandler(int signum) {
    exit(signum);
}

void exitHandler(MESSAGE& msg) { // TODO: update the broadcast for this function
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        std::cerr << "Error in socket creation." << endl;
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in broadcastAddress;
    memset(&broadcastAddress, 0, sizeof(broadcastAddress));
    broadcastAddress.sin_family = AF_INET;
    broadcastAddress.sin_port = htons(PORT_NUMBER);
    inet_pton(AF_INET, "172.18.255.255", &(broadcastAddress.sin_addr)); // TODO: Automate retrieving this docker network address

    if (connect(sockfd, (struct sockaddr*)&broadcastAddress, sizeof(broadcastAddress)) == -1) {
        perror("connect");
        close(sockfd);
        return;
    }

    ssize_t bytesSent = send(sockfd, &msg, sizeof(msg), 0);
    if (bytesSent == -1) {
        perror("send");
    }

    close(sockfd);
}

void sendData(const string& containerName, const string& msg) {
    // sends data to drone
    // create message, DNS resolution, then send to drone
    struct addrinfo hints, *result;
    std::memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET; // Use IPv4
    hints.ai_socktype = SOCK_STREAM; // Use TCP
    
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

    if (connect(sockfd, result->ai_addr, result->ai_addrlen) == -1) {
        std::cerr << "Error: " << strerror(errno) << endl;
        close(sockfd);
        freeaddrinfo(result);
        return;
    }

    ssize_t bytesSent = send(sockfd, msg.c_str(), msg.size(), 0);
    if (bytesSent == -1) {
        std::cerr << "Error: " << strerror(errno) << endl;
    }

    freeaddrinfo(result);
    close(sockfd);
}

void broadcastMessage(const string& msg) {
    int swarmSize = 15; // temp hardcode
    for (int i = 1; i <= swarmSize; ++i) {
        string containerName = "drone" + std::to_string(i) + "-service.default";
        sendData(containerName, msg);
    }
    cout << "Broadcast Message sent." << endl;
}

void initializeServer() {
    int listenSock;
    struct sockaddr_in server_addr;

    // Create TCP socket
    listenSock = socket(AF_INET, SOCK_STREAM, 0);
    if (listenSock < 0) {
        std::cerr << "Error in socket creation." << endl;
        exit(EXIT_FAILURE);
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT_NUMBER);
    server_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(listenSock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        std::cerr << "Error in binding." << endl;
        exit(EXIT_FAILURE);
    }

    if (listen(listenSock, 5) < 0) {
        std::cerr << "Error in listening." << endl;
        exit(EXIT_FAILURE);
    }

    int inn, inn1;
    string containerName;
    cout << "GCS Server running on port " << PORT_NUMBER << endl;

    while (true) {
        cout << "1) Initiate Route Discovery\n2) Verify Routes\n3) Delete Routes\n4) Exit " << endl; // tests built with assumptions made on # of drones & distances
        cout << "> ";
        std::cin >> inn; 
        // WARNING: THERE IS NO ERROR HANDLING FOR IMPROPER INPUTS
        GCS_MESSAGE msg;
        string jsonStr, destAddr;
        switch(inn){
            case 1:
                // select which drone does route discovery
                cout << "Enter drone ID [number]: ";
                std::cin >> inn1;
                containerName = "drone" + std::to_string(inn1) + "-service.default";
                cout << "Enter destination ID [number]: ";
                std::cin >> inn1;
                destAddr = "drone" + std::to_string(inn1) + "-service.default";
                if (containerName == destAddr){
                    cout << "Error: Cannot send message to self" << endl;
                    break;
                }
                msg = GCS_MESSAGE(containerName, destAddr, INIT_ROUTE_DISCOVERY);
                jsonStr = msg.serialize();
                sendData(containerName, jsonStr);
                break;
            case 2:
                cout << "Enter drone ID [number]: ";
                std::cin >> inn1;
                containerName = "drone" + std::to_string(inn1) + "-service.default";
                msg = GCS_MESSAGE(containerName, "NILL", VERIFY_ROUTE);
                jsonStr = msg.serialize();
                sendData(containerName, jsonStr);
                break;
            case 3:
                cout << "Enter drone ID [number]: ";
                std::cin >> inn1;
                // Add deletion functionality here.
                break;
            case 4:
                return;
            default:
                break;
        }       
    }
}

int main() {
    signal(SIGINT, signalHandler);
    initializeServer();
    return 0;
}
