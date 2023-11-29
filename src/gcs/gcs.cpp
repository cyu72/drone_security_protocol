#include "gcs.hpp"

const int PORT = 65456;
const int BUFFER_SIZE = 1024;

void signalHandler(int signum) {
    exit(signum);
}

void clientThread(int newSD){
    char buffer[BUFFER_SIZE];
    while (true) {
        
        // Send a response back to the client
        const char* response = "Hello from server!";
        ssize_t send_len = send(newSD, response, strlen(response), 0);
    }
}

void exitHandler(MESSAGE& msg){
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        std::cerr << "Error in socket creation." << std::endl;
        exit(EXIT_FAILURE);
    }

    int broadcastEnable = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_BROADCAST, &broadcastEnable, sizeof(broadcastEnable)) == -1) {
        perror("setsockopt");
        close(sockfd);
        return;
    }

    struct sockaddr_in broadcastAddress;
    memset(&broadcastAddress, 0, sizeof(broadcastAddress));
    broadcastAddress.sin_family = AF_INET;
    broadcastAddress.sin_port = htons(PORT);
    inet_pton(AF_INET, "172.18.255.255", &(broadcastAddress.sin_addr)); // TODO: Automate retrieving this docker network address

    ssize_t bytesSent = sendto(sockfd, &msg, sizeof(msg), 0, (struct sockaddr*)&broadcastAddress, sizeof(broadcastAddress));
    if (bytesSent == -1) {
        perror("sendto");
    }
}

void sendData(std::string containerName, MESSAGE& msg){
    // sends data to drone
    // create message, docker DNS resolution, then send to drone
    struct addrinfo hints, *result;
    std::memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET; // Use IPv4
    hints.ai_socktype = SOCK_DGRAM;
    
    int status = getaddrinfo(containerName.c_str(), std::to_string(PORT_NUMBER).c_str(), &hints, &result);
    if (status != 0) {
        std::cerr << "Error resolving host: " << gai_strerror(status) << std::endl;
        return;
    }

    int sockfd = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (sockfd == -1) {
        std::cerr << "Error creating socket" << std::endl;
        freeaddrinfo(result);
        return;
    }

    ssize_t bytesSent = sendto(sockfd, &msg, sizeof(msg), 0, (struct sockaddr*) result->ai_addr, result->ai_addrlen);
    if (bytesSent == -1) {
        std::cerr << "Error: " << strerror(errno) << std::endl;
    }

    freeaddrinfo(result);
    close(sockfd);
}

void initalizeServer(){
    int sockfd;
    struct sockaddr_in server_addr, client_addr;
    char buffer[BUFFER_SIZE];

    // Create UDP socket
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        std::cerr << "Error in socket creation." << std::endl;
        exit(EXIT_FAILURE);
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT_NUMBER);
    server_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        std::cerr << "Error in binding." << std::endl;
        exit(EXIT_FAILURE);
    }

    int inn, inn1;
    std::string containerName;
    std::cout << "GCS Server running on port " << PORT_NUMBER << std::endl;

    while (true) {
        std::cout << "1) Initiate Route Discovery\n2) Verify Neighbors\n3) Verify Message Contents\n4) Exit " << std::endl; // tests built with assumptions made on # of drones & distances
        std::cout << "> ";
        std::cin >> inn; 
        MESSAGE msg;
        // WARNING: THERE IS NO ERROR HANDLING FOR INPROPER INPUTS
        switch(inn){
            case 1:
                // select which drone does route discovery
                msg.type = INIT_ROUTE_DISCOVERY;
                std::cout << "Enter drone ID [number]: ";
                std::cin >> inn1;
                std::cout << "Enter destination ID [number]: ";
                std::cin >> msg.destID;
                containerName = "drone_security_protocol-drone" + std::to_string(inn1) + "-1";
                sendData(containerName, msg);
                break;
            case 2:
                // select which drone to verify neighbors
                msg.type = TEST;
                std::cout << "Enter drone ID [number]: ";
                std::cin >> inn1;   
                containerName = "drone_security_protocol-drone" + std::to_string(inn1) + "-1";
                sendData(containerName, msg);
                // send verify neighbors [temp: print out neighbor list for now]
                break;
            case 3:
                // select which drone to send request to 
                // send verify message contents
                break;
            case 4:
                msg.type = EXIT;
                exitHandler(msg);
                return;
            default:
                break;
        }       
        // wait for response from drone
        std::memset(&msg, 0, sizeof(msg));
    }
}


int main(){
    // signal(SIGINT, signalHandler);
    initalizeServer();
    return 0;
}