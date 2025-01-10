#include <cstring>
#include <stdexcept>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <iostream>
#include <chrono>
#include <thread>

class ipc_client {
private:
    int sock;
    int port;
    std::string host;
    struct sockaddr_in serv_addr;
    bool connected = false;

    void connect_to_server() {
        if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
            throw std::runtime_error("Socket creation error");
        }
  
        struct addrinfo hints = {}, *result;
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        
        // Convert port to string for getaddrinfo
        auto port_str = std::to_string(port);
        
        int status = getaddrinfo(host.c_str(), port_str.c_str(), &hints, &result);
        if (status != 0) {
            throw std::runtime_error("Failed to resolve host: " + std::string(gai_strerror(status)));
        }

        // Try each address until we successfully connect
        bool connected = false;
        for (struct addrinfo *rp = result; rp != nullptr; rp = rp->ai_next) {
            if (connect(sock, rp->ai_addr, rp->ai_addrlen) == 0) {
                connected = true;
                break;
            }
        }

        freeaddrinfo(result);

        if (!connected) {
            close(sock);
            throw std::runtime_error("Connection failed");
        }

        connected = true;
        std::cout << "Connected to server " << host << " on port " << port << std::endl;
    }

public:
    ipc_client(int port) : port(port) {
        // Get host from environment variable or use localhost as fallback
        const char* env_host = std::getenv("ROUTING_HOST");
        host = env_host ? env_host : "127.0.0.1";
        connect_to_server();
    }

    void sendData(const std::string& data) {
        if (!connected) {
            try {
                connect_to_server();
            } catch (const std::exception& e) {
                throw std::runtime_error("Failed to reconnect: " + std::string(e.what()));
            }
        }

        if (send(sock, data.c_str(), data.length(), 0) < 0) {
            connected = false;
            throw std::runtime_error("Failed to send data");
        }

        char buffer[1024] = {0};
        int bytes_read = read(sock, buffer, sizeof(buffer)-1);
        if (bytes_read <= 0) {
            connected = false;
            throw std::runtime_error("Failed to receive acknowledgment");
        }
    }

    ~ipc_client() {
        if (sock != -1) {
            close(sock);
        }
    }
};